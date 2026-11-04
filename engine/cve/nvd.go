package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// CVSS is an NVD severity assessment for a CVE.
type CVSS struct {
	Score    float64 `json:"score"`
	Severity string  `json:"severity"`
	Vector   string  `json:"vector,omitempty"`
	Version  string  `json:"version,omitempty"`
}

// CVEID returns the CVE identifier for an advisory: its own id when it is a CVE
// id, otherwise the first CVE alias (GHSA advisories carry one).
func (a Advisory) CVEID() string {
	if strings.HasPrefix(a.ID, "CVE-") {
		return a.ID
	}
	for _, alias := range a.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			return alias
		}
	}
	return ""
}

// NVDClient looks up CVSS metrics from the NVD 2.0 API. An API key is optional
// (NVD_API_KEY) and raises the rate limit.
type NVDClient struct {
	HTTP   *http.Client
	URL    string
	APIKey string
}

// NewNVDClient returns a client for the production NVD endpoint.
func NewNVDClient() *NVDClient {
	return &NVDClient{
		HTTP:   &http.Client{Timeout: 20 * time.Second},
		URL:    "https://services.nvd.nist.gov/rest/json/cves/2.0",
		APIKey: "",
	}
}

type nvdMetric struct {
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
		VectorString string  `json:"vectorString"`
	} `json:"cvssData"`
	BaseSeverity string `json:"baseSeverity"`
}

// Lookup returns the best CVSS metrics for a CVE id. ok is false when NVD has
// no metrics for it.
func (c *NVDClient) Lookup(ctx context.Context, cveID string) (CVSS, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL+"?cveId="+url.QueryEscape(cveID), nil)
	if err != nil {
		return CVSS{}, false, err
	}
	if c.APIKey != "" {
		req.Header.Set("apiKey", c.APIKey)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return CVSS{}, false, fmt.Errorf("NVD lookup %s: %w", cveID, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return CVSS{}, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return CVSS{}, false, fmt.Errorf("NVD HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	var out struct {
		Vulnerabilities []struct {
			CVE struct {
				Metrics struct {
					V31 []nvdMetric `json:"cvssMetricV31"`
					V30 []nvdMetric `json:"cvssMetricV30"`
					V2  []nvdMetric `json:"cvssMetricV2"`
				} `json:"metrics"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&out); err != nil {
		return CVSS{}, false, fmt.Errorf("decode NVD response: %w", err)
	}
	if len(out.Vulnerabilities) == 0 {
		return CVSS{}, false, nil
	}
	m := out.Vulnerabilities[0].CVE.Metrics
	for _, cand := range []struct {
		list    []nvdMetric
		version string
	}{{m.V31, "3.1"}, {m.V30, "3.0"}, {m.V2, "2.0"}} {
		if len(cand.list) == 0 {
			continue
		}
		d := cand.list[0].CVSSData
		severity := d.BaseSeverity
		if severity == "" {
			severity = cand.list[0].BaseSeverity
		}
		return CVSS{Score: d.BaseScore, Severity: severity, Vector: d.VectorString, Version: cand.version}, true, nil
	}
	return CVSS{}, false, nil
}

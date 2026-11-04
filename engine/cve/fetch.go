package cve

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client fetches live advisories. OSV has a per-package query API; the CISA KEV
// catalog is a single JSON document.
type Client struct {
	HTTP   *http.Client
	OSVURL string
	KEVURL string
}

// NewClient returns a client with production endpoints.
func NewClient() *Client {
	return &Client{
		HTTP:   &http.Client{Timeout: 20 * time.Second},
		OSVURL: "https://api.osv.dev/v1/query",
		KEVURL: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
	}
}

// QueryOSV asks the OSV API about one package version.
func (c *Client) QueryOSV(ctx context.Context, pkg Package) ([]Advisory, error) {
	body, err := json.Marshal(map[string]any{
		"package": map[string]string{"name": pkg.Name, "ecosystem": pkg.Ecosystem},
		"version": pkg.Version,
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.OSVURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("OSV query %s: %w", pkg.Name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("OSV HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	var out struct {
		Vulns []json.RawMessage `json:"vulns"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode OSV response: %w", err)
	}

	var advisories []Advisory
	for _, raw := range out.Vulns {
		advs, err := ParseOSV(bytes.NewReader(raw))
		if err != nil {
			continue
		}
		advisories = append(advisories, advs...)
	}
	return advisories, nil
}

// FetchKEV downloads and parses the CISA KEV catalog.
func (c *Client) FetchKEV(ctx context.Context) (map[string]bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.KEVURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch KEV: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("KEV HTTP %d", resp.StatusCode)
	}
	return ParseKEV(io.LimitReader(resp.Body, 64<<20))
}

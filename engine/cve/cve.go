// Package cve correlates known vulnerabilities with the packages a workload
// actually runs.
//
// Ingestion is file-based for the MVP (OSV advisories + the CISA KEV catalog),
// which keeps correlation deterministic and testable. Live feed ingestion is a
// later step; the matching logic is the same.
package cve

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Advisory is one known vulnerability relevant to a package.
type Advisory struct {
	ID             string    `json:"id"`
	Aliases        []string  `json:"aliases,omitempty"`
	Source         string    `json:"source"` // osv | kev
	Ecosystem      string    `json:"ecosystem,omitempty"`
	Package        string    `json:"package,omitempty"`
	Summary        string    `json:"summary,omitempty"`
	RawSeverity    string    `json:"severity,omitempty"`
	KnownExploited bool      `json:"known_exploited,omitempty"`
	Ranges         []Range   `json:"ranges,omitempty"`
	Versions       []string  `json:"versions,omitempty"`
	Published      time.Time `json:"published,omitempty"`
}

// Range is one affected version interval.
type Range struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

// Package is one dependency of a workload.
type Package struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}

// Match is an affected package.
type Match struct {
	Workload string   `json:"workload"`
	Package  Package  `json:"package"`
	Advisory Advisory `json:"advisory"`
	Fixed    string   `json:"fixed,omitempty"`
	// CVSS is populated when NVD enrichment is requested.
	CVSS *CVSS `json:"cvss,omitempty"`
}

// ---- OSV ----

type osvDoc struct {
	ID        string   `json:"id"`
	Aliases   []string `json:"aliases"`
	Summary   string   `json:"summary"`
	Details   string   `json:"details"`
	Published string   `json:"published"`
	Affected  []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string              `json:"type"`
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
		Versions []string `json:"versions"`
	} `json:"affected"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
}

// ParseOSV reads one OSV document (including its "affected" entries).
func ParseOSV(r io.Reader) ([]Advisory, error) {
	var doc osvDoc
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("parse OSV: %w", err)
	}
	if doc.ID == "" {
		return nil, fmt.Errorf("parse OSV: missing id")
	}
	var out []Advisory
	sev := ""
	if len(doc.Severity) > 0 {
		sev = doc.Severity[0].Score
	}
	published, _ := time.Parse(time.RFC3339, doc.Published)
	for _, a := range doc.Affected {
		adv := Advisory{
			ID:          doc.ID,
			Aliases:     doc.Aliases,
			Source:      "osv",
			Ecosystem:   a.Package.Ecosystem,
			Package:     a.Package.Name,
			Summary:     firstNonEmpty(doc.Summary, doc.Details),
			RawSeverity: sev,
			Versions:    a.Versions,
			Published:   published,
		}
		for _, rg := range a.Ranges {
			adv.Ranges = append(adv.Ranges, rangesToSegments(rg.Events)...)
		}
		out = append(out, adv)
	}
	return out, nil
}

func rangesToSegments(events []map[string]string) []Range {
	var segs []Range
	var cur Range
	for _, e := range events {
		if v, ok := e["introduced"]; ok {
			cur.Introduced = v
		}
		if v, ok := e["fixed"]; ok {
			cur.Fixed = v
			segs = append(segs, cur)
			cur = Range{}
		}
		if v, ok := e["last_affected"]; ok {
			cur.LastAffected = v
			segs = append(segs, cur)
			cur = Range{}
		}
	}
	if cur.Introduced != "" || cur.LastAffected != "" {
		segs = append(segs, cur)
	}
	return segs
}

// ---- CISA KEV ----

type kevDoc struct {
	Vulnerabilities []struct {
		CVEID                      string `json:"cveID"`
		VulnerabilityName          string `json:"vulnerabilityName"`
		DateAdded                  string `json:"dateAdded"`
		KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
		ShortDescription           string `json:"shortDescription"`
	} `json:"vulnerabilities"`
}

// ParseKEV returns the set of CVE ids in the CISA KEV catalog.
func ParseKEV(r io.Reader) (map[string]bool, error) {
	var doc kevDoc
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("parse KEV: %w", err)
	}
	out := make(map[string]bool, len(doc.Vulnerabilities))
	for _, v := range doc.Vulnerabilities {
		if v.CVEID != "" {
			out[strings.ToUpper(v.CVEID)] = true
		}
	}
	return out, nil
}

// ---- matching ----

// Correlate matches packages against advisories. KEV membership (by id or
// alias) marks an advisory as known-exploited.
func Correlate(workload string, pkgs []Package, advisories []Advisory, kev map[string]bool) []Match {
	var out []Match
	for _, p := range pkgs {
		for _, a := range advisories {
			if !strings.EqualFold(a.Package, p.Name) {
				continue
			}
			if a.Ecosystem != "" && p.Ecosystem != "" && !strings.EqualFold(a.Ecosystem, p.Ecosystem) {
				continue
			}
			ok, fixed := Affected(p.Version, a)
			if !ok {
				continue
			}
			a.KnownExploited = kev[strings.ToUpper(a.ID)] || anyAliasInKEV(a.Aliases, kev)
			out = append(out, Match{Workload: workload, Package: p, Advisory: a, Fixed: fixed})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Advisory.KnownExploited != out[j].Advisory.KnownExploited {
			return out[i].Advisory.KnownExploited
		}
		if out[i].Package.Name != out[j].Package.Name {
			return out[i].Package.Name < out[j].Package.Name
		}
		return out[i].Advisory.ID < out[j].Advisory.ID
	})
	return out
}

// Affected reports whether version falls in the advisory's affected set, and
// the fixed version for the matching range when known.
func Affected(version string, a Advisory) (bool, string) {
	for _, v := range a.Versions {
		if cmpVersion(v, version) == 0 {
			return true, bestFixed(a)
		}
	}
	for _, r := range a.Ranges {
		if r.Introduced != "" && r.Introduced != "0" && cmpVersion(version, r.Introduced) < 0 {
			continue
		}
		if r.Fixed != "" && cmpVersion(version, r.Fixed) >= 0 {
			continue
		}
		if r.LastAffected != "" && cmpVersion(version, r.LastAffected) > 0 {
			continue
		}
		return true, r.Fixed
	}
	return false, ""
}

func bestFixed(a Advisory) string {
	for _, r := range a.Ranges {
		if r.Fixed != "" {
			return r.Fixed
		}
	}
	return ""
}

func anyAliasInKEV(aliases []string, kev map[string]bool) bool {
	for _, al := range aliases {
		if kev[strings.ToUpper(al)] {
			return true
		}
	}
	return false
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// cmpVersion compares dotted numeric versions (major.minor.patch). Pre-release
// and build metadata are ignored, which is sufficient for the npm ecosystem's
// advisory ranges in this MVP.
func cmpVersion(a, b string) int {
	pa := parseVersion(a)
	pb := parseVersion(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func parseVersion(s string) [3]int {
	var v [3]int
	s = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(s), "v"))
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	for i := 0; i < 3 && i < len(parts); i++ {
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			return v
		}
		v[i] = n
	}
	return v
}

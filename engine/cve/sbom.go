package cve

import "time"

// SBOMEntry is one affected package in an uploaded software bill of materials.
type SBOMEntry struct {
	Name           string   `json:"name"`
	Version        string   `json:"version"`
	AdvisoryID     string   `json:"advisory_id"`
	Aliases        []string `json:"aliases,omitempty"`
	Summary        string   `json:"summary,omitempty"`
	Fixed          string   `json:"fixed,omitempty"`
	KnownExploited bool     `json:"known_exploited,omitempty"`
	CVSS           *CVSS    `json:"cvss,omitempty"`
}

// SBOM is the correlated software bill of materials an agent uploads so the
// control plane can show CVE exposure without fetching anything itself.
type SBOM struct {
	Workload  string      `json:"workload"`
	ScannedAt time.Time   `json:"scanned_at"`
	Packages  int         `json:"packages"`
	Entries   []SBOMEntry `json:"entries"`
}

// BuildSBOM turns correlation matches into an uploadable SBOM.
func BuildSBOM(workload string, packages int, matches []Match) SBOM {
	s := SBOM{Workload: workload, ScannedAt: time.Now().UTC(), Packages: packages}
	for _, m := range matches {
		s.Entries = append(s.Entries, SBOMEntry{
			Name:           m.Package.Name,
			Version:        m.Package.Version,
			AdvisoryID:     m.Advisory.ID,
			Aliases:        m.Advisory.Aliases,
			Summary:        m.Advisory.Summary,
			Fixed:          m.Fixed,
			KnownExploited: m.Advisory.KnownExploited,
			CVSS:           m.CVSS,
		})
	}
	return s
}

package cve

import (
	"strings"
	"testing"
)

const osv = `{
  "id": "GHSA-test-0001",
  "aliases": ["CVE-2026-0001"],
  "summary": "RCE in next",
  "published": "2026-01-02T00:00:00Z",
  "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
  "affected": [{
    "package": {"ecosystem": "npm", "name": "next"},
    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "15.0.4"}]}]
  }]
}`

const kev = `{"vulnerabilities":[{"cveID":"CVE-2026-0001","vulnerabilityName":"next RCE","dateAdded":"2026-01-03"}]}`

func TestParseAndMatch(t *testing.T) {
	advs, err := ParseOSV(strings.NewReader(osv))
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 1 || advs[0].ID != "GHSA-test-0001" {
		t.Fatalf("advisories = %+v", advs)
	}
	kevSet, err := ParseKEV(strings.NewReader(kev))
	if err != nil {
		t.Fatal(err)
	}

	pkgs := []Package{{Name: "next", Version: "15.0.2", Ecosystem: "npm"}}
	matches := Correlate("web", pkgs, advs, kevSet)
	if len(matches) != 1 {
		t.Fatalf("matches = %+v", matches)
	}
	m := matches[0]
	if !m.Advisory.KnownExploited {
		t.Error("advisory should be marked known-exploited via alias")
	}
	if m.Fixed != "15.0.4" {
		t.Errorf("fixed = %q, want 15.0.4", m.Fixed)
	}
}

func TestAffectedRanges(t *testing.T) {
	a := Advisory{
		Package: "next",
		Ranges:  []Range{{Introduced: "13.4.0", Fixed: "13.5.1"}, {Introduced: "14.0.0", Fixed: "14.2.5"}},
	}
	cases := []struct {
		v    string
		want bool
	}{
		{"13.4.0", true},
		{"13.5.0", true},
		{"13.5.1", false},
		{"13.3.0", false},
		{"14.2.4", true},
		{"14.2.5", false},
		{"15.0.0", false},
	}
	for _, c := range cases {
		got, _ := Affected(c.v, a)
		if got != c.want {
			t.Errorf("Affected(%s) = %v, want %v", c.v, got, c.want)
		}
	}
}

func TestExplicitVersions(t *testing.T) {
	a := Advisory{Versions: []string{"1.0.0", "1.0.1"}}
	if ok, _ := Affected("1.0.1", a); !ok {
		t.Error("explicit version should be affected")
	}
	if ok, _ := Affected("1.0.2", a); ok {
		t.Error("1.0.2 should not be affected")
	}
}

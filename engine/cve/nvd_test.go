package cve

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNVDLookupPrefersV31(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cveId") != "CVE-2024-43796" {
			t.Errorf("cveId = %q", r.URL.Query().Get("cveId"))
		}
		w.Write([]byte(`{"vulnerabilities":[{"cve":{"metrics":{
			"cvssMetricV31":[{"cvssData":{"baseScore":6.1,"baseSeverity":"MEDIUM","vectorString":"CVSS:3.1/AV:N"}}],
			"cvssMetricV2":[{"cvssData":{"baseScore":4.3},"baseSeverity":"MEDIUM"}]
		}}}]}`))
	}))
	defer srv.Close()

	c := NewNVDClient()
	c.URL = srv.URL
	got, ok, err := c.Lookup(context.Background(), "CVE-2024-43796")
	if err != nil || !ok {
		t.Fatalf("lookup: ok=%v err=%v", ok, err)
	}
	if got.Score != 6.1 || got.Severity != "MEDIUM" || got.Version != "3.1" {
		t.Fatalf("cvss = %+v", got)
	}
}

func TestCVSSFallsBackToV2AndCVEID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"vulnerabilities":[{"cve":{"metrics":{
			"cvssMetricV2":[{"cvssData":{"baseScore":4.3},"baseSeverity":"MEDIUM"}]
		}}}]}`))
	}))
	defer srv.Close()

	c := NewNVDClient()
	c.URL = srv.URL
	got, ok, err := c.Lookup(context.Background(), "CVE-2000-0001")
	if err != nil || !ok || got.Severity != "MEDIUM" || got.Version != "2.0" {
		t.Fatalf("v2 fallback: ok=%v err=%v cvss=%+v", ok, err, got)
	}

	if id := (Advisory{Aliases: []string{"GHSA-x", "CVE-2024-1"}}).CVEID(); id != "CVE-2024-1" {
		t.Fatalf("CVEID from alias = %q", id)
	}
	if id := (Advisory{ID: "CVE-2025-2"}).CVEID(); id != "CVE-2025-2" {
		t.Fatalf("CVEID = %q", id)
	}
}

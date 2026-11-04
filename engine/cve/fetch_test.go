package cve

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestQueryOSVLive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		var req struct {
			Package struct {
				Name      string `json:"name"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			Version string `json:"version"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.Package.Name != "next" || req.Version != "15.0.2" {
			t.Errorf("unexpected query: %+v", req)
		}
		json.NewEncoder(w).Encode(map[string]any{
			"vulns": []any{map[string]any{
				"id":      "GHSA-live-1",
				"aliases": []string{"CVE-2026-9999"},
				"summary": "RCE in next",
				"affected": []any{map[string]any{
					"package": map[string]string{"ecosystem": "npm", "name": "next"},
					"ranges": []any{map[string]any{
						"type":   "SEMVER",
						"events": []map[string]string{{"introduced": "0"}, {"fixed": "15.0.4"}},
					}},
				}},
			}},
		})
	}))
	defer srv.Close()

	c := NewClient()
	c.OSVURL = srv.URL
	advs, err := c.QueryOSV(context.Background(), Package{Name: "next", Version: "15.0.2", Ecosystem: "npm"})
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 1 || advs[0].ID != "GHSA-live-1" {
		t.Fatalf("advisories = %+v", advs)
	}
}

func TestFetchKEVLive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"vulnerabilities": []any{map[string]any{"cveID": "CVE-2026-9999"}},
		})
	}))
	defer srv.Close()

	c := NewClient()
	c.KEVURL = srv.URL
	kev, err := c.FetchKEV(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !kev["CVE-2026-9999"] {
		t.Fatalf("kev = %+v", kev)
	}
}

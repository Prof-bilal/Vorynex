package verify

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func srv() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health", "/echo":
			w.Write([]byte(`{"ok":true}`))
		case "/ping":
			w.Write([]byte(`{"error":"EACCES"}`))
		default:
			w.WriteHeader(404)
		}
	}))
}

func TestHealthNeverOverridesFailingWorkflow(t *testing.T) {
	s := srv()
	defer s.Close()
	rep := Run(s.URL, Corpus{
		Features: []string{"health", "ping"},
		Workflows: []Workflow{
			{Name: "health", Feature: "health", Required: true, Count: 3, Path: "/health", ExpectBody: `"ok":true`},
			{Name: "ping", Feature: "ping", Required: true, Count: 2, Path: "/ping", ExpectBody: `"ok":true`},
		},
	})
	if rep.Ready() || rep.Decision != "DO NOT ENFORCE" {
		t.Fatalf("failing required workflow must block: %s", rep.Decision)
	}
	if rep.Features["ping"] != StateConflict || rep.Features["health"] != StateVerified {
		t.Fatalf("states: %v", rep.Features)
	}
	if _, _, denied := rep.Totals(); denied != 2 {
		t.Fatalf("denied=%d", denied)
	}
}

func TestUncoveredFeatureBlocks(t *testing.T) {
	s := srv()
	defer s.Close()
	rep := Run(s.URL, Corpus{
		Features:  []string{"health", "upload"},
		Workflows: []Workflow{{Name: "health", Feature: "health", Required: true, Count: 1, Path: "/health"}},
	})
	if rep.Ready() || rep.Features["upload"] != StateInsufficient {
		t.Fatalf("uncovered feature must block: %v %s", rep.Features, rep.Decision)
	}
}

func TestAllPass(t *testing.T) {
	s := srv()
	defer s.Close()
	rep := Run(s.URL, Corpus{
		Features:  []string{"echo"},
		Workflows: []Workflow{{Name: "echo", Feature: "echo", Required: true, Count: 2, Path: "/echo"}},
	})
	if !rep.Ready() {
		t.Fatalf("should be ready: %v", rep.Reasons)
	}
}

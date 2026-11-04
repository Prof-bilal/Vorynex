package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestSBOMUploadAndRead(t *testing.T) {
	s := policyServer(t)
	h := s.Handler()
	do(t, h, http.MethodPost, "/v1/enroll", `{"host_id":"h1","hostname":"web"}`, true)

	body := `{"sbom":{"workload":"web","packages":10,"entries":[{"name":"next","version":"15.0.2","advisory_id":"GHSA-1","known_exploited":true}]}}`
	if rec := do(t, h, http.MethodPost, "/v1/hosts/h1/sbom", body, true); rec.Code != 200 {
		t.Fatalf("upload sbom: %d %s", rec.Code, rec.Body)
	}
	rec := do(t, h, http.MethodGet, "/v1/hosts/h1/sbom", "", true)
	if rec.Code != 200 {
		t.Fatalf("read sbom: %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "GHSA-1") {
		t.Fatalf("sbom round-trip lost data: %s", rec.Body)
	}
	// Malformed SBOM is rejected.
	if rec := do(t, h, http.MethodPost, "/v1/hosts/h1/sbom", `{"sbom":`, true); rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed sbom: got %d, want 400", rec.Code)
	}
	// Unknown host has no SBOM.
	if rec := do(t, h, http.MethodGet, "/v1/hosts/nope/sbom", "", true); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown host sbom: got %d, want 404", rec.Code)
	}
}

func TestRolloutStagesValidatedDesiredState(t *testing.T) {
	s := policyServer(t)
	h := s.Handler()
	do(t, h, http.MethodPost, "/v1/enroll", `{"host_id":"h1","hostname":"web"}`, true)

	// Invalid policy is rejected before anything is stored.
	body := `{"mode":"protect","policy_yaml":"filesystem: [broken"}`
	if rec := do(t, h, http.MethodPost, "/v1/hosts/h1/rollout", body, true); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid rollout policy: got %d, want 422 (%s)", rec.Code, rec.Body)
	}

	stage, _ := json.Marshal(map[string]string{"mode": "protect", "policy_yaml": validPolicyYAML})
	if rec := do(t, h, http.MethodPost, "/v1/hosts/h1/rollout", string(stage), true); rec.Code != 200 {
		t.Fatalf("stage rollout: %d %s", rec.Code, rec.Body)
	}

	rec := do(t, h, http.MethodGet, "/v1/hosts/h1/desired", "", true)
	if rec.Code != 200 {
		t.Fatalf("desired: %d %s", rec.Code, rec.Body)
	}
	var got struct {
		Rollout struct {
			Revision   int    `json:"revision"`
			Mode       string `json:"mode"`
			PolicyYAML string `json:"policy_yaml"`
		} `json:"rollout"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Rollout.Revision != 1 || got.Rollout.Mode != "protect" || got.Rollout.PolicyYAML == "" {
		t.Fatalf("desired = %+v", got.Rollout)
	}

	// A second staging bumps the revision.
	if rec := do(t, h, http.MethodPost, "/v1/hosts/h1/rollout", `{"mode":"lockdown"}`, true); rec.Code != 200 {
		t.Fatalf("restage: %d %s", rec.Code, rec.Body)
	}
	rec = do(t, h, http.MethodGet, "/v1/hosts/h1/desired", "", true)
	json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Rollout.Revision != 2 || got.Rollout.Mode != "lockdown" || got.Rollout.PolicyYAML == "" {
		t.Fatalf("after restage, desired = %+v", got.Rollout)
	}

	// Unknown host is a 404.
	if rec := do(t, h, http.MethodPost, "/v1/hosts/nope/rollout", `{"mode":"protect"}`, true); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown host rollout: %d", rec.Code)
	}
}

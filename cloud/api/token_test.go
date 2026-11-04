package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func doTok(t *testing.T, h http.Handler, method, path, body, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestEnrollIssuesPerHostTokenAndRotates(t *testing.T) {
	s := policyServer(t)
	h := s.Handler()

	// Enroll as admin: the control plane issues a per-host token.
	rec := do(t, h, http.MethodPost, "/v1/enroll", `{"host_id":"h1","hostname":"web"}`, true)
	if rec.Code != 200 {
		t.Fatalf("enroll: %d %s", rec.Code, rec.Body)
	}
	var enrolled struct {
		HostToken string `json:"host_token"`
	}
	json.Unmarshal(rec.Body.Bytes(), &enrolled)
	if enrolled.HostToken == "" {
		t.Fatal("no per-host token issued")
	}

	// Enrolling again does not re-issue (and never leaks the stored token).
	rec = do(t, h, http.MethodPost, "/v1/enroll", `{"host_id":"h1"}`, true)
	if strings.Contains(rec.Body.String(), enrolled.HostToken) {
		t.Fatalf("enroll leaked the host token: %s", rec.Body)
	}
	if strings.Contains(rec.Body.String(), "host_token") {
		t.Fatalf("enroll re-issued a token: %s", rec.Body)
	}

	// The host token can post that host's events...
	if rec := doTok(t, h, http.MethodPost, "/v1/events", `{"host_id":"h1","records":[]}`, enrolled.HostToken); rec.Code != 200 {
		t.Fatalf("host token events: %d %s", rec.Code, rec.Body)
	}
	// ...but not another host's.
	if rec := doTok(t, h, http.MethodPost, "/v1/events", `{"host_id":"h2","records":[]}`, enrolled.HostToken); rec.Code != http.StatusUnauthorized {
		t.Fatalf("host token crossed hosts: %d", rec.Code)
	}
	// ...and cannot list hosts (admin only).
	if rec := doTok(t, h, http.MethodGet, "/v1/hosts", "", enrolled.HostToken); rec.Code != http.StatusUnauthorized {
		t.Fatalf("host token listed hosts: %d", rec.Code)
	}
	// The host token can read its own policy endpoint (404 until uploaded).
	if rec := doTok(t, h, http.MethodGet, "/v1/hosts/h1/policy", "", enrolled.HostToken); rec.Code != http.StatusNotFound {
		t.Fatalf("host token policy read: %d", rec.Code)
	}

	// Rotate: the old token stops working, the new one works.
	rec = do(t, h, http.MethodPost, "/v1/hosts/h1/rotate-token", "", true)
	if rec.Code != 200 {
		t.Fatalf("rotate: %d %s", rec.Code, rec.Body)
	}
	var rotated struct {
		HostToken string `json:"host_token"`
	}
	json.Unmarshal(rec.Body.Bytes(), &rotated)
	if rotated.HostToken == "" || rotated.HostToken == enrolled.HostToken {
		t.Fatalf("rotation did not change the token: %+v", rotated)
	}
	if rec := doTok(t, h, http.MethodPost, "/v1/events", `{"host_id":"h1","records":[]}`, enrolled.HostToken); rec.Code != http.StatusUnauthorized {
		t.Fatalf("old token still works: %d", rec.Code)
	}
	if rec := doTok(t, h, http.MethodPost, "/v1/events", `{"host_id":"h1","records":[]}`, rotated.HostToken); rec.Code != 200 {
		t.Fatalf("new token rejected: %d %s", rec.Code, rec.Body)
	}
}

func TestRotateRequiresAdmin(t *testing.T) {
	s := policyServer(t)
	h := s.Handler()
	do(t, h, http.MethodPost, "/v1/enroll", `{"host_id":"h1"}`, true)
	if rec := doTok(t, h, http.MethodPost, "/v1/hosts/h1/rotate-token", "", "some-host-token"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("rotate without admin: got %d, want 401", rec.Code)
	}
}

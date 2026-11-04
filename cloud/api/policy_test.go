package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const validPolicyYAML = `version: 1
filesystem:
  read: ["/app"]
  write: ["/app/uploads"]
  protect_secrets: true
network:
  allow: ["api.stripe.com"]
process:
  exec:
    allow: ["/usr/bin/node"]
    deny: ["/bin/bash"]
`

func policyServer(t *testing.T) *Server {
	t.Helper()
	store := NewStore(t.TempDir() + "/store.jsonl")
	return New("tok", store)
}

func do(t *testing.T, h http.Handler, method, path, body string, auth bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if auth {
		req.Header.Set("Authorization", "Bearer tok")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestPolicyUploadAndRead(t *testing.T) {
	s := policyServer(t)
	h := s.Handler()

	if rec := do(t, h, http.MethodPost, "/v1/enroll", `{"host_id":"h1","hostname":"web"}`, true); rec.Code != 200 {
		t.Fatalf("enroll: %d %s", rec.Code, rec.Body)
	}

	body, _ := json.Marshal(map[string]string{"yaml": validPolicyYAML})
	rec := do(t, h, http.MethodPost, "/v1/hosts/h1/policy", string(body), true)
	if rec.Code != 200 {
		t.Fatalf("upload: %d %s", rec.Code, rec.Body)
	}

	rec = do(t, h, http.MethodGet, "/v1/hosts/h1/policy", "", true)
	if rec.Code != 200 {
		t.Fatalf("get: %d %s", rec.Code, rec.Body)
	}
	var got struct {
		Summary struct {
			Version        int      `json:"version"`
			Read           []string `json:"read"`
			ExecDeny       []string `json:"exec_deny"`
			NetworkAllow   []string `json:"network_allow"`
			ProtectSecrets bool     `json:"protect_secrets"`
		} `json:"summary"`
		BlastRadius struct {
			Workload  string `json:"workload"`
			Contained []struct {
				Class string `json:"class"`
			} `json:"contained"`
		} `json:"blast_radius"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Summary.Version != 1 || len(got.Summary.Read) != 1 || !got.Summary.ProtectSecrets {
		t.Fatalf("summary = %+v", got.Summary)
	}
	if got.Summary.ExecDeny[0] != "/bin/bash" {
		t.Fatalf("exec deny = %v", got.Summary.ExecDeny)
	}
	if got.BlastRadius.Workload != "h1" || len(got.BlastRadius.Contained) == 0 {
		t.Fatalf("blast radius = %+v", got.BlastRadius)
	}
}

func TestPolicyUploadRejectsInvalid(t *testing.T) {
	s := policyServer(t)
	h := s.Handler()

	body, _ := json.Marshal(map[string]string{"yaml": "filesystem: [not: a: policy"})
	if rec := do(t, h, http.MethodPost, "/v1/hosts/h1/policy", string(body), true); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid policy: got %d, want 422 (%s)", rec.Code, rec.Body)
	}
}

func TestPolicyRequiresAuth(t *testing.T) {
	s := policyServer(t)
	rec := do(t, s.Handler(), http.MethodGet, "/v1/hosts/h1/policy", "", false)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", rec.Code)
	}
}

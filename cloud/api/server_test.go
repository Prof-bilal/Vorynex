package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/vorynex/vorynex/engine/audit"
	"github.com/vorynex/vorynex/engine/telemetry"
)

func TestServerEnrollIngestAuth(t *testing.T) {
	st := NewStore(filepath.Join(t.TempDir(), "events.jsonl"))
	ts := httptest.NewServer(New("secret", st).Handler())
	defer ts.Close()

	post := func(path, token string, body any) *http.Response {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPost, ts.URL+path, bytes.NewReader(b))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	resp := post("/v1/enroll", "wrong", map[string]string{"host_id": "h1"})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong token: want 401, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = post("/v1/enroll", "secret", map[string]string{"host_id": "h1", "hostname": "web"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enroll: got %d", resp.StatusCode)
	}
	resp.Body.Close()

	recs := []telemetry.Record{{Seq: 1, Event: audit.Event{Type: "file", Action: "openat", Resource: "/app", Allowed: true}}}
	resp = post("/v1/events", "secret", map[string]any{"host_id": "h1", "records": recs})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("events: got %d", resp.StatusCode)
	}
	var out struct {
		Accepted int `json:"accepted"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	if out.Accepted != 1 {
		t.Fatalf("accepted = %d, want 1", out.Accepted)
	}

	if hosts := st.Hosts(); len(hosts) != 1 {
		t.Fatalf("hosts = %v, want 1", hosts)
	}
}

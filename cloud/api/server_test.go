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

func TestServerLifecycle(t *testing.T) {
	st := NewStore(filepath.Join(t.TempDir(), "events.jsonl"))
	ts := httptest.NewServer(New("secret", st).Handler())
	defer ts.Close()

	do := func(method, path, token string, body any) (*http.Response, []byte) {
		var rdr *bytes.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rdr = bytes.NewReader(b)
		} else {
			rdr = bytes.NewReader(nil)
		}
		req, _ := http.NewRequest(method, ts.URL+path, rdr)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		buf.ReadFrom(resp.Body)
		resp.Body.Close()
		return resp, buf.Bytes()
	}

	if resp, _ := do("GET", "/v1/hosts", "wrong", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong token: got %d, want 401", resp.StatusCode)
	}
	if resp, _ := do("POST", "/v1/enroll", "secret", map[string]string{"host_id": "h1", "hostname": "web"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("enroll: got %d", resp.StatusCode)
	}

	recs := []telemetry.Record{
		{Seq: 1, Event: audit.Event{Type: "file", Action: "openat", Resource: "/app/server.js", Allowed: true}},
		{Seq: 2, Event: audit.Event{Type: "file", Action: "execve", Resource: "/usr/bin/bash", Allowed: false, Reason: "denied by policy"}},
	}
	if resp, _ := do("POST", "/v1/events", "secret", map[string]any{"host_id": "h1", "records": recs}); resp.StatusCode != http.StatusOK {
		t.Fatalf("ingest: got %d", resp.StatusCode)
	}

	var hosts struct {
		Hosts []Host `json:"hosts"`
	}
	_, body := do("GET", "/v1/hosts", "secret", nil)
	json.Unmarshal(body, &hosts)
	if len(hosts.Hosts) != 1 || hosts.Hosts[0].Mode != "observe" {
		t.Fatalf("hosts = %+v", hosts.Hosts)
	}

	var evs struct {
		Events []StoredEvent `json:"events"`
	}
	_, body = do("GET", "/v1/events?limit=10", "secret", nil)
	json.Unmarshal(body, &evs)
	if len(evs.Events) != 2 {
		t.Fatalf("events = %d, want 2", len(evs.Events))
	}
	if evs.Events[0].Record.Seq != 2 {
		t.Fatalf("events not newest-first: %+v", evs.Events)
	}

	if resp, _ := do("POST", "/v1/hosts/h1/mode", "secret", map[string]string{"mode": "protect"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("set mode: got %d", resp.StatusCode)
	}
	_, body = do("GET", "/v1/hosts", "secret", nil)
	hosts.Hosts = nil
	json.Unmarshal(body, &hosts)
	if len(hosts.Hosts) != 1 || hosts.Hosts[0].Mode != "protect" {
		t.Fatalf("mode not persisted: %+v", hosts.Hosts)
	}

	if resp, _ := do("POST", "/v1/hosts/h1/mode", "secret", map[string]string{"mode": "nonsense"}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid mode: got %d, want 400", resp.StatusCode)
	}
}

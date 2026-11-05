package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/vorynex/vorynex/engine/audit"
	"github.com/vorynex/vorynex/engine/telemetry"
)

// TestSupabaseMirrorPersistsFleetState verifies the PostgREST integration shape:
// hosts (with their policy) are upserted on register/mode/policy, and events are
// inserted on ingest. A real Supabase project is not required — the test server
// stands in for PostgREST and asserts the path, headers, and body.
func TestSupabaseMirrorPersistsFleetState(t *testing.T) {
	var mu sync.Mutex
	type captured struct {
		path        string
		conflict    string
		apikey      string
		auth        string
		prefer      string
		contentType string
		body        []byte
	}
	var got []captured

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(b)
		mu.Lock()
		got = append(got, captured{
			path:        r.URL.Path,
			conflict:    r.URL.Query().Get("on_conflict"),
			apikey:      r.Header.Get("apikey"),
			auth:        r.Header.Get("Authorization"),
			prefer:      r.Header.Get("Prefer"),
			contentType: r.Header.Get("Content-Type"),
			body:        b,
		})
		mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	st := NewStore(t.TempDir() + "/store.jsonl")
	st.EnableSupabase(&SupabaseMirror{baseURL: srv.URL + "/rest/v1", key: "service-role-key", http: srv.Client()})

	st.RegisterHost("h1", "web")
	st.SetMode("h1", "protect")
	st.SetPolicy("h1", "version: 1\n")
	if _, err := st.AppendRecords("h1", []telemetry.Record{
		{Seq: 1, Event: mustEvent(t, "openat", "/app/.env", false, "EACCES")},
	}); err != nil {
		t.Fatal(err)
	}

	// Mirror writes are queued; drain them so the assertions see a settled state.
	st.FlushMirror(5 * time.Second)

	// Writes are FIFO, so the last host upsert must be the SetPolicy one: the
	// earlier RegisterHost write (mode=observe, no policy) must not win.
	deadline := time.Now().Add(3 * time.Second)
	var hosts, events []captured
	for time.Now().Before(deadline) {
		mu.Lock()
		hosts, events = nil, nil
		for _, c := range got {
			switch c.path {
			case "/rest/v1/hosts":
				hosts = append(hosts, c)
			case "/rest/v1/events":
				events = append(events, c)
			}
		}
		mu.Unlock()
		if len(hosts) >= 1 && len(events) >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if len(hosts) == 0 {
		t.Fatalf("no host upsert reached PostgREST; captured=%d", len(got))
	}
	last := hosts[len(hosts)-1]
	if last.conflict != "id" {
		t.Errorf("host upsert on_conflict = %q, want id", last.conflict)
	}
	if last.apikey != "service-role-key" || last.auth != "Bearer service-role-key" {
		t.Errorf("host upsert auth headers = %q / %q", last.apikey, last.auth)
	}
	if last.prefer != "resolution=merge-duplicates,return=minimal" {
		t.Errorf("host upsert Prefer = %q", last.prefer)
	}
	var row supabaseHostRow
	if err := json.Unmarshal(last.body, &row); err != nil {
		t.Fatalf("decode host row: %v (%s)", err, last.body)
	}
	if row.ID != "h1" || row.Mode != "protect" || row.PolicyYAML == "" {
		t.Errorf("host row = %+v", row)
	}

	if len(events) == 0 {
		t.Fatal("no events insert reached PostgREST")
	}
	var evRows []supabaseEventRow
	if err := json.Unmarshal(events[0].body, &evRows); err != nil {
		t.Fatalf("decode event rows: %v (%s)", err, events[0].body)
	}
	if len(evRows) != 1 || evRows[0].HostID != "h1" || evRows[0].Resource != "/app/.env" {
		t.Errorf("event rows = %+v", evRows)
	}
}

func TestSupabaseMirrorDisabledWithoutEnv(t *testing.T) {
	t.Setenv("SUPABASE_URL", "")
	t.Setenv("SUPABASE_SERVICE_ROLE_KEY", "")
	if m := NewSupabaseMirrorFromEnv(); m != nil {
		t.Fatal("mirror should be nil when SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY are unset")
	}
	t.Setenv("SUPABASE_URL", "https://example.supabase.co")
	t.Setenv("SUPABASE_SERVICE_ROLE_KEY", "k")
	m := NewSupabaseMirrorFromEnv()
	if m == nil || m.Endpoint() != "https://example.supabase.co/rest/v1" {
		t.Fatalf("mirror endpoint = %v", m)
	}
}

func mustEvent(t *testing.T, action, resource string, allowed bool, reason string) audit.Event {
	t.Helper()
	return audit.Event{
		Timestamp: time.Now().UTC(),
		Type:      "file",
		Action:    action,
		Resource:  resource,
		Allowed:   allowed,
		Reason:    reason,
	}
}

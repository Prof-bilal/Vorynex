package telemetry

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
)

func TestClientExportResumable(t *testing.T) {
	var mu sync.Mutex
	var received []Record
	var enrolled bool

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/v1/enroll":
			enrolled = true
			json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		case "/v1/events":
			var req struct {
				HostID  string   `json:"host_id"`
				Records []Record `json:"records"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			mu.Lock()
			received = append(received, req.Records...)
			mu.Unlock()
			json.NewEncoder(w).Encode(map[string]int{"accepted": len(req.Records)})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	spool, err := OpenSpool(filepath.Join(t.TempDir(), "s.jsonl"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		spool.Append(ev("x"))
	}

	c := NewClient(ts.URL, "tok")
	ctx := context.Background()
	if err := c.Enroll(ctx, "host_x", "testhost"); err != nil {
		t.Fatal(err)
	}
	if !enrolled {
		t.Fatal("enroll not received")
	}

	cursor, sent, err := c.Export(ctx, spool, "host_x", 0)
	if err != nil {
		t.Fatal(err)
	}
	if sent != 5 || cursor != 5 {
		t.Fatalf("export sent=%d cursor=%d, want 5/5", sent, cursor)
	}

	// A second export from the same cursor sends nothing (resumable).
	_, sent2, err := c.Export(ctx, spool, "host_x", cursor)
	if err != nil {
		t.Fatal(err)
	}
	if sent2 != 0 {
		t.Fatalf("second export sent %d, want 0", sent2)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 5 {
		t.Fatalf("server received %d records, want 5", len(received))
	}
}

func TestClientExportStopsOnError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer ts.Close()

	spool, _ := OpenSpool(filepath.Join(t.TempDir(), "s.jsonl"), 1<<20)
	spool.Append(ev("x"))
	c := NewClient(ts.URL, "")
	cursor, sent, err := c.Export(context.Background(), spool, "h", 0)
	if err == nil {
		t.Fatal("expected an error when the cloud is down")
	}
	if sent != 0 || cursor != 0 {
		t.Fatalf("cursor must not advance on error: cursor=%d sent=%d", cursor, sent)
	}
}

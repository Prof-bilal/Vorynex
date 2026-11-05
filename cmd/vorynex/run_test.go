package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestCheckHealthHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ok" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	if err := checkHealth(srv.URL + "/ok"); err != nil {
		t.Fatalf("healthy URL rejected: %v", err)
	}
	if err := checkHealth(srv.URL + "/down"); err == nil {
		t.Fatal("503 should fail the health check")
	}
}

func TestCheckHealthCommand(t *testing.T) {
	if err := checkHealth("true"); err != nil {
		t.Fatalf("`true` should be healthy: %v", err)
	}
	if err := checkHealth("exit 3"); err == nil {
		t.Fatal("`exit 3` should fail the health check")
	}
}

func TestWaitHealthyTimesOut(t *testing.T) {
	start := time.Now()
	err := waitHealthy("exit 1", 10*time.Millisecond, 150*time.Millisecond, 1)
	if err == nil {
		t.Fatal("expected a timeout error")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("timeout took %s, expected ~150ms", elapsed)
	}
}

func TestWaitHealthyRequiresConsecutivePasses(t *testing.T) {
	dir := t.TempDir()
	flag := dir + "/ready"
	go func() {
		time.Sleep(80 * time.Millisecond)
		_ = os.WriteFile(flag, nil, 0o600)
	}()
	if err := waitHealthy("test -f "+flag, 20*time.Millisecond, 3*time.Second, 2); err != nil {
		t.Fatalf("should become healthy after the flag appears: %v", err)
	}
}

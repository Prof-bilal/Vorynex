package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// SupabaseMirror persists control-plane state to a Supabase (Postgres) project
// over PostgREST, so fleet state survives past a single JSONL file and is
// queryable for multi-node deployments.
//
// It is best-effort by design: writes run with a short timeout and a failure is
// logged, never returned. The control plane stays authoritative locally, so a
// Supabase outage cannot break ingestion or (much more importantly) enforcement
// on the host.
type SupabaseMirror struct {
	baseURL string
	key     string
	http    *http.Client
}

// NewSupabaseMirrorFromEnv returns a mirror when SUPABASE_URL and
// SUPABASE_SERVICE_ROLE_KEY are set, otherwise nil (JSONL-only mode).
func NewSupabaseMirrorFromEnv() *SupabaseMirror {
	url := strings.TrimRight(strings.TrimSpace(os.Getenv("SUPABASE_URL")), "/")
	key := strings.TrimSpace(os.Getenv("SUPABASE_SERVICE_ROLE_KEY"))
	if url == "" || key == "" {
		return nil
	}
	return &SupabaseMirror{
		baseURL: url + "/rest/v1",
		key:     key,
		http:    &http.Client{Timeout: 5 * time.Second},
	}
}

// Endpoint reports the PostgREST base URL (for startup logging).
func (m *SupabaseMirror) Endpoint() string {
	if m == nil {
		return ""
	}
	return m.baseURL
}

func (m *SupabaseMirror) upsert(ctx context.Context, table, onConflict string, rows any) error {
	if m == nil {
		return nil
	}
	body, err := json.Marshal(rows)
	if err != nil {
		return err
	}
	u := m.baseURL + "/" + table
	if onConflict != "" {
		u += "?on_conflict=" + onConflict
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("apikey", m.key)
	req.Header.Set("Authorization", "Bearer "+m.key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Prefer", "resolution=merge-duplicates,return=minimal")

	resp, err := m.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return fmt.Errorf("supabase %s: HTTP %d: %s", table, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

type supabaseHostRow struct {
	ID         string `json:"id"`
	Hostname   string `json:"hostname,omitempty"`
	Mode       string `json:"mode,omitempty"`
	PolicyYAML string `json:"policy_yaml,omitempty"`
}

type supabaseEventRow struct {
	HostID   string    `json:"host_id"`
	Seq      uint64    `json:"seq"`
	TS       time.Time `json:"ts"`
	Type     string    `json:"type"`
	Action   string    `json:"action"`
	Resource string    `json:"resource"`
	Allowed  bool      `json:"allowed"`
	Reason   string    `json:"reason,omitempty"`
}

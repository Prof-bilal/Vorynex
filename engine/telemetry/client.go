package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client is the outbound-only telemetry exporter. It never blocks enforcement:
// callers run it separately and may retry indefinitely.
type Client struct {
	Endpoint  string
	Token     string
	BatchSize int
	HTTP      *http.Client
}

// NewClient builds an exporter for a cloud endpoint.
func NewClient(endpoint, token string) *Client {
	return &Client{
		Endpoint:  strings.TrimRight(endpoint, "/"),
		Token:     token,
		BatchSize: 256,
		HTTP:      &http.Client{Timeout: 10 * time.Second},
	}
}

// Enroll registers this host with the cloud control plane.
func (c *Client) Enroll(ctx context.Context, hostID, hostname string) error {
	body, _ := json.Marshal(map[string]string{"host_id": hostID, "hostname": hostname})
	var out struct {
		OK bool `json:"ok"`
	}
	if err := c.post(ctx, "/v1/enroll", body, &out); err != nil {
		return err
	}
	if !out.OK {
		return fmt.Errorf("telemetry: enrollment rejected")
	}
	return nil
}

// Send uploads a batch of records.
func (c *Client) Send(ctx context.Context, hostID string, records []Record) (int, error) {
	body, _ := json.Marshal(map[string]any{"host_id": hostID, "records": records})
	var out struct {
		Accepted int `json:"accepted"`
	}
	if err := c.post(ctx, "/v1/events", body, &out); err != nil {
		return 0, err
	}
	return out.Accepted, nil
}

// Export drains the spool after cursor in batches and returns the new cursor.
// It stops at the first error so the caller can retry later.
func (c *Client) Export(ctx context.Context, spool *Spool, hostID string, cursor uint64) (uint64, int, error) {
	records, err := spool.ReadAfter(cursor)
	if err != nil {
		return cursor, 0, err
	}
	sent := 0
	for start := 0; start < len(records); start += c.BatchSize {
		end := start + c.BatchSize
		if end > len(records) {
			end = len(records)
		}
		batch := records[start:end]
		if _, err := c.Send(ctx, hostID, batch); err != nil {
			return cursor, sent, err
		}
		cursor = batch[len(batch)-1].Seq
		sent += len(batch)
	}
	return cursor, sent, nil
}

func (c *Client) post(ctx context.Context, path string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("telemetry: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("telemetry: %s: HTTP %d: %s", path, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return err
		}
	}
	return nil
}

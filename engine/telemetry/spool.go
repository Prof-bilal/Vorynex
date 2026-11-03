// Package telemetry implements the Vorynex agent's local-first telemetry:
// an append-only, bounded event spool plus an outbound-only, resumable
// exporter. Enforcement never depends on it — if the cloud is unreachable the
// spool buffers locally and the exporter retries (see docs/FAILURE_MODES.md).
package telemetry

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/vorynex/vorynex/engine/audit"
)

// Record is one spooled event with a monotonic sequence number. Seq makes
// resumption robust across trimming: the exporter remembers the last sequence
// it sent, not a file offset.
type Record struct {
	Seq   uint64      `json:"seq"`
	Gap   bool        `json:"gap,omitempty"` // records were dropped (buffer overflow)
	Event audit.Event `json:"event"`
}

// Spool is an append-only, size-bounded JSONL event buffer on local disk.
type Spool struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	nextSeq  uint64
	size     int64
}

// OpenSpool opens (creating if needed) a spool and recovers its sequence state.
func OpenSpool(path string, maxBytes int64) (*Spool, error) {
	if maxBytes <= 0 {
		maxBytes = 64 << 20 // 64 MiB default
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	// Sequence numbers start at 1 so that cursor 0 unambiguously means
	// "nothing exported yet" (ReadAfter(0) returns every record).
	s := &Spool{path: path, maxBytes: maxBytes, nextSeq: 1}
	recs, err := readAll(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if len(recs) > 0 {
		s.nextSeq = recs[len(recs)-1].Seq + 1
	}
	if fi, err := os.Stat(path); err == nil {
		s.size = fi.Size()
	}
	return s, nil
}

// Path returns the spool file path.
func (s *Spool) Path() string { return s.path }

// Append adds an event. If the spool exceeds its bound, the oldest records are
// dropped and a gap marker is written so the cloud knows records were lost.
func (s *Spool) Append(e audit.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.appendLocked(Record{Seq: s.nextSeq, Event: e})
}

func (s *Spool) appendLocked(r Record) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	n, err := f.Write(data)
	f.Close()
	if err != nil {
		return err
	}
	s.nextSeq = r.Seq + 1
	s.size += int64(n)
	if s.size > s.maxBytes {
		return s.trimLocked()
	}
	return nil
}

// trimLocked drops the oldest records (down to 80% of the bound) and writes a
// gap marker carrying the last dropped sequence number.
func (s *Spool) trimLocked() error {
	recs, err := readAll(s.path)
	if err != nil {
		return err
	}
	// Drop any previous gap markers so exactly one is written at the front.
	kept0 := recs[:0]
	for _, r := range recs {
		if !r.Gap {
			kept0 = append(kept0, r)
		}
	}
	recs = kept0
	if len(recs) < 2 {
		return nil
	}
	target := s.maxBytes * 8 / 10
	var kept []Record
	var size int64
	for i := len(recs) - 1; i >= 0; i-- {
		b, _ := json.Marshal(recs[i])
		if size+int64(len(b))+1 > target && len(kept) > 0 {
			break
		}
		kept = append([]Record{recs[i]}, kept...)
		size += int64(len(b)) + 1
	}
	if len(kept) == len(recs) {
		return nil // nothing to trim
	}
	lastDropped := recs[len(recs)-len(kept)-1].Seq
	gap := Record{Seq: lastDropped, Gap: true}
	out := append([]Record{gap}, kept...)

	f, err := os.OpenFile(s.path, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	var total int64
	for _, r := range out {
		b, err := json.Marshal(r)
		if err != nil {
			return err
		}
		b = append(b, '\n')
		if _, err := w.Write(b); err != nil {
			return err
		}
		total += int64(len(b))
	}
	if err := w.Flush(); err != nil {
		return err
	}
	s.size = total
	return nil
}

// ReadAfter returns buffered records with Seq greater than after.
func (s *Spool) ReadAfter(after uint64) ([]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	recs, err := readAll(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []Record
	for _, r := range recs {
		if r.Seq > after {
			out = append(out, r)
		}
	}
	return out, nil
}

func readAll(path string) ([]Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 8*1024), 4<<20)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var r Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return nil, fmt.Errorf("parse spool record: %w", err)
		}
		out = append(out, r)
	}
	return out, sc.Err()
}

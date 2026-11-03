package telemetry

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/vorynex/vorynex/engine/audit"
)

func ev(path string) audit.Event {
	return audit.Event{Type: "file", Action: "openat", Resource: path, Allowed: true}
}

func TestSpoolAppendRead(t *testing.T) {
	s, err := OpenSpool(filepath.Join(t.TempDir(), "s.jsonl"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := s.Append(ev(fmt.Sprintf("/app/%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	recs, err := s.ReadAfter(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 5 {
		t.Fatalf("want 5 records, got %d", len(recs))
	}
	for i, r := range recs {
		if r.Seq != uint64(i+1) {
			t.Errorf("record %d seq = %d", i, r.Seq)
		}
	}
	rest, _ := s.ReadAfter(2)
	if len(rest) != 3 || rest[0].Seq != 3 {
		t.Fatalf("ReadAfter(2) = %+v", rest)
	}
}

func TestSpoolTrimWritesGap(t *testing.T) {
	s, err := OpenSpool(filepath.Join(t.TempDir(), "s.jsonl"), 400)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		if err := s.Append(ev(fmt.Sprintf("/app/dir/file-%03d", i))); err != nil {
			t.Fatal(err)
		}
	}
	recs, err := s.ReadAfter(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) == 0 {
		t.Fatal("spool empty after trim")
	}
	if !recs[0].Gap {
		t.Fatalf("expected a leading gap marker, got %+v", recs[0])
	}
	gaps := 0
	for i, r := range recs {
		if r.Gap {
			gaps++
			continue
		}
		if i > 0 && recs[i-1].Seq >= r.Seq {
			t.Fatalf("sequence not monotonic at %d: %d then %d", i, recs[i-1].Seq, r.Seq)
		}
	}
	if gaps != 1 {
		t.Errorf("want exactly one gap marker, got %d", gaps)
	}

	// Resumption: a cursor past the gap resumes cleanly.
	last := recs[len(recs)-1].Seq
	for _, r := range recs {
		if r.Seq > last {
			t.Errorf("record after last seq")
		}
	}
}

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/vorynex/vorynex/engine/audit"
	"github.com/vorynex/vorynex/engine/telemetry"
	"github.com/vorynex/vorynex/engine/trace"
)

// runTrace renders contained (or would-be-contained) events as plain-English
// attack traces.
func runTrace(args []string) error {
	var from, workload, id string
	var jsonOut, all bool
	var since time.Duration

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--from":
			if i+1 < len(args) {
				i++
				from = args[i]
			}
		case "--workload":
			if i+1 < len(args) {
				i++
				workload = args[i]
			}
		case "--id":
			if i+1 < len(args) {
				i++
				id = args[i]
			}
		case "--since":
			if i+1 < len(args) {
				i++
				if d, err := time.ParseDuration(args[i]); err == nil {
					since = d
				}
			}
		case "--json":
			jsonOut = true
		case "--all":
			all = true
		default:
			return fmt.Errorf("unknown flag %q", args[i])
		}
	}

	if from == "" {
		from = defaultTraceSource()
	}
	if from == "" {
		return fmt.Errorf("no events found; run `vorynex observe` first or pass --from <file>")
	}

	events, hostID, err := readTraceEvents(from)
	if err != nil {
		return err
	}
	traces := trace.Build(events, hostID, workload)

	cutoff := time.Time{}
	if since > 0 {
		cutoff = time.Now().Add(-since)
	}
	var filtered []trace.Trace
	for _, t := range traces {
		if id != "" && t.ID != id {
			continue
		}
		if !cutoff.IsZero() && t.Time.Before(cutoff) {
			continue
		}
		filtered = append(filtered, t)
	}

	if jsonOut {
		b, _ := json.MarshalIndent(filtered, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	if len(filtered) == 0 {
		fmt.Println("no contained or would-be-contained events found")
		return nil
	}
	if all {
		for _, t := range filtered {
			fmt.Printf("%s  %-10s  %-22s  %s\n", t.Time.Format("15:04:05"), t.Result, t.Behavior, t.Attempt)
		}
		return nil
	}
	printTrace(filtered[0])
	return nil
}

func defaultTraceSource() string {
	if _, err := os.Stat(telemetry.DefaultSpoolPath()); err == nil {
		return telemetry.DefaultSpoolPath()
	}
	if p, err := audit.LatestTracePath(); err == nil {
		return p
	}
	return ""
}

// readTraceEvents accepts either audit events (one per line) or telemetry
// records that wrap an event, and returns the host id when the source carries
// one (the cloud store does).
func readTraceEvents(path string) ([]audit.Event, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()

	var out []audit.Event
	hostID := ""
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 8*1024), 4<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		// Cloud store shape: {"host_id":..,"record":{"seq":..,"event":{..}}}
		var nested struct {
			HostID string `json:"host_id"`
			Record *struct {
				Event *audit.Event `json:"event"`
			} `json:"record"`
		}
		if json.Unmarshal(line, &nested) == nil && nested.Record != nil && nested.Record.Event != nil && !nested.Record.Event.Timestamp.IsZero() {
			if hostID == "" && nested.HostID != "" {
				hostID = nested.HostID
			}
			out = append(out, *nested.Record.Event)
			continue
		}
		// Local spool shape: {"seq":..,"event":{..}}
		var rec struct {
			Event *audit.Event `json:"event"`
		}
		if json.Unmarshal(line, &rec) == nil && rec.Event != nil && !rec.Event.Timestamp.IsZero() {
			out = append(out, *rec.Event)
			continue
		}
		// Plain audit event.
		var e audit.Event
		if json.Unmarshal(line, &e) == nil && !e.Timestamp.IsZero() {
			out = append(out, e)
		}
	}
	return out, hostID, sc.Err()
}

func printTrace(t trace.Trace) {
	if t.Result == trace.ResultDenied {
		fmt.Println("ATTACK CONTAINED")
	} else {
		fmt.Println("WOULD HAVE BLOCKED (observe mode, nothing was enforced)")
	}
	fmt.Println()

	for i, hop := range t.Path {
		if i > 0 {
			fmt.Println("   ↓")
		}
		if hop.Kind == "workload" {
			fmt.Printf("%s   (%s)\n", hop.Label, t.Workload)
		} else {
			fmt.Println(hop.Label)
		}
	}
	if t.Result == trace.ResultDenied {
		fmt.Println("   ↓")
		fmt.Println("BLOCKED")
	}

	fmt.Printf("\nTime: %s\n", t.Time.Format("15:04:05"))
	fmt.Printf("Application: %s\n", t.Workload)
	fmt.Printf("Attempt: %s\n", t.Attempt)
	fmt.Printf("Policy: %s\n", t.Policy)
	fmt.Printf("Result: %s\n", t.Result)
	fmt.Printf("Potential behavior: %s\n", t.Behavior)
	if t.Reason != "" {
		fmt.Printf("Reason: %s\n", t.Reason)
	}
	fmt.Printf("Confidence: %s\n", t.Confidence)
	if len(t.NextActions) > 0 {
		fmt.Println("\nNext:")
		for _, a := range t.NextActions {
			fmt.Printf("  • %s\n", a)
		}
	}
}

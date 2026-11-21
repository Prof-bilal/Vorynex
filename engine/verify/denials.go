package verify

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/vorynex/vorynex/engine/audit"
)

// Denial is a syscall that failed with EACCES or EPERM while the workload ran.
// Tier 0 emits no event of its own, so this is inferred from an strace capture:
// it is a candidate for "the sandbox refused this", not proof, because an app can
// also get EACCES from ordinary file modes (e.g. cgroup files).
type Denial struct {
	Action   string
	Resource string
	Count    int
}

// Denials parses an strace file (-f, -Z or full) into deduplicated denials.
func Denials(path string) ([]Denial, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	counts := map[[2]string]int{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		ev, ok := audit.ParseStraceLine(sc.Text())
		if !ok || ev.Allowed || !(strings.Contains(ev.Reason, "EACCES") || strings.Contains(ev.Reason, "EPERM")) {
			continue
		}
		counts[[2]string{ev.Action, ev.Resource}]++
	}
	var out []Denial
	for k, n := range counts {
		out = append(out, Denial{k[0], k[1], n})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Count > out[j].Count || (out[i].Count == out[j].Count && out[i].Resource < out[j].Resource)
	})
	return out, sc.Err()
}

// FormatDenials renders denials for the report.
func FormatDenials(d []Denial) string {
	if len(d) == 0 {
		return "\nDenied operations (strace): none\n"
	}
	var b strings.Builder
	b.WriteString("\nDenied operations (strace; candidates, not proof of a sandbox refusal):\n")
	for _, x := range d {
		fmt.Fprintf(&b, "  %-8s %s  x%d\n", x.Action, x.Resource, x.Count)
	}
	return b.String()
}

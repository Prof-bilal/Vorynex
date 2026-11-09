// Package verify runs a defined corpus of legitimate workflows against a
// workload that is already running under a candidate policy and decides whether
// that policy may be enforced.
//
// Two rules shape it. A passing health check never outweighs a failing required
// workflow. And a clean run over a finite corpus is reported as "verified
// against the defined tests", never as proof of zero production false positives:
// features with no workflow are reported as insufficient coverage and block the
// decision.
package verify

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Workflow is one legitimate operation, repeated Count times.
type Workflow struct {
	Name         string `json:"name"`
	Feature      string `json:"feature"`
	Required     bool   `json:"required"`
	Count        int    `json:"count"`
	Method       string `json:"method,omitempty"` // default GET
	Path         string `json:"path"`
	Body         string `json:"body,omitempty"`
	ExpectStatus int    `json:"expect_status,omitempty"` // default 200
	ExpectBody   string `json:"expect_body,omitempty"`   // regexp
	// DenySignature marks a failing response as a sandbox denial rather than an
	// application failure. Default: EACCES|EPERM.
	DenySignature string `json:"deny_signature,omitempty"`
}

// Corpus is the verification input. Features lists every user-facing feature the
// operator says the application has; any without a workflow is a coverage gap.
type Corpus struct {
	Features  []string   `json:"features"`
	Workflows []Workflow `json:"workflows"`
}

// Feature states.
const (
	StateVerified     = "verified against defined tests"
	StateConflict     = "known conflict"
	StateInsufficient = "insufficient coverage"
	StateIncomplete   = "verification incomplete"
)

// Result is the outcome for one workflow.
type Result struct {
	Workflow Workflow
	Attempts int
	Passed   int
	Denied   int
	Sample   string
}

// Report is the full verification outcome.
type Report struct {
	Results  []Result
	Features map[string]string // feature -> state
	Decision string
	Reasons  []string
}

var defaultDeny = regexp.MustCompile(`EACCES|EPERM|Permission denied`)

// Run executes the corpus against base (e.g. http://127.0.0.1:3000).
func Run(base string, c Corpus) Report {
	base = strings.TrimRight(base, "/")
	client := &http.Client{Timeout: 8 * time.Second}
	rep := Report{Features: map[string]string{}}
	for _, w := range c.Workflows {
		rep.Results = append(rep.Results, runWorkflow(client, base, w))
	}
	return decide(rep, c)
}

func runWorkflow(client *http.Client, base string, w Workflow) Result {
	r := Result{Workflow: w, Attempts: max(w.Count, 1)}
	method := w.Method
	if method == "" {
		method = http.MethodGet
	}
	want := w.ExpectStatus
	if want == 0 {
		want = 200
	}
	var bodyRe *regexp.Regexp
	if w.ExpectBody != "" {
		bodyRe = regexp.MustCompile(w.ExpectBody)
	}
	deny := defaultDeny
	if w.DenySignature != "" {
		deny = regexp.MustCompile(w.DenySignature)
	}
	for i := 0; i < r.Attempts; i++ {
		req, _ := http.NewRequest(method, base+w.Path, strings.NewReader(w.Body))
		resp, err := client.Do(req)
		var body string
		status := 0
		if err == nil {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
			resp.Body.Close()
			body, status = string(b), resp.StatusCode
		} else {
			body = err.Error()
		}
		if err == nil && status == want && (bodyRe == nil || bodyRe.MatchString(body)) {
			r.Passed++
			continue
		}
		if deny.MatchString(body) {
			r.Denied++
		}
		if r.Sample == "" {
			r.Sample = fmt.Sprintf("status %d: %.100s", status, body)
		}
	}
	return r
}

func decide(rep Report, c Corpus) Report {
	byFeature := map[string][]Result{}
	for _, r := range rep.Results {
		byFeature[r.Workflow.Feature] = append(byFeature[r.Workflow.Feature], r)
	}
	for _, f := range c.Features {
		rs := byFeature[f]
		required := 0
		state := StateVerified
		for _, r := range rs {
			if r.Workflow.Required {
				required++
			}
			if r.Passed != r.Attempts {
				if r.Denied > 0 {
					state = StateConflict
				} else if state != StateConflict {
					state = StateIncomplete
				}
			}
		}
		if required == 0 {
			state = StateInsufficient
		}
		rep.Features[f] = state
		switch state {
		case StateConflict:
			rep.Reasons = append(rep.Reasons, f+": the sandbox denied a legitimate operation")
		case StateIncomplete:
			rep.Reasons = append(rep.Reasons, f+": failed without a sandbox denial; cannot attribute it to the policy")
		case StateInsufficient:
			rep.Reasons = append(rep.Reasons, f+": no required workflow exercises this feature")
		}
	}
	if len(rep.Reasons) == 0 {
		rep.Decision = "VERIFIED AGAINST DEFINED TESTS (not a guarantee of production compatibility)"
	} else {
		rep.Decision = "DO NOT ENFORCE"
	}
	return rep
}

// Ready reports whether the decision permits enforcement.
func (r Report) Ready() bool { return len(r.Reasons) == 0 }

// Totals returns operations attempted, passed and denied.
func (r Report) Totals() (attempted, passed, denied int) {
	for _, x := range r.Results {
		attempted += x.Attempts
		passed += x.Passed
		denied += x.Denied
	}
	return
}

// Format renders the human report.
func (r Report) Format() string {
	var b strings.Builder
	a, p, d := r.Totals()
	fmt.Fprintf(&b, "Candidate Policy Verification\n\nLegitimate requests: %d\nPassed: %d\nDenied by sandbox: %d\n\nRequired workflows:\n", a, p, d)
	for _, x := range r.Results {
		st := "PASS"
		if x.Passed != x.Attempts {
			st = "FAIL"
		}
		req := ""
		if !x.Workflow.Required {
			req = " (optional)"
		}
		fmt.Fprintf(&b, "  %-18s %s %d/%d%s\n", x.Workflow.Name, st, x.Passed, x.Attempts, req)
		if st == "FAIL" && x.Sample != "" {
			fmt.Fprintf(&b, "      sample: %s\n", x.Sample)
		}
	}
	b.WriteString("\nFeature coverage:\n")
	for f, s := range r.Features {
		fmt.Fprintf(&b, "  %-12s %s\n", f, s)
	}
	fmt.Fprintf(&b, "\nDecision: %s\n", r.Decision)
	for _, why := range r.Reasons {
		fmt.Fprintf(&b, "  - %s\n", why)
	}
	return b.String()
}

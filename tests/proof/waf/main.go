// CRS arm for the Vorynex containment proof.
//
// A reverse proxy that runs OWASP Coraza with the OWASP Core Rule Set in front
// of a target, so the harness can measure what a request-layer filter actually
// stops — and attribute every block to a rule id.
//
// This is a *stand-in* for a managed WAF: it is the same rule family Cloudflare's
// OWASP ruleset implements, it is version-pinned, and it can run in DetectionOnly
// so the harness can prove a request would have been blocked.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/corazawaf/coraza-coreruleset"
	"github.com/corazawaf/coraza/v3"
)

type auditEvent struct {
	TS       time.Time `json:"ts"`
	Method   string    `json:"method"`
	URI      string    `json:"uri"`
	Blocked  bool      `json:"blocked"`
	Status   int       `json:"status"`
	RuleID   int       `json:"rule_id,omitempty"`
	Action   string    `json:"action,omitempty"`
	Matched  []int     `json:"matched,omitempty"`
	Mode     string    `json:"mode"`
	Paranoia int       `json:"paranoia"`
}

func main() {
	listen := flag.String("listen", "127.0.0.1:3230", "listen address")
	upstream := flag.String("upstream", "http://127.0.0.1:3220", "upstream target")
	mode := flag.String("mode", "blocking", "blocking or detection")
	paranoia := flag.Int("paranoia", 1, "paranoia level 1..4")
	auditPath := flag.String("audit", "", "JSONL audit log path")
	extra := flag.String("extra", "", "file of extra directives appended to the config")
	flag.Parse()

	if *mode != "blocking" && *mode != "detection" {
		log.Fatalf("mode must be blocking or detection, got %q", *mode)
	}
	if *paranoia < 1 || *paranoia > 4 {
		log.Fatalf("paranoia must be 1..4, got %d", *paranoia)
	}

	engine := "On"
	if *mode == "detection" {
		engine = "DetectionOnly"
	}
	directives := fmt.Sprintf(`
Include @coraza.conf-recommended
Include @crs-setup.conf.example
Include @owasp_crs/*.conf
SecRuleEngine %s
SecRequestBodyAccess On
SecResponseBodyAccess Off
SecAction "id:900000,phase:1,nolog,pass,t:none,setvar:tx.blocking_paranoia_level=%d"
SecAction "id:900001,phase:1,nolog,pass,t:none,setvar:tx.detection_paranoia_level=%d"
`, engine, *paranoia, *paranoia)

	// Deployments add body processors and exclusions here; CRS assumes the
	// server parses its own body formats.
	if *extra != "" {
		b, err := os.ReadFile(*extra)
		if err != nil {
			log.Fatalf("extra directives: %v", err)
		}
		directives += string(b) + "\n"
	}

	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithRootFS(coreruleset.FS).
			WithRequestBodyAccess().
			WithDirectives(directives),
	)
	if err != nil {
		log.Fatalf("build WAF: %v", err)
	}

	target, err := url.Parse(*upstream)
	if err != nil {
		log.Fatalf("upstream: %v", err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, e error) {
		http.Error(w, "upstream error: "+e.Error(), http.StatusBadGateway)
	}

	var auditMu sync.Mutex
	var audit *os.File
	if *auditPath != "" {
		audit, err = os.Create(*auditPath)
		if err != nil {
			log.Fatalf("audit log: %v", err)
		}
		defer audit.Close()
	}
	writeAudit := func(ev auditEvent) {
		if audit == nil {
			return
		}
		auditMu.Lock()
		defer auditMu.Unlock()
		b, _ := json.Marshal(ev)
		_, _ = audit.Write(append(b, '\n'))
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tx := waf.NewTransaction()
		defer tx.Close()

		client, clientPort, _ := splitHostPort(r.RemoteAddr)
		tx.ProcessConnection(client, clientPort, "127.0.0.1", 0)
		tx.ProcessURI(r.URL.RequestURI(), r.Method, r.Proto)
		for k, vv := range r.URL.Query() {
			for _, v := range vv {
				tx.AddGetRequestArgument(k, v)
			}
		}
		for k, vv := range r.Header {
			for _, v := range vv {
				tx.AddRequestHeader(k, v)
			}
		}
		tx.ProcessRequestHeaders()

		blocked := false
		status := 0
		ruleID := 0
		action := ""
		if it := tx.Interruption(); it != nil {
			blocked = true
			status = it.Status
			ruleID = it.RuleID
			action = it.Action
		}

		if !blocked && r.Body != nil {
			body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			if err == nil {
				_ = r.Body.Close()
				r.Body = io.NopCloser(bytes.NewReader(body))
				if len(body) > 0 {
					tx.WriteRequestBody(body)
				}
			}
		}
		// Phase 2 runs here; it must be called even for a bodyless request or
		// the attack rules never evaluate.
		if !blocked {
			tx.ProcessRequestBody()
			if it := tx.Interruption(); it != nil {
				blocked = true
				status = it.Status
				ruleID = it.RuleID
				action = it.Action
			}
		}

		matched := make([]int, 0, len(tx.MatchedRules()))
		for _, mr := range tx.MatchedRules() {
			if mr.Rule() != nil {
				matched = append(matched, mr.Rule().ID())
			}
		}

		if blocked {
			code := status
			if code == 0 {
				code = http.StatusForbidden
			}
			writeAudit(auditEvent{
				TS: time.Now().UTC(), Method: r.Method, URI: r.URL.RequestURI(),
				Blocked: true, Status: code, RuleID: ruleID, Action: action,
				Matched: matched, Mode: *mode, Paranoia: *paranoia,
			})
			w.Header().Set("x-proof-waf", "blocked")
			if ruleID != 0 {
				w.Header().Set("x-proof-waf-rule", fmt.Sprintf("%d", ruleID))
			}
			http.Error(w, "blocked by CRS", code)
			return
		}

		// DetectionOnly still reports what it would have blocked.
		if len(matched) > 0 {
			w.Header().Set("x-proof-waf", "detected")
			w.Header().Set("x-proof-waf-rule", fmt.Sprintf("%d", matched[0]))
		}
		writeAudit(auditEvent{
			TS: time.Now().UTC(), Method: r.Method, URI: r.URL.RequestURI(),
			Blocked: false, Status: 0, Matched: matched, Mode: *mode, Paranoia: *paranoia,
		})
		proxy.ServeHTTP(w, r)
	})

	fmt.Printf("WAF_READY listen=%s upstream=%s mode=%s pl=%d crs=4.0 (embedded, pinned)\n",
		*listen, *upstream, *mode, *paranoia)
	if err := http.ListenAndServe(*listen, handler); err != nil {
		log.Fatal(err)
	}
}

func splitHostPort(addr string) (string, int, error) {
	u, err := url.Parse("//" + addr)
	if err != nil {
		return addr, 0, err
	}
	host := u.Hostname()
	port := 0
	if p := u.Port(); p != "" {
		_, _ = fmt.Sscanf(p, "%d", &port)
	}
	return host, port, nil
}

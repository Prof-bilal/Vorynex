package main

import (
	"testing"

	"github.com/corazawaf/coraza-coreruleset"
	"github.com/corazawaf/coraza/v3"
)

// The CRS arm is only meaningful if it actually enforces. This pins the two
// things that silently broke it before: the engine mode, and calling
// ProcessRequestBody so phase 2 (the attack rules) runs.
func TestCRSBlocksKnownPayloads(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithRootFS(coreruleset.FS).
		WithRequestBodyAccess().
		WithDirectives(`
Include @coraza.conf-recommended
Include @crs-setup.conf.example
Include @owasp_crs/*.conf
SecRuleEngine On
SecAction "id:900000,phase:1,nolog,pass,t:none,setvar:tx.blocking_paranoia_level=1"
SecAction "id:900001,phase:1,nolog,pass,t:none,setvar:tx.detection_paranoia_level=1"
`))
	if err != nil {
		t.Fatalf("build WAF: %v", err)
	}

	cases := []struct {
		name, key, value string
	}{
		{"command-injection", "host", "127.0.0.1;cat /etc/passwd"},
		{"xss", "q", "<script>alert(1)</script>"},
		{"sqli", "q", "' OR 1=1--"},
	}
	for _, c := range cases {
		tx := waf.NewTransaction()
		tx.ProcessConnection("127.0.0.1", 1234, "127.0.0.1", 80)
		tx.ProcessURI("/probe", "GET", "HTTP/1.1")
		tx.AddGetRequestArgument(c.key, c.value)
		tx.ProcessRequestHeaders()
		tx.ProcessRequestBody()
		it := tx.Interruption()
		var matched []int
		for _, mr := range tx.MatchedRules() {
			if mr.Rule() != nil {
				matched = append(matched, mr.Rule().ID())
			}
		}
		tx.Close()
		if it == nil {
			t.Errorf("%s: not blocked (matched %v)", c.name, matched)
			continue
		}
		t.Logf("%s: blocked by rule %d (matched %d rules)", c.name, it.RuleID, len(matched))
	}
}

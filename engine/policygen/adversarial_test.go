package policygen

import (
	"testing"

	"github.com/vorynex/vorynex/engine/audit"
	"github.com/vorynex/vorynex/engine/profiler"
)

func ex(path string) audit.Event {
	return audit.Event{Type: "process", Action: "execve", Resource: path, Allowed: true}
}
func conn(hostport string) audit.Event {
	return audit.Event{Type: "network", Action: "connect", Resource: hostport, Allowed: true}
}
func rd(path string) audit.Event {
	return audit.Event{Type: "file", Action: "openat", Resource: path, Allowed: true}
}

func has(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// An attacker who is active during the recording window, in every session and
// repeatedly, must not turn their tooling into grants. Observed != allowed.
func TestAttackerDuringRecordingWindowIsNotPromoted(t *testing.T) {
	attack := []audit.Event{
		ex("/usr/bin/bash"), ex("/usr/bin/bash"), // shell: caught by name
		ex("/tmp/.x/node"), ex("/tmp/.x/node"), // renamed shell copy: basename looks benign
		ex("/usr/bin/curl"), ex("/usr/bin/curl"), // exfil tooling
		ex("/usr/bin/nc"), ex("/usr/bin/nc"),
		ex("/usr/bin/python3"), ex("/usr/bin/python3"),
		rd("/home/app/.ssh/id_rsa"), rd("/home/app/.ssh/id_rsa"),
		conn("169.254.169.254:80"), conn("169.254.169.254:80"),
		conn("203.0.113.9:443"), conn("203.0.113.9:443"), // raw IP
	}
	// Baseline: the first exec of a session is the workload itself.
	session := append([]audit.Event{ex("/opt/app/node")}, attack...)
	session = append(session, rd("/opt/app/server.js"), rd("/opt/app/server.js"))
	sessions := [][]audit.Event{session, session, session}

	for _, opts := range []profiler.Options{
		{MinSessions: 1, MinCount: 2}, // what observe/protect actually use
		{MinSessions: 2, MinCount: 1},
	} {
		p := Generate(profiler.Build(sessions, opts), DefaultOptions()).Policy
		for _, bad := range []string{"/usr/bin/bash", "/tmp/.x/node", "/usr/bin/curl", "/usr/bin/nc", "/usr/bin/python3"} {
			if has(p.Process.Exec.Allow, bad) {
				t.Errorf("opts %+v: attacker exec %s promoted into exec.allow", opts, bad)
			}
		}
		for _, bad := range []string{"/home/app/.ssh/id_rsa", "/home/app/.ssh"} {
			if has(p.Filesystem.Read, bad) {
				t.Errorf("opts %+v: secret %s promoted to read", opts, bad)
			}
		}
		for _, bad := range []string{"169.254.169.254", "203.0.113.9"} {
			if has(p.Network.Allow, bad) {
				t.Errorf("opts %+v: destination %s promoted to network.allow", opts, bad)
			}
		}
		if !has(p.Filesystem.Read, "/opt/app/server.js") {
			t.Errorf("opts %+v: legitimate read lost", opts)
		}
	}
}

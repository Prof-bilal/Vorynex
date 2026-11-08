package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/vorynex/vorynex/engine/enforce/live"
	"github.com/vorynex/vorynex/engine/enforce/spawntime"
	"github.com/vorynex/vorynex/engine/policy"
	"github.com/vorynex/vorynex/engine/telemetry"
)

// preflight is the deployment gate. It exists because the failure that matters
// is discovering *after* you have pointed users at a host that the control plane
// is unauthenticated, the policy does not grant the workload its own files, or
// the workload sits somewhere that can never be granted.
//
// Every check reports a status and, when it fails, the command that fixes it.
// It never changes anything.
type preflightStatus string

const (
	statusPass preflightStatus = "pass"
	statusWarn preflightStatus = "warn"
	statusFail preflightStatus = "fail"
	statusNone preflightStatus = "not-configured"
)

type preflightCheck struct {
	Group  string          `json:"group"`
	ID     string          `json:"id"`
	Status preflightStatus `json:"status"`
	Detail string          `json:"detail"`
	Fix    string          `json:"fix,omitempty"`
}

type preflightReport struct {
	Checks  []preflightCheck `json:"checks"`
	Failed  int              `json:"failed"`
	Warned  int              `json:"warned"`
	Verdict string           `json:"verdict"`
}

func runPreflight(args []string) error {
	envFile, cloudEnv, tokenFile := "", "", ""
	asJSON, behindProxy := false, false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--env-file":
			if i+1 < len(args) {
				i++
				envFile = args[i]
			}
		case "--cloud-env":
			if i+1 < len(args) {
				i++
				cloudEnv = args[i]
			}
		case "--token-file":
			if i+1 < len(args) {
				i++
				tokenFile = args[i]
			}
		case "--json":
			asJSON = true
		case "--behind-proxy":
			behindProxy = true
		default:
			return fmt.Errorf("usage: vorynex preflight [--env-file <path>] [--cloud-env <path>] " +
				"[--token-file <path>] [--behind-proxy] [--json]")
		}
	}

	rep := preflightReport{}
	add := func(c preflightCheck) { rep.Checks = append(rep.Checks, c) }

	checkHost(add)
	checkAgent(add, envFile)
	checkCloud(add, cloudEnv, tokenFile, behindProxy)
	checkRelease(add)

	for _, c := range rep.Checks {
		switch c.Status {
		case statusFail:
			rep.Failed++
		case statusWarn:
			rep.Warned++
		}
	}
	if rep.Failed > 0 {
		rep.Verdict = "not ready to deploy"
	} else {
		rep.Verdict = "ready to deploy"
	}

	if asJSON {
		b, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(b))
	} else {
		printPreflight(rep)
	}
	if rep.Failed > 0 {
		return fmt.Errorf("%d check(s) failed", rep.Failed)
	}
	return nil
}

func printPreflight(rep preflightReport) {
	fmt.Println("Vorynex preflight — deployment readiness")
	group := ""
	for _, c := range rep.Checks {
		if c.Group != group {
			group = c.Group
			fmt.Printf("\n%s\n", strings.ToUpper(group))
		}
		label := map[preflightStatus]string{
			statusPass: "PASS", statusWarn: "WARN", statusFail: "FAIL", statusNone: "----",
		}[c.Status]
		fmt.Printf("  %-4s  %-16s %s\n", label, c.ID, c.Detail)
		if c.Fix != "" {
			fmt.Printf("        %-16s fix: %s\n", "", c.Fix)
		}
	}
	fmt.Printf("\n%s — %d failed, %d warnings\n", rep.Verdict, rep.Failed, rep.Warned)
	if rep.Failed > 0 {
		fmt.Println("This host is not ready. Fix the failures above; warnings are judgement calls.")
	}
}

// --- host ------------------------------------------------------------------

func checkHost(add func(preflightCheck)) {
	abi := spawntime.LandlockABI()
	switch {
	case abi == 0:
		add(preflightCheck{Group: "host", ID: "landlock", Status: statusFail,
			Detail: "unavailable: Tier 0 cannot enforce anything on this kernel",
			Fix:    "run on a kernel >= 5.13 with CONFIG_SECURITY_LANDLOCK; check `vorynex doctor`"})
	case abi < 4:
		add(preflightCheck{Group: "host", ID: "landlock", Status: statusWarn,
			Detail: fmt.Sprintf("ABI %d: filesystem and exec containment work, outbound TCP denial does not", abi),
			Fix:    "kernel >= 6.7 gives ABI 4; without it a policy cannot restrict egress"})
	default:
		add(preflightCheck{Group: "host", ID: "landlock", Status: statusPass,
			Detail: fmt.Sprintf("ABI %d (filesystem, exec and TCP connect are enforceable)", abi)})
	}

	if _, err := exec.LookPath("strace"); err != nil {
		add(preflightCheck{Group: "host", ID: "strace", Status: statusWarn,
			Detail: "not found: `vorynex observe` cannot record a workload",
			Fix:    "install strace (apt install strace / apk add strace)"})
	} else {
		add(preflightCheck{Group: "host", ID: "strace", Status: statusPass, Detail: "found"})
	}

	caps := live.Detect()
	if caps.Available {
		add(preflightCheck{Group: "host", ID: "tier1", Status: statusPass,
			Detail: "available: live attach to a running workload is possible"})
	} else {
		add(preflightCheck{Group: "host", ID: "tier1", Status: statusWarn,
			Detail: "unavailable: " + strings.Join(caps.Reasons, "; "),
			Fix:    "Tier 0 still works; Tier 1 needs root and a kernel with BPF-LSM"})
	}
}

// --- agent -----------------------------------------------------------------

func firstExisting(paths []string) string {
	for _, p := range paths {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func checkAgent(add func(preflightCheck), explicit string) {
	path := firstExisting([]string{explicit, os.Getenv("VORYNEX_ENV_FILE"),
		"/etc/vorynex/agent.env", "/usr/local/etc/vorynex/agent.env"})
	if path == "" {
		add(preflightCheck{Group: "agent", ID: "config", Status: statusNone,
			Detail: "no agent.env found: nothing is configured to be protected",
			Fix:    "install.sh writes /etc/vorynex/agent.env; point it at your workload"})
		return
	}
	env, err := parseEnvFile(path)
	if err != nil {
		add(preflightCheck{Group: "agent", ID: "config", Status: statusFail,
			Detail: fmt.Sprintf("%s: %v", path, err)})
		return
	}
	add(preflightCheck{Group: "agent", ID: "config", Status: statusPass, Detail: path})

	policyPath := env["VORYNEX_POLICY"]
	if policyPath == "" {
		add(preflightCheck{Group: "agent", ID: "policy", Status: statusFail,
			Detail: "VORYNEX_POLICY is not set",
			Fix:    "vorynex policy generate --from <trace> --from <trace> --min-sessions 2 --out <file>"})
		return
	}
	p, err := policy.Load(policyPath)
	if err != nil {
		add(preflightCheck{Group: "agent", ID: "policy", Status: statusFail,
			Detail: fmt.Sprintf("%s does not load: %v", policyPath, err),
			Fix:    "regenerate it: vorynex policy generate ... --out " + policyPath})
		return
	}
	add(preflightCheck{Group: "agent", ID: "policy", Status: statusPass,
		Detail: fmt.Sprintf("%s loads (%d read, %d write, %d exec-allow grants)",
			policyPath, len(p.Filesystem.Read), len(p.Filesystem.Write), len(p.Process.Exec.Allow))})

	// The workload command: <interpreter> <entry> or a single binary.
	cmdline := strings.TrimSpace(env["VORYNEX_COMMAND"])
	if cmdline == "" {
		add(preflightCheck{Group: "agent", ID: "workload", Status: statusFail,
			Detail: "VORYNEX_COMMAND is not set",
			Fix:    "e.g. VORYNEX_COMMAND=/usr/bin/node /srv/app/server.js"})
		return
	}
	fields := strings.Fields(cmdline)
	bin := fields[0]
	if _, err := exec.LookPath(bin); err != nil {
		add(preflightCheck{Group: "agent", ID: "workload", Status: statusFail,
			Detail: fmt.Sprintf("%s is not executable: %v", bin, err),
			Fix:    "use an absolute path to the interpreter that exists on this host"})
		return
	}
	entry := bin
	if len(fields) > 1 && strings.HasPrefix(fields[len(fields)-1], "/") {
		entry = fields[len(fields)-1]
	}
	if _, err := os.Stat(entry); err != nil {
		add(preflightCheck{Group: "agent", ID: "workload", Status: statusFail,
			Detail: fmt.Sprintf("%s does not exist: %v", entry, err)})
		return
	}
	add(preflightCheck{Group: "agent", ID: "workload", Status: statusPass, Detail: entry})

	appDir := filepath.Dir(entry)
	// RuntimePath is the same predicate the policy generator uses to decide what
	// it will never grant, so this is not a guess.
	if policy.RuntimePath(appDir) {
		add(preflightCheck{Group: "agent", ID: "grantable", Status: statusFail,
			Detail: fmt.Sprintf("%s is runtime scratch (/tmp, /usr, /lib, /proc, /dev): "+
				"it can be observed but never granted, so it can never be protected", appDir),
			Fix: "move the application to a stable path such as /srv, /opt, /var/lib or $HOME"})
	} else {
		covered := false
		for _, g := range p.Filesystem.Read {
			if policy.Within(appDir, g) || policy.Within(entry, g) {
				covered = true
				break
			}
		}
		if covered {
			add(preflightCheck{Group: "agent", ID: "grantable", Status: statusPass,
				Detail: appDir + " is covered by a read grant"})
		} else {
			add(preflightCheck{Group: "agent", ID: "grantable", Status: statusFail,
				Detail: appDir + " is not covered by any read grant: the workload cannot read " +
					"its own files, so the first protected launch will roll back",
				Fix: "observe two sessions and regenerate, or add the path to filesystem.read"})
		}
	}

	if env["VORYNEX_HEALTH"] == "" {
		add(preflightCheck{Group: "agent", ID: "health", Status: statusWarn,
			Detail: "VORYNEX_HEALTH is empty: a workload that breaks under the policy will not be rolled back",
			Fix:    "set VORYNEX_HEALTH to a URL or command the app exposes when healthy"})
	} else {
		add(preflightCheck{Group: "agent", ID: "health", Status: statusPass, Detail: env["VORYNEX_HEALTH"]})
	}

	dir := telemetry.DefaultDir()
	if info, err := os.Stat(dir); err == nil {
		if info.Mode().Perm()&0o077 != 0 {
			add(preflightCheck{Group: "agent", ID: "state", Status: statusFail,
				Detail: fmt.Sprintf("%s is %04o: the state is readable by other users", dir, info.Mode().Perm()),
				Fix:    "chmod 700 " + dir})
		} else if err := unix.Access(dir, unix.W_OK); err != nil {
			add(preflightCheck{Group: "agent", ID: "state", Status: statusFail,
				Detail: fmt.Sprintf("%s is not writable: %v", dir, err),
				Fix:    "the agent must be able to record its mode, policy digest and journal"})
		} else {
			add(preflightCheck{Group: "agent", ID: "state", Status: statusPass, Detail: dir})
		}
	} else if ok, why := creatable(dir); ok {
		add(preflightCheck{Group: "agent", ID: "state", Status: statusPass,
			Detail: dir + " (created on first use; preflight writes nothing)"})
	} else {
		add(preflightCheck{Group: "agent", ID: "state", Status: statusFail,
			Detail: fmt.Sprintf("%s cannot be created: %s", dir, why),
			Fix:    "the agent must be able to record its mode, policy digest and journal"})
	}
}

// creatable reports whether a directory could be created at path, by walking up
// to the nearest existing ancestor and testing that. It writes nothing.
func creatable(path string) (bool, string) {
	dir := path
	for {
		parent := filepath.Dir(dir)
		if parent == dir {
			return false, "no existing ancestor directory"
		}
		if _, err := os.Stat(parent); err == nil {
			if err := unix.Access(parent, unix.W_OK); err != nil {
				return false, fmt.Sprintf("%s is not writable", parent)
			}
			return true, ""
		}
		dir = parent
	}
}

// --- cloud -----------------------------------------------------------------

func checkCloud(add func(preflightCheck), explicit, tokenFileFlag string, behindProxy bool) {
	path := firstExisting([]string{explicit, os.Getenv("VORYNEX_CLOUD_ENV"),
		"/etc/vorynex/cloud.env", "/usr/local/etc/vorynex/cloud.env"})
	if path == "" {
		add(preflightCheck{Group: "cloud", ID: "config", Status: statusNone,
			Detail: "no cloud.env found: control plane not configured (fine if you do not run one)"})
		return
	}
	env, err := parseEnvFile(path)
	if err != nil {
		add(preflightCheck{Group: "cloud", ID: "config", Status: statusFail, Detail: err.Error()})
		return
	}
	add(preflightCheck{Group: "cloud", ID: "config", Status: statusPass, Detail: path})

	addr := env["VORYNEX_CLOUD_ADDR"]
	if addr == "" {
		addr = "127.0.0.1:8787"
	}
	host := addr
	if h, _, err := splitHostPortLoose(addr); err == nil {
		host = h
	}
	exposed := !(host == "127.0.0.1" || host == "localhost" || host == "::1" || host == "[::1]")
	if exposed {
		add(preflightCheck{Group: "cloud", ID: "address", Status: statusWarn,
			Detail: fmt.Sprintf("listening on %s, which is not loopback", addr),
			Fix:    "keep it on loopback behind a reverse proxy unless clients connect directly"})
	} else {
		add(preflightCheck{Group: "cloud", ID: "address", Status: statusPass, Detail: addr})
	}

	token := env["VORYNEX_CLOUD_TOKEN"]
	tokenPath := firstExisting([]string{tokenFileFlag, "/etc/vorynex/cloud-token.env",
		"/usr/local/etc/vorynex/cloud-token.env"})
	if token == "" && tokenPath != "" {
		if te, err := parseEnvFile(tokenPath); err == nil {
			token = te["VORYNEX_CLOUD_TOKEN"]
		}
	}
	if token == "" {
		status := preflightStatus(statusWarn)
		detail := "no admin token: the API is unauthenticated (acceptable on loopback only)"
		fix := "install.sh generates one; or set VORYNEX_CLOUD_TOKEN / the token file"
		if exposed {
			status = statusFail
			detail = "no admin token, and the API is reachable beyond loopback: anyone who can " +
				"reach it can read and write fleet state"
		}
		add(preflightCheck{Group: "cloud", ID: "token", Status: status, Detail: detail, Fix: fix})
	} else {
		add(preflightCheck{Group: "cloud", ID: "token", Status: statusPass,
			Detail: fmt.Sprintf("set (%d chars, not shown)", len(token))})
	}

	if tokenPath != "" {
		if info, err := os.Stat(tokenPath); err == nil {
			if info.Mode().Perm()&0o077 != 0 {
				add(preflightCheck{Group: "cloud", ID: "token-file", Status: statusFail,
					Detail: fmt.Sprintf("%s is %04o: the admin token is readable by other users",
						tokenPath, info.Mode().Perm()),
					Fix: "chmod 600 " + tokenPath})
			} else {
				add(preflightCheck{Group: "cloud", ID: "token-file", Status: statusPass,
					Detail: fmt.Sprintf("%s (%04o)", tokenPath, info.Mode().Perm())})
			}
		}
	}

	tls := strings.TrimSpace(env["VORYNEX_CLOUD_TLS_ARGS"])
	if exposed && tls == "" && !behindProxy {
		add(preflightCheck{Group: "cloud", ID: "tls", Status: statusFail,
			Detail: "plaintext on a non-loopback address, with no proxy acknowledged",
			Fix:    "set VORYNEX_CLOUD_TLS_ARGS=\"--tls-cert <crt> --tls-key <key>\", or re-run with --behind-proxy if a proxy terminates TLS"})
	} else if tls != "" {
		add(preflightCheck{Group: "cloud", ID: "tls", Status: statusPass, Detail: "configured"})
	} else if behindProxy {
		add(preflightCheck{Group: "cloud", ID: "tls", Status: statusPass,
			Detail: "terminated by a proxy in front (as declared with --behind-proxy)"})
	} else {
		add(preflightCheck{Group: "cloud", ID: "tls", Status: statusPass, Detail: "not exposed beyond loopback"})
	}

	store := env["VORYNEX_CLOUD_STORE"]
	if store == "" {
		store = "/var/lib/vorynex/cloud-events.jsonl"
	}
	dir := filepath.Dir(store)
	if ok, why := creatable(dir); !ok {
		add(preflightCheck{Group: "cloud", ID: "store", Status: statusFail,
			Detail: fmt.Sprintf("%s is not writable: %s", dir, why),
			Fix:    "create the directory and give the service user ownership"})
	} else if _, err := os.Stat(store); err == nil {
		add(preflightCheck{Group: "cloud", ID: "store", Status: statusPass, Detail: store})
	} else {
		add(preflightCheck{Group: "cloud", ID: "store", Status: statusPass,
			Detail: dir + " is writable; the store is created on first write"})
	}
}

// --- release ---------------------------------------------------------------

func checkRelease(add func(preflightCheck)) {
	raw, err := os.ReadFile("VERSION")
	if err != nil {
		add(preflightCheck{Group: "release", ID: "version", Status: statusNone,
			Detail: "no VERSION file here (fine outside a checkout): the binary's own version is authoritative"})
		return
	}
	v := strings.TrimSpace(string(raw))
	if v == "" || strings.Contains(v, "dev") {
		add(preflightCheck{Group: "release", ID: "version", Status: statusWarn,
			Detail: fmt.Sprintf("VERSION is %q: this is a development build", v),
			Fix:    "set a release version before shipping artifacts"})
	} else {
		add(preflightCheck{Group: "release", ID: "version", Status: statusPass, Detail: "v" + v})
	}

	if _, err := os.Stat(".git"); err != nil {
		return
	}
	if out, err := exec.Command("git", "status", "--porcelain").Output(); err == nil {
		if strings.TrimSpace(string(out)) != "" {
			add(preflightCheck{Group: "release", ID: "tree", Status: statusWarn,
				Detail: "the working tree has uncommitted changes: the artifact will not match any commit",
				Fix:    "commit or stash before building a release"})
		} else {
			add(preflightCheck{Group: "release", ID: "tree", Status: statusPass, Detail: "clean"})
		}
	}
	if out, err := exec.Command("git", "tag", "-l", "v"+v).Output(); err == nil {
		if strings.TrimSpace(string(out)) == "" {
			add(preflightCheck{Group: "release", ID: "published", Status: statusWarn,
				Detail: fmt.Sprintf("no tag v%s: there is no downloadable release for this version", v),
				Fix:    fmt.Sprintf("git tag v%s && git push origin v%s && gh release create v%s dist/*.tar.gz dist/checksums.txt", v, v, v)})
		} else {
			add(preflightCheck{Group: "release", ID: "published", Status: statusPass,
				Detail: fmt.Sprintf("tag v%s exists", v)})
		}
	}
}

// --- helpers ---------------------------------------------------------------

func parseEnvFile(path string) (map[string]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		m[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
	}
	return m, nil
}

// splitHostPortLoose accepts "host:port", "host" and "[::1]:port".
func splitHostPortLoose(addr string) (string, string, error) {
	if strings.HasPrefix(addr, "[") {
		if end := strings.LastIndex(addr, "]"); end > 0 {
			host := addr[1:end]
			port := strings.TrimPrefix(addr[end+1:], ":")
			return host, port, nil
		}
	}
	if i := strings.LastIndex(addr, ":"); i > 0 {
		return addr[:i], addr[i+1:], nil
	}
	return addr, "", nil
}

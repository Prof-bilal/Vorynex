# Safe Policy Engine v1: status

Done: root cause; capability gate for directory-granular exec; `vorynex verify` with coverage states; safe fixture + corpus; demo with control arm; CI job (unrun on GitHub).

Not done (honest list):

1. **Partly done:** `run --watch` gives bounded post-activation verification. Still open: multi-level rollback (single snapshot), supervisor-crash handling (untested), watch is not continuous.
2. Tier 0 still emits no denial events of its own. **Partly done:** `vorynex verify --trace` captures EACCES/EPERM syscalls via strace and names the refused call (e.g. `execve .../ping x20`). These are candidates, not proof (cgroup files also give EACCES). Still open: `observe`/`trace` integration and Landlock audit on newer kernels. **New finding from the trace:** `/etc/resolv.conf` is denied under the default policy (likely a symlink outside the readable runtime dirs); the `dns` workflow only resolves `localhost`, so it misses it. Add a real-resolver workflow next.
3. **Done for exec, open for egress.** `engine/policygen/adversarial_test.go` replays an attacker active in every recording session. It found a real hole (curl, nc, python3 and a renamed shell copy were promoted into `exec.allow`, including by `observe`/`protect`, which use MinSessions=1). Fixed: only the workload's own binary (first exec of a session) can be promoted; anything else is a new `review` decision that never becomes a grant and is listed by `observe`. **Still open:** a non-IP destination (e.g. an attacker's domain) seen in the window is still promoted into `network.allow`. Closing it means every learned egress host needs review, which changes the product's learning UX, so it is left as a decision.
4. Corpus gaps: restart/cold start, concurrency, outbound API/DB, retries, graceful shutdown, worker subprocesses. No Express/Next.js/worker fixtures.
5. Exception schema with approver/reason; approval workflow; `conflicts`/`rollback` CLI verbs.
6. Tier 1, Docker integration, performance of memory/CPU/startup: not measured.
7. Competitor research was not source-verified (see COMPETITIVE_POLICY_ENGINEERING.md).
8. Ping via the private copy goes stale on package updates; re-stage on update.

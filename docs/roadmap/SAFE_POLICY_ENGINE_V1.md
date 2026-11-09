# Safe Policy Engine v1: status

Done: root cause; capability gate for directory-granular exec; `vorynex verify` with coverage states; safe fixture + corpus; demo with control arm; CI job (unrun on GitHub).

Not done (honest list):

1. Continuous post-activation verification and multi-level rollback; supervisor-crash handling untested (see POLICY_ROLLOUT.md).
2. Tier 0 still emits no denial events of its own. **Partly done:** `vorynex verify --trace` captures EACCES/EPERM syscalls via strace and names the refused call (e.g. `execve .../ping x20`). These are candidates, not proof (cgroup files also give EACCES). Still open: `observe`/`trace` integration and Landlock audit on newer kernels. **New finding from the trace:** `/etc/resolv.conf` is denied under the default policy (likely a symlink outside the readable runtime dirs); the `dns` workflow only resolves `localhost`, so it misses it. Add a real-resolver workflow next.
3. Adversarial learning (Phase 7) only verified by reading code: profiler/policygen never promote shells, secret reads or metadata egress. No test replays an attack-during-observe window; add one.
4. Corpus gaps: restart/cold start, concurrency, outbound API/DB, retries, graceful shutdown, worker subprocesses. No Express/Next.js/worker fixtures.
5. Exception schema with approver/reason; approval workflow; `conflicts`/`rollback` CLI verbs.
6. Tier 1, Docker integration, performance of memory/CPU/startup: not measured.
7. Competitor research was not source-verified (see COMPETITIVE_POLICY_ENGINEERING.md).
8. Ping via the private copy goes stale on package updates; re-stage on update.

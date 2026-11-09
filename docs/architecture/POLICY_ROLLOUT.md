# Policy rollout and rollback

## What exists today (read from `cmd/vorynex/run.go`, `engine/state`)

- `vorynex run --policy P --health URL -- cmd` snapshots the current posture (`state.BeginTransition`), starts the workload under `vorynex exec`, and polls health. If health never passes within the timeout it kills the workload and calls `state.Revert()` (back to the snapshotted posture, or observe with no policy if none).
- The supervisor is **outside** the sandbox (the child is the sandboxed `vorynex exec`), so rollback does not depend on the restricted process.
- State is a local file; the cloud is not involved. A cloud outage cannot block or hide a rollback.

## Gaps found

| Question | Answer |
|---|---|
| Startup only? | **Yes.** After the first healthy window, no check runs. A feature that breaks later (ping, upload) is never detected. A passing `/health` was the only gate. |
| Feature-level regression? | No, until `vorynex verify`, which runs required workflows but is a separate pre-flight step, not wired into `run`. |
| Restores the actual previous state? | Single-level snapshot only. A second transition overwrites the first. |
| Agent crash / interrupted apply? | **Not tested.** If the supervisor dies after `BeginTransition`, state says "protect" with the new policy and nothing reverts it. Treat as an open risk. |
| Cloud offline? | Fine: local. |
| Recover without SSH? | No. There is no watchdog; `vorynex protect --off` is a manual command. |

## Lifecycle (target; only the first three steps exist as commands)

```
Candidate -> Verified -> Approved -> Canary -> Active
                                       |
                          regression --+--> Rollback -> previous Verified policy
```

- **Candidate -> Verified**: `vorynex verify` (capability gate + required workflows + coverage). Built.
- **Verified -> Approved**: operator promotes the file; no workflow built.
- **Canary**: MVP form is a *staged replacement workload*, not weighted traffic: start the new workload under the candidate on a second port, run the corpus, switch only on pass. `tests/safe-policy` scenario 6 demonstrates the decision logic with shell, **not** a shipped rollback controller: the active policy file is left untouched when verification fails and the running app keeps serving. Rollback of an already-switched policy after a post-activation failure is not built.
- **Next step** (recommended): make `run` call the verifier periodically for N minutes after start and `state.Revert()` on a required-workflow failure; journal the verification report with the policy digest; keep a list of previous verified digests instead of one snapshot.

Argo Rollouts-style analysis (metric-gated promotion, auto-abort) is the model; weighted canaries need a proxy or orchestrator and are out of MVP scope.

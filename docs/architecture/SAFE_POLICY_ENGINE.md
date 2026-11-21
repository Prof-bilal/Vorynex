# Safe Policy Engine v1

Goal: no policy is enforced on the strength of "it started and /health is 200".

```
observe -> candidate policy -> capability gate -> compatibility verify -> security regression -> operator approval -> staged run -> monitor
 (exists)     (exists)          NEW                 NEW                   NEW (script)          (manual)             (exists: run)   (partial)
```

## What exists vs what this change adds

| Component | Status |
|---|---|
| Behavior collector | Exists: `vorynex observe` (strace). Collects exec/fs/connect, not env values, bodies or file contents. Not extended. |
| Candidate generator | Exists: `engine/policygen`, `engine/profiler`. Shells, secret paths and metadata egress are never auto-promoted. Observed != allowed. |
| Compatibility verifier | **New**: `engine/verify`, `vorynex verify`. |
| Coverage tracker | **New**, inside verify: states *verified against defined tests / known conflict / insufficient coverage / verification incomplete*. A feature with no required workflow blocks the decision. |
| Exception manager | **New, deliberately small**: no exception schema. An exec exception is an `exec.allow` entry, accepted only when its directory contains nothing else executable (`policy.BroadExecGrants`). Otherwise a capability error. Argument/ancestry/container constraints cannot be enforced by either backend, so they are not offered. |
| Security regression | **New**: `tests/safe-policy/run-demo.sh` with a bare control arm. Run it after every policy change (`make safe-policy`, in CI). |
| Operator approval | Manual: the operator copies a verified policy into place. No approval workflow built. |

## Decision rule

`vorynex verify` exits 2 ("DO NOT ENFORCE") when any required workflow fails (health never compensates), any declared feature lacks a required workflow, the workload never becomes healthy, or the capability gate rejects a rule. Exit 0 prints "verified against defined tests (not a guarantee of production compatibility)".

## The ping decision (Phase 5)

| Option | Result |
|---|---|
| A. Drop the shell (`execFile`, validated host) | Removes the injection but still needs `exec` of a ping binary, which the directory-granular backend cannot grant narrowly from `/usr/bin`. Alone, insufficient. |
| B. Narrow exception on `/usr/bin/ping` | Rejected by the backend: it is a grant on all of `/usr/bin`, shell included. |
| C. Separate helper workload | Correct for privileged needs; heavier (second boundary, IPC, lifecycle). ping needs no privilege here. |
| **Chosen: A + B' (exclusive exec directory)** | App uses `execFile(PING_BIN, [...])` with a regex-validated host; the policy allows one binary copied into a directory holding only it. Verified: ping 20/20, `sh`/`cp` and the system `/usr/bin/ping` denied. |

Tradeoffs of the choice: the copied binary does not receive distro updates (re-stage on package update); ICMP to arbitrary hosts remains possible because Tier 0 cannot police ICMP, so an attacker who controls `host` can probe the network; the vulnerable proof target is left unchanged because it exists to be attacked.

## Limits

Zero failures on the corpus is a statement about the corpus. The corpus covers health, echo, read, write, ping, upload, tmp file, DNS and a background job on a plain-`http` Node fixture. It does not cover cold-start/restart, concurrency, outbound API/database calls, retries, graceful shutdown or worker subprocesses, and no Express or Next.js fixture was added.

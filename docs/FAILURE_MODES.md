# FAILURE_MODES.md

Default principle:

> **Existing local protection must continue independently of Vorynex Cloud.
> We never build a SaaS dependency that can accidentally take customer
> production offline.**

Two different failure axes, with opposite defaults:

- **Enforcement primitives missing → fail closed.** Do not silently run
  unprotected.
- **Cloud unavailable → fail open (for the cloud).** Local enforcement continues;
  the app keeps running.

## Cloud is offline

| Aspect | Behavior |
|---|---|
| Enforcement | **Unaffected.** Policies are local and already loaded. |
| Dashboard | Shows stale data; agent buffers events locally. |
| Policy changes | Queued; applied when the cloud returns. |
| New host enrollment | Blocked (needs cloud). Existing hosts unaffected. |
| Emergency Shield | Cannot deliver new advisories while offline; existing rules stay. |

**Never:** block requests, disable protection, or refuse to start because the
cloud is unreachable.

## Network disappears

| Aspect | Behavior |
|---|---|
| Local enforcement | Unaffected. |
| Telemetry | Buffered locally with bounded size; oldest dropped first; a gap marker
is uploaded on reconnect. |
| Egress allowlist for the app | Uses local rules; the agent never depends on the
network to make decisions. |

## Agent crashes

| Aspect | Behavior |
|---|---|
| If launched via Tier 0 (entrypoint) | The confined process is a child of the
agent; a crash kills or orphans the workload. **Restart policy: supervised
restart**, and the container/orchestrator health check restarts the workload. |
| If Tier 1 (live attach) | Kernel enforcement persists in-kernel while the agent is
down; on agent restart it re-attaches. |
| Detection | Absence of heartbeats raises a "protection degraded" alert in the
cloud and, if configured, locally. |

**Never:** leave a workload running *believing* it is protected when the agent is
gone. The status must always be honest: `protected` / `degraded` / `unprotected`.

## Policy cannot load

| Cause | Behavior |
|---|---|
| Corrupt/invalid policy | **Fail closed**: keep the last-known-good signed policy;
refuse to load the bad one; alert. Never fall back to "no policy". |
| Signature/attestation mismatch | Refuse the new policy; keep the current one;
alert. |
| First boot, no policy | Observe mode only (no enforcement); cannot enter Protect
without a valid signed policy. |

## Kernel feature unavailable

| Missing | Consequence | Behavior |
|---|---|---|
| eBPF-LSM (kernel < 5.7 / no `CONFIG_BPF_LSM`) | No Tier 1 live exec/path blocking | Degrade to Tier 0 for relaunchable workloads; report `Tier 1 unavailable` in `doctor`. Never claim live protection. |
| Landlock ABI too old | No FS/exec restrictions in Tier 0 shim | Report the ABI; disable the specific restriction; do not silently pretend. |
| `CAP_BPF` unavailable | No Tier 1 | Same as above. |
| No unprivileged user namespaces (`bwrap` path) | No host Tier 0 | Use Landlock+seccomp shim, or require restart-under-protection. |
| `strace` missing (Warden audit dependency) | No file-access audit | Run without file-audit events but **say so**; still enforce what the tier can enforce. |

Principle: **never claim a protection level the host cannot enforce.**

## Application changes version

| Change | Behavior |
|---|---|
| New deploy / image tag | Capabilities tied to the app artifact lose "stable" status; re-enter Observe for the changed surface; never-promote denies remain active. |
| Dependency/lockfile change | Re-evaluate egress baseline and exec allowlist; flag new capabilities for review. |
| Runtime major upgrade (e.g. Node 20→22) | Treat as a new baseline window; do not widen rules automatically. |

## Policy conflicts

| Conflict | Behavior |
|---|---|
| Two rules disagree on the same target | **Deny wins.** Always. |
| Cloud-pushed rule conflicts with a local reviewed rule | Local reviewed rule wins unless the cloud rule is signed and explicitly marked authoritative; disagreement is alerted, never silently resolved. |
| Malformed merge | Reject the merge, keep the current policy, alert. |

## Resource pressure on the agent

| Condition | Behavior |
|---|---|
| CPU/memory pressure | Tier 1 enforcement stays in-kernel (cheap). The profiler and telemetry throttle first; enforcement is never starved. |
| Disk full for event buffer | Drop oldest telemetry, record a gap; never drop enforcement. |

## The invariant, stated once

```text
Local enforcement  : never depends on the cloud, never silently disabled.
Cloud              : optional for protection, required only for management.
Trust              : a degraded state is always reported, never hidden.
```

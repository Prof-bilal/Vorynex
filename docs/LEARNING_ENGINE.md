# LEARNING_ENGINE.md

The biggest adoption risk is **Vorynex breaks production**. A boundary that
blocks legitimate behavior is worse than no boundary. The learning engine exists
to make the boundary safe, and to resist the second-biggest risk: **learning an
attacker's behavior as if it were normal.**

## The three modes

### Observe
```text
No enforcement.
Record what would have been blocked.
```
Used during development, staging, and the first deployment window. Produces a
"would-have-blocked" report and a candidate baseline. **Enforcement is off, so
Observe can never break the app.**

### Protect  *(recommended default)*
```text
Block only high-confidence dangerous behavior.
```
The seven MVP protections, plus any capability the profiler has marked
*stable + safe*. Everything else is allowed and recorded. Protect should be
adoptable on day one after a short observe window.

### Lockdown
```text
Strict generated allowlist.
Only known capabilities work.
```
For hardened production and stable workloads. Everything not in the allowlist
is denied. Requires a mature baseline and is opt-in.

---

## What the profiler learns

For a bounded observation window, the profiler records low-level events (reusing
Warden's `audit.Event` shape) and derives candidate capabilities:

| Signal | Example | Promotable? |
|---|---|---|
| Exec of an interpreter | `/usr/bin/node` | yes |
| Exec of a shell from a web worker | `/bin/bash`, `/bin/sh` | **never auto-promote** |
| File read in the app tree | `/app/server.js` | yes |
| File write to a cache dir | `/app/.next/cache/*` | yes |
| Read of a secret path | `/app/.env`, `~/.ssh` | **never auto-promote** |
| Outbound connect | `api.stripe.com:443` | yes |
| Outbound connect to raw IP:odd port | `1.2.3.4:4444` | **never auto-promote** |
| IMDS access | `169.254.169.254` | **never auto-promote** |
| Privilege change | `setuid`, caps | **never auto-promote** |

## Rules for safe promotion

A capability becomes an allow rule only when **all** hold:

1. **Frequency** — observed in ≥ N independent sessions (not just once).
2. **Stability** — the same capability appears across the window and is not
   correlated with a single anomalous burst.
3. **Provenance** — the process making the request is a known, stable process
   (not a newly appeared child of a web worker).
4. **Safety class** — the capability is not in a never-promote class
   (shell/secret/metadata/privilege/raw-egress).
5. **Confidence threshold** — a score above a conservative bar; below the bar it
   stays "observed but not enforced".

Rules default to **not promoting**. Silence is safer than a wrong allow rule.

## Defenses against learning malicious behavior

This is the hard problem. A naive `observe → allow everything seen` design lets
an attacker who strikes during the learning window bake a permanent allow rule
into the policy.

Defenses (cumulative):

1. **Never-promote classes.** Shell exec from a web worker, secret-path reads,
   IMDS, privilege changes, and raw-egress are *always denied in Protect*
   regardless of observation. They can never be promoted by the profiler. This
   alone neutralizes the most valuable attacker behaviors.
2. **Provenance tracking.** A capability is only attributable to a stable,
   expected process. A capability first seen from a process that itself appeared
   during the window (i.e., a spawned child) is treated as untrusted and not
   promotable.
3. **Time-window sanity.** Capabilities first observed *after* adoption or in a
   burst correlated with an alert are flagged for review, not auto-promoted.
4. **Two-person review for high-impact rules.** Any allow rule touching egress
   or process exec outside the app's own tree requires explicit human approval,
   not automatic promotion.
5. **Baseline segmentation.** Learn from *pre-adoption* traffic and from
   *deploy-known-good* windows; exclude windows flagged by anomaly signals on the
   profiler itself.
6. **Signed, versioned policies.** Policies are signed (reuse Warden's
   `attestation` design) and versioned, so a bad learning result is auditable
   and reversible.

```text
observe ─► candidate capabilities
              │
              ├─ never-promote class? ──► keep denied
              ├─ low confidence? ───────► keep observing
              ├─ high impact (egress/exec)? ──► human review
              └─ otherwise ─────────────► promotable allow rule
```

## Dynamic workloads

Deploys change behavior. Handling:

- A **change in the workload's artifact/version** invalidates "stable" status
  for capabilities tied to the app tree; the policy re-enters Observe for the
  changed surface while never-promote denies stay active.
- Never-promote classes are never re-learned.
- New capabilities after a deploy require a **second observation window** before
  promotion.

## What the engine is not

- Not AI-driven enforcement. AI may summarize and propose; the promotion rules
  above are deterministic.
- Not "allow everything observed." Silence is safer than a wrong allow.
- Not invisible. Every promotion, denial, and review decision is logged and
  surfaced.

Related: [SAFE_DEPLOY.md](SAFE_DEPLOY.md) (the UX),
THREAT_MODEL.md (poisoned-learning threat), [ARCHITECTURE.md](ARCHITECTURE.md).

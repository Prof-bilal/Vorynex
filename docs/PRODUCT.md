# PRODUCT.md — What Vorynex Is

## One sentence

Vorynex is a managed runtime security platform that automatically creates and
enforces a least-privilege runtime boundary around internet-facing web
applications, so that a successful exploit does not automatically become full
server compromise.

## The question Vorynex asks

Traditional WAFs ask:

> Is this HTTP request malicious?

Vorynex asks:

> Even if the attacker successfully executes application code, what should this
> workload actually be allowed to do?

That is a **post-exploitation** question. It is answerable at the OS layer
(process spawn, file access, network egress, privilege) regardless of how the
attacker got code execution.

## What Vorynex is

- A **runtime least-privilege** system for web workloads.
- A **blast-radius reduction** tool: it limits what a compromised workload can
  reach.
- A **learning** system: it observes normal behavior and proposes a boundary,
  with a safe path from observation to enforcement.
- A **managed** platform: fleet dashboard, event history, attack timelines,
  CVE correlation.

## What Vorynex is not

| Not this | Why |
|---|---|
| A WAF | Vorynex does not primarily filter HTTP requests. |
| A vulnerability scanner | It does not find the bug; it limits the consequences. |
| "AI cybersecurity" | AI analyzes advisories and drafts policies; enforcement is deterministic. |
| Antivirus for websites | It does not signature-match payloads. |
| A replacement for patching | Mitigation ≠ fix. See EMERGENCY_SHIELD.md. |
| A guarantee of safety | It contains; it does not prevent. |

## Language we use

Use:
- contain compromise
- reduce blast radius
- restrict post-exploitation behavior
- runtime least privilege

Never:
- impossible to hack
- fully secure
- blocks every zero-day

## The three modes

| Mode | Behavior | When |
|---|---|---|
| **Observe** | No enforcement. Records what *would* have been blocked. | Development, staging, first deployment. |
| **Protect** | Blocks only high-confidence dangerous behavior. **Recommended default.** | Production after an observe period. |
| **Lockdown** | Strict generated allowlist; only known capabilities work. | Hardened production, stable workloads. |

Details: [LEARNING_ENGINE.md](LEARNING_ENGINE.md).

## High-confidence dangerous behavior (Protect mode)

```text
web worker → /bin/bash
web worker → ~/.ssh/id_rsa
web worker → /etc/shadow
web worker → cloud metadata (169.254.169.254)
web worker → arbitrary binary download-and-execute
web worker → unexpected privilege escalation
```

These are the behaviors that real post-RCE incidents exhibit most often
(see [COMPETITIVE_RESEARCH.md](COMPETITIVE_RESEARCH.md)). They are the first
things Vorynex blocks, because they are high-signal and low-false-positive.

## Positioning test

The current hypothesis under test is:

> **Vorynex automatically creates and enforces a least-privilege runtime
> boundary around web applications so that successful exploitation does not
> automatically become full server compromise.**

[VALIDATION.md](VALIDATION.md) tests whether this is the strongest positioning
and [DIFFERENTIATION.md](DIFFERENTIATION.md) records what survives.

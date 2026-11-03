# SECURITY.md

Vorynex is security software whose purpose is to contain untrusted processes. A
bug that lets a protected workload escape the boundary, or that makes Vorynex run
anything unprotected, is by definition a security vulnerability. This policy
mirrors Warden's, whose engine Vorynex builds on.

## Status

**Pre-alpha. Not production-ready.** Read [THREAT_MODEL.md](THREAT_MODEL.md)
before protecting anything sensitive, and verify native enforcement on the OS
where you deploy.

## Reporting a vulnerability

Report privately — do not open a public issue. Use GitHub Security Advisories
("Report a vulnerability") on the Vorynex repository, or the contact listed
there. Include:

- Vorynex version, kernel version, distribution, container runtime
- The policy used (redact secrets)
- Reproduction steps for the escape/bypass
- Relevant local event log

Expected: acknowledgment within 72 hours; triage within 7 days; escape-class bugs
are treated as the highest priority.

## In scope

- **Bypasses** — a protected workload reaching a file, process, or host outside
  its policy grants.
- **Fail-open behavior** — any code path that runs a workload unprotected, or
  claims protection it does not have.
- **Policy bypasses** — malformed policies, symlink tricks, env leakage, DNS
  leakage past the allowlist, egress that escapes the allowlist.
- **Evidence integrity** — blocked events that silently go unlogged where the
  product claims they are logged.
- **Learning poisoning** — a path that lets observed attacker behavior become an
  enforced allow rule.

## Out of scope (documented limitations)

- Bugs where enforcement works as documented but is too strict (usability).
- The limitations in [THREAT_MODEL.md](THREAT_MODEL.md): in-process RCE, root
  attacker, kernel exploits, serverless, exfil over allowed egress, app-level
  authorization bugs.
- Attacks that require the operator to disable enforcement themselves.

## Design principles upheld

1. **Enforcement is local.** No cloud dependency for protection.
2. **Fail closed on missing primitives**; fail open only for the cloud.
3. **Deny by default.** No implicit grants.
4. **Honest state.** `protected` / `degraded` / `unprotected` is always reported
   accurately.
5. **AI proposes, deterministic validation disposes.**

## Security-relevant documents

- [THREAT_MODEL.md](THREAT_MODEL.md) — what Vorynex can and cannot protect.
- [FAILURE_MODES.md](FAILURE_MODES.md) — fail-open / fail-closed behavior.
- [LEARNING_ENGINE.md](LEARNING_ENGINE.md) — poisoning defenses.
- [WARDEN_AUDIT.md](WARDEN_AUDIT.md) — inherited risks from the foundation.
- [SECURITY_TESTING.md](SECURITY_TESTING.md) — the proof-of-value lab.

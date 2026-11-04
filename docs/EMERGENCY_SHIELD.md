# EMERGENCY_SHIELD.md

When a new CVE appears, Vorynex can propose and validate **containment** for the
affected workloads — reducing the blast radius while the customer patches.

> **Vorynex mitigation is NOT a replacement for patching.** Emergency Shield
> buys time; it does not fix the bug.

## The workflow

```text
new CVE appears
      ↓
Vorynex identifies affected workloads
      ↓
understands likely exploitation behavior
      ↓
generates candidate containment
      ↓
tests candidate  (simulation + deterministic validation)
      ↓
observe
      ↓
protect
```

## Sources

Ingested continuously:

- **CISA KEV** — known-exploited, prioritized.
- **NVD** — CVSS, CPE matching.
- **GitHub Security Advisories (GHSA)** — ecosystem/package level, includes
  malware advisories.
- **OSV** — open-source vulnerability database.
- **Vendor advisories** — precise affected versions and observed behavior.

Behavior hints are derived from incident reports and PoCs (e.g. React2Shell
showed `next-server → /bin/sh`; PHP2Shell wrote webshells into web roots).

## From CVE → affected workloads

- Map the advisory's package/product to workloads (image SBOM, package lockfile,
  runtime version).
- Rank by KEV membership and exploit maturity.
- Surface only workloads Vorynex actually sees, never hypotheticals.

## From CVE → candidate containment

Behaviors, not payloads. Examples:

| CVE class | Likely post-exploit behavior | Candidate containment |
|---|---|---|
| RSC/SSR RCE | `node → /bin/sh`, outbound C2 | deny web-worker shell; restrict egress |
| PHP RCE | webshell written to web root | deny writes outside app-owned paths |
| SSRF/RCE chain | IMDS query | deny `169.254.169.254`/`169.254.170.2` |
| Deserialization | child process, temp ELF | deny exec outside allowlist; deny `/tmp` ELF exec |
| Path traversal | read `.env` | deny secret-path reads |

The candidate is expressed in the same policy model as everything else.

## AI's role — and its limits

AI **may**:
- summarize an advisory,
- cluster CVEs by likely post-exploitation behavior,
- draft a candidate containment policy,
- explain a blocked event in plain language.

AI **MUST NOT**:
- autonomously push untested blocking rules to production.

```text
AI proposes
      ↓
deterministic validation      (schema, never-promote classes, policy checks)
      ↓
simulation                    (replay against recorded traffic; must not break the app)
      ↓
observe                       (deploy in Observe; confirm it would fire only on attack)
      ↓
confidence                    (deterministic threshold)
      ↓
enforcement                   (Protect/Lockdown)
```

Every stage is deterministic and auditable. The AI's output is an *input* to
validation, never a rule that skips it.

## Validation gates (all required before enforce)

1. **Schema + safety**: valid policy; never-promote classes respected; no
   blanket grants.
2. **Simulation**: replays recorded normal traffic; **zero** new denials on
   benign traffic (else rejected).
3. **Attack simulation**: the known exploitation behavior **is** denied
   (see [SECURITY_TESTING.md](SECURITY_TESTING.md)).
4. **Observe window**: in Observe, it fires only on attack-shaped events.
5. **Confidence gate**: deterministic score above threshold, then enforce.

## Customer-facing UX

```text
⚠ New exploited vulnerability: CVE-2026-XXXX (KEV, CVSS 9.8)

Affects 2 workloads:
  api-server     next 15.0.2   ← you are on 15.0.2
  staging-web    next 15.0.2

Containment generated (not yet active):
  • deny web-worker shell execution        [validated ✓]
  • deny IMDS access                        [validated ✓]
  • restrict egress to known hosts          [needs review]

Patch available: next 15.0.4

[ Apply containment ]   [ Review policy ]   [ Dismiss ]
```

Clear messaging on every surface:

> **Vorynex mitigation is not a replacement for patching.**

## Scope limits (stated honestly)

- Only helps when the exploit manifests as observable OS behavior.
- Cannot contain pure in-process exploitation or exfil over allowed egress.
- Depends on advisory quality and how quickly behavior is understood.

## Implementation status (MVP)

- `engine/cve` parses **OSV** advisories (GitHub Security Advisories are OSV
  format) and the **CISA KEV** catalog; it correlates an npm `package-lock.json`
  against advisories with semver ranges, and KEV membership (by id or alias)
  marks an advisory known-exploited.
- `vorynex cve scan --lockfile <package-lock.json> --osv <file> [--kev <file>]
  [--workload <name>] [--json]`.
- Not yet: live feed fetching, NVD CVSS enrichment, and turning a match into a
  **candidate containment** with the validation pipeline above (Milestone 12).

## Emergency Shield implementation (M12)

- `engine/shield` turns CVE matches into a **candidate containment policy**. It
  only adds denies and safe defaults (shell/download exec denies,
  `protect_secrets`, sensitive path denies) and **never grants anything**.
- **Deterministic validation** rejects a candidate that grants a shell, allowlists
  cloud metadata, grants filesystem root, drops an existing deny, or adds a new
  grant.
- **Simulation** replays recorded events through the base and candidate
  policies: new denials of dangerous behavior are the goal, new denials of
  anything else are breakage, and dangerous behavior neither policy denies is a
  coverage gap.
- **Verdict**: `rejected` (validation failed), `needs-review` (benign breakage),
  or `approved` (may proceed to observe). Nothing is applied automatically.
- CLI: `vorynex shield --lockfile <package-lock.json> --osv <file> [--kev <file>]
  [--policy <base.yaml>] [--events <events.jsonl>] [--out <candidate.yaml>]
  [--json]`.

The workflow remains: AI proposes -> deterministic validation -> simulation ->
observe -> confidence -> enforcement. The current build ships deterministic
proposal and validation; AI-drafted, advisory-specific rules and automatic
rollout are the remaining items.

# PROOF.md — containment proof

**Status: P1 complete (synthetic target). P2 (OWASP CRS arm) and P3 (real app)
pending.** This file is the living report; a table only appears here once the
run that produced it exists in `tests/proof/evidence/`.

## The claim (pre-registered)

> On a deliberately vulnerable Node app, these attacks **land when unprotected**
> and are **contained when Vorynex is enforcing** — while legitimate requests
> keep working.

The request is never what Vorynex blocks. The **effect** is what it denies.

## What has been measured (P1, synthetic target)

`make proof` → `tests/proof/evidence/<stamp>/`

```
Attacks: 5   PASS 5 / FAIL 0 / VOID 0   Benign: ok
```

| Scenario | Bare (control) | Vorynex Tier 0 | Verdict |
|---|---|---|---|
| `cmd_marker` — `exec()` injection → touch a file | landed | **blocked** | PASS |
| `cmd_secret` — `exec()` injection → read decoy `.env` into a file | landed | **blocked** | PASS |
| `path_traversal` — `readFile` with `../` → decoy secret | landed | **blocked** | PASS |
| `ssrf_egress` — server-side fetch to a loopback collector | landed | **blocked** | PASS |
| `arbitrary_write` — write outside the granted tree | landed | **blocked** | PASS |
| `benign_echo` — legitimate request | landed | landed | PASS |
| `benign_read` — legitimate file read | landed | landed | PASS |

Evidence per run: `summary.json`, `results.jsonl`, `arm-a.jsonl`, `arm-c.jsonl`,
`env.json` (git SHA + dirty flag, kernel, Landlock ABI, node, engine),
`manifest.sha256`.

**VOID semantics:** if an attack does not land unprotected, the row proves
nothing and is counted as VOID — not as a pass. Any legit-operation denial is a
release blocker.

## Method

- **Arm A** — the target alone. Every attack must land here, or the row is VOID.
- **Arm C** — the same target launched under `vorynex exec --policy` (Tier 0,
  Landlock: read only the app tree, write only a scratch dir, no outbound TCP,
  no shell exec).
- Targets are **loopback only**; fixtures are decoys (`DECOY-VORYNEX-NOT-REAL`);
  payloads only touch the run's temp dir. `make proof` refuses unless
  `PROOF_AUTHORIZED=1` is set.
- Effects are checked **host-side** (marker/leak file, collector hit count,
  written file), not from the workload's own output.

## What this does NOT prove (yet)

- **No WAF comparison yet.** P2 adds OWASP CRS (Coraza, pinned) at PL1/PL2 with
  a benign corpus, so we can report TPR *and* TNR — and show that a
  request-layer filter blocks known payloads while the effect still lands when
  the payload is mutated. Until P2 exists, this document makes no claim about
  WAFs, Cloudflare or Vercel.
- **The P1 target is ours, not someone else's code.** P3 adds a real, maintained
  app (DVWS-node, GPL-3.0) with a genuine `exec` sink and an unauthenticated
  metadata SSRF.
- **Tier 0 only.** Tier 1 (eBPF-LSM) is host-only and not measured here.
- **No performance numbers yet.** `vorynex bench` (P4) reports p50/p95/p99,
  CPU/RSS and startup delta, interleaved A/B.
- Not covered by design: in-process RCE detection, root attackers, kernel
  exploits, serverless, app-level authz (IDOR/BOLA), exfiltration over an
  *allowed* egress.

## Reproduce

```bash
make proof
# or, explicitly:
PROOF_AUTHORIZED=1 tests/proof/run-proof.sh
```

Requires `go`, `node`, `python3`, `curl`, and a kernel with Landlock. The run
writes only under `tests/proof/evidence/<stamp>/` (gitignored) and a temp dir.

## Why the framing matters

A WAF asks "is this request malicious?" Vorynex asks "even if this code runs,
what is it allowed to do?" P1 measures the second question directly: identical
requests, one arm enforcing nothing, one arm enforcing the effect boundary.

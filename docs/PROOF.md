# PROOF.md — containment proof

**Status: P1 and P2 complete on a controlled target; P3 complete on a real
third-party app (bare / CRS / Vorynex Tier 1); P4 (performance) pending.** This
file is the living report; a table only appears here once the run that produced
it exists in `tests/proof/evidence/` or `tests/proof/evidence-real/`.

## The claim (pre-registered)

> On a deliberately vulnerable Node app, these attacks **land when unprotected**
> and are **contained when Vorynex is enforcing** — while legitimate requests
> keep working. A request-layer filter (OWASP CRS) blocks the payloads it
> recognises; an encoded form of the same attack can pass and still land.

The request is never what Vorynex blocks. The **effect** is what it denies.

## What has been measured

`make proof` → `tests/proof/evidence/<stamp>/`

```
Attacks: 7   PASS 7 / FAIL 0 / VOID 0   Benign: ok
CRS blocked 6/7 at PL1 and 7/7 at PL2 (0 false positives on 2 benign requests)
```

| Scenario | Bare | CRS PL1 | CRS PL2 | Vorynex Tier 0 |
|---|---|---|---|---|
| `cmd_marker` — exec injection → marker file | landed | blocked | blocked | **blocked** |
| `cmd_secret` — exec injection → read decoy `.env` | landed | blocked | blocked | **blocked** |
| `path_traversal` — `../` → decoy secret | landed | blocked | blocked | **blocked** |
| `ssrf_dotted` — fetch `127.0.0.1:<port>` | landed | blocked | blocked | **blocked** |
| `ssrf_decimal` — **same host as `2130706433`** | landed | **landed** | blocked | **blocked** |
| `persistence_write` — write into the app tree | landed | blocked | blocked | **blocked** |
| `arbitrary_write` — write outside the grant | landed | blocked | blocked | **blocked** |

The one CRS miss is the point: a signature engine sees a string, not a
destination. Vorynex never had to recognise it. Full detail and limits:
[BENCHMARKS.md](BENCHMARKS.md).

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

- **The WAF arm is a stand-in.** Coraza + OWASP CRS 4.0, not Cloudflare or
  Vercel: their Free/Hobby tiers cannot run the managed rulesets that matter, and
  bypasses are WAF×framework specific. No claim about a commercial WAF is made.
- **The real-app arm (P3) covers two scenarios so far.** On DVWS-node, CRS at
  PL1/PL2 (stock and tuned) let an authenticated `exec()` injection through, and
  only "blocked" the XML-RPC SSRF by failing to parse the body; one Tier 1 hook
  set (deny exec, block connect) contained both without restarting the container
  or breaking its normal requests. XXE, NoSQL injection and SSTI are present in
  that app and not yet measured, and the Tier 1 hooks were chosen by hand, not
  derived from the observed behaviour.
- **The corpus is small.** 7 attacks on our fixture, 2 on the real app; no
  TNR/false-positive rate is claimed from either. A real FP study needs a
  public benign corpus.
- **Tier 0 only** on our fixture. Tier 1 (eBPF-LSM) is measured on the real app
  once armed, and nowhere else.
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

# PROOF.md — containment proof

**Status: P1–P5 complete.** Containment and the WAF comparison on a controlled
target (P1/P2), the same on a real third-party app with Tier 1 armed on a
running container (P3), enforcement overhead (P4), and false positives against
containment (P5). This file is the living report; a table only appears here once
the run that produced it exists in `tests/proof/evidence*/`.

## The claim (pre-registered)

> On a deliberately vulnerable Node app, these attacks **land when unprotected**
> and are **contained when Vorynex is enforcing** — while legitimate requests
> keep working. A request-layer filter (OWASP CRS) blocks the payloads it
> recognises; an encoded form of the same attack can pass and still land.

The request is never what Vorynex blocks. The **effect** is what it denies.

## What has been measured

Four phases, all reproducible from this repo:

| Phase | Target | Arms compared | Headline | Detail |
|---|---|---|---|---|
| **P1** | this repo's fixture | bare vs Vorynex Tier 0 | 5/5 attacks land bare, 5/5 contained; the 2 benign controls pass (thin — see P5) | below |
| **P2** | this repo's fixture | + OWASP CRS PL1/PL2 | CRS blocks 6/7 at PL1, 7/7 at PL2; the payload it missed still landed | [BENCHMARKS.md](BENCHMARKS.md) |
| **P3** | **DVWS-node** (real third-party app, Docker) | bare / CRS (PL1, PL2, tuned) / Vorynex Tier 1 live attach | CRS let the authenticated `exec()` injection through at every setting; Tier 1 contained 2/3. The in-process template-evaluation row is the mirror: CRS blocked it, Tier 1 could not see it | [BENCHMARKS.md](BENCHMARKS.md#p3--the-same-comparison-against-a-real-application) |
| **P4** | the same endpoint | bare / Tier 0 / CRS in the request path | Tier 0 below its own noise floor; CRS +1.5 ms p50 and ~6× CPU, slower in 7/7 rounds | [PERFORMANCE.md](PERFORMANCE.md) |
| **P5** | the same fixture | the generated policy vs one that allows a shell | the default denies a legitimate feature (14.3% of a 140-op corpus); granting the shell costs the containment | [BENCHMARKS.md](BENCHMARKS.md#p5--false-positives-vs-containment) |

`make proof` → `tests/proof/evidence/<stamp>/` (P1+P2, also a CI job):

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

**Correction, from P5.** "Benign: ok" above is two requests — an echo and a file
read. Neither exercises this application's ability to spawn a command, and under
the default policy that feature is denied: measured against a 140-operation
corpus, the generated policy refuses 20 of them. Containment is real and the
default is a defensible choice for a service that should not shell out, but the
cost was invisible while the benign set stayed at two requests. See
[P5](BENCHMARKS.md#p5--false-positives-vs-containment).

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
- **P3** adds a real target in Docker and arms **Tier 1** on the *running*
  container's cgroup (`live attach --deny-exec /proc/<pid>/root/bin/sh
  --block-connect <collector>`). The app is never restarted, and the denied inode
  is resolved through the container's mount namespace — the image's shell is a
  different file from the host's.
- **P4** interleaves arms round by round, drives them open-loop at a fixed rate
  so a stall cannot be hidden by the generator, and reports paired per-round
  deltas against a bare-vs-bare noise floor.
- Targets are **loopback only**; fixtures are decoys (`DECOY-VORYNEX-NOT-REAL`);
  payloads only touch the run's temp dir. `make proof` refuses unless
  `PROOF_AUTHORIZED=1` is set.
- Effects are checked **host-side** (marker/leak file, collector hit count,
  written file), never from the workload's own output — the DVWS XML-RPC reply
  still claims success while the fetch was denied.
- Every arm asserts its own mechanism separately from observing the effect: an
  attach that armed nothing, a collector that never started, or a client that
  sent chunked bodies all produced wrong results during development, in both
  directions.

## What this does NOT prove (yet)

- **The WAF arm is a stand-in.** Coraza + OWASP CRS 4.0, not Cloudflare or
  Vercel: their Free/Hobby tiers cannot run the managed rulesets that matter, and
  bypasses are WAF×framework specific. No claim about a commercial WAF is made.
- **The real-app arm (P3) covers three scenarios.** On DVWS-node, CRS at PL1/PL2
  (stock and tuned) let an authenticated `exec()` injection through and only
  "blocked" the XML-RPC SSRF by failing to parse the body; one Tier 1 hook set
  contained those two without restarting the container. The third scenario is
  deliberately unflattering: an in-process template evaluation
  (`${process.env.X}`) is blocked by CRS's `${…}` signature and **not** contained
  by Tier 1, because nothing observable happens — no exec, no file open, no
  connection. **In-process data flows are out of scope for the measured hooks.**
  XXE and NoSQL injection remain unmeasured, and the Tier 1 hooks were chosen by
  hand, not derived from the observed behaviour.
- **The corpus is small.** 7 attacks on our fixture, 2 on the real app; no
  TNR/false-positive rate is claimed from either. A real FP study needs a
  public benign corpus.
- **Tier 0 only** on our fixture. Tier 1 (eBPF-LSM) is measured on the real app
  once armed, and nowhere else.
- **No throughput ceiling, and Tier 1 cost is not measured.** P4
  ([PERFORMANCE.md](PERFORMANCE.md)) shows Tier 0 is below the noise floor of the
  measurement (paired deltas mixed-sign, like two bare runs compared to each
  other) while the request-path filter costs 2.5–3.5× latency and ~6× CPU in
  7/7 rounds. Tier 1 (per-syscall hooks) is *not* measured — any "free" claim is
  about Tier 0 only, on one shared machine, over loopback, at 200 rps.
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

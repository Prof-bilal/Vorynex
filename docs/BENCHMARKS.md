# BENCHMARKS.md — request-layer WAF vs runtime containment

Measured, not asserted. Produced by `make proof`; the run's raw evidence is in
`tests/proof/evidence/<stamp>/` (gitignored, uploaded as a CI artifact).

## What was compared

| Arm | What it is |
|---|---|
| **Bare** | the target with nothing in front (control — every attack must land) |
| **CRS PL1 / PL2** | OWASP Coraza + **OWASP CRS 4.0** (embedded, pinned by module) as a reverse proxy, **blocking** mode, paranoia 1 and 2 |
| **Vorynex** | the same target under `vorynex exec` (Tier 0, Landlock: read only the app tree, write only a scratch dir, no outbound TCP, no shell) |

**Why CRS and not "Cloudflare":** the Cloudflare **Free** plan cannot run the
Cloudflare Managed Ruleset or the OWASP Core Ruleset (both Pro+), has no `Log`
action and no regex; Vercel's OWASP ruleset is **Enterprise-only**. A free-tier
number would mostly measure rules we wrote. Coraza + CRS is the same rule family
Cloudflare's OWASP ruleset implements, is version-pinned, and attributes every
block to a rule id. We therefore **do not claim** to have tested Cloudflare or
Vercel — see the limits below.

## Results

```
Attacks: 7   PASS 7 / FAIL 0 / VOID 0   Benign: ok
CRS blocked 6/7 at PL1 and 7/7 at PL2
CRS false positives on benign traffic: PL1 0, PL2 0
```

| Scenario (7 attacks) | Bare | CRS PL1 | CRS PL2 | Vorynex |
|---|---|---|---|---|
| `cmd_marker` — `exec()` injection → write a marker | landed | blocked | blocked | **blocked** |
| `cmd_secret` — `exec()` injection → read decoy `.env` | landed | blocked | blocked | **blocked** |
| `path_traversal` — `readFile` with `../` → decoy | landed | blocked | blocked | **blocked** |
| `ssrf_dotted` — server fetch to `127.0.0.1:<port>` | landed | blocked | blocked | **blocked** |
| `ssrf_decimal` — **same destination as `2130706433`** | landed | **landed** | blocked | **blocked** |
| `persistence_write` — write a file into the app tree | landed | blocked | blocked | **blocked** |
| `arbitrary_write` — write outside the granted tree | landed | blocked | blocked | **blocked** |

Benign controls (`/api/echo`, a legitimate file read) passed in every arm.

## How to read it

1. **CRS is good at what it can recognise.** Every shell-injection spelling,
   traversal and dotted-IP SSRF was blocked at PL1, with a rule id in the audit
   log. This is not a "WAFs are useless" result.
2. **Recognition is the whole mechanism.** The decimal form of the *same*
   destination (`2130706433` == `127.0.0.1`) passed at PL1 and the request
   reached the collector. CRS sees a string; it does not resolve intent.
3. **PL2 closes that gap — at a cost.** Raising paranoia caught the encoded form.
   In real traffic higher paranoia is a false-positive trade-off; our benign
   corpus is two requests, so we make **no TNR claim**.
4. **Vorynex does not need to recognise anything.** All seven effects were
   denied, including the one CRS missed, because the policy is about what the
   workload may *do* (write, connect, exec, read), not about what the request
   *looks like*.

## Limits (do not overstate this)

- **CRS 4.0** (the version embedded by the pinned Go module), not 4.25+, and not
  a managed commercial ruleset. Cloudflare's OWASP ruleset implements CRS 3.3.0;
  results are not portable between engines — bypasses are WAF×framework specific.
- **One synthetic target, seven attacks.** No real application yet (that is P3),
  and the corpus is small on purpose so every row is inspected.
- **No bot/DDoS layer, no ML scoring, no rate limiting** — a real edge product
  has those in front of the WAF, and they change what reaches it.
- **Tier 0 only.** Tier 1 (eBPF-LSM) is host-only and not measured here.
- **No performance numbers yet** (P4): latency/CPU/RSS deltas are not claimed.

## Reproduce

```bash
make proof                       # P1+P2 arms, writes evidence/<stamp>/
PROOF_AUTHORIZED=1 tests/proof/run-proof.sh
```

Evidence per run: `arm-a.jsonl`, `arm-b-pl1.jsonl`, `arm-b-pl2.jsonl`,
`arm-c.jsonl`, `waf-pl{1,2}-audit.jsonl` (rule ids), `summary.json`,
`env.json` (git SHA, kernel, Landlock ABI, node, CRS pin), `manifest.sha256`.

## P3 — the same comparison against a real application

Target: **`snoopysecurity/dvws-node`** (GPL-3.0, maintained) in its own Docker
stack — a real third-party app, not our fixture. Two genuine sinks:

- `GET /api/v2/sysinfo/:command` → `exec(req.params.command + " -a")`, behind a
  normal login (`/api/v2/login`, seeded `admin/letmein`), i.e. authenticated RCE
- `POST /xmlrpc` → `dvws.CheckUptime` fetches a caller-supplied URL, no auth
- (also present: XXE file read, `$where` NoSQL injection, SSTI — not yet in the
  corpus)

```bash
make proof-real        # Docker; ~2.5 GB on first run; not part of CI
```

```
Attacks 2: landed bare 2, VOID 0. Controls on bare: ok.
```

| Scenario | Bare | CRS PL1 | CRS PL2 | CRS PL1 tuned | Vorynex Tier 1 |
|---|---|---|---|---|---|
| `rce_exec` — `id;touch /proof/rce-marker` via `sysinfo` | landed | **landed** | **landed** | **landed** | n/a¹ |
| `ssrf_uptime` — XML-RPC fetch to the collector | landed | blocked² | blocked² | blocked² | n/a¹ |
| `benign_login` — `admin/letmein` | landed | landed | landed | landed | n/a¹ |
| `benign_info` — `GET /api/v1/info` | landed | landed | landed | landed | n/a¹ |

¹ The Tier 1 column needs root: it arms BPF hooks on the running container's
cgroup. Run `sudo tests/proof/real/run-real.sh` (or `sudo make proof-real`).
² Blocked by rule **200002** — Coraza's *body-parsing* rule, because CRS 4.0
has no XML body processor. The request never reached the app, so the SSRF was
prevented, but no SSRF rule matched: it is a blunt instrument that would also
block legitimate XML APIs (the "tuned" arm adds JSON/XML body processors and the
block persists).

Findings:

1. **An `exec()` injection in a path parameter passes every CRS configuration
   we tried** — stock and tuned, PL1 and PL2 — and the marker was written. The
   payload arrives as `/api/v2/sysinfo/id%3Btouch%20%2Fproof%2Frce-marker`; no
   CRS rule matched it at all (`app_rules_matched=[]` in the audit). CRS scans
   arguments and a normalised URI, and this injection is neither.
2. **Enabling a body processor changes the reason for a block, not the
   protection.** Both the stock and tuned arms stop the XML-RPC request, but
   only because the body cannot be parsed.
3. **No false positives here once the harness was correct.** The first run
   showed CRS 403-ing the login. That was *our* bug: the attacker sent the body
   with chunked encoding, so the WAF could not read it and raised a body error.
   Fixed in the harness; the false positive disappeared. Recording it because
   the same mistake would have produced a flattering, wrong result in the other
   direction.

### Limits of P3

- Two scenarios so far (RCE + SSRF); XXE, NoSQL injection and SSTI are in the
  app and not yet measured.
- Tier 1 column requires root and is not yet produced.
- DVWS-node is a deliberately vulnerable teaching app. It is *real third-party
  code*, but it is not a production workload; a production app has far more
  allowed behaviour, which cuts both ways.

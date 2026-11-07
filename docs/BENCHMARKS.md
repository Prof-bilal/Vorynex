# BENCHMARKS.md — request-layer WAF vs runtime containment

Measured, not asserted. Produced by `make proof`; the run's raw evidence is in
`tests/proof/evidence/<stamp>/` (gitignored, uploaded as a CI artifact).

Enforcement **cost** (latency, CPU, memory, startup) is a separate measurement:
[PERFORMANCE.md](PERFORMANCE.md) — Tier 0 sits below its own noise floor, the
request-path filter costs 2.5–3.5× latency and ~6× CPU.

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
# the Vorynex column arms BPF hooks, so it needs root:
PROOF_SUDO_PASSWORD=... make proof-real
```

```
Attacks 3: landed bare 3, VOID 0. Controls on bare: ok.
Vorynex Tier 1 contained 2/3.
```

| Scenario | Bare | CRS PL1 | CRS PL2 | CRS PL1 tuned | Vorynex Tier 1 |
|---|---|---|---|---|---|
| `rce_exec` — `id;touch /proof/rce-marker` via `sysinfo` | landed | **landed** | **landed** | **landed** | **blocked** |
| `ssrf_uptime` — XML-RPC fetch to the collector | landed | blocked² | blocked² | blocked² | **blocked** |
| `ssti_env` — `${process.env.SSTI_CANARY}` via `greeter` | landed | **blocked**³ | **blocked**³ | **blocked**³ | **landed** |
| `benign_login` — `admin/letmein` | landed | landed | landed | landed | landed |
| `benign_info` — `GET /api/v1/info` | landed | landed | landed | landed | landed |

² Blocked by rule **200002** — Coraza's *body-parsing* rule, because CRS 4.0
has no XML body processor. The request never reached the app, so the SSRF was
prevented, but no SSRF rule matched: it is a blunt instrument that would also
block legitimate XML APIs (the "tuned" arm adds JSON/XML body processors and the
block persists).

³ Blocked by rule **932130**, which matches the *shape* `${…}` / `$(…)` in an
argument. It is a signature on how the payload looks, not an understanding of
what it does — which is precisely why it is listed next to the row Vorynex
misses.

**How the Tier 1 column is produced** — the app is never restarted. The harness
resolves the running container's cgroup, then runs
`vorynex live attach --object ... --cgroup <id> --deny-exec /proc/<pid>/root/bin/sh
--block-connect <collector>:3290 --seconds 40`, which arms eBPF-LSM hooks on that
cgroup and disarms itself when the window closes. Two details that matter:

- the denied inode must be resolved **through the container's mount namespace**
  (`/proc/<pid>/root/bin/sh`). The image's shell is an overlay file (inode
  1826004) and is a different file from the host's `/bin/sh` (inode 7369); using
  the host path would arm a hook that never fires.
- only `--deny-exec` and `--block-connect` are needed. The workload keeps its DB
  connections because each hook is per-operation — this is why Tier 1, not
  Tier 0, is the right tier for an already-running app (Tier 0 denies all
  outbound TCP at spawn time, which would stop the app reaching Mongo/MySQL).

Findings:

1. **An `exec()` injection in a path parameter passes every CRS configuration
   we tried** — PL1, PL2, stock and tuned — and the marker was written. The audit
   shows no CRS rule matched it (`app_rules_matched=[]`). CRS scans arguments and
   a normalised URI; this injection is neither.
2. **The same injection is denied by one Tier 1 hook**, and the container keeps
   serving: `benign_login` and `benign_info` still return 200 during the armed
   window, and the app is healthy after disarm.
3. **The app lies about the SSRF, and the harness doesn't care.** Under Tier 1,
   `/xmlrpc` still replies `200 CheckUptime ... "Checking uptime for: ..."`, but
   the collector logged zero hits — the fetch never happened. The effect is
   checked at the collector, not in the reply.
4. **Enabling a body processor changes the reason for a block, not the
   protection.** Both stock and tuned arms stop the XML-RPC request, but only
   because the body cannot be parsed.
5. **The two approaches cover different classes, and neither covers everything.**
   The in-process template evaluation is *blocked by CRS and not contained by
   Vorynex*: it runs inside the application process, so there is no exec, no file
   open and no connection for a runtime hook to deny. The exec injection is the
   exact mirror — contained by Vorynex, missed by CRS at every setting. A
   runtime boundary is not a substitute for fixing an injection sink, and a
   signature engine is not a substitute for containing what runs after one is
   exploited. Claiming either alone would be wrong.

### Two bugs this harness had (and why they are recorded)

- The first run showed CRS 403-ing the login — a flattering result. It was ours:
  the attacker sent bodies chunked, so Coraza raised a body error and blocked.
- The next runs showed Tier 1 "containing" everything and later "containing
  nothing"; both were wrong. The collector container was not running, so the SSRF
  effect was being read from the application's optimistic reply, and an unarmed
  attach reported success. The harness now fails loudly when the collector is
  down or the cgroup cannot be resolved, and never reports a column it did not
  actually produce.

### Limits of P3

- Three scenarios (RCE, SSRF, in-process template evaluation). XXE and NoSQL
  injection are present in the app and not yet measured.
- **In-process data flows are out of scope for the measured hooks.** The SSTI row
  is the demonstration: reading an environment variable inside the app process
  produces no syscall the boundary can see. Containing that needs a different
  control (fix the sink, or an in-process policy) — it is a limit, not a bug in
  the hooks.
- DVWS-node is deliberately vulnerable teaching code. It is real third-party
  software, but not a production workload; a production app allows far more
  behaviour, which cuts both ways.
- The Tier 1 column requires root. It is one hook set chosen by hand for these
  three attacks, not an automatically derived policy.

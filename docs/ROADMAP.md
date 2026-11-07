# ROADMAP.md

Milestones, not calendar dates. Each milestone should leave something demoable.

## Legend

- `[x]` — done and verified (unit tests; the security lab for enforcement).
- **✅ done** — every item listed under the milestone is complete.
- **✅ core done** — the milestone's headline capability is implemented,
  unit-tested, and verified end-to-end (lab/CI), but **at least one sub-item is
  deliberately deferred** — usually because it is blocked on a later milestone,
  on the continuous recorder/agent, or on real-world data. It does **not** mean
  the milestone is complete; read the unchecked items under it.

## Milestone 0 — Architecture validation
- [x] Warden deep audit ([WARDEN_AUDIT.md](WARDEN_AUDIT.md))
- [x] Competitive + incident research ([COMPETITIVE_RESEARCH.md](COMPETITIVE_RESEARCH.md))
- [x] Attempt to disprove the product ([VALIDATION.md](VALIDATION.md))
- [x] Differentiation + ICP + MVP defined
- [ ] ICP validation interviews (self-hosted Docker / small SaaS) — business
      task, needs real users
- [x] Freeze the enforcement-tier design — see
      [ARCHITECTURE.md](ARCHITECTURE.md#enforcement-tier-design-frozen):
      Tier 0 = Landlock (unprivileged, spawn-time); Tier 1 = eBPF-LSM
      (`capable`, `bprm_check_security`, `file_open`, `socket_connect`),
      cgroup-scoped and disarmed by default

## Milestone 1 — Extract/reuse the Warden runtime engine  ✅ done
- [x] Vendor/adapt `policy`, `proxy`, `audit`, and `envfilter` into `engine/`
      with MIT attribution ([`engine/NOTICE.md`](../engine/NOTICE.md))
- [x] Single Go module (`github.com/vorynex/vorynex`) tying `engine/` and
      `cmd/vorynex`
- [x] CI: gofmt + vet + build + unit tests (`.github/workflows/ci.yml`)
- [x] `cmd/vorynex` scaffold (`version`, `help`)
- [x] `vorynex doctor` (platform capability report)
- **Decision — spawn-time arg builders (`BuildBwrapArgs`/`BuildDockerArgs`)
  are *not* vendored.** Tier 0 uses Landlock, which is unprivileged and works
  inside a container where `bwrap` cannot run; vendoring a second backend that
  the MVP does not use would be premature complexity. `bwrap` remains a
  possible future stronger *host* backend (mount-level hiding) — revisit only
  if a host deployment needs it. See [ARCHITECTURE.md](ARCHITECTURE.md).

## Milestone 2 — Node/Docker workload discovery  ✅ done
- [x] Docker API/inspect (read-only) workload detection
      (`engine/discovery`: list + `docker inspect`)
- [x] Node/Next.js/Express identification
- [x] Discover writable paths, sensitive paths, and secret env **names**
      (`vorynex discover --details`)
- Note: static discovery covers mounts, working dir, network mode, published
  ports, and secret-named env vars. Runtime **egress dependencies** (which hosts
  the app actually talks to) are learned in Observe mode (Milestone 3).

## Milestone 3 — Observe mode  ✅ core done
- [x] Behavioral profiler with confidence scoring (`engine/profiler`)
- [x] Local event bus (JSONL; the audit trace file)
- [x] Poisoning defenses implemented + tested: never-promote classes (shell
      exec, secret reads, cloud metadata, raw-IP egress) plus confidence
      thresholds
- [x] Zero enforcement; "would-have-blocked" report (`vorynex observe -- <cmd>`)
- [x] Multi-session aggregation: `policy generate --from a --from b
      --min-sessions N`; provenance is the session count

## Milestone 4 — Protect mode (Tier 0)  ✅ core done
- [x] Policy `process` section (Vorynex extension) + `vorynex exec` command
- [x] Landlock spawn-time shim for filesystem, exec, and egress
- [x] Shell/exec containment (lab `shell_spawn`/`bash_spawn` PASS) — fixed the
      ELF-interpreter EXECUTE bug and the `NET_CONNECT_TCP` bit
- [x] Lab 7/7 PASS under `LAB_ENGINE=vorynex`; CI enforces it
- [x] High-confidence blocking wired to the profiler:
      `vorynex protect --from <events> -- <command>` (generates the policy and
      launches under Tier 0)
- [x] File-granular exec control via Tier 1 (M5 `bprm_check_security` inode hook)
- [ ] False-positive measurement on real production traffic (needs a real
      workload; the lab's benign operations pass)

## Milestone 5 — Tier 1 live enforcement  ✅ core done
- [x] Capability detection: kernel, LSM list, BTF, CAP_BPF/CAP_PERFMON, with
      honest reasons (`engine/enforce/live`); `vorynex live status`
- [x] Deterministic enforcement plan from a policy (`vorynex live plan`)
- [x] BPF-LSM loader (`cilium/ebpf`): **four hooks** — `capable`,
      `bprm_check_security`, `file_open`, `socket_connect` — attached
      **disarmed** and scoped to one cgroup
- [x] File-granular exec denial (allow node, deny bash) by inode — validated
- [x] Path/file denial by inode, and IPv4[:port] egress denial — validated
- [x] Privileged integration test: denied inside the armed cgroup, unaffected
      outside it, restored after clearing the deny and after disarm; a running
      workload is **not killed**
- [x] `vorynex live attach --object <path> --cgroup <path> [--pid <pid>]
      [--deny-exec <path>] [--deny-open <path>] [--block-connect <ip[:port]>]
      [--cap N] [--seconds N]` — cgroup anchoring by PID included
- [ ] Full policy → hook translation (path prefixes, hostname allowlists via a
      DNS-resolved IP map); rollback orchestration via the control plane
- Note: egress is enforced at `socket_connect`; a separate nftables layer is
  not required for the MVP.

## Milestone 6 — Policy generation  ✅ core done
- [x] Turn the observed baseline into a reviewable policy (`engine/policygen`)
- [x] Versioned schema (`version: 1` field on the policy)
- [x] Signed policy: Ed25519 detached signature over the policy bytes
- [x] Never-promote classes become explicit denies; safe defaults
      (`protect_secrets: true`)
- [x] `vorynex policy generate --from <events.jsonl> [--out <file>] [--sign-key <file>]`
- [x] Trust root: `vorynex policy pubkey` prints the public key to pin;
      `vorynex policy verify --policy --sig --pubkey` checks a detached
      signature; `vorynex exec --sig --pubkey` refuses an unverified policy

## Milestone 7 — Telemetry API  ✅ core done
- [x] Local-first, size-bounded event spool with gap markers on overflow
- [x] Resumable, outbound-only exporter (`engine/telemetry`); enforcement never
      depends on it
- [x] Host identity (`hostid`) + enrollment + persisted export cursor
- [x] `vorynex telemetry status | export --endpoint <url> [--token <t>] [--once] [--policy <file>]`
- [x] Minimal cloud ingestion API: `POST /v1/enroll`, `POST /v1/events`
      (`cloud/api`, `cmd/vorynex-cloud`)
- [x] Per-host tokens: issued at enrollment, stored by the agent and used for
      events/policy/SBOM; a host token cannot act for another host or as admin;
      rotation via `POST /v1/hosts/{id}/rotate-token` (old token dies instantly)
- [x] TLS: `--tls-cert`/`--tls-key` (or terminate TLS at a reverse proxy)
- [x] Durable store: Supabase Postgres via PostgREST (`SUPABASE_URL` +
      `SUPABASE_SERVICE_ROLE_KEY`); hosts (with their effective policy) and
      events are mirrored best-effort, so a Supabase outage cannot affect
      ingestion or enforcement. JSONL remains the local default.
      Schema: [`web/supabase/schema.sql`](../web/supabase/schema.sql)
- [x] Agent-enforced signing trust root (Milestone 6): the agent verifies the
      policy signature before it loads it

## Milestone 8 — Dashboard  ✅ core done
- [x] **Product app in `web/` (Next.js)**: landing at `/`, auth at
      `/login` + `/signup` (Supabase), and the dashboard at `/dashboard`
      (fleet, mode control, containment timeline, per-host policy, blast radius,
      CVEs). The browser never holds the control-plane token.
- [x] Served by `vorynex-cloud` at `/` (static UI + `/v1` API) — kept as a
      dependency-free fallback dashboard
- [x] Workload list with **persisted** protection mode
      (`GET /v1/hosts`, `POST /v1/hosts/{id}/mode`)
- [x] Containment event timeline: contained vs allowed, host filter,
      contained-only; `GET /v1/events`
- [x] Loading, empty, and error states; keyboard focus; responsive layout
- [x] Readable dark UI (no SOC-console styling)
- [x] Token/auth: sign-in form on 401, sign-out, `?token=` support
- [x] Live updates: 15s poll, pauses when the tab is hidden or the operator is
      interacting; manual refresh
- [x] Workload detail panel: mode, counts, last event, recent containment
- [x] Policies view: the agent uploads its effective policy
      (`telemetry export --policy <file>`); `POST|GET /v1/hosts/{id}/policy`
      validates and stores it; the dashboard shows the rule set and a
      control-plane-derived summary
- [x] Blast Radius view: policy-derived when a policy is uploaded, else the
      observed reach from telemetry

## Milestone 9 — Attack Trace  ✅ core done
- [x] Derive traces from recorded events (`engine/trace`): `DENIED` (enforced)
      and `WOULD_DENY` (observed)
- [x] Plain-English fields: attempt, policy, result, behavior, reason,
      confidence, next actions
- [x] CLI: `vorynex trace [--from <events.jsonl>] [--workload <id>] [--all]
      [--json] [--since <dur>] [--id <id>]`
- [x] Dashboard: expandable trace on every contained event (native `<details>`)
- [x] Process lineage from fork/exec evidence (`clone`/`fork`/`execve`); a trace
      becomes `exact` (e.g. `node → /bin/bash`) only when the lineage is proven,
      otherwise it stays `inferred`
- [ ] Join the ingress HTTP request (needs access logs at the edge)

## Milestone 10 — Blast Radius  ✅ core done
- [x] `engine/blastradius`: derive reachable resources and contained classes
      from an effective policy; no invented score
- [x] CLI: `vorynex blast-radius --policy <file> [--workload <name>] [--mode <mode>] [--json]`
- [x] Dashboard panel: observed reach vs containment from telemetry
- [x] Diff view: `blast-radius --policy <a> --compare <b>`
- [x] Policy-based dashboard view (derived from the uploaded policy)
- [ ] Graph view

## Milestone 11 — CVE correlation  ✅ core done
- [x] Parse OSV advisories (which include GitHub Security Advisories) and the
      CISA KEV catalog
- [x] Semver range matching plus explicit affected-version lists
- [x] Correlate a workload's `package-lock.json` dependencies; KEV membership by
      id or alias marks an advisory known-exploited
- [x] CLI: `vorynex cve scan --lockfile <package-lock.json> --osv <file>
      [--kev <file>] [--workload <name>] [--json]`
- [x] Live OSV querying and live CISA KEV download (`cve scan --live
      --kev-live`)
- [x] NVD CVSS enrichment (`cve scan --nvd`; `NVD_API_KEY` raises the rate limit)
- [x] SBOM upload (`cve scan --upload`) and a dashboard CVE view (severity,
      package, installed/fixed, KEV badge)

## Milestone 12 — Emergency Shield  ✅ core done
- [x] `engine/shield`: propose containment from CVE matches (adds denies only,
      never grants)
- [x] Deterministic validation: schema, no shell/metadata/root grants, no
      dropped denies, no new grants
- [x] Simulation against recorded traffic: new dangerous denials vs benign
      breakage, plus coverage gaps
- [x] Verdict gate: `rejected` / `needs-review` / `approved`; never auto-applied
- [x] CLI: `vorynex shield --lockfile <package-lock.json> --osv <file>
      [--kev <file>] [--policy <base.yaml>] [--events <events.jsonl>]
      [--out <candidate.yaml>] [--json]`
- [x] Rollout orchestration: the control plane stages a desired mode/policy
      (`POST /v1/hosts/{id}/rollout`, validated on staging) and the agent
      converges (`vorynex rollout pull|status`); the supervisor applies it — no
      silent restart of a customer's workload
- [ ] AI-drafted, advisory-specific rules (deterministic propose/validate/
      simulate is done; AI drafting needs a model backend)

## Milestone 13 — Private beta
- [x] **Proof harness** (`make proof`, `docs/PROOF.md`, `docs/BENCHMARKS.md`):
      bare vs OWASP CRS (PL1/PL2) vs Vorynex on a controlled target. 7/7 effects
      contained; CRS missed the decimal-IP SSRF at PL1 (it landed) and caught it
      at PL2. CI job uploads the evidence.
- [ ] Proof on a **real application** (DVWS-node): done — bare, OWASP CRS
      (PL1/PL2 stock + tuned) and Vorynex Tier 1 live attach, in
      `docs/BENCHMARKS.md`. CRS let the `exec()` injection through at every
      setting; Tier 1 contained both attacks without restarting the container.
      Remaining: more scenarios (XXE, NoSQLi, SSTI) and `vorynex bench` numbers
- [ ] `vorynex connect` + `vorynex status` (onboarding and posture)
- [ ] Installable without the repo: release build, `install.sh`, systemd unit,
      control-plane Dockerfile, deploy docs
- [ ] Reversible protect: `--off`, `--from-desired`, health-check rollback
- [ ] Real self-hosted Docker/Node workloads
- [ ] Success metrics from [MVP.md](MVP.md) tracked

---

## Do NOT build before the core runtime protection is validated

Billing. Kubernetes. Enterprise SSO. Compliance dashboards. Ten languages.
Serverless. macOS/Windows enforcement. A second cloud.

Every item above must first answer the feature test:

> Who needs it? What attack does it stop? Can Warden already do part of it?
> Does a competitor do it better? Is it required for the MVP? Will someone pay
> for it?

If not: do not build it.

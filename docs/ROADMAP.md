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
- [ ] ICP validation interviews (self-hosted Docker / small SaaS)
- [ ] Freeze the enforcement-tier design (Tier 0 Landlock+seccomp; Tier 1 eBPF-LSM)

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
- [ ] Multi-session aggregation + provenance scoring (needs the continuous
      recorder / agent)

## Milestone 4 — Protect mode (Tier 0)  ✅ core done
- [x] Policy `process` section (Vorynex extension) + `vorynex exec` command
- [x] Landlock spawn-time shim for filesystem, exec, and egress
- [x] Shell/exec containment (lab `shell_spawn`/`bash_spawn` PASS) — fixed the
      ELF-interpreter EXECUTE bug and the `NET_CONNECT_TCP` bit
- [x] Lab 7/7 PASS under `LAB_ENGINE=vorynex`; CI enforces it
- [ ] High-confidence-only blocking wired to the profiler (Milestone 3)
- [ ] False-positive measurement on real traffic
- [ ] File-granular exec control via Tier 1 (Landlock exec control is
      directory-scoped)

## Milestone 5 — Tier 1 live enforcement  ◐ partial
- [x] Capability detection: kernel, LSM list, BTF, CAP_BPF/CAP_PERFMON, with
      honest reasons (`engine/enforce/live`); `vorynex live status`
- [x] Deterministic enforcement plan from a policy — `bprm_check_security`,
      `file_open`, `socket_connect`, `capable` (`vorynex live plan --policy`)
- [x] `doctor` reports Tier 1 availability from real capabilities, not guesses
- [ ] BPF-LSM loader — requires root/CAP_BPF and a clang-built object; **not
      shipped untested**. This is the remaining work.
- [ ] cgroups v2 anchoring and nftables egress
- [ ] Verify no-workload-kill by default; no-outage containment

## Milestone 6 — Policy generation  ✅ core done
- [x] Turn the observed baseline into a reviewable policy (`engine/policygen`)
- [x] Versioned schema (`version: 1` field on the policy)
- [x] Signed policy: Ed25519 detached signature over the policy bytes
- [x] Never-promote classes become explicit denies; safe defaults
      (`protect_secrets: true`)
- [x] `vorynex policy generate --from <events.jsonl> [--out <file>] [--sign-key <file>]`
- [ ] Signing-key management / trust root (cloud-side, Milestone 7)

## Milestone 7 — Telemetry API  ✅ core done
- [x] Local-first, size-bounded event spool with gap markers on overflow
- [x] Resumable, outbound-only exporter (`engine/telemetry`); enforcement never
      depends on it
- [x] Host identity (`hostid`) + enrollment + persisted export cursor
- [x] `vorynex telemetry status | export --endpoint <url> [--token <t>] [--once]`
- [x] Minimal cloud ingestion API: `POST /v1/enroll`, `POST /v1/events`
      (`cloud/api`, `cmd/vorynex-cloud`)
- [ ] Real auth (per-host tokens, rotation), TLS, durable store (DB not JSONL)
- [ ] Agent-enforced signing trust root (from Milestone 6)

## Milestone 8 — Dashboard  ✅ core done
- [x] Served by `vorynex-cloud` at `/` (static UI + `/v1` API)
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
- [ ] Policies view (needs the agent to upload its effective policy)
- [ ] Blast Radius view (Milestone 10)

## Milestone 9 — Attack Trace  ✅ core done
- [x] Derive traces from recorded events (`engine/trace`): `DENIED` (enforced)
      and `WOULD_DENY` (observed)
- [x] Plain-English fields: attempt, policy, result, behavior, reason,
      confidence, next actions
- [x] CLI: `vorynex trace [--from <events.jsonl>] [--workload <id>] [--all]
      [--json] [--since <dur>] [--id <id>]`
- [x] Dashboard: expandable trace on every contained event (native `<details>`)
- [ ] Join the ingress HTTP request and process lineage (needs pid/ppid and
      access logs; traces are currently marked `inferred`)

## Milestone 10 — Blast Radius  ✅ core done
- [x] `engine/blastradius`: derive reachable resources and contained classes
      from an effective policy; no invented score
- [x] CLI: `vorynex blast-radius --policy <file> [--workload <name>] [--mode <mode>] [--json]`
- [x] Dashboard panel: observed reach vs containment from telemetry
- [ ] Policy-based dashboard view (needs the agent to upload its policy)
- [ ] Diff and graph views

## Milestone 11 — CVE correlation  ✅ core done
- [x] Parse OSV advisories (which include GitHub Security Advisories) and the
      CISA KEV catalog
- [x] Semver range matching plus explicit affected-version lists
- [x] Correlate a workload's `package-lock.json` dependencies; KEV membership by
      id or alias marks an advisory known-exploited
- [x] CLI: `vorynex cve scan --lockfile <package-lock.json> --osv <file>
      [--kev <file>] [--workload <name>] [--json]`
- [ ] Live feed fetching (OSV/NVD/KEV APIs) and NVD CVSS enrichment
- [ ] Dashboard CVE view (needs workload SBOM upload)

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
- [ ] Live advisory ingestion and AI-drafted, advisory-specific rules
- [ ] Automatic observe -> protect rollout orchestration via the control plane

## Milestone 13 — Private beta
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

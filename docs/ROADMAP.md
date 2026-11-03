# ROADMAP.md

Milestones, not calendar dates. Each milestone should leave something demoable.

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

## Milestone 5 — Tier 1 live enforcement
- [ ] eBPF-LSM attach per cgroup (`security_bprm_check`, `file_open`,
      `socket_connect`, `capable`) — **priority: file-granular exec containment**
- [ ] cgroups v2 resource anchoring; nftables egress
- [ ] Kernel capability detection + honest degradation
- [ ] Verify no-workload-kill by default; no-outage containment

## Milestone 6 — Policy generation
- [ ] Turn the baseline into a reviewable, signed policy
- [ ] Review/approve UX; safe defaults; versioned schema

## Milestone 7 — Telemetry API
- [ ] Outbound-only, resumable exporter; local-first buffering
- [ ] Auth, host enrollment, event ingestion

## Milestone 8 — Dashboard
- [ ] login, host, application, runtime status, policies, event timeline,
      protection-mode switch

## Milestone 9 — Attack Trace
- [ ] Render one event as a plain-English containment story
      ([ATTACK_TRACE.md](ATTACK_TRACE.md))

## Milestone 10 — Blast Radius
- [ ] Derive the reach graph from real policies/capabilities
      ([BLAST_RADIUS.md](BLAST_RADIUS.md))

## Milestone 11 — CVE correlation
- [ ] Ingest CISA KEV, NVD, GHSA, OSV
- [ ] Map advisories → affected workloads

## Milestone 12 — Emergency Shield
- [ ] AI-proposes → deterministic-validation → simulate → observe → enforce
      ([EMERGENCY_SHIELD.md](EMERGENCY_SHIELD.md))

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

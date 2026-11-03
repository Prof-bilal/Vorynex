# ROADMAP.md

Milestones, not calendar dates. Each milestone should leave something demoable.

## Milestone 0 — Architecture validation
- [x] Warden deep audit ([WARDEN_AUDIT.md](WARDEN_AUDIT.md))
- [x] Competitive + incident research ([COMPETITIVE_RESEARCH.md](COMPETITIVE_RESEARCH.md))
- [x] Attempt to disprove the product ([VALIDATION.md](VALIDATION.md))
- [x] Differentiation + ICP + MVP defined
- [ ] ICP validation interviews (self-hosted Docker / small SaaS)
- [ ] Freeze the enforcement-tier design (Tier 0 Landlock+seccomp; Tier 1 eBPF-LSM)

## Milestone 1 — Extract/reuse the Warden runtime engine
- [ ] Vendor/adapt `policy`, `proxy`, `audit`, and spawn-time arg builders into
      `engine/` with MIT attribution
- [ ] `go.work` tying `engine/` and `cmd/vorynex`
- [ ] CI: lint + build + unit tests
- [ ] `vorynex doctor` (platform capability report)

## Milestone 2 — Node/Docker workload discovery
- [ ] Docker API/inspect (read-only) workload detection
- [ ] Node/Next.js/Express identification
- [ ] Discover writable paths, network deps, sensitive paths

## Milestone 3 — Observe mode
- [ ] Behavioral profiler with confidence scoring
- [ ] Local event bus (JSONL)
- [ ] Poisoning defenses implemented + tested
- [ ] Zero enforcement; "would-have-blocked" report

## Milestone 4 — Protect mode (Tier 0)
- [ ] Landlock + seccomp spawn-time shim (unprivileged, in-container)
- [ ] Shell/exec allowlist; sensitive-path denies; egress baseline
- [ ] High-confidence-only blocking (the seven MVP protections)
- [ ] False-positive measurement on real traffic

## Milestone 5 — Tier 1 live enforcement
- [ ] eBPF-LSM attach per cgroup (`security_bprm_check`, `file_open`,
      `socket_connect`, `capable`)
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

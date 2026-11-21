# Vorynex Features Analysis

**Generated:** 2026-11-06  
**Purpose:** Comprehensive analysis of current Vorynex features and capabilities  
**Status:** Draft - Planning Phase  
**Based on:** Repository scan, README.md, docs/, cmd/vorynex/, engine/ directories

---

## Executive Summary

Vorynex is a **pre-alpha but functionally complete** runtime security platform for internet-facing web applications. The core value proposition is **post-exploitation containment** - limiting what an attacker can do after successfully exploiting a vulnerability.

**Maturity Level:** High technical completion (Milestones 0-12 core done), but pre-production ready

---

## Table of Contents

1. [Current Feature Inventory](#1-current-feature-inventory)
2. [Technical Architecture](#2-technical-architecture)
3. [Feature Completeness Matrix](#3-feature-completeness-matrix)
4. [Strengths and Gaps](#4-strengths-and-gaps)
5. [Technical Debt and Risks](#5-technical-debt-and-risks)
6. [Recommendations](#6-recommendations)

---

## 1. Current Feature Inventory

### 1.1 Core Platform Features

#### 🎯 Runtime Enforcement
- **Tier 0 (Spawn-time):** Landlock + seccomp shim for containers, `bwrap` for host
  - Status: ✅ Implemented and tested
  - Capabilities: Filesystem, exec, and egress control
  - Limitations: Cannot confine already-running processes from outside

- **Tier 1 (Live):** eBPF-LSM + cgroups v2 + nftables
  - Status: ✅ Core done (Milestone 5)
  - Capabilities: `capable`, `bprm_check_security`, `file_open`, `socket_connect` hooks
  - Requirements: Kernel ≥ 5.7, `CONFIG_BPF_LSM`, `CAP_BPF`
  - Features:
    - File-granular exec denial by inode
    - Path/file denial by inode
    - IPv4[:port] egress denial
    - cgroup-scoped enforcement

#### 🎯 Modes of Operation
1. **Observe Mode** - No enforcement, records would-be blocks
   - ✅ Multi-session aggregation
   - ✅ Confidence scoring
   - ✅ "Would-have-blocked" reports

2. **Protect Mode** - Blocks high-confidence dangerous behavior
   - ✅ Default recommended mode
   - ✅ High-confidence blocking only
   - ✅ Tier 0 enforcement via Landlock

3. **Lockdown Mode** - Strict generated allowlist
   - ✅ Defined
   - ⚠️ Not MVP-critical (deferred)

### 1.2 Agent Features

#### Workload Discovery
- ✅ Docker API/inspect workload detection (`engine/discovery`)
- ✅ Node/Next.js/Express identification
- ✅ Writable paths, sensitive paths discovery
- ✅ Secret env names detection
- ✅ Static discovery (mounts, working dir, network mode, published ports)

#### Behavioral Profiling
- ✅ Profiler with confidence scoring (`engine/profiler`)
- ✅ Local event bus (JSONL audit trace file)
- ✅ Poisoning defenses implemented:
  - Never-promote classes (shell exec, secret reads, cloud metadata, raw-IP egress)
  - Confidence thresholds
- ✅ Multi-session aggregation for policy generation

#### Policy Management
- ✅ Policy generation from observed events (`engine/policygen`)
- ✅ Versioned schema (version: 1)
- ✅ Signed policies (Ed25519 detached signatures)
- ✅ Never-promote classes become explicit denies
- ✅ Safe defaults (`protect_secrets: true`)
- ✅ Trust root verification

#### Policy Enforcement
- ✅ `vorynex exec` - Execute with policy enforcement
- ✅ `vorynex protect` - Enable high-confidence denials
- ✅ `vorynex observe` - Profile workload
- ✅ Policy verification before loading

### 1.3 Telemetry and Events

#### Event System
- ✅ Local-first, size-bounded event spool
- ✅ Gap markers on overflow
- ✅ Resumable, outbound-only exporter (`engine/telemetry`)
- ✅ Host identity + enrollment
- ✅ Persisted export cursor

#### Telemetry CLI
- ✅ `vorynex telemetry status`
- ✅ `vorynex telemetry export --endpoint <url>`
- ✅ `--token`, `--once`, `--policy` options

### 1.4 Security Features

#### Minimum Protection (All 7 MVP Requirements)
1. ✅ **Sensitive filesystem paths** unreadable: `.env`, `~/.ssh`, `~/.aws`, `/etc/shadow`, docker socket
2. ✅ **Unexpected child processes** from web worker denied
3. ✅ **Shell execution** (`/bin/bash`, `/bin/sh`) denied
4. ✅ **Unauthorized outbound connections** blocked
5. ✅ **Cloud metadata** (`169.254.169.254`, `169.254.170.2`) blocked
6. ✅ **Dangerous host access** (docker socket, host mounts) denied
7. ✅ **Privilege-escalation attempts** denied

#### Attack Trace
- ✅ Plain-English trace rendering (`engine/trace`)
- ✅ CLI: `vorynex trace [--from <events.jsonl>] [--workload <id>] [--all] [--json] [--since <dur>] [--id <id>]`
- ✅ Dashboard: Expandable trace on contained events
- ✅ Process lineage from fork/exec evidence
- ✅ Fields: attempt, policy, result, behavior, reason, confidence, next actions

#### Blast Radius
- ✅ Derive reachable resources from effective policy (`engine/blastradius`)
- ✅ CLI: `vorynex blast-radius --policy <file> [--workload <name>] [--mode <mode>] [--json]`
- ✅ Dashboard panel
- ✅ Diff view: Compare two policies
- ⚠️ Graph view (deferred)

#### CVE Correlation
- ✅ Parse OSV advisories (includes GitHub Security Advisories)
- ✅ Parse CISA KEV catalog
- ✅ Semver range matching + explicit affected-version lists
- ✅ Correlate workload dependencies (package-lock.json)
- ✅ CLI: `vorynex cve scan --lockfile <package-lock.json>`
- ✅ Live OSV querying (`--live`)
- ✅ Live CISA KEV download (`--kev-live`)
- ✅ NVD CVSS enrichment (`--nvd`)
- ✅ SBOM upload (`--upload`)
- ✅ Dashboard CVE view

#### Emergency Shield
- ✅ Propose containment from CVE matches (`engine/shield`)
- ✅ Adds denies only, never grants
- ✅ Deterministic validation
- ✅ Simulation against recorded traffic
- ✅ Verdict gate: rejected / needs-review / approved
- ✅ CLI: `vorynex shield --lockfile <package-lock.json> [--osv <file>] [--kev <file>] [--policy <base.yaml>] [--events <events.jsonl>]`
- ✅ Rollout orchestration via control plane

### 1.5 Cloud Features

#### Control Plane (`vorynex-cloud`)
- ✅ Minimal ingestion API
- ✅ `POST /v1/enroll` - Host enrollment
- ✅ `POST /v1/events` - Event ingestion
- ✅ `POST /v1/hosts/{id}/mode` - Protection mode control
- ✅ `POST /v1/hosts/{id}/policy` - Policy upload
- ✅ `POST /v1/hosts/{id}/rotate-token` - Token rotation
- ✅ Per-host tokens (issued at enrollment)
- ✅ TLS support (`--tls-cert`/`--tls-key`)

#### Durable Store
- ✅ Supabase Postgres via PostgREST
- ✅ Best-effort mirroring (outage doesn't affect enforcement)
- ✅ Hosts and events mirrored to Postgres
- ✅ JSONL remains local default
- ✅ Schema: `web/supabase/schema.sql`

#### Rollout Management
- ✅ Rollout orchestration
- ✅ Staging and validation
- ✅ CLI: `vorynex rollout pull|status`
- ✅ Supervisor applies rollouts (no silent restart)

### 1.6 Dashboard and UI

#### Web Application (Next.js)
- ✅ Landing page (`/`)
- ✅ Auth: `/login`, `/signup` (Supabase email/password, GitHub/Google OAuth)
- ✅ Dashboard (`/dashboard`)
- ✅ Fleet overview
- ✅ Protection mode control
- ✅ Containment timeline
- ✅ Per-host policy view
- ✅ Blast radius view
- ✅ CVE view

#### Dashboard Features
- ✅ Workload list with persisted protection mode
- ✅ Containment event timeline (contained vs allowed, host filter)
- ✅ Loading, empty, and error states
- ✅ Keyboard focus, responsive layout
- ✅ Readable dark UI
- ✅ Token/auth: sign-in form on 401, sign-out, `?token=` support
- ✅ Live updates: 15s poll (pauses when tab hidden or user interacting)
- ✅ Workload detail panel: mode, counts, last event, recent containment
- ✅ Policies view: agent uploads effective policy
- ✅ Blast Radius view: policy-derived when available

### 1.7 CLI Commands

#### Main Commands
- ✅ `vorynex version` - Version information
- ✅ `vorynex help` - Help system
- ✅ `vorynex doctor` - Platform capability report
- ✅ `vorynex connect` - Authenticate host, install/verify agent
- ✅ `vorynex discover` - Discover workloads
- ✅ `vorynex observe` - Profile workload (no enforcement)
- ✅ `vorynex protect` - Enable high-confidence denials
- ✅ `vorynex status` - Current mode, policy summary, recent events
- ✅ `vorynex trace` - Human-readable attack trace
- ✅ `vorynex exec` - Execute with policy enforcement
- ✅ `vorynex policy` - Policy management (generate, verify, pubkey)
- ✅ `vorynex telemetry` - Telemetry management (status, export)
- ✅ `vorynex blast-radius` - Blast radius analysis
- ✅ `vorynex cve` - CVE scanning and correlation
- ✅ `vorynex shield` - Emergency shield generation
- ✅ `vorynex live` - Tier 1 live enforcement management
- ✅ `vorynex rollout` - Rollout management

### 1.8 Testing and Validation

#### Security Lab
- ✅ 7 scenarios must pass
- ✅ Lab validates: shell_spawn, bash_spawn, file_access, metadata_access, egress_block, privilege_escalation, unexpected_child
- ✅ CI enforces lab passing
- ✅ Current: 7/7 PASS under `LAB_ENGINE=vorynex`

#### Testing Infrastructure
- ✅ `make build` - Go build
- ✅ `make test` - Go tests
- ✅ `make ci` - vet + build + test
- ✅ `make lab` - Tier 0 security lab
- ✅ `make bpf` - Tier 1 eBPF object
- ✅ `make bpf-test` - Privileged Tier 1 test
- ✅ Next.js: `npm run typecheck`, `npm run build`

---

## 2. Technical Architecture

### 2.1 High-Level Architecture

```
┌───────────────── Vorynex Agent (on customer host) ──────────────────┐
│  workload discovery → profiler → signed policy store                    │
│                                                                         │
│   TIER 0  spawn-time   : Landlock + seccomp shim, or bwrap on host      │
│   TIER 1  live         : eBPF-LSM + cgroups v2 + nftables               │
│                                                                         │
│   modes: OBSERVE → PROTECT → LOCKDOWN                                   │
└──────────────────────────────────┬──────────────────────────────────────┘
                                   │ outbound-only, async
                                   ▼
┌───────────────── Vorynex Cloud (never in request path) ─────────────┐
│  dashboard · orgs/hosts/workloads · policies · event history            │
│  attack timelines · Blast Radius · CVE intelligence · Emergency Shield  │
└─────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Component Structure

```
Vorynex Repository
├── cmd/
│   ├── vorynex/           # CLI agent
│   │   ├── main.go        # Entry point
│   │   ├── connect.go     # Host authentication
│   │   ├── observe.go     # Observe mode
│   │   ├── protect.go     # Protect mode
│   │   ├── policy.go      # Policy management
│   │   ├── telemetry.go   # Telemetry management
│   │   ├── trace.go       # Attack trace
│   │   ├── blast.go       # Blast radius
│   │   ├── cve.go         # CVE scanning
│   │   ├── shield.go      # Emergency shield
│   │   ├── live.go        # Tier 1 enforcement
│   │   ├── rollout.go     # Rollout management
│   │   ├── doctor.go      # Capability detection
│   │   └── ...
│   └── vorynex-cloud/     # Control plane server
│       └── main.go
├── engine/
│   ├── discovery/        # Workload discovery
│   ├── profiler/          # Behavioral profiler
│   ├── policy/            # Policy engine
│   ├── policygen/         # Policy generation
│   ├── enforce/           # Enforcement engine
│   │   └── live/           # Tier 1 eBPF enforcement
│   ├── audit/             # Audit event system
│   ├── telemetry/         # Telemetry export
│   ├── blastradius/       # Blast radius analysis
│   ├── cve/               # CVE correlation
│   ├── shield/            # Emergency shield
│   ├── trace/             # Attack trace
│   ├── envfilter/         # Environment filtering
│   ├── proxy/             # Egress proxy
│   └── state/             # State management
├── web/
│   ├── app/               # Next.js application
│   ├── supabase/          # Database schema
│   └── ...
├── cloud/
│   └── dashboard/         # Dashboard (fallback)
└── docs/
    └── (documentation)
```

### 2.3 Enforcement Tier Design (Frozen)

| Tier | Mechanism | Privileges | Scope | Status |
|------|-----------|------------|-------|--------|
| Tier 0 | Landlock + seccomp | Unprivileged | Spawn-time | ✅ Implemented |
| Tier 1 | eBPF-LSM | CAP_BPF | Live (running processes) | ✅ Core done |

- **Tier 0:** Works inside containers where bwrap cannot run
- **Tier 1:** Requires kernel ≥ 5.7, CONFIG_BPF_LSM, CAP_BPF
- **Both tiers:** Can enforce the same policy

### 2.4 Data Flow

```
1. Discovery: vorynex discover → engine/discovery → workload info
2. Observe: vorynex observe → engine/profiler → events.jsonl
3. Policy: vorynex policy generate → engine/policygen → policy.yaml + sig
4. Protect: vorynex protect → engine/enforce → Tier 0/1 enforcement
5. Telemetry: vorynex telemetry export → engine/telemetry → cloud
6. Dashboard: web/ app → vorynex-cloud API → Supabase
```

---

## 3. Feature Completeness Matrix

### 3.1 MVP Requirements (from docs/MVP.md)

| Requirement | Status | Notes |
|-------------|--------|-------|
| Scope: Linux + Docker + Node.js | ✅ Complete | Explicitly focused |
| `vorynex connect` | ✅ Implemented | Host authentication |
| `vorynex observe` | ✅ Implemented | Profile workload |
| `vorynex protect` | ✅ Implemented | Enable enforcement |
| `vorynex status` | ✅ Implemented | Mode, policy, events |
| `vorynex trace <id>` | ✅ Implemented | Attack trace |
| Sensitive filesystem paths | ✅ Implemented | All 7 minimum protections |
| Unexpected child processes | ✅ Implemented | |
| Shell execution | ✅ Implemented | |
| Unauthorized outbound connections | ✅ Implemented | |
| Cloud metadata | ✅ Implemented | |
| Dangerous host access | ✅ Implemented | |
| Privilege escalation | ✅ Implemented | |
| Cloud MVP features | ✅ Implemented | Login, connect, app, status, policies, events, mode switch |
| Tier 0 enforcement | ✅ Implemented | Landlock + seccomp |
| Tier 1 enforcement | ✅ Core done | eBPF-LSM |
| Success metrics defined | ✅ Defined | In MVP.md |

### 3.2 Milestone Completion

| Milestone | Status | Notes |
|-----------|--------|-------|
| M0 - Architecture validation | ✅ Done | Warden audit, competitive research, differentiation |
| M1 - Extract Warden runtime | ✅ Done | Policy, proxy, audit, envfilter vendored |
| M2 - Node/Docker discovery | ✅ Done | Docker API, Node/Express/Next.js identification |
| M3 - Observe mode | ✅ Core done | Profiler, event bus, poisoning defenses |
| M4 - Protect mode (Tier 0) | ✅ Core done | Policy process section, exec command, Landlock shim |
| M5 - Tier 1 live enforcement | ✅ Core done | Capability detection, BPF-LSM loader, 4 hooks |
| M6 - Policy generation | ✅ Core done | Versioned schema, signed policies, never-promote classes |
| M7 - Telemetry API | ✅ Core done | Event spool, resumable exporter, per-host tokens |
| M8 - Dashboard | ✅ Core done | Next.js app, landing, auth, dashboard, all views |
| M9 - Attack Trace | ✅ Core done | Plain-English traces, CLI, dashboard |
| M10 - Blast Radius | ✅ Core done | Reachable resources, diff view, dashboard |
| M11 - CVE correlation | ✅ Core done | OSV, KEV, NVD, SBOM upload |
| M12 - Emergency Shield | ✅ Core done | Containment proposals, validation, simulation, rollout |
| M13 - Private beta | ⚠️ Partial | Proof benchmarks, connect/status, installable artifacts, reversible protect |

### 3.3 Additional Features Beyond MVP

| Feature | Status | Priority |
|---------|--------|----------|
| Reversible protect | ⚠️ Blocking M13 | High |
| Health-check rollback | ⚠️ Blocking M13 | High |
| Installable artifacts | ⚠️ Blocking M13 | High |
| systemd unit | ⚠️ Blocking M13 | High |
| Control-plane Dockerfile | ⚠️ Blocking M13 | High |
| Deploy docs | ⚠️ Blocking M13 | High |
| AI-drafted rules (Emergency Shield) | ⚠️ Deferred | Medium |
| Full policy → hook translation | ⚠️ Deferred | Medium |
| Join ingress HTTP request | ⚠️ Deferred | Low |
| Graph view (Blast Radius) | ⚠️ Deferred | Low |

---

## 4. Strengths and Gaps

### 4.1 Technical Strengths

✅ **Unique Architecture:** Two-tier enforcement under one policy is unique
✅ **Comprehensive Protection:** All 7 minimum protections implemented
✅ **Local-First:** Cloud outage never disables protection
✅ **Developer UX:** CLI-first, observe → verify → protect workflow
✅ **Poisoning Defense:** Never-promote classes + confidence thresholds
✅ **Security Lab:** 7/7 scenarios passing validates enforcement
✅ **Open Source Foundation:** Built on MIT-licensed Warden
✅ **Technical Depth:** eBPF-LSM, Landlock, cgroups v2, nftables

### 4.2 Product Strengths

✅ **Clear Positioning:** Post-exploitation containment (not prevention)
✅ **Honest Marketing:** "Contain compromise / reduce blast radius / runtime least privilege"
✅ **Automatic Learning:** Behavioral profiling with confidence scoring
✅ **Fleet Management:** Dashboard, event history, attack timelines
✅ **CVE Intelligence:** OSV + KEV + NVD integration
✅ **Emergency Shield:** CVE-driven containment workflow

### 4.3 Gaps and Missing Features

⚠️ **MVP Blockers (Milestone 13):**
- Proof benchmarks (three-arm experiment) - **CRITICAL**
- ICP validation interviews - **CRITICAL**
- Installable artifacts (install.sh, systemd, Docker) - **CRITICAL**
- Reversible protect with health-check rollback - **CRITICAL**
- Real self-hosted Docker/Node workloads validation - **CRITICAL**

⚠️ **Production Readiness:**
- False-positive measurement on real production traffic
- Performance benchmarks (latency, CPU, memory, startup)
- Full policy → hook translation for Tier 1
- AI-drafted rules for Emergency Shield

⚠️ **Enterprise Features:**
- Multi-language support (Python, Java, Go)
- Kubernetes support
- Multi-cloud support
- Billing system
- Enterprise SSO (SAML, OIDC)
- RBAC and audit logs
- Compliance dashboards

⚠️ **Developer Features:**
- Windows/macOS enforcement
- Serverless support
- IDE integrations
- CI/CD integrations

### 4.4 Competitive Gaps

✅ **Vorynex has:**
- Automatic behavioral learning with poisoning defense
- Developer-first UX
- Non-Kubernetes focus
- Two-tier enforcement
- Local-first managed fleet
- Blast Radius / Attack Trace
- Competitive pricing (mid-tier)

⚠️ **Competitors have that Vorynex doesn't:**
- CrowdSec: Free, but requires hand-assembled rules
- Tetragon/KubeArmor: Kubernetes-native, but static analysis only
- Oligo: Commercial, no-outage, but black box
- Sysdig: Enterprise console, drift detection

---

## 5. Technical Debt and Risks

### 5.1 Technical Debt

| Issue | Impact | Priority | Resolution |
|-------|--------|----------|------------|
| Deferred policy → hook translation | Limits Tier 1 policy expressiveness | Medium | Implement full translation |
| No performance benchmarks | Can't claim overhead numbers | High | Measure and document |
| No false-positive measurement | Risk of breaking production | Critical | Test with real workloads |
| Incomplete ICP validation | Market fit uncertainty | Critical | Conduct interviews |
| Missing installable artifacts | Blocks private beta | Critical | Build packages |

### 5.2 Technical Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Kernel compatibility (eBPF-LSM) | Medium | High | Capability detection + graceful degradation |
| Performance overhead too high | Low | High | Design for minimal overhead, benchmark |
| False positives in Protect mode | Medium | High | High-confidence-only blocking, observe first |
| Cloud outage affects enforcement | Very Low | High | Local-first architecture, outbound-only telemetry |
| Policy poisoning by attacker | Low | High | Never-promote classes, confidence thresholds |

### 5.3 Business Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Market doesn't understand value | Medium | High | Clear positioning, education, proof benchmarks |
| Adoption barriers too high | Medium | High | Simple install, observe-first, reversible protect |
| Competition catches up | Medium | Medium | Move fast, build moat with behavioral learning |
| Pricing too high/low | Medium | Medium | Validate with ICP, A/B test pricing |
| Security vulnerabilities in agent | Low | Critical | Security audits, minimal privileges, Warden foundation |

---

## 6. Recommendations

### 6.1 Immediate Actions (Next 30 Days)

**Priority 1 - MVP Completion:**
1. ✅ Complete proof benchmarks (three-arm experiment)
   - Bare workload vs request-layer filter vs Vorynex
   - Show WAF blocks payload but Vorynex contains post-exploitation
   - Document in docs/PROOF.md

2. ✅ Conduct ICP validation interviews
   - Target: 10-20 self-hosted Docker/Node.js users
   - Validate pain points, willingness to pay, adoption barriers
   - Document findings in docs/ICP.md update

3. ✅ Build installable artifacts
   - `install.sh` script
   - systemd unit file
   - Docker images for agent and cloud
   - Deploy documentation

4. ✅ Implement reversible protect
   - `--off` flag
   - `--from-desired` option
   - Health-check rollback mechanism
   - Document in docs/SAFE_DEPLOY.md

**Priority 2 - Production Readiness:**
5. ⚠️ Measure false positives on real workloads
   - Recruit beta testers with production workloads
   - Monitor in Observe mode first
   - Collect and analyze false positive rates

6. ⚠️ Establish performance baselines
   - Measure latency overhead (p50/p95/p99)
   - Measure CPU overhead
   - Measure memory overhead
   - Measure startup overhead
   - Document as regression gates

### 6.2 Short-term Actions (Next 90 Days)

**Priority 1 - Private Beta:**
7. ✅ Launch private beta with 10-20 customers
   - Select from ICP validation interviews
   - Provide hands-on support
   - Collect detailed feedback
   - Iterate on UX and features

8. ✅ Finalize pricing model
   - Validate with beta customers
   - A/B test different pricing tiers
   - Finalize freemium vs paid features

**Priority 2 - Product Enhancements:**
9. ⚠️ Complete Tier 1 policy translation
   - Full path prefixes support
   - Hostname allowlists via DNS-resolved IP map
   - Rollback orchestration via control plane

10. ⚠️ Implement AI-drafted rules for Emergency Shield
    - Integrate with model backend
    - Maintain deterministic validation
    - Ensure AI proposes, human validates

### 6.3 Medium-term Actions (Next 6 Months)

**Priority 1 - Market Expansion:**
11. ✅ Expand to additional runtimes
    - Python (FastAPI, Django, Flask)
    - Java (Spring Boot)
    - Go (Gin, Echo, Fiber)

12. ✅ Build enterprise features
    - SSO (SAML, OIDC)
    - RBAC and audit logs
    - Compliance dashboards (SOC2, HIPAA, PCI)

**Priority 2 - Ecosystem:**
13. ⚠️ Establish partner ecosystem
    - Hosting providers (DigitalOcean, Linode, Hetzner)
    - Dev tools (GitHub Actions, GitLab CI)
    - Monitoring tools (Datadog, Prometheus, Grafana)

14. ⚠️ Build thought leadership
    - Publish blog posts on runtime security
    - Speak at conferences (Def Con, Black Hat, KubeCon)
    - Create educational content
    - Establish as authority in post-exploitation containment

### 6.4 Long-term Vision (6-12 Months)

**Priority 1 - Platform Maturity:**
15. ⚠️ Kubernetes support
    - DaemonSet deployment
    - CRDs for policy management
    - Integration with existing K8s security tools

16. ⚠️ Multi-cloud support
    - AWS, GCP, Azure
    - Cloud-specific IMDS protection
    - Cloud-native enforcement where available

**Priority 2 - Advanced Features:**
17. ⚠️ Windows/macOS enforcement
    - Windows: Minifilter driver
    - macOS: System Extension / Endpoint Security

18. ⚠️ Serverless support
    - AWS Lambda, Google Cloud Functions, Azure Functions
    - Layer-based or extension-based enforcement

**Priority 3 - Business Scaling:**
19. ⚠️ Build sales team
    - Hire first sales engineer
    - Develop sales playbook
    - Build customer success function

20. ⚠️ Scale marketing
    - Paid advertising (targeted at ICP)
    - Content marketing
    - Community building
    - Developer advocacy

---

## Appendix A: Command Reference

### CLI Commands

```bash
# Installation and setup
vorynex doctor                    # Platform capability report
vorynex version                   # Version information
vorynex connect                   # Authenticate host

# Discovery and observation
vorynex discover                  # Discover workloads
vorynex observe -- <command>      # Profile workload
vorynex status                    # Current status

# Protection
vorynex protect --from <events> -- <command>  # Enable high-confidence blocking
vorynex exec --policy <file> -- <command>     # Execute with policy

# Policy management
vorynex policy generate --from <events> --out <file>  # Generate policy
vorynex policy verify --policy <file> --sig <sig> --pubkey <key>  # Verify policy
vorynex policy pubkey --key <file>  # Print public key

# Telemetry
vorynex telemetry status          # Telemetry status
vorynex telemetry export --endpoint <url>  # Export telemetry

# Security analysis
vorynex trace [--from <events>]   # Attack trace
vorynex blast-radius --policy <file>  # Blast radius analysis
vorynex cve scan --lockfile <file>  # CVE scanning
vorynex shield --lockfile <file>  # Emergency shield

# Live enforcement
vorynex live status               # Tier 1 capability report
vorynex live attach --object <path> --cgroup <path>  # Attach Tier 1 enforcement

# Rollout
vorynex rollout pull              # Pull staged rollout
vorynex rollout status            # Rollout status
```

### Build and Test Commands

```bash
make build          # Go build ./...
make test           # Go test ./...
make ci             # vet + build + test
make lab            # Tier 0 security lab (7 scenarios)
make bpf            # Build Tier 1 eBPF object
make bpf-test       # Privileged Tier 1 test (needs root)

cd web
npm run typecheck
npm run build
```

---

## Appendix B: File Structure

### Key Directories

```
├── cmd/
│   ├── vorynex/              # CLI agent (15+ commands)
│   └── vorynex-cloud/        # Control plane server
├── engine/
│   ├── audit/                # Audit event system
│   ├── blastradius/          # Blast radius analysis
│   ├── cve/                  # CVE correlation
│   ├── discovery/            # Workload discovery
│   ├── enforce/
│   │   └── live/             # Tier 1 eBPF enforcement
│   ├── envfilter/            # Environment filtering
│   ├── policy/               # Policy engine
│   ├── policygen/            # Policy generation
│   ├── profiler/             # Behavioral profiler
│   ├── proxy/                # Egress proxy
│   ├── shield/               # Emergency shield
│   ├── state/                # State management
│   ├── telemetry/            # Telemetry export
│   └── trace/                # Attack trace
├── web/
│   ├── app/                  # Next.js application
│   └── supabase/             # Database schema
└── docs/                     # Documentation
```

---

## Appendix C: Glossary

| Term | Definition |
|------|------------|
| Tier 0 | Spawn-time enforcement using Landlock + seccomp |
| Tier 1 | Live enforcement using eBPF-LSM + cgroups v2 |
| Observe Mode | No enforcement, records would-be blocks |
| Protect Mode | Blocks high-confidence dangerous behavior |
| Lockdown Mode | Strict generated allowlist |
| ICP | Initial Customer Profile (small SaaS, self-hosted Docker) |
| MVP | Minimum Viable Product (scope defined in docs/MVP.md) |
| IMDS | Instance Metadata Service (169.254.169.254) |
| KEV | Known Exploited Vulnerabilities (CISA catalog) |
| OSV | Open Source Vulnerabilities (database) |
| NVD | National Vulnerability Database |
| CVSS | Common Vulnerability Scoring System |
| LSM | Linux Security Module |
| eBPF | Extended Berkeley Packet Filter |

---

*Generated by Mistral Vibe - Features Analysis*
*Last Updated: 2026-11-06*
*Status: Draft - Planning Phase Only*

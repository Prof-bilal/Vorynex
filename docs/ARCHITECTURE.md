# ARCHITECTURE.md

Vorynex is **two systems**: a local Agent that enforces, and a Cloud control
plane that manages. Enforcement is always local. The cloud is never in the
request path.

```text
┌──────────────────────── Vorynex Agent (customer host) ─────────────────────────┐
│                                                                                │
│   discovery ──► profiler ──► signed policy store ──► enforcement                │
│       │             │                  │                     │                 │
│       │             │                  │                     ▼                 │
│       │             │                  │        ┌──────────────────────────┐   │
│       │             │                  │        │ TIER 0  spawn-time       │   │
│       │             │                  │        │  Landlock + seccomp shim │   │
│       │             │                  │        │  (unprivileged, or bwrap │   │
│       │             │                  │        │   on host)               │   │
│       │             │                  │        ├──────────────────────────┤   │
│       │             │                  │        │ TIER 1  live             │   │
│       │             │                  │        │  eBPF-LSM + cgroups v2   │   │
│       │             │                  │        │  + nftables, per cgroup  │   │
│       │             │                  │        └────────────┬─────────────┘   │
│       │             │                  │                     ▼                 │
│       │             │                  │          structured event bus        │
│       │             │                  │          (JSONL, local-first)        │
│       │             │                  │                     │                 │
│       ▼             ▼                  ▼                     ▼                 │
│   docker/ps      confidence        policy.json        blast-radius graph       │
│   /proc scan     scoring           + attestation      + attack-trace builder   │
│                                                                                │
│   modes: OBSERVE ─► PROTECT ─► LOCKDOWN                                        │
└──────────────────────────────────┬─────────────────────────────────────────────┘
                                   │ outbound-only, async, resumable
                                   ▼
┌──────────────────── Vorynex Cloud (never in the request path) ─────────────────┐
│ auth/orgs · hosts · workloads · policies · event history · attack timelines      │
│ CVE intelligence (KEV/NVD/GHSA/OSV) · Emergency Shield · Blast Radius views      │
│ notifications · RBAC (later) · billing (later)                                   │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## A. Vorynex Agent

Runs on the customer's machine. It is the only component that can enforce, and
it must keep working with no cloud connection.

Responsibilities: workload discovery, local monitoring, policy enforcement,
process/fs/network controls, secrets protection, telemetry, attack-event
generation.

### Enforcement tiers

The foundation (Warden) enforces **only at process spawn**. That is a real
constraint, and the architecture is explicit about it: a running workload
cannot be confined by a primitive that binds at `exec`.

| Tier | Applies to | Primitives | Strength |
|---|---|---|---|
| **Tier 0 — spawn-time** | A workload Vorynex launches (or relaunches) | `bwrap` (host), **Landlock + seccomp** (inside a container) | Strongest; structural |
| **Tier 1 — live** | An already-running workload | **eBPF-LSM + cgroups v2 + nftables** | Enforces without restart; kernel-gated |

**Why both.** Tier 0 is strictly stronger — the process *cannot* even see what
it was not granted — but requires launching the workload under Vorynex. Tier 1
attaches to a workload that is already running and is the only way to block on a
process you did not launch. Neither tier alone covers the deployment reality, so
Vorynex ships both under one policy model.

**Critical design decisions:**

- **Tier 0 inside Docker uses Landlock + seccomp, not bwrap.** `bwrap` needs
  unprivileged user namespaces; Docker's default seccomp profile blocks
  `unshare`/`mount`/`pivot_root`, so `bwrap` cannot run in a default container
  without granting `SYS_ADMIN`/`--privileged` (unacceptable). Landlock and
  seccomp are unprivileged and work inside a container. `bwrap` stays the Tier 0
  path for host (non-container) deployments.
- **Process-exec containment is new code, not inherited.** Warden bind-mounts
  `/usr` and `/bin` read-only, so `/bin/bash` is executable inside a Warden
  sandbox. Blocking shell exec requires a seccomp `execve` allowlist and/or
  Landlock `EXECUTE` denial — built in `engine/enforce/`, not reused.
- **Tier 1 requires kernel capability.** eBPF-LSM needs kernel ≥ 5.7,
  `CONFIG_BPF_LSM`, BTF, and `CAP_BPF`/`CAP_PERFMON`. When unavailable, the
  agent degrades to cgroups v2 + nftables (no exec/path blocking) and says so
  loudly. See [FAILURE_MODES.md](FAILURE_MODES.md).

### Local monitoring / learning

- Discovery: Docker API/socket (read-only), `/proc` scan, cgroup inspection.
- Profiler: builds a behavior baseline with confidence scoring; only
  *consistent* behavior with sufficient stability is promotable to an allow
  rule. See [LEARNING_ENGINE.md](LEARNING_ENGINE.md).
- Events: a single structured JSONL stream (reuse Warden's `audit.Event` shape)
  is the source for telemetry, Blast Radius, and Attack Trace.

### Local-first guarantee

```text
cloud unreachable  →  existing signed policy keeps enforcing
agent restart      →  policy reloaded from local store, no cloud needed
```

## B. Vorynex Cloud

Control plane only. It must not sit synchronously in the application's request
path; a cloud outage must not take the customer's application down.

Responsibilities: dashboard, account management, organizations, hosts,
workloads, policies, centralized event history, CVE intelligence, attack
timelines, notifications, fleet management, policy recommendations, Emergency
Shield. Billing and RBAC are later.

Data flow is **agent → cloud**, async and resumable. Cloud → agent carries only
policy and recommendation changes, which the agent validates and can reject.

## Policy model

Vorynex adopts Warden's declarative, deny-by-default policy as the contract,
extended with runtime capabilities:

```yaml
version: 1
workload: payments-api
enforcement: protect            # observe | protect | lockdown

filesystem:
  read:  ["/app", "/app/node_modules"]
  write: ["/app/.next/cache", "/tmp"]
  deny:  ["/app/.env", "~/.ssh", "~/.aws", "/etc/shadow", "/var/run/docker.sock"]

process:
  exec:
    allow: ["/usr/bin/node", "/usr/local/bin/node"]
    deny:  ["/bin/bash", "/bin/sh", "/usr/bin/curl", "/usr/bin/wget"]
  spawn_from_web_worker: deny   # the highest-signal rule

network:
  allow: ["api.stripe.com", "api.resend.com", "*.amazonaws.com"]
  deny:  ["169.254.169.254", "169.254.170.2"]   # cloud metadata
  raw_tcp: deny                 # beyond the HTTP proxy

environment:
  allow: ["NODE_ENV", "PORT"]
  deny:  ["AWS_*", "*_TOKEN", "*_SECRET*"]

limits:
  memory_mb: 1024
  pids: 256
```

The `filesystem`, `network`, `environment`, and `limits` sections map directly
onto Warden's engine. The `process` section is Vorynex-specific and is what
Warden cannot currently enforce.

## Technology choices

Warden first, proven Linux primitives second, no reinvention of kernel
primitives:

- **Reuse (from Warden):** policy engine, egress proxy, env filter, audit event
  model, spawn-time mount/namespace translation, attestation design.
- **Orchestrate:** `bwrap`, `Landlock`, `seccomp`, `eBPF-LSM`, `cgroups v2`,
  `nftables`, `namespaces`, Docker APIs. Vorynex composes these; it does not
  replace them.
- **Language:** Go for the agent/engine (matches Warden, single binary, no root
  where possible). Cloud API in Go or TypeScript; dashboard in TypeScript.

## Repository structure

The smallest structure that avoids unnecessary complexity — **one Go module**
for the engine and CLI, a separate service for the cloud, and upstream Warden as
a submodule.

```text
vorynex/
├── go.mod                       # single module: github.com/vorynex/vorynex
├── upstream/warden/             # git submodule (Prof-bilal/Warden) — not imported directly
├── engine/                      # the enforcement + learning core
│   ├── policy/                  # vendored from Warden (MIT) — see engine/NOTICE.md
│   ├── proxy/                   # vendored from Warden (egress)
│   ├── audit/                   # vendored from Warden (event schema + JSONL)
│   ├── envfilter/               # vendored from Warden
│   ├── enforce/
│   │   ├── spawntime/           # Landlock + seccomp shim; bwrap host path (new)
│   │   └── live/                # eBPF-LSM + cgroups v2 + nftables (new)
│   ├── profiler/                # safe learning engine (new)
│   ├── blastradius/             # graph model + calculator (new)
│   └── tracestore/              # attack-trace builder (new)
├── cmd/vorynex/                 # connect | observe | protect | status | trace
├── cloud/                       # separate service (control plane)
│   ├── api/                     # orgs/hosts/policies/events/CVE
│   └── dashboard/               # web UI
├── tests/
│   ├── integration/
│   └── security-lab/            # defensive proof-of-value lab (Phase 14)
├── docs/
└── THIRD_PARTY_NOTICES.md
```

**Why one module, not a `go.work` workspace:** the engine and the CLI are a
single consumer of the same packages today. Splitting them into separate modules
before a second consumer exists would be premature complexity.

**Why Warden is vendored, not imported:** Warden's reusable code lives in
`internal/` packages, which Go forbids importing from another module. Vorynex
therefore vendors the specific packages it reuses (`policy`, `proxy`, `audit`,
`envfilter`) into `engine/`, rewires their import paths, and records provenance
in [`engine/NOTICE.md`](../engine/NOTICE.md). The `upstream/warden` submodule
remains the source of truth for reviewing and pulling future changes; generally
useful fixes go upstream.

## What we deliberately do not build

- Another edge HTTP proxy (Cloudflare's game).
- A Kubernetes admission controller (Tetragon/SPO territory) — later, if ever.
- Our own kernel module.
- A custom seccomp/eBPF profiler from scratch when `Security Profiles Operator`
  / `karmor` patterns already exist to learn from.
- Serverless/edge enforcement (no host OS to enforce in).

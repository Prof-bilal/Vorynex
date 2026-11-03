# MVP.md

## Scope

The MVP targets **one** runtime, deliberately:

```text
Linux + Docker + Node.js (Next.js / Express)
```

No multi-language, no multi-cloud, no Kubernetes, no serverless. Those are
explicitly out until the runtime protection is validated.

## Commands

```bash
vorynex connect     # authenticate the host, install/verify the agent
vorynex observe     # profile the workload; record would-be blocks; enforce nothing
vorynex protect     # enable high-confidence denials (recommended default)
vorynex status      # current mode, policy summary, recent events
vorynex trace <id>  # human-readable attack trace for one event
```

Deferred: `lockdown` (exists but not MVP-critical), `verify`, `simulate`.

## Minimum protection (MVP must deliver all seven)

1. **Sensitive filesystem paths** unreadable: `.env`, `~/.ssh`, `~/.aws`,
   `/etc/shadow`, docker socket.
2. **Unexpected child processes** from the web worker denied.
3. **Shell execution** (`/bin/bash`, `/bin/sh`) denied.
4. **Unauthorized outbound connections** blocked (including non-HTTP where the
   tier supports it).
5. **Cloud metadata** (`169.254.169.254`, `169.254.170.2`) blocked.
6. **Dangerous host access** (docker socket, host mounts) denied.
7. **Privilege-escalation attempts** denied.

Each must be demonstrable in [the security lab](SECURITY_TESTING.md).

## Cloud MVP

- login
- connect host
- one application
- runtime status
- policies
- event timeline
- attack trace
- protection-mode switch

**Nothing else** unless proven necessary.

## Enforcement tiers in the MVP

- **Tier 0 (spawn-time)** ships first: Landlock + seccomp shim for containers,
  `bwrap` for host. This delivers items 1–7 without kernel-matrix risk.
- **Tier 1 (live)** ships in Milestone 5 for already-running workloads, gated on
  kernel capability, with a clear capability report when unavailable.

## Success metrics

Metrics are defined **before** implementation. Acceptable numeric thresholds are
**not invented** — they are established by benchmarking the MVP, then frozen as
regression gates.

### Security (functional pass/fail)

- [ ] A command-injection test **cannot** spawn a shell.
- [ ] Unauthorized egress **is blocked** (IMDS, arbitrary host, odd ports).
- [ ] Sensitive files (`.env`, `~/.ssh`, `~/.aws`) are **inaccessible**.
- [ ] Every blocked event is **correctly traced** (Attack Trace renders it).

### Reliability

- [ ] The application's own test suite **continues to pass** under Protect.
- [ ] A restart **does not lose** policies (loaded from local store).
- [ ] A **cloud outage does not disable** protection.
- [ ] No false-positive denial on the app's **real** traffic during a
      representative window.

### Performance (measure, then freeze)

Measure and record, per tier:
- request latency overhead (p50/p95/p99)
- CPU overhead (steady-state %)
- memory overhead (agent RSS)
- startup overhead (time-to-first-request delta)

No target is claimed until measured. Once measured, regressions beyond the
frozen baseline block release.

### Developer experience

Target journey, minimal manual security configuration:

```text
clone app
   ↓
install Vorynex
   ↓
vorynex observe      (learn)
   ↓
vorynex protect      (enforce)
```

- [ ] No hand-written policy required for the default path.
- [ ] Time from `install` → `protect` is driven by the observe window, not
      manual YAML authoring.
- [ ] The user never needs to understand eBPF, seccomp, capabilities,
      AppArmor, or nftables.

## Explicit non-goals for the MVP

Billing, Kubernetes, enterprise SSO, compliance dashboards, multi-language
support, serverless, Windows/macOS enforcement.

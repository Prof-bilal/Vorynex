# OSS_COMMERCIAL_BOUNDARY.md

Warden remains open source. Vorynex is the commercial product. The open-source
project must remain **genuinely useful** — we do not cripple Warden to protect
Vorynex.

## The split

### Warden OSS (MIT — stays upstream, stays useful)

- Enforcement engine (policy → bwrap/Seatbelt/AppContainer/Docker).
- Local CLI (`run`, `trace`, `init`, `logs`, `doctor`, `validate`, `gateway`,
  `proxy`, …).
- Filesystem rules, network policies, environment policies.
- Process sandboxing (as it exists today).
- Local tracing and local logs.
- Manual policy files.
- Docker/local runtime support.
- The MCP/AI-agent features (`agent`, `mcp`, `connect`, `add`, `packs`) — these
  stay in Warden, not Vorynex.

### Vorynex (commercial)

- Managed cloud control plane.
- Automatic workload profiling (the learning engine).
- Centralized dashboard, fleet management, multi-host.
- **Blast Radius.**
- **Emergency Shield.**
- **CVE correlation** and threat intelligence.
- **Attack timelines** and Attack Trace.
- Managed/signed policy library and recommendations.
- Alerts and notifications.
- Event history and retention.
- Collaboration, RBAC (later), compliance (later).
- Enterprise integrations.
- **Live enforcement tier (Tier 1)** — new code, not in Warden.

## The rule

> If a capability is a *primitive an individual can run locally*, it belongs in
> Warden and stays free. If it requires *fleet-scale operation, managed
> intelligence, or a hosted control plane*, it belongs in Vorynex.

This is the line. It keeps Warden genuinely useful (a developer can secure their
own box for free) while giving Vorynex a real reason to exist (operating this at
scale, with intelligence and history, is the product).

## How Vorynex consumes Warden

- `upstream/warden` is a **git submodule**, pinned to a release, periodically
  updated. Vorynex is **not** a permanent fork.
- Shared code is imported as a dependency where possible; where Vorynex needs
  changes, it **contributes them upstream** or wraps them locally — it does not
  silently diverge.
- Directly adapted code retains the upstream MIT notice
  ([THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md)).

## What we explicitly won't do

- Remove capabilities from Warden to force an upgrade.
- Add artificial limits, licensing gates, or telemetry to Warden.
- Make Warden depend on the Vorynex cloud to function.
- Rebrand Warden as Vorynex or convert the repo.

## Attribution

Warden is MIT-licensed (© Warden contributors). Any Vorynex file that adapts
Warden code must carry the upstream license notice. Vorynex's own code and
service are commercial; the boundary above governs which is which.

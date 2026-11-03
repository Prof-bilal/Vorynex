# ICP.md — Initial Target Customer

## Hypothesis

> Small SaaS companies, indie developers, agencies, and small engineering teams
> running public Node.js applications in Docker/Linux environments **without a
> dedicated security team**.

**Result: partially correct, needs narrowing.** "Indie developers" and
"agencies" are too broad and split into two groups with opposite economics.
The segment that will actually adopt *and pay* is narrower.

## Segment comparison

| Segment | Pain | Urgency | Will install agent? | Grant kernel visibility? | Will pay? | Verdict |
|---|---|---|---|---|---|---|
| Indie developer | Low–med | Low | Maybe | Maybe | Low ($0–20) | **Self-serve, freemium only** |
| Small SaaS (self-hosted Docker) | **High** | **High** | **Yes** | **Yes** | **Yes ($50–500/mo)** | **Primary ICP** |
| Agency | Med | Med (client pressure) | Yes, per-client | Yes | Yes, but fragmented | Secondary |
| Startup (funded) | Med | Med | Yes | Yes | Yes | Secondary (may graduate to CNAPP) |
| Managed hosting provider | High | High | Yes | Yes (platform) | Yes, at scale | **Later (channel)** |
| Enterprise security team | High | High | Yes | Yes | Yes | **Not first** — they have CNAPP/eBPF in K8s |

## Primary ICP (validate first)

**Self-hosted Docker on VPS or bare metal, holding real customer data, with no
security team and no Kubernetes.**

Characteristics:
- A Next.js/Express/Node app in Docker on a single VM or small fleet.
- Has real users and real data (so a breach is existential, not cosmetic).
- Pays a VPS/hosting bill already; comfortable with `docker`/`ssh`.
- Already anxious about CVEs (they read the React2Shell/Next.js headlines).
- No K8s; the eBPF/K8s tools do not fit and feel like enterprise overkill.

Why this segment:
- The free runtime tools (Tetragon/KubeArmor/SPO) **do not serve them**.
- They have the pain, the urgency, the technical ability, and the budget.
- They are reachable (developer communities, not procurement).

## Adoption barriers (ranked)

1. **Fear of breaking production.** The #1 blocker. Mitigated by Observe →
   Protect and high-confidence-only blocking. See [LEARNING_ENGINE.md](LEARNING_ENGINE.md).
2. **Kernel-level visibility / privileges.** Live enforcement needs `CAP_BPF`,
   modern kernels, or a container restart. Must be explained honestly and
   degrade gracefully.
3. **Trust in a new startup's agent.** Mitigated by local-first enforcement, the
   open-source Warden foundation, and signed attestation.
4. **"Docker already isolates me."** Educate: a container shares the host
   kernel, the app runs as root in many images, and RCE inside the container
   reaches `.env`, the docker socket, and IMDS. Blast Radius makes this visible.
5. **Price sensitivity** for the indie tier → freemium self-serve.

## Current alternatives they use (and why they are insufficient)

- Nothing (most common) — they rely on the hosting provider.
- Cloudflare (free) — request-layer only; no post-exploitation control.
- CrowdSec — requires assembling auditd + bouncers + scenarios.
- Manual hardening (non-root, read-only, dropped caps) — helps but is static,
  per-image, and breaks on deploys.

## What they need to hear

Not "we block hackers." Instead:

> "If your app gets exploited tonight, Vorynex means the attacker lands in a
> dead end: no shell, no secrets, no cloud credentials, no CVE needed to
> escape — and you get a plain-English trace of exactly what they tried."

## Open questions to validate (before Milestone 3)

1. Will they run an agent that needs `CAP_BPF` (or a restart) on their prod box?
2. Is the willingness to pay ~$50–500/mo real for a 1–3 VM footprint?
3. Do they prefer a CLI-first or dashboard-first experience?
4. Does "contain compromise" or "runtime least privilege" drive the purchase,
   or does the CVE/Emergency-Shield story drive it more?

# SAFE_DEPLOY.md

The strongest developer experience is the differentiator. Deployment should feel
like Vercel/Railway/Docker — not like configuring eBPF.

## The workflow

```bash
vorynex connect
```

or, on one line:

```bash
vorynex protect
```

The user should never need to understand eBPF, seccomp, capabilities, AppArmor,
or nftables.

## What happens

```text
$ vorynex connect

Analyzing application...

  ✓ runtime detected          Node.js 22 / Next.js 15
  ✓ platform detected         Ubuntu 24.04, Docker 27, kernel 6.8
  ✓ network dependencies      api.stripe.com, api.resend.com, *.sentry.io
  ✓ writable paths            /app/.next/cache, /tmp
  ✓ sensitive paths           /app/.env, ~/.ssh, ~/.aws, docker.sock
  ✓ dangerous process exec    /bin/bash, /bin/sh, curl, wget
  ✓ egress baseline           created
  ✓ monitoring enabled        observe mode

Observe mode active. Vorynex is recording what would be blocked.
Re-run `vorynex protect` after ~24h of normal traffic.
```

After the observe window:

```text
$ vorynex protect

Applying protection...

  ✓ policy signed              (backend: landlock+seccomp)
  ✓ shell execution            restricted
  ✓ secret paths               protected
  ✓ cloud metadata             blocked
  ✓ egress baseline            enforced
  ✓ telemetry                  connected

Application protected.
```

## Discovery — what Vorynex detects automatically

- **Platform:** distro, kernel version, container runtime (Docker/Podman).
- **Runtime:** Node.js / Next.js / Express (from the image and process tree).
- **Workload:** container name/id, image, entrypoint, user, cgroups.
- **Network dependencies:** observed egress (DNS + connect) → baseline.
- **Writable paths:** observed writes under the app tree and tmpfs.
- **Sensitive paths:** `.env`, `~/.ssh`, `~/.aws`, `~/.kube`,
  `/var/run/docker.sock`, `/etc/shadow`, IMDS endpoints.
- **Process exec:** observed execs; shells flagged as dangerous.
- **Services:** Postgres, Stripe, Resend, etc., inferred from egress/ports.

## Capability handling (honest UX)

`vorynex doctor` (also run implicitly by `connect`) reports which enforcement
tier is available and explains the trade-off in plain language:

```text
Enforcement capability
  Tier 0 (spawn-time)  ✓ available  (Landlock + seccomp)
  Tier 1 (live)        ✓ available  (kernel 6.8, CONFIG_BPF_LSM, CAP_BPF)
```

```text
Enforcement capability
  Tier 0 (spawn-time)  ✓ available
  Tier 1 (live)        ✗ unavailable — kernel 5.4 (needs ≥ 5.7 + BPF-LSM)
                       Live protection requires a container restart under
                       Vorynex, or a kernel upgrade. Spawn-time still applies
                       to any workload Vorynex launches.
```

Never pretend to protect at a tier the host cannot enforce.

## Deployment models

| Model | Tier 0 | Tier 1 | Restart needed |
|---|---|---|---|
| Agent as container entrypoint/init | ✓ (Landlock+seccomp) | ✓ | yes (one time) |
| Agent sidecar + live attach | — | ✓ (eBPF-LSM per cgroup) | no |
| Host agent (non-container) | ✓ (`bwrap`) | ✓ | yes for Tier 0 |

Default recommendation: **entrypoint wrapper** (Tier 0 strength, one restart) for
new deployments; **sidecar live attach** (Tier 1) for existing ones where a
restart is unacceptable.

## Guardrails

- **Observe first, always.** `connect` never starts in Protect. It requires an
  explicit `vorynex protect` (or a verified observe window).
- **Automatic rollback.** If Protect causes the app to fail health checks,
  Vorynex returns to Observe and alerts. (Definition of "fail" is the app's own
  health signal; see [FAILURE_MODES.md](FAILURE_MODES.md).)
- **App-level breakage is treated as a security incident** — a false positive is
  a real failure, not a tuning note.
- **Everything reversible.** `vorynex protect --off` restores the exact prior
  state; policies are versioned.

## The one-liner

> `vorynex connect` finds the app, learns what it needs, and protects it — and
> the developer never reads a syscall name.

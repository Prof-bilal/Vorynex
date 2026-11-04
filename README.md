# Vorynex

**A managed runtime security platform for internet-facing web applications.**

Vorynex learns what an application normally needs, restricts unnecessary
capabilities, and contains post-exploitation behavior when a vulnerability is
successfully exploited.

> The application may still contain vulnerabilities.
> Vorynex reduces what an attacker can do **after** exploiting one.

Vorynex is **not** a WAF, not a vulnerability scanner, not "AI cybersecurity",
and not an antivirus for websites. It does not ask *"is this HTTP request
malicious?"* It asks *"even if the attacker successfully executes application
code, what should this workload actually be allowed to do?"*

```text
Internet
   ↓
vulnerable Next.js API
   ↓
RCE succeeds
   ↓
attacker tries /bin/bash        → BLOCK
attacker tries ~/.ssh           → BLOCK
attacker tries cloud metadata   → BLOCK
attacker tries outbound host    → BLOCK
attacker writes system binary   → BLOCK
```

The goal is **blast-radius reduction and post-exploitation containment**, not
attack prevention.

---

## Project status

**Pre-alpha. Not production-ready.** Read
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before protecting anything
sensitive. Verify native enforcement on the operating system where you run it.

## Relationship to Warden

Vorynex is built on [Warden](https://github.com/Prof-bilal/Warden), an
open-source (MIT) deny-by-default sandbox for AI agents, MCP servers, and local
tools. Warden remains its own open-source project and is **not** renamed,
converted, or crippled.

- Warden lives here as a git submodule at [`upstream/warden`](upstream/warden),
  so Vorynex can consume upstream updates instead of becoming an unrelated fork.
- Vorynex reuses Warden's policy engine, egress proxy, environment filter, audit
  event model, spawn-time sandbox translation, and evidence-attestation design.
- Vorynex **adds** what Warden does not have: live runtime enforcement on an
  already-running workload, a safe learning engine, a managed cloud control
  plane, and post-exploitation containment features.

See [docs/WARDEN_AUDIT.md](docs/WARDEN_AUDIT.md) for exactly what is reused and
what is not, and [docs/OSS_COMMERCIAL_BOUNDARY.md](docs/OSS_COMMERCIAL_BOUNDARY.md)
for the open-source / commercial split.

---

## Architecture at a glance

Two systems. Enforcement is always local; the cloud is control plane only.

```text
┌───────────────── Vorynex Agent (on the customer host) ──────────────────┐
│  workload discovery → profiler → signed policy store                    │
│                                                                         │
│   TIER 0  spawn-time   : Landlock + seccomp shim, or bwrap on host      │
│   TIER 1  live         : eBPF-LSM + cgroups v2 + nftables               │
│                                                                         │
│   modes: OBSERVE → PROTECT → LOCKDOWN                                   │
└──────────────────────────────────┬──────────────────────────────────────┘
                                   │ outbound-only, async
                                   ▼
┌───────────────── Vorynex Cloud (never in the request path) ─────────────┐
│  dashboard · orgs/hosts/workloads · policies · event history            │
│  attack timelines · Blast Radius · CVE intelligence · Emergency Shield  │
└─────────────────────────────────────────────────────────────────────────┘
```

- **Enforcement is local.** If Vorynex Cloud is unavailable, existing policies
  keep protecting the application.
- **The cloud is never synchronous in the request path.** A cloud outage must
  not take a customer's application down.
- **AI proposes; deterministic validation disposes.** AI never autonomously
  pushes untested blocking rules to production.

Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Try it locally

The control plane serves the API **and** the dashboard, so start it first and
leave it running (one terminal):

```bash
go run ./cmd/vorynex-cloud --addr 127.0.0.1:8787 --token ""
```

Set a real `--token` to require auth: the agent enrolls with it once, the control
plane issues a **per-host token** the agent uses from then on, and the dashboard
signs in with the admin token. Rotate a host with
`POST /v1/hosts/{id}/rotate-token`. Add `--tls-cert`/`--tls-key` for HTTPS.

In a second terminal, record a workload with no enforcement, then export:

```bash
# a real, short-lived command (it exits on its own)
go run ./cmd/vorynex observe -- node -e 'require("fs").readFileSync("/etc/hostname")'

# push the recorded events to the control plane
go run ./cmd/vorynex telemetry export --endpoint http://127.0.0.1:8787 --once

# render the most recent containment as a plain-English attack trace
go run ./cmd/vorynex trace
```

Other commands:

```bash
# learn from several sessions at once; a capability must appear in N of them
vorynex policy generate --from a.jsonl --from b.jsonl --min-sessions 2 --out policy.yaml --sign-key key.hex

# pin the trust root, then verify a policy before running it
vorynex policy pubkey --key key.hex
vorynex policy verify --policy policy.yaml --sig policy.yaml.sig --pubkey <hex>
vorynex exec --policy policy.yaml --sig policy.yaml.sig --pubkey <hex> -- node server.js

# observe once, then launch under the generated high-confidence policy
vorynex protect --from events.jsonl -- node server.js

# blast radius, and the difference between two policies
vorynex blast-radius --policy policy.yaml
vorynex blast-radius --policy before.yaml --compare after.yaml

# CVE correlation, live from OSV + the CISA KEV catalog, with NVD severity
vorynex cve scan --lockfile package-lock.json --live --kev-live --nvd

# upload the correlated SBOM so the dashboard shows CVE exposure
vorynex cve scan --lockfile package-lock.json --live --nvd --upload --endpoint http://127.0.0.1:8787

# upload the effective policy so the dashboard can show it
vorynex telemetry export --endpoint http://127.0.0.1:8787 --policy policy.yaml --once

# converge to a rollout the control plane staged (the supervisor applies it)
vorynex rollout pull --endpoint http://127.0.0.1:8787
vorynex rollout status

# Tier 1 capability report and live enforcement (requires root)
vorynex live status
make bpf
vorynex live attach --object engine/enforce/live/bpf/live.bpf.o \
  --cgroup /sys/fs/cgroup/<group> --pid <pid> \
  --deny-exec /bin/bash --deny-open /app/.env --block-connect 169.254.169.254:80 --cap 21
```

Then open <http://127.0.0.1:8787> in a browser.

To observe your own long-running app instead, point it at your entrypoint and
press Ctrl-C when you have exercised it:

```bash
go run ./cmd/vorynex observe -- node dist/server.js
```


The landing page is a single self-contained file: [`landing/index.html`](landing/index.html).
To see the dashboard without running the server, generate the sample preview:
`python3 cloud/dashboard/mkpreview.py` then open `cloud/dashboard/preview.html`.

## Documentation

| Doc | Purpose |
|---|---|
| [PRODUCT.md](docs/PRODUCT.md) | What Vorynex is and is not; positioning |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Agent + Cloud design, enforcement tiers |
| [WARDEN_AUDIT.md](docs/WARDEN_AUDIT.md) | Audit of the Warden foundation |
| [COMPETITIVE_RESEARCH.md](docs/COMPETITIVE_RESEARCH.md) | Competitor + incident research |
| [DIFFERENTIATION.md](docs/DIFFERENTIATION.md) | The wedge, and what is commodity |
| [VALIDATION.md](docs/VALIDATION.md) | Attempt to disprove the product |
| [ICP.md](docs/ICP.md) | Initial target customer |
| [MVP.md](docs/MVP.md) | Scope and success metrics |
| [ROADMAP.md](docs/ROADMAP.md) | Milestones |
| [LEARNING_ENGINE.md](docs/LEARNING_ENGINE.md) | Observe/Protect/Lockdown + poisoning defense |
| [SAFE_DEPLOY.md](docs/SAFE_DEPLOY.md) | `vorynex connect` developer experience |
| [BLAST_RADIUS.md](docs/BLAST_RADIUS.md) | "If this is compromised, what can it reach?" |
| [ATTACK_TRACE.md](docs/ATTACK_TRACE.md) | Developer-readable containment evidence |
| [EMERGENCY_SHIELD.md](docs/EMERGENCY_SHIELD.md) | CVE-driven containment workflow |
| [THREAT_MODEL.md](docs/THREAT_MODEL.md) | What Vorynex can and cannot protect against |
| [FAILURE_MODES.md](docs/FAILURE_MODES.md) | Fail-open / fail-closed behavior |
| [SECURITY.md](docs/SECURITY.md) | Security policy and limitations |
| [SECURITY_TESTING.md](docs/SECURITY_TESTING.md) | The proof-of-value attack lab |
| [OSS_COMMERCIAL_BOUNDARY.md](docs/OSS_COMMERCIAL_BOUNDARY.md) | OSS vs commercial split |

---

## Product rules (non-negotiable)

1. We never claim Vorynex prevents hacking. We say **contain compromise**,
   **reduce blast radius**, **restrict post-exploitation behavior**, and
   **runtime least privilege**.
2. HTTP request filtering is not the moat.
3. Enforcement is deterministic. AI analyzes and proposes; it does not enforce.
4. Observe → Verify → Protect. We never block first and debug later.
5. Developer-first UX, closer to Vercel/Railway/Docker than to a SOC console.
6. Every feature must answer: who needs it, what attack it stops, and whether
   Warden or a competitor already does it.

---

## License and attribution

Warden is MIT-licensed (© Warden contributors). Vorynex documentation and code
that adapts Warden retain the upstream MIT notice in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). See
[docs/OSS_COMMERCIAL_BOUNDARY.md](docs/OSS_COMMERCIAL_BOUNDARY.md).

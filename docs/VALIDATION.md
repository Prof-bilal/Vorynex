# VALIDATION.md

This doc actively tries to **disprove** Vorynex. It assumes nothing. It ends
with a mandatory verdict.

The question: is Vorynex unnecessary because existing products already provide
automatic workload profiling, runtime least privilege, eBPF enforcement, RCE
containment, shell-blocking, filesystem restrictions, egress control, virtual
patching, CVE mitigation, developer-friendly onboarding, attack tracing, and
automated policy generation?

## 1. Do the capabilities already exist, free?

| Capability | Who already provides it | Cost | Verdict |
|---|---|---|---|
| Runtime least privilege (K8s) | Tetragon, KubeArmor, Security Profiles Operator | Free | **Commodity** |
| eBPF detection | Falco, Tracee, Cilium+Hubble | Free | **Commodity** |
| File/exec/cap deny (kernel) | seccomp, AppArmor, SELinux, Landlock | Free, in-kernel | **Commodity** |
| Egress allowlist | Cilium DNS-aware policy, nftables | Free | **Commodity** |
| Kill-on-detection response | Falco Talon, Tetragon Signal | Free | **Commodity** |
| Post-exploitation containment (OS) | CrowdSec (auditd execve → kill + ban) | Free | **Commodity-ish**, hand-assembled |
| Containment without outage | Oligo (eBPF, function-level) | Enterprise, opaque | **Competes** |
| Profile recording | SPO recorder, `karmor` (static) | Free | **Commodity** (not behavioral) |
| Attack tracing / forensics | Tracee, Sysdig | Free/Enterprise | **Competes** |
| CVE → virtual patch | Cloudflare/Wallarm/Fastly managed rules | Paid | **Request-layer only** |

**Conclusion so far:** almost every *primitive* is free, and much of the
*orchestration* exists in the Kubernetes world. A product that merely wraps
seccomp/Landlock/eBPF in a wrapper is not defensible.

## 2. Where the existing solutions do not reach

The defensible slivers, stated as falsifiable claims:

1. **Non-K8s Docker / single-VM workloads.** Tetragon/KubeArmor/SPO assume
   Kubernetes CRDs and a DaemonSet. A solo developer running
   `docker compose up` on a VPS has no good, *automatic* runtime least-privilege
   product. *(Test: install Tetragon/KubeArmor on a plain Docker host. Confirm
   friction.)*
2. **Automatic, poison-resistant behavioral profiling.** Nearly nobody does
   live learning that resists an attacker poisoning the baseline. SPO and
   `karmor` lean on *static* analysis; Falco/Tetragon require hand-written
   policies. *(Test: find any OSS tool that (a) learns live behavior and
   (b) documents poisoning defenses.)*
3. **Developer-grade UX for containment.** The field is enterprise consoles
   (Sysdig/Oligo) or hand-assembled scripts (CrowdSec). A Vercel/Railway-feeling
   product in this space is genuinely open.
4. **Two-tier enforcement under one policy.** Spawn-time (strict) *and* live
   (no-restart) does not appear unified in any single OSS project.
5. **Managed fleet on a local-first agent** for the small/mid segment (event
   history, attack timelines, blast radius, emergency shield) — thin below
   enterprise price points.

## 3. Hard technical problems (the honest ones)

These are where the idea can die. None are trivial.

| Problem | Severity | Notes |
|---|---|---|
| **False positives** | Fatal to adoption | Blocking legit `node`→`sh` (build scripts, postinstall) breaks apps. Protect mode must be high-confidence only. |
| **Incomplete learning** | High | A prod workload's behavior varies (deploys, cron, traffic spikes). A short observe window under-captures. |
| **Legitimate process spawning** | High | Many Node apps spawn children legitimately (sharp, prisma, esbuild). "web worker → shell" is not always malicious. |
| **Dynamic workloads** | High | New deploys invalidate the allowlist; must re-learn without weakening security. |
| **Serverless limitations** | Fatal for that segment | Vercel/Cloudflare Workers have no host OS. Vorynex **cannot** protect them. Out of scope, stated clearly. |
| **Encrypted traffic** | Medium | Egress hostnames are visible (SNI/DNS) but not payloads; fine for allowlisting, useless for content inspection — which is not the product. |
| **Kernel compatibility** | High | Live exec/path blocking needs ≥ 5.7 + `CONFIG_BPF_LSM` + `CAP_BPF`. Many VPS kernels are locked/old. |
| **Containers** | High | Inside Docker, `bwrap` is blocked by default seccomp → must use Landlock+seccomp. |
| **Root permissions** | High | A root attacker can detach/disable a userspace agent. Only kernel enforcement (eBPF-LSM) resists; nothing resists a kernel exploit. |
| **Bypass possibilities** | High | `memfd_create` anonymous exec, interpreter-only RCE, in-process data theft. Must be documented, not hidden. |
| **Policy poisoning during learning** | High | Observe mode during an active attack could learn malicious behavior. Needs explicit defenses. |
| **Attacker behavior that looks legitimate** | Medium | `npm install` running a preinstall payload looks like a normal `node` process. |
| **Database credential compromise** | Medium | If the app legitimately holds DB creds, Vorynex cannot stop the app from using them — only from *reaching* them if they are file/env-protected. |
| **Application-level authorization bugs** | **Out of scope** | IDOR/BOLA exploit *legitimate* app logic. No runtime boundary helps. State this. |

## 4. What we would need to be true (kill criteria)

Vorynex is only worth building if **all** hold:

- [ ] Live enforcement (Tier 1) demonstrably blocks `execve` of shells and writes
      to protected paths on a real deployed container, **on commonly available
      kernels**.
- [ ] False-positive denial rate on the app's **real** traffic is ~zero.
- [ ] Spawn-time tier works **unprivileged inside Docker** (Landlock+seccomp).
- [ ] The learning engine resists an active-attack poisoning attempt.
- [ ] Local-first fail-open is proven: cloud outage does not disable protection.
- [ ] A paying ICP exists that will grant kernel-level visibility, *and* runs
      self-hosted Docker with real data.

If any of the first five fails after prototyping, **stop**.

## 5. Commodity features we must NOT use as our USP

- seccomp / AppArmor / SELinux / Landlock themselves.
- eBPF detection and DaemonSet agents.
- Kill-on-detection.
- Read-only rootfs / dropped caps / `RuntimeDefault` seccomp for K8s.
- HTTP virtual patching.
- "We use AI."

## 6. Crowded areas where competing directly is stupid

- Edge HTTP filtering (Cloudflare/Fastly/Wallarm).
- Kubernetes admission + eBPF profiles (Tetragon/KubeArmor/SPO).
- Enterprise CNAPP consoles (Sysdig/Wiz).
- RASP-with-SDK for a specific language (Aikido Zen).

## 7. Verdict

**BUILD WITH MAJOR CHANGES.**

The core idea — contain what a compromise can do, rather than only trying to
prevent the compromise — is real, and the research shows it is undersupplied for
the self-hosted Docker/Node segment. But the premise "Warden powers it" is wrong
as stated:

1. Warden **cannot block shell execution** — `/bin/bash` is executable in every
   Warden sandbox today. The flagship demo must be built, not inherited.
2. Warden enforces **only at spawn**. Protecting a running workload requires a
   **new live engine** (eBPF-LSM + cgroups + nftables) or a
   restart-under-protection.
3. `bwrap` cannot run inside a default container, so the spawn-time tier must
   become **Landlock + seccomp**.

**Change requirements:**

- Build the live enforcement tier as first-class, not an afterthought.
- Narrow the ICP to **self-hosted Docker on VPS/bare-metal with real data and no
  security team** — validate before Milestone 3.
- Position strictly as **blast-radius reduction / runtime least privilege**.
  Never as a WAF, never as "AI security", never as "prevents hacking".
- Accept and document the scope limits: no serverless, no app-level authz bugs,
  no in-process RCE visibility, no kernel-exploit resistance.

With those changes, the differentiation in
[DIFFERENTIATION.md](DIFFERENTIATION.md) holds. Without them, this is a free
seccomp wrapper with a dashboard, and the answer would be **KILL IT**.

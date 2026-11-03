# DIFFERENTIATION.md

## The positioning test

The working hypothesis:

> **Vorynex automatically creates and enforces a least-privilege runtime
> boundary around web applications so that successful exploitation does not
> automatically become full server compromise.**

**Result: the hypothesis is correct but incomplete.** "Automatically creates and
enforces a boundary" is necessary but not sufficient for differentiation. The
boundary itself is partly commodity (seccomp/Landlock/eBPF are free). What makes
Vorynex defensible is the *combination*: automatic behavior learning, a
developer-grade UX, and post-exploitation containment delivered as a managed
product for workloads the K8s-native tools do not serve.

## The question that separates us

| | Traditional WAF | Vorynex |
|---|---|---|
| Asks | Is this HTTP request malicious? | Even if the attacker executes code, what should this workload be allowed to do? |
| Enforces | At the request layer | At the process / filesystem / network layer |
| Stops | The attempt | The consequence |
| Fails when | The attack bypasses the rule | The attacker acts within legitimate app capabilities |

Vorynex is **post-exploitation containment** with a developer UX. That is the
frame. Not "WAF", not "AI security", not "vulnerability scanner", not "antivirus
for websites".

## Is it truly differentiated? (checked against research)

**Commodity — not our USP:**

- seccomp / AppArmor / SELinux / Landlock / cgroups / nftables.
- eBPF *detection* and DaemonSet agents (Falco/Tracee/Cilium).
- kill-on-detection response.
- K8s `RuntimeDefault` seccomp, read-only rootfs, dropped caps.
- HTTP request filtering.

**Crowded — competing directly is stupid:**

- Edge HTTP filtering (Cloudflare/Fastly/Wallarm/open-appsec).
- K8s admission + eBPF profiles (Tetragon/KubeArmor/SPO).
- Enterprise CNAPP consoles (Sysdig/Wiz).
- Language-specific RASP with SDK integration (Aikido Zen).

**Genuinely defensible — the wedge:**

1. **The non-Kubernetes Docker / single-VM segment.** Tetragon/KubeArmor/SPO
   assume CRDs and a DaemonSet. A developer or small team running
   `docker compose` on a VPS has no automatic, low-friction runtime
   least-privilege product. This segment is large and underserved.
2. **Automatic, poison-resistant behavioral profiling.** Nearly nobody does live
   learning that resists an attacker poisoning the baseline (SPO/`karmor` use
   static analysis; Falco/Tetragon require hand-written policy). This is the
   strongest differentiator *if* it is built well.
3. **Containment with developer-grade UX.** The field is enterprise consoles or
   hand-assembled scripts. A Vercel/Railway/Docker-feeling experience is open.
4. **Two-tier enforcement under one policy** — spawn-time (strict) *and* live
   (no-restart). No OSS project unifies both.
5. **Managed fleet on a local-first agent** for the small/mid segment — event
   history, attack timelines, blast radius, emergency shield at a price point
   below enterprise CNAPP.

## The named comparison

| Capability | CrowdSec | Tetragon/KubeArmor | Oligo | Sysdig | **Vorynex** |
|---|---|---|---|---|---|
| Non-K8s Docker | partial | ✗ | ✗ | ✗ | **✓ target** |
| Automatic behavioral learning | ✗ | ✗ | ✗ | partial | **✓ core** |
| Poisoning-resistant learning | ✗ | ✗ | ? | ? | **✓ planned** |
| Synchronous exec blocking | ✗ (kill) | ✓ | ✓ | ✓ (kernel≥5.0) | ✓ (both tiers) |
| No source changes | ✓ | ✓ | ✓ | ✓ | ✓ |
| Developer UX | scripts | CRDs | enterprise | enterprise | **✓ core** |
| Local-first (no cloud outage) | ✓ | ✓ | ? | ✗ (console) | **✓ invariant** |
| Blast Radius / Attack Trace | ✗ | ✗ | ✗ | partial | **✓ core** |
| Price | free | free | high | high | **mid** |

## What we will never claim

- That Vorynex prevents hacking.
- That it blocks every zero-day.
- That it is "fully secure."
- That it replaces patching.

## The one-line pitch

> **Vorynex makes a compromised web application a dead end — no shell, no
> secrets, no cloud credentials, no arbitrary egress — and shows you exactly
> what the attacker tried, automatically.**

## Positioning risk

The strongest rival framing is: *"this is just KubeArmor/Tetragon for Docker."*
The answer must be concrete, not marketing: automatic behavior learning with
poisoning defense, a developer-first UX, and a managed control plane that the
K8s-native tools deliberately do not provide. If those three are not visibly
better than the free alternatives, the positioning fails. See
[VALIDATION.md](VALIDATION.md).

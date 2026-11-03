# COMPETITIVE_RESEARCH.md

Fresh research (November 2026), primary sources preferred. The goal is not a
competitor list — it is to answer, for each relevant product: **what happens
after exploitation succeeds?**

## The questions asked of every product

1. What exactly does it protect?
2. Where does it enforce protection?
3. What happens after exploitation succeeds?
4. Does it block or only detect?
5. Does protection require modifying application source?
6. Request, application, container, OS, kernel, or network layer?
7. How difficult is deployment?
8. What causes false positives?
9. Enterprise or developer targeted?
10. What can Vorynex do meaningfully differently?

---

## Request-layer WAF / WAAP

### Cloudflare WAF / WAAP
1. L7 HTTP/S at the edge — OWASP Top 10, virtual patching, API scanning.
2. Cloudflare's anycast edge (reverse proxy) before the origin.
3. **Nothing.** The origin is uninstrumented. (Cloudflare's V8-isolate sandbox
   protects *Cloudflare's own Workers platform*, not customer origins.)
4. Blocks or logs per rule action.
5. None; agentless.
6. Request / edge network.
7. Easiest (DNS onboarding).
8. Managed rulesets (CRS-derived) over-block APIs, uploads, admin panels.
9. Enterprise + broad.
10. Vorynex does not compete here.

### Fastly Next-Gen WAF (Signal Sciences)
1. L7 HTTP/S apps/APIs/microservices.
2. Fastly edge, On-Prem module+agent, or Cloud WAF; agent ships request data
   out-of-band to a cloud engine.
3. **Nothing.** Documented limitation: inspects HTTP/HTTPS only — no TCP/UDP/ICMP.
4. Allow/block/tag/rate-limit/deceptive (~90% blocking claimed).
5. Module or agent; no app rewrite.
6. Request.
7. Edge (DNS), on-prem module+agent, or cloud WAF.
8. Docs admit good traffic mistaken for bad; app-specific vulns without a rule
   pass through.
9. Enterprise.
10. Vorynex does not compete here.

### Wallarm
1. L7 WAAP; REST/SOAP/GraphQL; OWASP + API Top 10; bots, ATO.
2. Filtering nodes in customer infra (in-line or out-of-band) + Wallarm Cloud.
3. **Nothing** — the in-line node blocks the request; no runtime containment.
4. Monitoring vs blocking.
5. None; filtering node.
6. Request / L7.
7. In-line or OOB node; moderate.
8. Signature-less ML detection; BOLA behavioral tuning.
9. Enterprise.
10. Vorynex does not compete here.

### open-appsec
1. L7 WAF/API; OWASP + zero-day via contextual ML.
2. Agent on NGINX or K8s ingress sidecar; Kong/Envoy/Istio.
3. **Nothing.**
4. Block + monitor modes.
5. None; add-on.
6. Request / L7.
7. Add-on (Helm/sidecar); moderate.
8. Unsupervised-learning warm-up; ML scoring.
9. Enterprise (Check Point) + DevOps.
10. Vorynex does not compete here.

### ModSecurity
1. L7 WAF engine; SecLang rules; OWASP CRS.
2. Embedded via connectors into NGINX/Apache.
3. **Nothing.**
4. Block or detect per rule.
5. None; needs web-server/connector build.
6. Request.
7. Library + connector; heavier ops.
8. CRS noisy on APIs; needs paranoia-level tuning.
9. Both (legacy enterprise + DIY).
10. Vorynex does not compete here.

### Coraza (Go WAF)
1. L7 WAF library; ModSecurity SecLang; 100% CRS v4.
2. Go library in-process, or connectors (Caddy, proxy-wasm/Envoy, Traefik WASM,
   HAProxy SPOE).
3. **Nothing.**
4. Block/detect.
5. Library needs Go integration; proxy connectors need none.
6. Request.
7. Library or proxy connector; moderate → easy.
8. CRS noise; build-tag behaviors change matching.
9. Developer / enterprise OSS.
10. Vorynex does not compete here.

---

## Runtime / kernel-layer products

### CrowdSec *(closest free analog for containment)*
1. Behavioral engine (log/execve parsing) + AppSec component (WAF); L3/4 + L7.
2. Infrastructure bouncers (iptables/netfilter) + application bouncers
   (NGINX/Apache/Traefik/HAProxy SPOA/OpenResty).
3. **Yes — the only documented free post-exploitation containment.** auditd
   `execve` monitoring + scenarios detect "download + execute backdoor" /
   `base64 | interpreter`; a PID-scoped decision triggers a bouncer that
   `SIGKILL`s the process and bans the attacker IP.
4. Blocks (in-band ban; firewall drop) + detects.
5. None; needs agent + bouncers + auditd rules/scenarios.
6. OS/kernel (netfilter) + process (PID kill) + application (L7).
7. Agent + bouncer(s); moderate; the kill step is a user-assembled script.
8. Behavioral scenarios can be noisy; broad auditd rules.
9. OSS-first (dev/SMB/enterprise).
10. **Vorynex competes directly here** — but with automatic profiling, a managed
    fleet, blast radius, and a developer UX, rather than hand-assembled rules.

### Falco (+ Falco Talon)
1. Kernel-level runtime *detection* (syscalls via eBPF or kmod).
2. Userspace agent; Talon adds a no-code response engine (kill/delete pod).
3. **Reactive only.** Talon acts "in milliseconds"; the race — attacker shells
   out before Talon fires — is real.
4. Detect (Falco); Talon reacts (not synchronous).
5. Policies hand-written (TracingRules / rule files).
6. Kernel events → userspace decision.
7. DaemonSet (K8s) or host agent.
8. Detection rules need tuning; noisy by default.
9. OSS + Sysdig enterprise console.
10. Vorynex enforces **synchronously** (pre-syscall), not react-after-the-fact.

### Tetragon (Cilium)
1. In-kernel eBPF on kprobes/tracepoints/**BPF-LSM hooks**.
2. **Override** (rewrite syscall/LSM return to `-EPERM`, op never executes) and
   **Signal** (`SIGKILL`, synchronous but not pre-emptive for `write`).
3. Can stop `execve`, `write`, connect with LSM hooks.
4. Enforces in-kernel.
5. Hand-written TracingPolicy; audit-mode-first advised.
6. Kernel (BPF-LSM ≥ 5.7, BTF/CO-RE, privileged DaemonSet).
7. DaemonSet; Kubernetes-centric.
8. Un-tested LSM enforce is effectively a workload-killing DoS.
9. OSS; enterprise via Isovalent/Cilium.
10. Vorynex targets the **non-Kubernetes** Docker/VM case, adds automatic
    profiling, and never kills the workload by default.

### KubeArmor
1. Enforcement engine (AppArmor, SELinux, or **BPF-LSM**) returning `-EPERM` at
   LSM hooks, keyed by pid/mnt namespace.
2. Blocks process exec, file access, and network per pod via CRDs.
3. Can block exec/file/network in a running pod.
4. Enforces.
5. CRDs (KSP/HSP/CSP); `karmor recommend` generates from **static** image
   analysis.
6. Kernel (BPF-LSM ≥ 5.7) or AppArmor/SELinux.
7. DaemonSet; Kubernetes-only.
8. Static recommendations under-capture runtime behavior → FP tuning.
9. CNCF Sandbox OSS.
10. Vorynex does **behavioral** learning (not static), non-K8s, managed.

### Sysdig Secure
1. Runtime threat detection + Drift Detection (block binaries not in the image).
2. Agent DaemonSet (kmod or eBPF).
3. Drift "Prevent" blocks execution pre-run on kernel ≥ 5.0; older kernels kill
   after detect. Container stop/pause/kill.
4. Enforces + detects.
5. None; agent.
6. Kernel + container.
7. DaemonSet; Kubernetes-centric.
8. Drift FP when images mutate at runtime (legit).
9. Enterprise (~$72/host/mo CNAPP, third-party estimate).
10. Vorynex is developer-first, cheaper, non-K8s, with automatic profiling.

### Oligo Security *(closest commercial neighbor)*
1. eBPF "Runtime Exploit Blocking."
2. Watches library-function/syscall patterns and blocks exploit *techniques*.
3. **Blocks without killing the container or process** (RASP-style) — unique.
4. Enforces.
5. None (library-level, no source changes).
6. Kernel eBPF; glibc/libc workloads.
7. Agent.
8. Black box; limited runtime coverage.
9. Enterprise; pricing opaque (raised $60M, Aug 2026).
10. **Vorynex competes** on containment-without-outage, but with a transparent,
    policy-based, developer-first model and local-first ownership.

### Security Profiles Operator (K8s SIG)
1. Manages seccomp/AppArmor/SELinux as CRDs and *records* profiles.
2. Does not enforce itself — the kernel LSM/seccomp denies.
3. Profile-based deny.
4. Enforces via the kernel once profiles are attached.
5. CRDs; recording from audit logs or eBPF.
6. Kernel.
7. Operator DaemonSet; Kubernetes-only.
8. Recording is a poisoning surface (a learning run can bake in bad syscalls).
9. K8s OSS (v1.0.0, June 2026, third-party audited).
10. Vorynex learns **behavior over time with confidence gating**, not one-shot
    recording.

---

## Kernel primitives (free — treat as commodity)

- **seccomp-bpf**: syscall allow-list, no path awareness, irreversible, applies
  to self+children. Cannot be attached to a running foreign process.
- **AppArmor / SELinux**: in-kernel MAC; path/type enforcement. Can tighten a
  confined process live, but **cannot newly confine an unconfined running
  process**.
- **Landlock**: unprivileged, self-applied, stackable (FS ABI1 5.13; TCP ABI4
  6.7; UDP ABI10). Cannot be applied to a running process from outside.
- **eBPF-LSM**: **the only primitive that enforces on an already-running
  process** — attach per-cgroup, kernel ≥ 5.7, `CONFIG_BPF_LSM`, `CAP_BPF`.
- **cgroups v2**: resource limits + the anchor for `BPF_LSM_CGROUP`; can move a
  running PID.
- **nftables**: live L3/L4 egress control; `socket cgroupv2` matching (5.9+).
- **gVisor**: container runtime, requires restart + daemon reconfig.
- **bubblewrap**: unprivileged spawn-time launcher; cannot confine an existing
  process; blocked inside default Docker seccomp.

Key asymmetry: **spawn-time primitives are strongest but require control at
launch; only eBPF-LSM enforces on a live, already-running process.**

---

## Real-world incidents (why containment matters)

Post-RCE behavior is remarkably consistent. From CISA/vendor research
(2024–2026):

- **Shell from the web worker:** `node`/`next-server → /bin/sh -c`; `php-fpm`/
  `apache`/`httpd → bash/sh`; `java → sh`. This is the single highest-signal OS
  event.
- **Credential theft:** `.env*`, `~/.aws/credentials`, `~/.kube/config`,
  `~/.docker/config.json`, `/run/secrets/*`, Vault token paths. Attackers deploy
  TruffleHog/Gitleaks.
- **Cloud metadata (IMDS):** query `169.254.169.254` / ECS `169.254.170.2` for
  identity tokens, then call Secrets Manager across regions.
- **Cryptomining:** the *majority* of post-RCE payloads are coin miners (XMRig),
  often with stratum-over-443 and impostor binaries.
- **Webshells:** written into web roots (PHP2Shell, Oct 2026); Node apps often
  need no file — RCE *is* the shell.
- **Supply chain:** Shai-Hulud / Mini Shai-Hulud npm worms via preinstall hooks:
  `node → shell → bun → payload`, exfil over 443 + the Git Data API.
- **Notable exploited-in-the-wild:** CVE-2025-29927 (Next.js middleware authz
  bypass), React2Shell / CVE-2025-55182 (CVSS 10.0, exploited within hours),
  PHP2Shell / CVE-2026-109618/109619.
- **Time-to-exploit is collapsing:** CISA KEV mean CVE→KEV 89 days (2024) → 57
  (2025) → ~20 days (2026 YTD; median 3 days). ~23% of 1H-2026 KEVs were
  exploited on/before disclosure day.

**Observable/blockable at the OS layer:** process spawn, file writes (webshells,
`/tmp` ELF, cron, `authorized_keys`), outbound connections (shell sockets,
odd-port HTTP, stratum ports), sensitive file reads, IMDS access.

**Invisible at the OS layer:** pure in-memory RCE, exfil riding the app's own
response, malware inside a legit-looking `npm install`, HTTP-200 exploitation
that leaves logs clean, serverless/edge without host telemetry.

**What worked in the field:** behavior-based rules on **child processes spawned
by web servers**; egress allowlisting; non-root / read-only / dropped caps. No
single signal tells the story.

---

## Synthesis

- **Request inspection only:** Cloudflare, Fastly, Wallarm, open-appsec,
  ModSecurity, Coraza. Zero post-exploitation control.
- **Runtime containment (free, hand-assembled):** CrowdSec.
- **Runtime containment (K8s-native):** Tetragon, KubeArmor, Sysdig drift.
- **Runtime containment (commercial, no-outage):** Oligo.
- **Commodity primitives:** seccomp, AppArmor, SELinux, Landlock, cgroups,
  nftables, eBPF detection.

**If "containment" means limiting blast radius after code execution, only
CrowdSec (OS/process), Tetragon/KubeArmor (K8s), Oligo (commercial, no-outage),
and Sysdig drift qualify.** Everything else is request filtering with
containment-adjacent marketing.

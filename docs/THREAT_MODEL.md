# THREAT_MODEL.md

Mandatory before calling the product secure. This document is intentionally
conservative: it states what Vorynex **can** and **cannot** protect against.

## Trust boundaries

```text
untrusted: the web application process (and any code it executes)
trusted:   the Vorynex agent (local enforcement) + the kernel primitives
untrusted: the network, the internet-facing request path
semi-trusted: Vorynex Cloud (control plane only; never in the request path)
```

## Threats

### 1. Remote RCE in the web application
**Threat.** Attacker exploits an internet-facing vulnerability to run code.
**Vorynex can.** Contain the *consequence*: deny shell exec, secret reads,
metadata, outbound egress, writes outside grants, privilege changes.
**Vorynex cannot.** Prevent the code execution itself, or see pure in-memory
execution. In-process secret use via the app's own runtime is not observable.

### 2. Compromised application process
**Threat.** The running process is attacker-controlled.
**Can.** Enforce the boundary around it (Tier 1 live, if kernel supports).
**Cannot.** Stop it from doing anything it was *legitimately* allowed to do
(e.g. reach the DB it needs).

### 3. Malicious dependency (supply chain)
**Threat.** A malicious npm package runs at install or runtime.
**Can.** Deny shell/download-and-exec patterns; deny egress outside allowlist;
deny reads of secret paths.
**Cannot.** Distinguish a malicious `node` process from a legitimate one inside
the app's own allowed behavior; a preinstall hook that only uses allowed
capabilities is invisible.

### 4. Compromised container
**Threat.** Attacker has code execution inside the container.
**Can.** Deny host escapes via the docker socket (denied by default), block
host filesystem access (deny-by-default), block IMDS.
**Cannot.** Survive a kernel escape or a container runtime vulnerability.

### 5. Attacker with the same UID as the app
**Threat.** Attacker acts as the app user.
**Can.** Tier 1 (eBPF-LSM) still enforces on that UID's processes.
**Cannot.** A userspace-only Tier 0 agent can be tampered with by the same user
in some configurations — Tier 0 relies on the process being launched confined.

### 6. Container escape attempts
**Threat.** Break out of the container to the host.
**Can.** Deny docker socket, deny host mounts, deny privileged operations, block
metadata.
**Cannot.** Stop a kernel-level escape (CVE in the runtime or kernel).

### 7. Policy bypass
**Threat.** Attacker circumvents enforcement.
**Can.** Kernel-mediated enforcement (Landlock/seccomp/eBPF-LSM) is not
bypassable from userspace; deny-by-default closes implicit paths.
**Cannot.** Defend against `memfd_create` anonymous exec, interpreter-only
execution, or a kernel bug. These are documented, not hidden.

### 8. Agent tampering
**Threat.** Attacker disables or modifies the local agent.
**Can.** Sign policies and binaries (Warden's attestation design); detect an
agent that stops reporting.
**Cannot.** Fully resist a **root** attacker on the host.

### 9. Local root attacker
**Threat.** Attacker already has root on the host.
**Can.** Little. Kernel enforcement can bind a root process, but root can often
detach it (or load a kernel module). **Root on the host is effectively game
over** — state this plainly.

### 10. Telemetry spoofing
**Threat.** Attacker forges or suppresses events.
**Can.** Sign/hash events locally; mark gaps; verify against host-side evidence
(the Warden attack-harness principle: confirm from artifacts the workload cannot
forge).
**Cannot.** Guarantee completeness if the agent itself is compromised.

### 11. Cloud control-plane compromise
**Threat.** Vorynex Cloud is breached.
**Can.** Keep enforcement local and policy-signed, so a cloud compromise cannot
silently weaken local protection; never let cloud push unsign/unvalidated rules.
**Cannot.** Protect the confidentiality of telemetry already uploaded.

### 12. Poisoned learning phase
**Threat.** Attacker acts during Observe to bake in malicious allow rules.
**Can.** Never-promote classes, provenance tracking, confidence thresholds, and
human review (see [LEARNING_ENGINE.md](LEARNING_ENGINE.md)).
**Cannot.** Fully eliminate the risk for arbitrary allowed behavior; hence the
conservative promotion defaults.

### 13. Application intentionally requesting capabilities
**Threat.** A malicious app deliberately asks for broad capabilities.
**Can.** Require explicit, reviewed grants for high-impact rules.
**Cannot.** Protect a host whose owner *chooses* to grant broad access. Policy
authoring mistakes remain possible.

### 14. Kernel exploit
**Threat.** Attacker exploits a kernel vulnerability.
**Can.** Nothing. All enforcement shares the kernel's trust.
**Cannot.** Any of it. Documented as a hard limit.

## Explicitly out of scope

- **Application-level authorization bugs** (IDOR/BOLA): these use legitimate app
  logic; no runtime boundary helps.
- **Serverless / edge** (Vercel, Cloudflare Workers): no host OS to enforce in.
- **Pure in-memory exploitation** with no observable OS behavior.
- **Exfiltration over allowed egress** (e.g. the Git Data API).
- **Kernel-level escape** from an already-compromised kernel.

## The honest summary

> Vorynex contains the **commodity majority** of post-exploitation behavior —
> shells, credential theft, miners, webshells, metadata theft, arbitrary egress —
> by enforcing runtime least privilege. It does **not** prevent exploitation, does
> **not** see in-process behavior, and does **not** stop a root or kernel-level
> attacker. It reduces blast radius; it does not guarantee safety.

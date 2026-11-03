# WARDEN_AUDIT.md

Audit of the foundation Vorynex is built on. Source: `upstream/warden`
(git submodule, pinned at `a7df7c0`, tag `v0.2.0-beta.4-6-ga7df7c0`).

Facts verified by reading the source, not the marketing:
- **Language:** Go 1.24. **Size:** ~34,000 LOC across 59 test-bearing files.
- **Module:** `github.com/warden-sandbox/warden`. **License:** MIT
  (© Warden contributors, 2026).
- **Dependencies:** only `gopkg.in/yaml.v3`, `github.com/pelletier/go-toml/v2`,
  `golang.org/x/sys`. Small supply-chain surface.
- **README self-description:** "A deny-by-default sandbox for AI agents, MCP
  servers, and local AI tools." Pre-1.0.

## What Warden actually is

Warden is a **spawn-time process wrapper** plus a policy engine. It does not run
as a background agent and does not confine processes it did not launch.

```text
warden run --policy p.yaml -- <cmd>
  → resolve backend → build args from policy → exec <cmd> under the sandbox
  → child sees only granted paths, fresh netns, filtered env
  → egress only via loopback HTTP proxy
  → strace (outside the sandbox) imports to audit.jsonl
```

Verified components and their real behavior:

| Area | Implementation | Reality |
|---|---|---|
| Linux sandbox | `bwrap` + `setpriv --nnp`; `--unshare-{user,ipc,pid,net}`; `--ro-bind`/`--bind`; deny masks (`--tmpfs`, `/dev/null`) | Deny-by-default FS; mature |
| macOS sandbox | `sandbox-exec`/Seatbelt profile | Works; deprecated by Apple |
| Windows sandbox | AppContainer + WFP + ETW + Job Object | Works; **requires admin**; fails closed |
| Docker sandbox | `docker run --network none --cap-drop ALL --read-only --security-opt no-new-privileges` | Fallback only |
| Policy engine | `internal/policy` — YAML, `KnownFields(true)`, path resolution, `DeniedPaths()`, `protect_secrets` | Solid, reusable |
| Egress proxy | `internal/proxy` — hostname allowlist checked **before DNS**, private/loopback/link-local refused | HTTP/HTTPS only |
| Env filter | `internal/envfilter` | Allowlist + deny patterns |
| Audit | `internal/audit` — `strace -f` outside sandbox → JSONL | Imported post-run, not live |
| Limits | RSS sampling every 25 ms + wall clock → SIGTERM→SIGKILL | No cgroups, no CPU |
| Container/K8s | `internal/container` renders Docker/K8s manifests + seccomp + NetworkPolicy | Naive; see risks |
| Attestation | `internal/attestation` — Ed25519 evidence binding policy/artifact/binary/observer hashes | Genuinely valuable |
| Attack harness | `testdata/attacks`, `testdata/agent-security` | Control-vs-sandbox with host-side evidence |

## Reusable directly

These are used as-is or with trivial wrapping:

- **Policy engine** (`internal/policy`): schema, validation, relative-path
  resolution, `DeniedPaths()` and `protect_secrets` masking, and
  `LoadVerified` (SHA-256 digest binding). This is the product's declarative
  contract.
- **Egress proxy** (`internal/proxy`): allowlist-before-DNS ordering and
  refusal of `IsPrivate/IsLoopback/IsLinkLocal` destinations after resolution —
  this blocks `169.254.169.254` IMDS over HTTP/HTTPS. Directly addresses metadata
  theft and reverse-shell egress.
- **Environment filter** (`internal/envfilter`): correct allowlist/deny
  semantics, small enough to audit.
- **Audit event model + strace importer** (`internal/audit`): becomes the
  telemetry schema. `Event{Type, Action, Resource, Allowed, Reason}` is a good
  primitive.
- **Fail-closed discipline**: `sandboxerr.RefuseToRun`; Warden never silently
  runs unprotected. Keep this as a core Vorynex value.
- **Attestation** (`internal/attestation`): Ed25519-signed evidence binding
  policy and binary hashes to a trusted issuer, with revocation. Reuse for
  policy/agent integrity and auditable protection proof.
- **Attack harness pattern**: every scenario runs unsandboxed (control must
  land) and sandboxed (must be contained), with containment confirmed host-side
  from artifacts the sandbox cannot forge. This is exactly the shape of
  `tests/security-lab/`.
- **Pure arg builders**: `BuildBwrapArgs`, `BuildDockerArgs`, and the seccomp
  generator are pure functions — unit-testable translators, a clean seam.

## Reusable after refactor

- **`sandbox.Run` orchestration** → becomes "launch the workload under
  protection" (Tier 0).
- **Container translator** (`internal/container`) → correct the network and
  seccomp behavior, then use it as the deployment-artifact generator.
- **`trace` + `init`** → seed of the real learning engine (currently one-shot,
  manual, and unsandboxed).
- **Audit pipeline** → become a streaming, local-buffered telemetry exporter.

## Warden-only functionality (do not bring into Vorynex's core)

These implement Warden's identity as an MCP/AI-agent tool. They stay upstream:

- `internal/mcpserver` (Warden exposing itself as an MCP server), `mcpproxy`,
  `mcpbridge`, `gateway`.
- `internal/clientconfig`, `connect`/`add`/`mcp` (rewriting AI client configs),
  `plugin/`, `mcp-test/`, `internal/packs`.
- `internal/agentworkspace` (sanitized AI-coding workspace) and the ROADMAP
  "AI browser / desktop isolation" long bet.
- `internal/compat` (18-server MCP compatibility matrix) and MCP message
  filtering.

**~40%+ of the tree serves MCP/AI-agent workflows.** Leaving it upstream is the
right call: it keeps Warden a coherent OSS product, and it means Vorynex's value
is *engine concepts + new enforcement*, not a repackaged Warden.

## Missing capabilities (required for web-runtime containment)

Ranked by importance. These are the gaps that define the build:

1. **No protection of an already-running process.** Every backend binds at
   `exec`. You cannot confine a process you did not launch.
2. **No process-exec containment at all.** `/usr`/`/bin` are bind-mounted
   read-only, so **`/bin/bash` is fully executable inside a Warden sandbox.** The
   headline `node → /bin/bash → BLOCK` is **not** delivered by Warden today.
   There is no seccomp filter, no Landlock, and no exec allowlist in the native
   path.
3. **No syscall/LSM live enforcement** — no eBPF-LSM, no cgroups v2, no
   nftables.
4. **No learning engine** — only manual `trace`/`init`, run unsandboxed; no
   confidence scoring, no poisoning defense, no continuous baseline.
5. **No telemetry, fleet, cloud, dashboard, or multi-tenant anything**
   (explicit non-goal).
6. **No CVE intelligence, Emergency Shield, Attack Trace UX, Blast Radius,
   RBAC, or alerting.**
7. **No raw TCP/UDP egress control** (proxy is HTTP/HTTPS only).
8. **No cgroup/CPU limits**; memory control is sampling-based.
9. **No Node/Next.js/Docker application awareness.**

## Security risks

Architectural weaknesses that would make Vorynex unsafe if copied blindly:

1. **Spawn-only enforcement** — the structural gap. Protect an already-running
   workload only via restart-under-protection or a new live engine.
2. **`bwrap` cannot run inside a default Docker container** — Docker's default
   seccomp blocks `unshare`/`mount`/`pivot_root`. Reusing bwrap for containers
   requires `SYS_ADMIN`/`--privileged`, which is unacceptable. Use Landlock +
   seccomp instead.
3. **Container translator is unsafe as-is:**
   - `generateDockerConfig` flips `NetworkMode` to `bridge` whenever any host is
     allowlisted, silently removing egress isolation.
   - The generated seccomp profile *allows* `execve` plus ~300 syscalls, so it
     contains nothing useful.
   - K8s `NetworkPolicy` cannot express hostnames (admitted in-code).
4. **Symlink semantics are inconsistent** — `docs/security.md` lists
   symlink-following inside granted paths as a known limitation, while the
   agent-security proof asserts `filesystem.symlink_escape` is blocked.
   **Reconcile before claiming "protect sensitive files".**
5. **Audit is post-hoc import**, not a live signal; an attacker can act before
   events land. Adequate for telemetry, insufficient as an enforcement loop.
6. **In-process RCE and allowed-egress exfil are invisible** at the OS layer.
   Must be stated publicly.
7. **Trust surface:** `bwrap` and the Docker daemon are trusted external code;
   the Docker fallback has a much larger attack surface than native primitives.
8. **Poisonable learning:** `trace` runs unsandboxed and observes the very code
   it trusts.
9. **Windows requires admin**; macOS Seatbelt is deprecated.

## Technical debt

To address before building the commercial layer:

- `cmd/warden/main.go` is ~64 KB / ~1,800 LOC — all CLI logic in one file. The
  Vorynex CLI must not inherit this pattern.
- Backend variance (Linux/macOS/Windows/Docker) is duplicated; unify behind one
  interface early.
- Container/K8s translation is incomplete and, per the risks above, partly
  wrong.
- No policy `version` field; no signed server-pushed policy (only local digest
  binding).
- `UnimplementedAdvisories()` returns empty; docs drift between `design.md` and
  `ARCHITECTURE.md`; the "limits are M3" comment is stale.
- MCP code is intertwined with core packages — needs a clean seam if any shared
  code is to be imported.
- Dependence on `strace` on Linux (refuses to run without it) is a deployment
  constraint and an overhead source.

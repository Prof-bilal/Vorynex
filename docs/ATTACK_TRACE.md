# ATTACK_TRACE.md

Attack Trace explains a contained attack in plain language. The audience is the
developer who owns the app — not a SOC analyst. It must be readable in one
screen.

## Example

```text
ATTACK CONTAINED

Internet
   ↓
POST /api/run
   ↓
node
   ↓
exec()
   ↓
/bin/bash
   ↓
BLOCKED
```

```text
Time: 10:41:02

Application:
payments-api

Attempt:
node → /bin/bash

Policy:
unexpected-child-process

Result:
DENIED

Potential behavior:
shell execution
```

## What a trace contains

| Field | Meaning |
|---|---|
| `id` | Stable trace id |
| `time` | When (host clock, UTC + local) |
| `workload` | Application/host |
| `path` | The request/interaction chain (e.g. `POST /api/run → node → exec() → /bin/bash`) |
| `attempt` | `parent → child` or `process → target` |
| `policy` | The rule id that fired |
| `result` | `DENIED` / `ALLOWED` (in observe: `WOULD_DENY`) |
| `potential_behavior` | Plain-English class: shell execution, credential read, egress, metadata access, privilege escalation |
| `evidence` | Linked events (host-side, un-forgeable) |
| `severity_hint` | Derived from the behavior class, not a fabricated score |
| `next_actions` | e.g. "Review the request that reached `/api/run`", "Patch the endpoint", "Keep rule" |

## The chain, specifically

Attack Trace reconstructs a causal chain from low-level events:

```text
network.request   →  process.exec(node)  →  process.exec(exec)  →  process.exec(/bin/bash → DENIED)
```

Alignment: the ingress request (from the app's own logs / reverse proxy, if
available) is joined to the syscall-level event that followed. When the ingress
request cannot be joined, the trace still renders from the syscall event alone —
it degrades to "node → /bin/bash → DENIED" without the HTTP hop, and says so.

## CLI

```bash
vorynex trace                      # most recent contained attack
vorynex trace <id>                 # a specific trace
vorynex trace --workload api-server --since 24h
vorynex trace <id> --json
vorynex trace <id> --raw           # underlying audit events
```

## Dashboard UX

- **Timeline** of traces, newest first; each is a one-line summary
  (`10:41 api-server: node → /bin/bash → DENIED`).
- Click → the visual chain + the fields above.
- The `path` is rendered as a vertical flow with the blocked node in red.
- **Observe-mode entries** render identically but say `WOULD HAVE DENIED`, so a
  user can preview what Protect would do before enabling it.
- `next_actions` are links where possible (the source endpoint, the policy rule).

## Design principles

1. **Plain language first.** The raw syscall is available (`--raw`) but never the
   default.
2. **Always show the policy that fired** and the result, so the trace is
   falsifiable.
3. **Never a false certainty.** If provenance/join is incomplete, say "inferred".
4. **Actionable.** Every trace ends with what to do next.
5. **Same shape in Observe and Protect**, so the learning phase already looks
   like the product.

Related: [BLAST_RADIUS.md](BLAST_RADIUS.md), [LEARNING_ENGINE.md](LEARNING_ENGINE.md).

## Implementation status (MVP)

- `engine/trace` derives traces from recorded events. Contained events
  (`EACCES`/`EPERM`) become `DENIED`; dangerous access that was not enforced
  becomes `WOULD_DENY`. Harmless failed syscalls (`ENOENT`) are ignored.
- `vorynex trace [--from <events.jsonl>] [--workload <id>] [--all] [--json]
  [--since <dur>] [--id <id>]` renders the CLI story; it reads audit events,
  the local telemetry spool, or the cloud store.
- The dashboard renders the same trace as an expandable section on every
  contained event.
- **Confidence is `inferred` today.** strace events carry no pid/parent and no
  ingress request, so the chain is `workload → action → target`. Joining the
  HTTP request and process lineage is the remaining work (needs pid/ppid and
  access logs). The trace says so rather than inventing a hop.

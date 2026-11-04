# BLAST_RADIUS.md

> If this application gets compromised right now, what can the attacker
> actually reach?

Blast Radius is derived **only** from real policies and observed capabilities. It
does **not** invent security scores. There is no 0–100 "risk number" — every
statement is either "reachable" or "contained", backed by a policy rule or a
capability fact.

## Example output

```text
IF API-SERVER IS COMPROMISED

Reachable:
  ⚠ PostgreSQL (10.0.1.5:5432)        via network.allow: internal-db
  ⚠ /app/uploads                      via filesystem.write: /app/uploads

Contained:
  ✓ host filesystem                   deny-by-default (no grant)
  ✓ SSH credentials                   deny: ~/.ssh
  ✓ AWS credentials                   deny: ~/.aws
  ✓ Docker socket                     deny: /var/run/docker.sock
  ✓ arbitrary internet access         egress allowlist only
  ✓ shell execution                   process.exec.deny: /bin/bash, /bin/sh
  ✓ other containers                  docker socket denied; no host net
  ✓ cloud metadata                    deny: 169.254.169.254
```

## Data model

Blast Radius is computed from **facts**, not guesses. Inputs:

```text
Capability        A single thing the workload can do.
  id              e.g. net.connect:10.0.1.5:5432
  kind            fs.read | fs.write | net.connect | proc.exec | env.read | cap
  target          path | host:port | binary | capability
  source          policy rule id | observed capability id
  allowed         bool
  reach_class     host | container | network | secret | cloud | lateral

Resource          A node an attacker could touch if reachable.
  id              e.g. db.postgres.payments
  kind            database | file_store | secret | credential | service | host
  sensitivity     low | medium | high | critical
  labels          e.g. {contains: pii}

Edge              workload → resource, justified by one or more capabilities.
  from, to
  via             [capability ids]
  confidence      exact | inferred
```

The graph: the **workload** is the root; resources are nodes; edges exist only
where a **granted capability** reaches the resource. No capability ⇒ no edge ⇒
"contained".

## Calculation

```text
for each granted/observed capability C of the workload:
    if C.allowed:
        resolve C.target to a resource node R (path → mount; host:port → service)
        add edge workload → R via [C]
    else:
        record C.target in the "contained" set

reachable  = resources with ≥1 allowed inbound edge
contained  = danger classes with zero allowed inbound edges
```

Key rules:

- **Deny wins.** A `filesystem.deny` over a granted tree removes the edge.
- **Never-promote classes are always contained** (shell, secrets, IMDS,
  privilege) unless an explicit, reviewed rule re-enables them.
- **Egress edges** are derived from `network.allow` + observed connections.
  "arbitrary internet access" is contained iff the egress mode is allowlist-only.
- **Sensitivity** ranks output, but does not fabricate a score.
- **Confidence** distinguishes `exact` (from an explicit rule) from `inferred`
  (from an egress/port heuristic), and inferred edges are labeled.

## CLI

```bash
vorynex blast-radius                 # current state for the default workload
vorynex blast-radius --workload api-server
vorynex blast-radius --json          # the raw graph for tooling
vorynex blast-radius --diff          # what changed since the last deploy
```

```text
$ vorynex blast-radius --workload api-server

Workload: api-server (node, container a1b2c3)
Mode: protect                              Generated: 2026-11-03T10:41Z

REACHABLE (2)
  ⚠ PostgreSQL      10.0.1.5:5432     network.allow: internal-db        [exact]
  ⚠ /app/uploads                      filesystem.write                  [exact]

CONTAINED (8)
  ✓ host filesystem      no grant
  ✓ SSH credentials      deny ~/.ssh
  ✓ AWS credentials      deny ~/.aws
  ✓ Docker socket        deny /var/run/docker.sock
  ✓ arbitrary egress     allowlist-only
  ✓ shell execution      process.exec.deny /bin/bash,/bin/sh
  ✓ other containers     no docker socket, no host network
  ✓ cloud metadata       deny 169.254.169.254
```

## Dashboard UX

- **Workload page → "If compromised" panel** (the CLI output, rendered).
- Reachable resources are amber; contained classes are green. No gauges, no
  scores.
- Each amber item is clickable → shows the exact policy rule granting it and an
  "how do I contain this?" hint (e.g., "restrict `network.allow` to port 5432
  from this workload only").
- A **diff view** shows what a deploy changed: new reachable edges are the thing
  to review.
- Every edge links to Blast Radius history, so drift is visible over time.

## Why this is not a meaningless score

- Every amber/green statement maps to a concrete rule or capability, visible on
  click.
- No aggregate "security score" is computed or displayed.
- "Contained" is falsifiable: the lab in [SECURITY_TESTING.md](SECURITY_TESTING.md)
  proves the corresponding access is actually denied.

## Data sources

- Policy store (Tier 0 + Tier 1 rules).
- Observed capabilities (profiler).
- Workload/resource inventory (Docker inspect, egress baseline, service
  inference).

Related: [ATTACK_TRACE.md](ATTACK_TRACE.md), [ARCHITECTURE.md](ARCHITECTURE.md).

## Implementation status (MVP)

- `engine/blastradius` computes the report from an **effective policy**:
  reachable = `network.allow`, `filesystem.read`/`write`, `process.exec.allow`;
  contained = the standard danger classes (host filesystem, credentials, docker
  socket, shell execution, cloud metadata, arbitrary egress, other containers).
  Risky grants (e.g. `/` in read, a shell allowlisted, metadata allowlisted)
  produce warnings. There is no numeric score.
- `vorynex blast-radius --policy <file> [--workload <name>] [--mode <mode>]
  [--json]` prints it.
- The **dashboard** shows an *observed* reach panel derived from telemetry:
  successful connects/writes vs denied classes. The policy-based dashboard view
  waits on the agent uploading its effective policy (same dependency as the
  Policies view).

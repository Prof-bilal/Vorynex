# SECURITY_TESTING.md

A controlled lab that proves Vorynex's value **defensively**: the same attack
succeeds without protection and is contained with it. All data is decoy; no real
targets are involved.

Location: [`tests/security-lab/`](../tests/security-lab/).

## Principle (inherited from Warden's attack harness)

Every scenario runs **twice**:

1. **Control phase** — the attack runs *unprotected* and must actually land. If
   the attack cannot succeed without protection, the scenario is **VOID** (it
   proves nothing).
2. **Protected phase** — the identical attack runs under enforcement and must be
   contained.

Containment is confirmed **host-side**, from artifacts the workload cannot forge
— never by trusting the workload's own output.

| Check | Host-side artifact |
|---|---|
| Shell never spawned | process tree snapshot (no `/bin/bash` child) |
| Egress never arrived | local collector request log (loopback) |
| Secret never read | decoy file access marker / absence of exfil |
| Metadata never reached | IMDS stub request log |
| No write outside grants | escape-probe file must not exist |

## The vulnerable application

`tests/security-lab/vulnerable-app/` — a deliberately vulnerable Express app:

- `GET /run?cmd=...` — an **intentional command-injection endpoint** (for
  defensive testing only).
- Decoy `.env`, decoy SSH key, decoy cloud creds in the fixture.
- Clearly marked `DELIBERATELY VULNERABLE — DO NOT DEPLOY`.

This exists to validate containment, never for real-world targeting.

## Scenarios

| # | Scenario | Attack | Expected containment |
|---|---|---|---|
| 01 | `shell_spawn` | `/run?cmd=id` → `node → /bin/sh` | shell exec denied |
| 02 | `secret_read` | `/run?cmd=cat .env` | decoy secret read denied |
| 03 | `ssh_exfil` | read `~/.ssh/id_rsa` | denied |
| 04 | `cloud_metadata` | curl `169.254.169.254` | denied |
| 05 | `reverse_shell` | `node → /bin/bash -i >& /dev/tcp/...` | shell + egress denied |
| 06 | `egress_c2` | outbound to an unlisted host:4444 | denied |
| 07 | `write_system` | write to `/usr/bin` | denied |
| 08 | `princ_esc` | `setuid` / cap request | denied |

## Benign-operation tests (the adoption gate)

Containment is worthless if it breaks the app. The lab also runs **legitimate**
paths and asserts they still work:

| Operation | Must still succeed |
|---|---|
| `GET /health` | 200 |
| `GET /api/data` | 200 |
| Legit outbound to a decoy "Stripe" host | allowed |
| Legit write to a cache dir | allowed |
| App's own test suite | passes |

**Any legit-operation denial is a FAIL**, not a tuning note.

## Running it

```bash
cd tests/security-lab
./run-lab.sh                      # builds the app, runs control + protected phases
```

Environment knobs: `PROTECTED_CMD` (the enforcement wrapper; defaults to the
Warden binary from `upstream/warden` until the Vorynex agent exists),
`LAB_TIMEOUT`, `LAB_OUT`.

Evidence is written under `tests/security-lab/evidence/<stamp>/`:
`summary.json`, `results.jsonl`, `control-*`, `protected-*`.

## Measured result (Warden as interim engine)

Running the lab against today's Warden engine (`--backend linux`, bwrap)
produced:

```text
Attacks: 7   PASS 5 / FAIL 2 / VOID 0
Benign: ok   Collector hits: control 2, protected 0
```

| Attack | Control | Protected | Verdict |
|---|---|---|---|
| shell_spawn (`/usr/bin/sh -c id`) | allowed | **allowed** | **FAIL** |
| bash_spawn (`/usr/bin/bash -c …`) | allowed | **allowed** | **FAIL** |
| secret_read | allowed | blocked | PASS |
| ssh_read | allowed | blocked | PASS |
| cloud_metadata | allowed | blocked | PASS |
| egress_c2 | allowed | blocked | PASS |
| write_system (outside grant) | allowed | blocked | PASS |

Interpretation:

- **Contained today (5/7):** secret reads, SSH exfil, metadata, arbitrary egress
  (`bwrap` netns + the egress proxy), and writes outside grants. The collector
  received 2 requests unprotected and **0** protected — egress containment is
  confirmed host-side.
- **NOT contained today (2/7):** **`execve` of a shell.** Warden bind-mounts
  `/usr` read-only, so `/usr/bin/bash` and `/usr/bin/sh` exist and run. This is
  precisely the gap Tier 0 (Landlock + seccomp) and Tier 1 (eBPF-LSM) must
  close.

This is why `process.exec` containment ([ROADMAP.md](ROADMAP.md), Milestone 4)
is the first enforcement capability built, not an afterthought. The lab will
only report `Overall: PASS` once shell execution is denied.

## Safety

- Decoy data only (`DECOY-...-NOT-REAL`).
- Loopback network only; no external hosts contacted.
- No persistent effects; all state is under the run directory.
- The app refuses to start if `NODE_ENV=production`.

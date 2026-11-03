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

Environment knobs: `LAB_ENGINE` (`vorynex`, the default, uses the Tier 0 shim;
`warden` uses the interim Warden engine), `PROTECTED_CMD` (override the wrapper),
`LAB_OUT`.

Evidence is written under `tests/security-lab/evidence/<stamp>/`:
`summary.json`, `results.jsonl`, `control-*`, `protected-*`.

## Measured results

### Vorynex Tier 0 engine (Landlock) — default

```text
Attacks: 7   PASS 7 / FAIL 0 / VOID 0
Benign: ok   Collector hits: control 2, protected 0
```

All seven attacks are contained under `LAB_ENGINE=vorynex`: shell execution,
secret/SSH reads, cloud metadata, arbitrary egress, and writes outside grants.
Legitimate operations still work, and the collector received 2 requests
unprotected and **0** protected (egress containment confirmed host-side).

### Warden interim engine (bwrap) — for comparison

```text
Attacks: 7   PASS 5 / FAIL 2 / VOID 0
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

Warden contains secrets, egress, and out-of-grant writes but **not shell
execution**: it bind-mounts `/usr` read-only, so `/usr/bin/bash` runs. That is
the gap the Vorynex Tier 0 shim closes.

## Tier 0 (Landlock): what it enforces, and the two bugs it took to get right

`engine/enforce/spawntime` (via `vorynex exec --policy <file> -- <cmd>`) applies
an unprivileged Landlock ruleset: read-only runtime libraries; read/write only
on granted paths; EXECUTE only on the workload's own directory **and its ELF
interpreter's directory**; and all outbound TCP denied.

Getting exec containment to work required fixing two real bugs in the shim,
initially misdiagnosed as a kernel anomaly:

1. **ELF interpreter EXECUTE.** Executing a dynamically linked binary requires
   EXECUTE on the binary *and* on its interpreter
   (`/lib64/ld-linux-x86-64.so.2`). Granting EXECUTE only on the binary's own
   directory left the interpreter non-executable, so `execve` failed with
   EACCES. Fixed by resolving `PT_INTERP` from the ELF header
   ([`elf_linux.go`](../engine/enforce/spawntime/elf_linux.go)) and granting its
   directory.
2. **Network access bit.** `LANDLOCK_ACCESS_NET_CONNECT_TCP` is `1<<1`, not
   `1<<0` (`1<<0` is `LANDLOCK_ACCESS_NET_BIND_TCP`). The shim was handling
   *bind*, so outbound connects were allowed.

[`tests/security-lab/landlock-probe.c`](../tests/security-lab/landlock-probe.c)
is a small standalone probe for verifying Landlock exec semantics on a host:

```bash
clang -o /tmp/p tests/security-lab/landlock-probe.c
/tmp/p /usr/bin/bash /usr/bin          # DENIED (interpreter not executable)
/tmp/p /usr/bin/bash /usr/bin /lib64   # RAN
```

**Status:** Tier 0 exec containment is verified on the local host (kernel 7.2.8,
Landlock ABI 10) and is exercised on CI (kernel 7.0.0-azure, Landlock ABI 8).
Shell execution is contained by directory-scoped exec control (Landlock cannot
deny an individual file inside an executable directory — see
[ARCHITECTURE.md](ARCHITECTURE.md) and Tier 1 for file-granular control).

## Safety

- Decoy data only (`DECOY-...-NOT-REAL`).
- Loopback network only; no external hosts contacted.
- No persistent effects; all state is under the run directory.
- The app refuses to start if `NODE_ENV=production`.

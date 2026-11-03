# Security lab (Phase 14)

A controlled, **defensive** proof-of-value harness. It proves that when a web
application is exploited, Vorynex contains the post-exploitation behavior — and,
just as importantly, that it does not break legitimate operations.

Design and results are documented in
[docs/SECURITY_TESTING.md](../../docs/SECURITY_TESTING.md).

## Safety

- **Decoy data only** (`DECOY-...-NOT-REAL`). No real secrets are used.
- **Loopback only.** No external hosts are contacted.
- **Local state only.** Everything lives under `evidence/<stamp>/` and a temp dir.
- The app refuses to start with `NODE_ENV=production`.

## Layout

```
security-lab/
├── run-lab.sh                 # control / protected / benign phases + verdicts
├── policy/protect.yaml.template
├── fixtures/                  # decoy .env and SSH key
└── vulnerable-app/            # DELIBERATELY VULNERABLE — never deploy
    ├── server.js              # intentional command-injection endpoint
    ├── attack.js              # post-exploitation action set
    └── benign.js             # legitimate operations that must keep working
```

## Run it

```bash
cd tests/security-lab
./run-lab.sh
```

Prerequisites: `node`, `python3`. The interim engine also needs `go`, `bwrap`,
and `strace` (to build/run the Warden engine from `upstream/warden`).

To use a different enforcement wrapper:

```bash
PROTECTED_CMD="vorynex protect --exec --" ./run-lab.sh
```

## Interpreting results

| Verdict | Meaning |
|---|---|
| **PASS** | The attack landed unprotected **and** was contained when protected. |
| **FAIL** | The attack landed unprotected but was **not** contained. |
| **VOID** | The attack did not land even unprotected — the scenario proves nothing. |
| **Benign FAIL** | Legitimate operations broke. This is a release blocker. |

An overall `PASS` requires zero FAIL, zero VOID, and benign operations intact.

## Measured results

**Vorynex Tier 0 engine (Landlock) — default:**
```text
Attacks: 7   PASS 7 / FAIL 0 / VOID 0
Benign: ok   Collector hits: control 2, protected 0
```
Every attack is contained: shell execution, secret/SSH reads, cloud metadata,
arbitrary egress, and writes outside the grant — and benign operations still
work.

**Warden interim engine (`LAB_ENGINE=warden`), for comparison:**
```text
Attacks: 7   PASS 5 / FAIL 2 / VOID 0
```
Warden contains secrets, egress, and out-of-grant writes but **not shell
execution** — it bind-mounts `/usr` read-only, so `/usr/bin/bash` runs.

The `landlock-probe.c` program checks what a host's kernel requires to execute a
binary under Landlock (executing a dynamically linked binary also needs EXECUTE
on its ELF interpreter directory, e.g. `/lib64`).

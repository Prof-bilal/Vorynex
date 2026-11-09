# Results (2026-11-08, this host, Linux 7.2.8, no root, no Docker)

| Command | Result |
|---|---|
| `make ci` (vet, build, test) | pass |
| `make features` | 42 passed, 0 failed (after fixing one regression this work introduced) |
| `make e2e` | 83 passed, 0 failed, 0 skipped |
| `make lab` | Overall: PASS |
| `make proof` | ran to completion; evidence under `tests/proof/evidence/` |
| `make fp` | unchanged: no-exec 120/140 (14.29%), allow-sh 140/140 with the in-grant injection LANDED |
| `make safe-policy` | 10 passed, 0 failed |
| `make bench` | vorynex vs bare paired delta p50 -0.006 ms, slower in 1/5 rounds; p95 -0.052 ms (2/5); p99 -0.15 ms (2/5). Not consistently one-signed, so **no measurable cost**; CRS +0.9 to +1.9 ms in 5/5 rounds. Memory/CPU/startup not measured. |
| `make proof-real`, `make bpf-test` | **not run** (Docker/root) |

## Compatibility before/after (original 9-feature corpus, 168 requests; now extended to 14 checks / 380 requests, all pass with the corrected policy)

| | before (generator default, no exec) | after (exclusive-dir exec grant) |
|---|---|---|
| health / echo / read / write | all pass | all pass |
| ping | 0/20 (known conflict) | 20/20 |
| upload, tmpfile, dns, job | pass | pass |
| decision | DO NOT ENFORCE | verified against defined tests |

The original `make fp` target is unchanged because it deliberately exercises the vulnerable app; its 14.29% figure is still the correct result for that app under a no-exec policy.

## Security (same demo, bare control vs sandboxed)

| Attack | Bare | Under the corrected policy |
|---|---|---|
| shell via injection (`touch marker`) | landed | marker absent |
| in-grant injection (`cp` into writable dir) | landed | file absent |
| read synthetic secret outside grants | landed | not returned, `EACCES` |
| connect to local lab listener | landed | 0 hits, `EACCES` |
| `/usr/bin/ping` exec grant | n/a | rejected as unenforceable |

## CI / skipped checks

`proof-real` runs only on `workflow_dispatch` or when the repo variable `PROOF_REAL_ON_PUSH=true` (`.github/workflows/ci.yml:129-133`); on a normal push it is **skipped, not passed**. The previous claim of "CI green for the jobs that ran" is consistent with this, but I did not query GitHub for the actual run of `21a96ce`, so it is unconfirmed. I added a `safe-policy` CI job that has **not run on GitHub**; it assumes the hosted runner kernel has Landlock and permits ICMP ping from an unprivileged process (`ping_group_range`). Either may be false there.

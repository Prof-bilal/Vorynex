# Enforcement capabilities

Only what was inspected or tested in this repository on 2026-11-08. "Not tested" means exactly that.

| Restriction | Primitive / backend | Kernel / privileges | Works in a container | Enforcement point | Pre-operation denial? | Known limits |
|---|---|---|---|---|---|---|
| Filesystem read/write | Landlock (Tier 0), `spawntime` | Landlock ABI >= 1; no root | Yes (no privileges) | per-open path check in kernel | Yes, `EACCES` before the op | Per-thread, inherited across fork/exec; granted dirs are subtree-wide |
| Exec allow/deny | Landlock `ACCESS_FS_EXECUTE` | same | Yes | `execve` | Yes | **Directory-granular.** Cannot name one file in a shared directory. Now rejected when it would widen (`policy.BroadExecGrants`) |
| Exec per inode | eBPF LSM `bprm_check_security` (Tier 1), `engine/enforce/live` | BPF LSM enabled, BTF, `CAP_BPF`+`CAP_PERFMON`, kernel >= 5.7 | Needs those caps | LSM hook | Yes | Needs root; `make bpf-test` was **not run** in this work |
| Outbound TCP | Landlock `NET_CONNECT_TCP` (ABI >= 4) | kernel >= 6.7 | Yes | `connect` | Yes | **Port-granular, not host-granular**; no ICMP/UDP control, so ICMP ping is not network-policed |
| Secret path denial | Tier 0 by omission from grants; Tier 1 `file_open` | as above | | open | Yes | Inside a granted tree, protection is by filename pattern (Tier 1 only) |
| Env filtering | `engine/envfilter` before exec | none | Yes | before the workload starts | Yes | Not a kernel control |
| seccomp, AppArmor, namespaces, Docker profiles | Not used by Tier 0. The older Warden backend uses bwrap. | | | | | **Not evaluated here.** Docker's own seccomp/AppArmor remain untouched underneath Vorynex |
| no_new_privs | `prctl` in `restrict()` | none | Yes | exec | Yes | Disables setuid/file-cap elevation, so tools like `ping` rely on `ping_group_range` (here `0 2147483647`) |

## Denial is not telemetry

Every row above is a *kernel refusal*, observed through an effect check, not a log line:
the demo asserts the marker file does not exist, the secret is not in the response, and the lab listener saw zero connections, each against a bare control arm where the same attack lands (`tests/safe-policy/run-demo.sh`). Tier 0 emits no denial event of its own, so nothing here should be read as "an alert fired". `vorynex verify --trace` infers denials from strace (requires strace; errors if absent).

## Capability gate (new)

`policy.BroadExecGrants` runs in `spawntime.Run` and in `vorynex verify`. A rule the backend cannot enforce as written fails with an explicit error. The only way past it is `VORYNEX_ACCEPT_BROAD_EXEC=1`, which prints a warning per widened directory. There is no silent downgrade.

## Not covered

Tier 1 live behavior, Docker/Kubernetes integration, ICMP/UDP egress, argument- and ancestry-based exec rules (neither backend can express them).

# Tier 1 BPF-LSM object

This directory holds the eBPF-LSM program used for live enforcement. The
compiled object (`live.bpf.o`) is **not committed**; build it locally.

```bash
make bpf          # clang -target bpf ... -> live.bpf.o
```

## What it enforces today

Four hooks, all scoped to one armed cgroup:

| Hook | Denies | Map |
|---|---|---|
| `lsm/capable` | one capability (e.g. `CAP_SYS_ADMIN`) | `denied_cap` |
| `lsm/bprm_check_security` | exec of one inode (file-granular: allow node, deny bash) | `denied_inode` |
| `lsm/file_open` | opening one inode (e.g. a secret file) | `denied_file_inode` |
| `lsm/socket_connect` | connect to one IPv4 address, optionally one port | `blocked_ip` / `blocked_port` |

The exec/file hooks use CO-RE (minimal struct definitions with
`preserve_access_index`), so no `vmlinux.h`/`bpftool` is required. Egress is
enforced at `socket_connect`, so no separate nftables layer is needed for the
MVP.

The privileged test validates all four: denied inside the armed cgroup,
unaffected outside it, restored after clearing the deny and after disarm, and a
running workload is never killed.

Remaining: translating a full policy into these maps (path prefixes, hostname
allowlists via a DNS-resolved IP map) and rollback orchestration.

## Safety model

The program is inert by default:

- `armed` starts at 0, so attaching changes nothing.
- When armed, it only affects the cgroup id in `target_cgroup`.
- Every other cgroup returns 0 (allow).
- Disarm sets `armed` back to 0; `Close()` detaches.

The privileged test asserts exactly this: `unshare(CLONE_NEWNS)` is denied
inside the armed cgroup, still succeeds outside it, and succeeds again after
disarm.

## Requirements

- Kernel ≥ 5.7 with `CONFIG_BPF_LSM` and `bpf` in `lsm=` (`/sys/kernel/security/lsm`).
- BTF (`/sys/kernel/btf/vmlinux`).
- `CAP_BPF` + `CAP_PERFMON` (or `CAP_SYS_ADMIN`) to load; typically root.
- `clang` with the `bpf` target, and libbpf headers (`bpf/bpf_helpers.h`,
  `bpf/bpf_tracing.h`).

`vorynex live status` reports all of this honestly.

## Test

```bash
make bpf-test
```

which builds the object, compiles the integration test, and runs it under
`sudo`. The test skips unless it is root and the host supports BPF-LSM.

## Notes

- The handler uses `BPF_PROG` because LSM arguments arrive through the BTF
  trampoline ctx array; a plain typed function is rejected by the verifier
  (`R3 !read_ok`).
- `cgroup.id` is not exposed on this kernel; `live.CgroupID` falls back to the
  kernfs file handle, whose first 8 bytes are the id.

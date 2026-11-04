# Tier 1 BPF-LSM object

This directory holds the eBPF-LSM program used for live enforcement. The
compiled object (`live.bpf.o`) is **not committed**; build it locally.

```bash
make bpf          # clang -target bpf ... -> live.bpf.o
```

## What it enforces today

One hook: `SEC("lsm/capable")`. It denies a chosen capability (default
`CAP_SYS_ADMIN`, 21) for one cgroup. That validates the whole live path —
load, attach, per-cgroup arm, deny, disarm, detach.

Path-based hooks (`bprm_check_security` for exec, `file_open` for files,
`socket_connect` for egress) are **not** in this object yet. They need kernel
struct access via CO-RE, which requires `vmlinux.h` from `bpftool` (not
installed here). The enforcement plan in `vorynex live plan` already describes
those hooks so the mapping is reviewable.

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

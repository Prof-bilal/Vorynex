// Tier 1 live enforcement (eBPF-LSM), capability hook.
//
// Safety model:
//   - The program is DISARMED by default (armed = 0), so attaching it changes
//     nothing until userspace arms it.
//   - When armed, it only affects the cgroup whose id is in target_cgroup.
//   - It denies one capability (default CAP_SYS_ADMIN) for that cgroup.
//
// LSM arguments arrive through the BTF trampoline ctx array, so the handler is
// declared with BPF_PROG rather than a plain typed function.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct cred;
struct user_namespace;

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1);
} armed SEC(".maps"); /* 0 = disarmed, 1 = armed */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1);
} target_cgroup SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} denied_cap SEC(".maps");

SEC("lsm/capable")
int BPF_PROG(deny_cap, const struct cred *cred, struct user_namespace *ns,
	     int cap, unsigned int opts)
{
	__u32 zero = 0;

	__u64 *is_armed = bpf_map_lookup_elem(&armed, &zero);
	if (!is_armed || *is_armed == 0)
		return 0;

	__u64 *cg = bpf_map_lookup_elem(&target_cgroup, &zero);
	if (!cg || *cg == 0)
		return 0;

	if (bpf_get_current_cgroup_id() != *cg)
		return 0;

	__u32 *dc = bpf_map_lookup_elem(&denied_cap, &zero);
	if (dc && cap == (int)*dc)
		return -1; /* -EPERM */

	return 0;
}

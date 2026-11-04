// Tier 1 live enforcement (eBPF-LSM).
//
// Safety model:
//   - The program set is DISARMED by default (armed = 0), so attaching it
//     changes nothing until userspace arms it.
//   - When armed, it only affects the cgroup whose id is in target_cgroup.
//   - Each hook denies only when its own map value is non-zero.
//
// Hooks:
//   lsm/capable              deny a capability
//   lsm/bprm_check_security  deny exec of an inode (allow node, deny bash)
//   lsm/file_open            deny opening an inode (e.g. /etc/shadow)
//   lsm/socket_connect       deny connecting to an IPv4 address[:port]
//
// LSM arguments arrive through the BTF trampoline ctx array, so handlers use
// BPF_PROG. Struct fields are read with CO-RE (minimal definitions) or
// bpf_probe_read_kernel for the raw sockaddr.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct cred;
struct user_namespace;
struct socket;
struct sockaddr;

/* Minimal CO-RE definitions: only the fields we read. */
struct inode {
	unsigned long i_ino;
} __attribute__((preserve_access_index));

struct file {
	struct inode *f_inode;
} __attribute__((preserve_access_index));

struct linux_binprm {
	struct file *file;
} __attribute__((preserve_access_index));

/* Raw sockaddr_in layout; read with bpf_probe_read_kernel (no CO-RE needed). */
struct sockaddr_in_min {
	__u16 sin_family;
	__u16 sin_port;
	__u32 sin_addr;
};

char LICENSE[] SEC("license") = "GPL";

#define ARRAY_U64(name)                              \
	struct {                                     \
		__uint(type, BPF_MAP_TYPE_ARRAY);    \
		__type(key, __u32);                  \
		__type(value, __u64);                \
		__uint(max_entries, 1);              \
	} name SEC(".maps")

#define ARRAY_U32(name)                              \
	struct {                                     \
		__uint(type, BPF_MAP_TYPE_ARRAY);    \
		__type(key, __u32);                  \
		__type(value, __u32);                \
		__uint(max_entries, 1);              \
	} name SEC(".maps")

ARRAY_U64(armed);          /* 0 = disarmed, 1 = armed */
ARRAY_U64(target_cgroup);
ARRAY_U32(denied_cap);
ARRAY_U64(denied_inode);
ARRAY_U64(denied_file_inode);
ARRAY_U32(blocked_ip);     /* host-endian u32 of the 4 address bytes; 0 = off */
ARRAY_U32(blocked_port);   /* host-order port; 0 = any port */

static __always_inline int is_armed_for_me(void)
{
	__u32 zero = 0;

	__u64 *is_armed = bpf_map_lookup_elem(&armed, &zero);
	if (!is_armed || *is_armed == 0)
		return 0;

	__u64 *cg = bpf_map_lookup_elem(&target_cgroup, &zero);
	if (!cg || *cg == 0)
		return 0;

	return bpf_get_current_cgroup_id() == *cg;
}

SEC("lsm/capable")
int BPF_PROG(deny_cap, const struct cred *cred, struct user_namespace *ns,
	     int cap, unsigned int opts)
{
	__u32 zero = 0;

	if (!is_armed_for_me())
		return 0;

	__u32 *dc = bpf_map_lookup_elem(&denied_cap, &zero);
	if (dc && *dc != 0 && cap == (int)*dc)
		return -1;

	return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(deny_exec, struct linux_binprm *bprm)
{
	__u32 zero = 0;

	if (!is_armed_for_me())
		return 0;

	__u64 *di = bpf_map_lookup_elem(&denied_inode, &zero);
	if (!di || *di == 0)
		return 0;

	if (BPF_CORE_READ(bprm, file, f_inode, i_ino) == *di)
		return -1;

	return 0;
}

SEC("lsm/file_open")
int BPF_PROG(deny_open, struct file *file)
{
	__u32 zero = 0;

	if (!is_armed_for_me())
		return 0;

	__u64 *di = bpf_map_lookup_elem(&denied_file_inode, &zero);
	if (!di || *di == 0)
		return 0;

	if (BPF_CORE_READ(file, f_inode, i_ino) == *di)
		return -1;

	return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(deny_connect, struct socket *sock, struct sockaddr *address,
	     int addrlen)
{
	__u32 zero = 0;

	if (!is_armed_for_me())
		return 0;

	__u32 *ip = bpf_map_lookup_elem(&blocked_ip, &zero);
	if (!ip || *ip == 0)
		return 0;

	struct sockaddr_in_min sa = {};
	if (bpf_probe_read_kernel(&sa, sizeof(sa), address) != 0)
		return 0;

	if (sa.sin_family != 2 /* AF_INET */)
		return 0;
	if (sa.sin_addr != *ip)
		return 0;

	__u32 *port = bpf_map_lookup_elem(&blocked_port, &zero);
	if (port && *port != 0) {
		__u16 host_port = (__u16)((sa.sin_port >> 8) | (sa.sin_port << 8));
		if (host_port != (__u16)*port)
			return 0;
	}

	return -1;
}

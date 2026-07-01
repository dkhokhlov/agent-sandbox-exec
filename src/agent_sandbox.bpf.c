// SPDX-License-Identifier: GPL-2.0
//
// agent-sandbox-exec BPF-LSM program.
//
// Denies opening of specific secret inodes for tasks running in a per-uid
// sandbox cgroup. Deny entries are keyed (cgid, device, inode): the cgid
// prefix scopes a user's denylist to that user's own sandbox cgroup, so a
// user-controlled home denylist can only block opens inside the user's own
// sandbox (cross-user isolation). Denied opens return -EPERM: "Operation not
// permitted" is the conventional errno for a security-policy denial (vs -EACCES
// for file-mode denial), so a sandboxed agent that sees the dirent via ls but
// gets EPERM on open reads it as "a policy is blocking me" instead of mistaking
// an ENOENT-on-a-visible-dirent for a broken inode / filesystem quirk. The
// kernel's own mode-bit check (inode_permission) runs before this hook and
// returns -EACCES, so EPERM stays a unique signal that the denylist fired.
//
// Scope: completely inert for every process not in a tracked per-uid sandbox
// cgroup (single HASH membership lookup on agent_cgid_set) -> zero system
// impact for the rest of the system.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "agent_sandbox.h"

#define EPERM 1

/* Deny errno — the single knob for deny behavior. Negative value returned from
 * the LSM hook becomes the open(2) errno. EPERM ("Operation not permitted")
 * signals a security-policy denial; it is distinct from EACCES, which the
 * kernel's mode-bit check already returns before this hook fires. */
#define DENY_ERRNO (-EPERM)

/* struct deny_key is defined in the shared header agent_sandbox.h. */

/* Denied inodes, scoped per cgroup. Presence of a {cgid, dev, ino} key => deny;
 * value is unused (stored as 1). Populated by agent-sandbox-execd as the union
 * of the root-controlled base list (/etc/agent-sandbox-exec/denylist) and the
 * user's home list (~/.config/agent-sandbox-exec/denylist) for that uid's
 * cgroup. NO_PREALLOC avoids ~1.6 MB preallocation for the larger map. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct deny_key);
	__type(value, __u8);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} deny_map SEC(".maps");

/* Set of per-uid sandbox cgroup ids tracked by the daemon (membership gate).
 * Key = cgid, value unused (1). A process is sandboxed iff its current cgroup
 * id is present here. Set by agent-sandbox-execd when it creates a per-uid
 * cgroup and repopulated from a /sys/fs/cgroup/agent-sandbox-exec re-scan on
 * daemon restart. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, __u8);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} agent_cgid_set SEC(".maps");

SEC("lsm/file_open")
int BPF_PROG(agent_file_open, struct file *file, int ret)
{
	__u64 cur = bpf_get_current_cgroup_id();
	__u8 *member;

	(void)ret;				/* prior LSM verdict; we decide independently */

	member = bpf_map_lookup_elem(&agent_cgid_set, &cur);
	if (!member)
		return 0;			/* not in any tracked sandbox cgroup: inert */

	struct inode *inode = BPF_CORE_READ(file, f_inode);
	struct deny_key key = {
		.cgid  = cur,
		.s_dev = BPF_CORE_READ(inode, i_sb, s_dev),
		.ino   = BPF_CORE_READ(inode, i_ino),
	};

	if (bpf_map_lookup_elem(&deny_map, &key))
		return DENY_ERRNO;

	return 0;
}

char _license[] SEC("license") = "GPL";

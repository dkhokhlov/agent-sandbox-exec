// SPDX-License-Identifier: GPL-2.0
//
// agent-sandbox-exec BPF-LSM program.
//
// Denies opening of specific secret inodes (matched by {device, inode}) for
// tasks running in the configured agent cgroup. Denied opens return -ENOENT so
// that tools treat the file as absent rather than hitting a permissions error.
//
// Scope: completely inert for every process outside the agent's cgroup
// (target_cgid_map == 0, or current cgroup id != target) -> zero system impact.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define ENOENT 2

/* Deny errno — the single knob for deny behavior. Negative value returned from
 * the LSM hook becomes the open(2) errno. */
#define DENY_ERRNO (-ENOENT)

/* Identifier of a file to deny: {containing-device, inode-number}. */
struct ino_key {
	__u32 s_dev;	/* inode->i_sb->s_dev (new_encode_dev format) */
	__u64 ino;	/* inode->i_ino                       */
};

/* Denied inodes. Presence of a key => deny; value is unused (stored as 1).
 * Populated by sandboxd from /etc/agent-sandbox/denylist (path -> stat -> ino). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct ino_key);
	__type(value, __u8);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} deny_map SEC(".maps");

/* The agent's cgroup id (single entry, index 0). Set by sandboxd once it has
 * created/delegated the agent cgroup. 0 => program is inert. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} target_cgid_map SEC(".maps");

SEC("lsm/file_open")
int BPF_PROG(agent_file_open, struct file *file, int ret)
{
	__u32 zero = 0;
	__u64 *cgid;

	(void)ret;				/* prior LSM verdict; we decide independently */

	cgid = bpf_map_lookup_elem(&target_cgid_map, &zero);
	if (!cgid || *cgid == 0)
		return 0;			/* no target configured: inert */

	if (bpf_get_current_cgroup_id() != *cgid)
		return 0;			/* not in the agent's cgroup */

	struct inode *inode = BPF_CORE_READ(file, f_inode);
	struct ino_key key = {
		.s_dev = BPF_CORE_READ(inode, i_sb, s_dev),
		.ino   = BPF_CORE_READ(inode, i_ino),
	};

	if (bpf_map_lookup_elem(&deny_map, &key))
		return DENY_ERRNO;

	return 0;
}

char _license[] SEC("license") = "GPL";

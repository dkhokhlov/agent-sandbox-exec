#ifndef AGENT_SANDBOX_H
#define AGENT_SANDBOX_H

/*
 * Shared between the BPF program (agent_sandbox.bpf.c, which has vmlinux.h for
 * __u32/__u64) and the daemon (agent-sandbox-execd.c, which has <linux/types.h>).
 * Keeping this in one place guarantees the deny-map key layout matches exactly.
 */

/* Identifier of a file to deny for a given cgroup:
 * {cgroup-id, containing-device, inode-number}. The cgid prefix scopes a
 * user's deny entries to that user's own per-uid sandbox cgroup, so a
 * user-controlled home denylist can only block opens inside the user's own
 * sandbox (cross-user isolation). All three fields are 64-bit so the struct
 * has NO padding — the BPF program and the daemon must build byte-identical
 * keys for the hash-map lookup. */
struct deny_key {
	__u64 cgid;	/* bpf_get_current_cgroup_id() of the per-uid sandbox cgroup */
	__u64 s_dev;	/* inode->i_sb->s_dev (== stat st_dev) */
	__u64 ino;	/* inode->i_ino (== stat st_ino)       */
};

#endif /* AGENT_SANDBOX_H */

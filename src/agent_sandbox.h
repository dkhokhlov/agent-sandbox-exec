#ifndef AGENT_SANDBOX_H
#define AGENT_SANDBOX_H

/*
 * Shared between the BPF program (agent_sandbox.bpf.c, which has vmlinux.h for
 * __u32/__u64) and the daemon (sandboxd.c, which has <linux/types.h>).
 * Keeping this in one place guarantees the deny-map key layout matches exactly.
 */

/* Identifier of a file to deny: {containing-device, inode-number}. */
struct ino_key {
	__u32 s_dev;	/* inode->i_sb->s_dev (== stat st_dev, low 32 bits) */
	__u64 ino;	/* inode->i_ino (== stat st_ino)                    */
};

#endif /* AGENT_SANDBOX_H */

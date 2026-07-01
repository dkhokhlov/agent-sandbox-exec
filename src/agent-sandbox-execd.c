// SPDX-License-Identifier: GPL-2.0
//
// agent-sandbox-execd — root daemon for agent-sandbox-exec.
//
//   * loads the BPF-LSM program (file_open) and holds the attachment link,
//   * owns deny_map (keyed {cgid, dev, ino}) and agent_cgid_set (the set of
//     tracked per-uid sandbox cgroup ids),
//   * ensures /sys/fs/cgroup/agent-sandbox-exec exists (root-owned, NOT
//     delegated) and creates a per-uid child /sys/fs/cgroup/agent-sandbox-exec/uid-<U>
//     for each sandboxed uid on first request,
//   * for each uid, applies the union of the root-controlled base list
//     (/etc/agent-sandbox-exec/denylist) and the user's home list
//     (~/.config/agent-sandbox-exec/denylist) to that uid's cgroup only — a
//     user-controlled home denylist is safe because per-cgid scoping confines
//     it to the user's own sandbox (cross-user isolation),
//   * on EVERY launch request, re-reads that uid's list (base ∪ home) from
//     disk and diff-applies it to the uid's cgid, so denylist edits take
//     effect on the next launch with no daemon restart (the #5 ping-driven
//     reload — safe because a deny list is self-restriction scoped to the
//     owner's own cgid, so live-updating that cgid only affects the owner's
//     own sandboxed processes). A restart re-scan remains as a
//     belt-and-suspenders refresh for a uid with a running sandbox but no
//     new launch,
//   * migrates launcher pids into their uid's cgroup on request via
//     /run/agent-sandbox-exec/req (the only inotify watched path).
//
// Runs as root (systemd Type=notify). The unprivileged launcher only drops a
// request and execs the agent; all the privilege lives here.

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pwd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/mount.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/types.h>
#include <linux/bpf.h>
#include <stdarg.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "agent_sandbox.h"
#include "agent_sandbox.skel.h"

#define CGROUP_PATH  "/sys/fs/cgroup/agent-sandbox-exec"
#define CGROUP_PARENT "/sys/fs/cgroup"
#define BPFFS_MNT    "/sys/fs/bpf"
#define DENYLIST_DIR "/etc/agent-sandbox-exec"
#define DENYLIST     DENYLIST_DIR "/denylist"
#define REQ_DIR      "/run/agent-sandbox-exec/req"
#define HOME_REL     "/.config/agent-sandbox-exec/denylist"

#ifndef BPF_FS_MAGIC
#define BPF_FS_MAGIC 0xcafe4a11
#endif

#define MAX_DENY 1024	/* max deny entries applied per uid (base ∪ home) */
#define MAX_UIDS 256	/* max concurrently sandboxed uids */

static int g_ifd = -1;
static int g_req_wd = -1;	/* watch on /run/agent-sandbox-exec/req only */

/* Per-uid sandbox state. A uid's list is re-read from disk on every launch
 * request (and at restart re-scan) and diff-applied to its cgid. */
struct uid_state {
	uid_t uid;
	__u64 cgid;
};
static struct uid_state g_uids[MAX_UIDS];
static int g_nuids;

/* Reused work buffers (single-threaded daemon). */
static char g_paths[MAX_DENY][PATH_MAX];
static struct deny_key g_newk[MAX_DENY];
static struct deny_key g_oldk[MAX_DENY];

/* ----- helpers ------------------------------------------------------------- */

static int libbpf_print_fn(enum libbpf_print_level level, const char *fmt, va_list ap)
{
	if (level >= LIBBPF_WARN)
		return vfprintf(stderr, fmt, ap);
	return 0;
}

/* Manual sd_notify(3) — avoids a libsystemd dependency. */
static void sd_notify_ready(void)
{
	const char *ns = getenv("NOTIFY_SOCKET");
	int fd;
	struct sockaddr_un addr;

	if (!ns || !*ns)
		return;
	fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	if (ns[0] == '@') {			/* abstract socket */
		addr.sun_path[0] = '\0';
		strncpy(addr.sun_path + 1, ns + 1, sizeof(addr.sun_path) - 2);
	} else {
		strncpy(addr.sun_path, ns, sizeof(addr.sun_path) - 1);
	}
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
		const char *msg = "READY=1\nSTATUS=agent-sandbox-exec active";
		(void)write(fd, msg, strlen(msg));
	}
	close(fd);
}

/* trim leading/trailing ws; NULL for blank lines / comments */
static char *line_path(char *s)
{
	while (*s == ' ' || *s == '\t')
		s++;
	if (*s == '#' || *s == '\n' || *s == '\r' || *s == '\0')
		return NULL;
	char *end = s + strlen(s);
	while (end > s &&
	       (end[-1] == '\n' || end[-1] == '\r' ||
	        end[-1] == ' '  || end[-1] == '\t'))
		*--end = '\0';
	return *s ? s : NULL;
}

/* Preflight: refuse to start if BPF-LSM is not active on this kernel, with a
 * legible message instead of a generic attach failure later. The runtime LSM
 * list at /sys/kernel/security/lsm is authoritative. */
static int preflight_bpf_lsm(void)
{
	FILE *f = fopen("/sys/kernel/security/lsm", "r");
	char buf[1024];
	char *p, *tok;
	int found = 0;

	if (!f) {
		fprintf(stderr, "agent-sandbox-execd: BPF-LSM not enabled: cannot read "
				"/sys/kernel/security/lsm (securityfs absent).\n"
				"agent-sandbox-execd: set CONFIG_BPF_LSM=y and add `bpf` to the "
				"kernel's LSM= boot param.\n");
		return -1;
	}
	if (!fgets(buf, sizeof(buf), f)) {
		fclose(f);
		fprintf(stderr, "agent-sandbox-execd: BPF-LSM not enabled: empty LSM list.\n"
				"agent-sandbox-execd: set CONFIG_BPF_LSM=y and add `bpf` to the "
				"kernel's LSM= boot param.\n");
		return -1;
	}
	fclose(f);
	/* /sys/kernel/security/lsm is a comma-separated list, e.g.
	 * "lockdown,capability,landlock,bpf". Match the bare token "bpf". */
	p = buf;
	while ((tok = strsep(&p, ",")) != NULL) {
		char *nl = tok + strcspn(tok, "\n\r");
		*nl = '\0';
		while (*tok == ' ' || *tok == '\t')
			tok++;
		if (strcmp(tok, "bpf") == 0) {
			found = 1;
			break;
		}
	}
	if (!found) {
		fprintf(stderr, "agent-sandbox-execd: BPF-LSM not enabled: `bpf` not in the "
				"active LSM list (%s).\n"
				"agent-sandbox-execd: set CONFIG_BPF_LSM=y and add `bpf` to the "
				"kernel's LSM= boot param.\n", buf);
		return -1;
	}
	return 0;
}

/* Read absolute file paths from `file` into g_paths starting at *n. Rejects
 * non-absolute lines. If reject_symlinks, lstat each candidate and skip symlink
 * entries (the home list is user-controlled; a symlink entry that later
 * retargets is a self-surprise). Updates *n. Returns -1 only if `file` cannot
 * be opened at all (missing home list is not an error — returns 0). */
static int denylist_read_file(const char *file, int *n, int max, int reject_symlinks)
{
	FILE *f = fopen(file, "r");
	char line[PATH_MAX];

	if (!f)
		return (errno == ENOENT) ? 0 : -1;
	if (*n >= max) {
		fprintf(stderr, "agent-sandbox-execd: denylist full (%d entries), %s truncated\n",
			*n, file);
		fclose(f);
		return 0;
	}
	while (fgets(line, sizeof(line), f)) {
		char *p = line_path(line);
		if (!p)
			continue;
		if (p[0] != '/') {
			fprintf(stderr, "agent-sandbox-execd: skip non-absolute path: %s\n", p);
			continue;
		}
		if (reject_symlinks) {
			struct stat lst;
			if (lstat(p, &lst) == 0 && S_ISLNK(lst.st_mode)) {
				fprintf(stderr, "agent-sandbox-execd: skip symlink entry in %s: %s "
						"(home list entries must be regular files)\n", file, p);
				continue;
			}
			/* missing entries are kept; the apply step reports the skip */
		}
		strncpy(g_paths[*n], p, PATH_MAX - 1);
		g_paths[*n][PATH_MAX - 1] = '\0';
		(*n)++;
		if (*n >= max) {
			fprintf(stderr, "agent-sandbox-execd: denylist full (%d entries), %s truncated\n",
				*n, file);
			break;
		}
	}
	fclose(f);
	return 0;
}

/* Build the per-uid deny set: union of the base list and the uid's home list. */
static int load_uid_list(uid_t uid, int max)
{
	int n = 0;
	char home[PATH_MAX];
	struct passwd *pw;

	denylist_read_file(DENYLIST, &n, max, 0);	/* base: root-controlled */

	pw = getpwuid(uid);
	if (pw && pw->pw_dir && *pw->pw_dir &&
	    snprintf(home, sizeof(home), "%s" HOME_REL, pw->pw_dir) < (int)sizeof(home))
		denylist_read_file(home, &n, max, 1);	/* home: user-controlled */
	else
		fprintf(stderr, "agent-sandbox-execd: uid %u: no home dir, home denylist skipped\n",
			(unsigned)uid);
	return n;
}

/* Collect all deny_map keys belonging to cgid into out[]. Returns count (<=max). */
static int deny_map_collect_cgid(int fd, __u64 cgid, struct deny_key *out, int max)
{
	struct deny_key cur;
	int n = 0;
	int err = bpf_map_get_next_key(fd, NULL, &cur);

	while (err == 0 && n < max) {
		if (cur.cgid == cgid)
			out[n++] = cur;
		err = bpf_map_get_next_key(fd, &cur, &cur);
	}
	return n;
}

/* Incrementally apply the deny set for one cgid. Inserts new entries first,
 * then removes stale ones not in the new set, so the live map always covers
 * the desired set (no transient allow window). Self-correcting across daemon
 * restart: the current map state for the cgid is the diff baseline, so no
 * persistent userspace record is needed. */
static void denylist_apply_cgid(struct agent_sandbox_bpf *skel, __u64 cgid,
				int npaths)
{
	int fd = bpf_map__fd(skel->maps.deny_map);
	int nnew = 0, applied = 0, removed = 0;

	for (int i = 0; i < npaths; i++) {
		struct stat st;
		if (stat(g_paths[i], &st) != 0) {
			fprintf(stderr, "agent-sandbox-execd: skip %s: %s\n",
				g_paths[i], strerror(errno));
			continue;
		}
		if (!S_ISREG(st.st_mode)) {
			fprintf(stderr, "agent-sandbox-execd: skip %s: not a regular file\n",
				g_paths[i]);
			continue;
		}
		if (nnew < MAX_DENY) {
			g_newk[nnew].cgid  = cgid;
			g_newk[nnew].s_dev = (__u64)st.st_dev;
			g_newk[nnew].ino   = (__u64)st.st_ino;
			nnew++;
		} else {
			fprintf(stderr, "agent-sandbox-execd: uid deny set exceeds %d, "
					"truncating\n", MAX_DENY);
			break;
		}
	}

	/* Insert/refresh new entries first so the map never drops below the
	 * desired set. */
	for (int i = 0; i < nnew; i++) {
		__u8 v = 1;
		if (bpf_map_update_elem(fd, &g_newk[i], &v, BPF_ANY) == 0)
			applied++;
		else
			fprintf(stderr, "agent-sandbox-execd: deny_map insert failed "
					"(dev=%llu ino=%llu): %s — map may be full (%d); "
					"entry NOT enforced\n",
				(unsigned long long)g_newk[i].s_dev,
				(unsigned long long)g_newk[i].ino,
				strerror(errno), 65536);
	}

	/* Remove entries for this cgid no longer in the new set. */
	int nold = deny_map_collect_cgid(fd, cgid, g_oldk, MAX_DENY);
	for (int j = 0; j < nold; j++) {
		int still = 0;
		for (int i = 0; i < nnew; i++)
			if (g_oldk[j].s_dev == g_newk[i].s_dev &&
			    g_oldk[j].ino == g_newk[i].ino) {
				still = 1;
				break;
			}
		if (!still) {
			if (bpf_map_delete_elem(fd, &g_oldk[j]) == 0)
				removed++;
		}
	}

	printf("agent-sandbox-execd: cgid %llu: applied %d deny entry(ies), removed %d stale\n",
	       (unsigned long long)cgid, applied, removed);
}

static int find_uid(uid_t uid)
{
	for (int i = 0; i < g_nuids; i++)
		if (g_uids[i].uid == uid)
			return i;
	return -1;
}

/* Ensure the per-uid sandbox cgroup exists, track it, and (re)load its deny
 * list from disk. Returns the cgroup id, or 0 on failure. On every request the
 * uid's list (base ∪ home) is re-read from disk and diff-applied to its cgid,
 * so denylist edits take effect on the next launch with no daemon restart (the
 * #5 ping-driven reload). The cgid is stable for the life of this daemon, so
 * this live-updates the deny set for that cgid (shared by any concurrent
 * sandboxes of the same uid) — safe because a deny list is self-restriction
 * scoped to the owner's own cgid only. The restart re-scan path is the same
 * function applied to every existing uid at start. */
static __u64 ensure_per_uid_cgroup(struct agent_sandbox_bpf *skel, uid_t uid)
{
	char cgpath[PATH_MAX];
	struct stat st;
	__u64 cgid;
	int idx, npaths;

	idx = find_uid(uid);
	if (idx >= 0) {
		/* #5 ping-driven reload: re-read on every request and diff-apply
		 * to the (stable) cgid so edits land on the next launch. */
		npaths = load_uid_list(uid, MAX_DENY);
		denylist_apply_cgid(skel, g_uids[idx].cgid, npaths);
		return g_uids[idx].cgid;
	}

	if (g_nuids >= MAX_UIDS) {
		fprintf(stderr, "agent-sandbox-execd: uid cap reached (%d), cannot sandbox uid %u\n",
			MAX_UIDS, (unsigned)uid);
		return 0;
	}

	snprintf(cgpath, sizeof(cgpath), CGROUP_PATH "/uid-%u", (unsigned)uid);
	if (mkdir(cgpath, 0755) != 0 && errno != EEXIST) {
		fprintf(stderr, "agent-sandbox-execd: mkdir %s: %s\n", cgpath, strerror(errno));
		return 0;
	}
	if (chown(cgpath, 0, 0) != 0) {
		fprintf(stderr, "agent-sandbox-execd: chown %s: %s\n", cgpath, strerror(errno));
		return 0;
	}
	if (chmod(cgpath, 0755) != 0) {
		fprintf(stderr, "agent-sandbox-execd: chmod %s: %s\n", cgpath, strerror(errno));
		return 0;
	}
	if (stat(cgpath, &st) != 0) {
		fprintf(stderr, "agent-sandbox-execd: stat %s: %s\n", cgpath, strerror(errno));
		return 0;
	}
	cgid = (__u64)st.st_ino;

	/* Track the cgroup in the BPF membership gate. */
	{
		__u8 one = 1;
		if (bpf_map_update_elem(bpf_map__fd(skel->maps.agent_cgid_set),
					&cgid, &one, BPF_ANY)) {
			fprintf(stderr, "agent-sandbox-execd: agent_cgid_set insert failed: %s\n",
				strerror(errno));
			return 0;
		}
	}

	/* Load and apply the per-uid deny set (base ∪ home). */
	npaths = load_uid_list(uid, MAX_DENY);
	denylist_apply_cgid(skel, cgid, npaths);

	g_uids[g_nuids].uid  = uid;
	g_uids[g_nuids].cgid = cgid;
	g_nuids++;
	printf("agent-sandbox-execd: tracking uid %u cgroup=%s id=%llu\n",
	       (unsigned)uid, cgpath, (unsigned long long)cgid);
	return cgid;
}

/* Scan existing uid-* children of the parent cgroup and (re)load each. This is
 * the restart path: it restores the membership gate + deny set for already-
 * running sandboxes, and re-reads every uid's list from disk. Under the #5
 * ping-driven reload model a uid's list is already re-read on each launch, so
 * this is mainly a belt-and-suspenders refresh for a uid whose sandbox is
 * running but has had no new launch since its list edit. */
static void rescan_uids(struct agent_sandbox_bpf *skel)
{
	DIR *d = opendir(CGROUP_PATH);
	struct dirent *e;

	if (!d)
		return;
	while ((e = readdir(d)) != NULL) {
		unsigned int uid;
		char extra;
		if (strncmp(e->d_name, "uid-", 4) != 0)
			continue;
		if (sscanf(e->d_name + 4, "%u%c", &uid, &extra) != 1)
			continue;
		ensure_per_uid_cgroup(skel, (uid_t)uid);
	}
	closedir(d);
}

/* One-time migration of pinned maps from the old single-tenant schema. The
 * prior version pinned deny_map with a 16-byte key and a target_cgid_map array;
 * the new schema uses a 24-byte deny_key and an agent_cgid_set hash. libbpf
 * refuses to reuse a pinned map whose key/value size differs, which would make
 * an upgrade fail at load with a confusing error. Remove only provably
 * incompatible/orphaned pins; matching pins are left for the normal reuse path
 * (so deny data + cgroup membership survive a same-version restart). */
static void migrate_stale_pins(void)
{
	int fd;

	/* target_cgid_map no longer exists in the schema; its pin is orphaned. */
	unlink("/sys/fs/bpf/target_cgid_map");

	fd = bpf_obj_get("/sys/fs/bpf/deny_map");
	if (fd >= 0) {
		struct bpf_map_info info = {};
		__u32 len = sizeof(info);
		if (bpf_obj_get_info_by_fd(fd, &info, &len) == 0 &&
		    info.key_size != sizeof(struct deny_key))
			unlink("/sys/fs/bpf/deny_map");
		close(fd);
	}
}

/* Ensure /sys/fs/bpf (bpffs) is mounted. */
static int ensure_bpffs(void)
{
	struct statfs sfs;
	if (statfs(BPFFS_MNT, &sfs) == 0 && (unsigned long)sfs.f_type == BPF_FS_MAGIC)
		return 0;
	if (mkdir(BPFFS_MNT, 0755) != 0 && errno != EEXIST) {
		perror("agent-sandbox-execd: mkdir " BPFFS_MNT);
		return -1;
	}
	if (mount("bpf", BPFFS_MNT, "bpf", 0, NULL) != 0) {
		perror("agent-sandbox-execd: mount " BPFFS_MNT);
		return -1;
	}
	return 0;
}

/* Create the parent agent cgroup (root-owned, NOT delegated). If a sandboxed
 * process could write under it, it could mkdir a child cgroup and migrate
 * there, escaping the exact-cgid membership check in the BPF program.
 * Migration is performed by this root daemon via the request-dir handshake, so
 * no user ever needs write access to any sandbox cgroup. */
static int setup_cgroup_parent(void)
{
	struct stat st;

	if (mkdir(CGROUP_PATH, 0755) != 0 && errno != EEXIST) {
		perror("agent-sandbox-execd: mkdir " CGROUP_PATH);
		return -1;
	}
	if (chown(CGROUP_PATH, 0, 0) != 0) {
		perror("agent-sandbox-execd: chown " CGROUP_PATH);
		return -1;
	}
	if (chmod(CGROUP_PATH, 0755) != 0) {
		perror("agent-sandbox-execd: chmod " CGROUP_PATH);
		return -1;
	}
	/* Reclaim control files a prior delegated build may have left user-owned. */
	{
		const char *const files[] = { CGROUP_PATH "/cgroup.procs",
					      CGROUP_PATH "/cgroup.threads",
					      NULL };
		for (int i = 0; files[i]; i++)
			if (chown(files[i], 0, 0) != 0 && errno != ENOENT)
				perror("agent-sandbox-execd: chown cgroup file");
	}
	if (stat(CGROUP_PATH, &st) != 0) {
		perror("agent-sandbox-execd: stat " CGROUP_PATH);
		return -1;
	}
	return 0;
}

/* Create /run/agent-sandbox-exec/req as a world-writable sticky dir owned by
 * root, so any unprivileged user can drop a migration request. The daemon
 * authenticates the requester via /proc/<pid>/status + fstat. Stale numeric
 * request files from a crashed daemon are cleaned up. */
static int setup_request_dir(void)
{
	DIR *d;
	struct dirent *e;

	if (mkdir("/run/agent-sandbox-exec", 0755) != 0 && errno != EEXIST) {
		perror("agent-sandbox-execd: mkdir /run/agent-sandbox-exec");
		return -1;
	}
	if (mkdir(REQ_DIR, 0777) != 0 && errno != EEXIST) {
		perror("agent-sandbox-execd: mkdir " REQ_DIR);
		return -1;
	}
	if (chown(REQ_DIR, 0, 0) != 0) {
		perror("agent-sandbox-execd: chown " REQ_DIR);
		return -1;
	}
	if (chmod(REQ_DIR, 01777) != 0) {		/* sticky, world-writable */
		perror("agent-sandbox-execd: chmod " REQ_DIR);
		return -1;
	}

	/* Clean stale numeric request files. */
	d = opendir(REQ_DIR);
	if (!d) {
		perror("agent-sandbox-execd: opendir " REQ_DIR);
		return -1;
	}
	while ((e = readdir(d)) != NULL) {
		char junk;
		unsigned long pid;
		char path[PATH_MAX];
		if (sscanf(e->d_name, "%lu%c", &pid, &junk) != 1)
			continue;
		snprintf(path, sizeof(path), REQ_DIR "/%s", e->d_name);
		if (unlink(path) != 0 && errno != ENOENT)
			perror("agent-sandbox-execd: unlink stale request");
	}
	closedir(d);
	return 0;
}

/* Handle one migration request. The request file is removed ONLY after a
 * verified successful migration, so its disappearance is a trustworthy success
 * signal to the launcher; on any failure the file is left in place and the
 * launcher fails closed (timeout).
 *
 * Auth: reject root (uid 0 — root must never be sandboxed into a deny cgroup
 * it could manipulate), and require the request file's owner to match the
 * target pid's real uid. The latter closes a pid-reuse race: if the requester
 * pid died and its number was reused by a different uid, the request file's
 * st_uid (the original requester's uid) will not match /proc/<pid>/status. */
static void handle_request(struct agent_sandbox_bpf *skel, const char *name)
{
	char path[PATH_MAX], proc[PATH_MAX], cgpath[PATH_MAX];
	struct stat rst;
	char line[256], *end;
	long pid;
	uid_t real_uid = (uid_t)-1;
	FILE *pf, *cf;
	__u64 cgid;

	pid = strtol(name, &end, 10);
	if (*end != '\0' || pid <= 0)
		return;				/* not a numeric pid filename */

	snprintf(path, sizeof(path), REQ_DIR "/%s", name);
	if (stat(path, &rst) != 0 || !S_ISREG(rst.st_mode))
		return;

	/* Auth: read the target's real uid. */
	snprintf(proc, sizeof(proc), "/proc/%ld/status", pid);
	pf = fopen(proc, "r");
	if (!pf)
		return;
	while (fgets(line, sizeof(line), pf)) {
		if (sscanf(line, "Uid: %u", &real_uid) == 1)
			break;
	}
	fclose(pf);
	if (real_uid == (uid_t)-1)
		return;
	if (real_uid == 0) {
		fprintf(stderr, "agent-sandbox-execd: refusing to sandbox root pid %ld\n", pid);
		return;
	}
	/* pid-reuse mitigation: request file owner must equal the target's real uid. */
	if (rst.st_uid != real_uid) {
		fprintf(stderr, "agent-sandbox-execd: rejecting pid %ld: request owner uid %u "
				"!= pid real uid %u (pid reuse?)\n",
			pid, (unsigned)rst.st_uid, (unsigned)real_uid);
		return;
	}

	cgid = ensure_per_uid_cgroup(skel, real_uid);
	if (!cgid)
		return;				/* leave request → launcher fails closed */

	snprintf(cgpath, sizeof(cgpath), CGROUP_PATH "/uid-%u/cgroup.procs",
		 (unsigned)real_uid);
	cf = fopen(cgpath, "w");
	if (!cf) {
		perror("agent-sandbox-execd: open cgroup.procs");
		return;
	}
	if (fprintf(cf, "%ld\n", pid) < 0 || fclose(cf) != 0) {
		fprintf(stderr, "agent-sandbox-execd: write %s failed: %s\n",
			cgpath, strerror(errno));
		return;
	}

	/* Verified migration: signal the launcher by removing the request. */
	if (unlink(path) != 0)
		perror("agent-sandbox-execd: unlink request");
}

int main(void)
{
	struct agent_sandbox_bpf *skel;
	struct bpf_link *link;

	libbpf_set_print(libbpf_print_fn);

	if (geteuid() != 0) {
		fprintf(stderr, "agent-sandbox-execd: must run as root\n");
		return 1;
	}
	if (preflight_bpf_lsm() != 0)
		return 1;
	if (ensure_bpffs() != 0)
		return 1;
	migrate_stale_pins();

	skel = agent_sandbox_bpf__open();
	if (!skel) {
		fprintf(stderr, "agent-sandbox-execd: open skeleton failed\n");
		return 1;
	}
	if (agent_sandbox_bpf__load(skel)) {
		fprintf(stderr, "agent-sandbox-execd: load failed: %s\n", strerror(errno));
		agent_sandbox_bpf__destroy(skel);
		return 1;
	}
	link = bpf_program__attach(skel->progs.agent_file_open);
	{
		long attach_err = libbpf_get_error(link);
		if (attach_err) {
			fprintf(stderr, "agent-sandbox-execd: attach file_open failed: %s\n",
				strerror(-attach_err));
			agent_sandbox_bpf__destroy(skel);
			return 1;
		}
	}

	if (setup_cgroup_parent() != 0) {
		bpf_link__destroy(link);
		agent_sandbox_bpf__destroy(skel);
		return 1;
	}
	printf("agent-sandbox-execd: parent cgroup=%s; BPF attached\n", CGROUP_PATH);

	if (setup_request_dir() != 0)
		fprintf(stderr, "agent-sandbox-execd: WARNING: request dir not ready; "
				"agents cannot be sandboxed\n");

	/* Restore the membership gate for already-running sandboxes and re-apply
	 * their lists from disk (the restart re-scan path; under the #5
	 * ping-driven reload a uid's list is already re-read on each launch, so
	 * this mainly refreshes a sandbox with no new launch since its edit). */
	rescan_uids(skel);

	/* Watch the request dir only — the migration IPC. No denylist watching,
	 * no polling: denylist changes require a daemon restart. */
	g_ifd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	if (g_ifd < 0) {
		perror("agent-sandbox-execd: inotify_init1");
		bpf_link__destroy(link);
		agent_sandbox_bpf__destroy(skel);
		return 1;
	}
	g_req_wd = inotify_add_watch(g_ifd, REQ_DIR, IN_CREATE | IN_CLOSE_WRITE | IN_MOVED_TO);
	if (g_req_wd < 0) {
		perror("agent-sandbox-execd: inotify_add_watch " REQ_DIR);
		bpf_link__destroy(link);
		agent_sandbox_bpf__destroy(skel);
		return 1;
	}

	sd_notify_ready();

	for (;;) {
		struct pollfd pfd = { .fd = g_ifd, .events = POLLIN };
		char buf[8192] __attribute__((aligned(8)));
		int r, n;

		r = poll(&pfd, 1, -1);		/* block indefinitely; no periodic wake */
		if (r < 0) {
			if (errno == EINTR)
				continue;
			perror("agent-sandbox-execd: poll");
			break;
		}
		n = read(g_ifd, buf, sizeof(buf));
		if (n < 0) {
			if (errno == EAGAIN)
				continue;
			perror("agent-sandbox-execd: inotify read");
			continue;
		}
		for (char *p = buf; p + sizeof(struct inotify_event) <= buf + n; ) {
			struct inotify_event *ev = (struct inotify_event *)p;
			if (ev->wd == g_req_wd && ev->len > 0)
				handle_request(skel, ev->name);
			p += sizeof(struct inotify_event) + ev->len;
		}
	}

	bpf_link__destroy(link);
	agent_sandbox_bpf__destroy(skel);
	return 0;
}
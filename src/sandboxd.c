// SPDX-License-Identifier: GPL-2.0
//
// sandboxd — root daemon for agent-sandbox-exec.
//
//   * loads the BPF-LSM program (file_open) and holds the attachment link,
//   * owns the deny_map (path -> {dev,ino} from /etc/agent-sandbox/denylist),
//   * creates + delegates /sys/fs/cgroup/agent-sandbox to AGENT_USER, and sets
//     its cgroup id in target_cgid_map (so the BPF program knows what to scope),
//   * watches the denylist + each secret file and re-resolves on change
//     (atomic-replace of a secret -> new inode -> map updated).
//
// Runs as root (systemd Type=notify). The unprivileged launcher only writes its
// pid into the delegated cgroup and execs the agent; all the privilege lives here.

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
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/mount.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/types.h>
#include <stdarg.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "agent_sandbox.h"
#include "agent_sandbox.skel.h"

#ifndef AGENT_USER
#define AGENT_USER "owner"
#endif

#define CGROUP_PATH  "/sys/fs/cgroup/agent-sandbox"
#define CGROUP_PARENT "/sys/fs/cgroup"
#define BPFFS_MNT    "/sys/fs/bpf"
#define DENYLIST_DIR "/etc/agent-sandbox"
#define DENYLIST     DENYLIST_DIR "/denylist"
#define REQ_DIR      "/run/agent-sandbox/req"

#ifndef BPF_FS_MAGIC
#define BPF_FS_MAGIC 0xcafe4a11
#endif

#define MAX_DENY 256

static int g_ifd = -1;
static int g_deny_wd = -1;	/* watch on /etc/agent-sandbox + secret files */
static int g_req_wd = -1;	/* watch on /run/agent-sandbox/req           */

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
		const char *msg = "READY=1\nSTATUS=agent-sandbox active";
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

static void map_clear(int fd)
{
	struct ino_key cur;
	/* Always fetch first key (NULL prev); delete; repeat. O(n) for tiny n. */
	while (bpf_map_get_next_key(fd, NULL, &cur) == 0) {
		if (bpf_map_delete_elem(fd, &cur) != 0)
			break;
	}
}

/* Read denylist paths into paths[]. Returns count, or -1 if unreadable. */
static int denylist_read(char paths[][PATH_MAX], int max)
{
	FILE *f = fopen(DENYLIST, "r");
	int n = 0;
	char line[PATH_MAX];

	if (!f) {
		fprintf(stderr, "sandboxd: cannot open %s: %s\n", DENYLIST, strerror(errno));
		return -1;
	}
	while (n < max && fgets(line, sizeof(line), f)) {
		char *p = line_path(line);
		if (!p)
			continue;
		if (p[0] != '/') {
			fprintf(stderr, "sandboxd: skip non-absolute path: %s\n", p);
			continue;
		}
		strncpy(paths[n], p, PATH_MAX - 1);
		paths[n][PATH_MAX - 1] = '\0';
		n++;
	}
	fclose(f);
	return n;
}

/* Clear map and repopulate from paths[] (stat -> {dev,ino}). */
static void denylist_apply(struct agent_sandbox_bpf *skel,
			   char paths[][PATH_MAX], int n)
{
	int applied = 0;

	map_clear(bpf_map__fd(skel->maps.deny_map));
	for (int i = 0; i < n; i++) {
		struct stat st;
		if (stat(paths[i], &st) != 0) {
			fprintf(stderr, "sandboxd: skip %s: %s\n", paths[i], strerror(errno));
			continue;
		}
		if (!S_ISREG(st.st_mode)) {
			fprintf(stderr, "sandboxd: skip %s: not a regular file\n", paths[i]);
			continue;
		}
		struct ino_key key = {
			.s_dev = (__u64)st.st_dev,
			.ino   = (__u64)st.st_ino,
		};
		__u8 val = 1;
		if (bpf_map_update_elem(bpf_map__fd(skel->maps.deny_map), &key, &val, BPF_ANY) == 0)
			applied++;
	}
	printf("sandboxd: denying %d file(s)\n", applied);
}

static void install_secret_watches(char paths[][PATH_MAX], int n)
{
	for (int i = 0; i < n; i++)
		inotify_add_watch(g_ifd, paths[i],
				  IN_MODIFY | IN_ATTRIB | IN_MOVE_SELF | IN_DELETE_SELF);
}

/* Ensure /sys/fs/bpf (bpffs) is mounted. */
static int ensure_bpffs(void)
{
	struct statfs sfs;
	if (statfs(BPFFS_MNT, &sfs) == 0 && (unsigned long)sfs.f_type == BPF_FS_MAGIC)
		return 0;
	if (mkdir(BPFFS_MNT, 0755) != 0 && errno != EEXIST) {
		perror("sandboxd: mkdir " BPFFS_MNT);
		return -1;
	}
	if (mount("bpf", BPFFS_MNT, "bpf", 0, NULL) != 0) {
		perror("sandboxd: mount " BPFFS_MNT);
		return -1;
	}
	return 0;
}

/* Create the agent cgroup (root-owned) and return its cgroup id (== st_ino),
 * 0 on err. The cgroup is deliberately NOT delegated to AGENT_USER: if a
 * sandboxed process could write under it, it could mkdir a child cgroup and
 * migrate there, escaping the exact-cgid equality check in the BPF program.
 * Migration is performed by this root daemon via the request-dir handshake, so
 * the agent user never needs write access to the cgroup itself. */
static __u64 setup_cgroup(void)
{
	struct stat st;

	if (mkdir(CGROUP_PATH, 0755) != 0 && errno != EEXIST) {
		perror("sandboxd: mkdir " CGROUP_PATH);
		return 0;
	}
	/* Reclaim root ownership in case a prior build delegated it to AGENT_USER. */
	if (chown(CGROUP_PATH, 0, 0) != 0) {
		perror("sandboxd: chown " CGROUP_PATH);
		return 0;
	}
	if (chmod(CGROUP_PATH, 0755) != 0) {
		perror("sandboxd: chmod " CGROUP_PATH);
		return 0;
	}
	/* File ownership does not follow a directory chown: a prior delegated build
	 * may have left cgroup.procs (and cgroup.threads) owned by AGENT_USER, which
	 * would let the agent self-migrate via a direct write, bypassing this
	 * daemon's UID-checked request path. Reclaim them too. */
	{
		const char *const files[] = { CGROUP_PATH "/cgroup.procs",
					      CGROUP_PATH "/cgroup.threads",
					      NULL };
		for (int i = 0; files[i]; i++) {
			if (chown(files[i], 0, 0) != 0 && errno != ENOENT)
				perror("sandboxd: chown cgroup file");
		}
	}
	if (stat(CGROUP_PATH, &st) != 0) {
		perror("sandboxd: stat " CGROUP_PATH);
		return 0;
	}
	return (__u64)st.st_ino;
}

/* Create /run/agent-sandbox/req, owned by the agent user, so the unprivileged
 * launcher can drop migration requests there. */
static int setup_request_dir(void)
{
	struct passwd *pw = getpwnam(AGENT_USER);
	if (!pw) {
		fprintf(stderr, "sandboxd: unknown AGENT_USER '%s'\n", AGENT_USER);
		return -1;
	}
	if (mkdir("/run/agent-sandbox", 0755) != 0 && errno != EEXIST) {
		perror("sandboxd: mkdir /run/agent-sandbox");
		return -1;
	}
	if (mkdir(REQ_DIR, 0770) != 0 && errno != EEXIST) {
		perror("sandboxd: mkdir " REQ_DIR);
		return -1;
	}
	if (chown(REQ_DIR, pw->pw_uid, pw->pw_gid) != 0) {
		perror("sandboxd: chown " REQ_DIR);
		return -1;
	}
	if (chmod(REQ_DIR, 0770) != 0) {
		perror("sandboxd: chmod " REQ_DIR);
		return -1;
	}
	return 0;
}

/* Migrate the pid named by `name` into the agent cgroup (root-only write).
 * The request file is removed ONLY after a verified successful migration, so
 * its disappearance is a trustworthy success signal to the launcher; on any
 * failure the file is left in place and the launcher fails closed (timeout).
 * The target pid is additionally restricted to AGENT_USER, so a same-uid caller
 * cannot drive migration of unrelated (e.g. root) pids through the daemon. */
static void migrate_pid(const char *name)
{
	char path[PATH_MAX], proc[PATH_MAX];
	struct stat st;
	struct passwd *pw;
	char line[256], *end;
	long pid;
	uid_t real_uid = (uid_t)-1;
	FILE *pf, *cf;

	pid = strtol(name, &end, 10);
	if (*end != '\0' || pid <= 0)
		return;				/* not a numeric pid filename */

	snprintf(path, sizeof(path), REQ_DIR "/%s", name);
	if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
		return;

	/* Auth: only migrate processes whose real uid is AGENT_USER. */
	snprintf(proc, sizeof(proc), "/proc/%ld/status", pid);
	pf = fopen(proc, "r");
	if (!pf)
		return;
	while (fgets(line, sizeof(line), pf)) {
		if (sscanf(line, "Uid: %u", &real_uid) == 1)
			break;
	}
	fclose(pf);
	pw = getpwnam(AGENT_USER);
	if (real_uid == (uid_t)-1 || !pw || real_uid != pw->pw_uid)
		return;

	cf = fopen(CGROUP_PATH "/cgroup.procs", "w");
	if (!cf) {
		perror("sandboxd: open cgroup.procs");
		return;
	}
	if (fprintf(cf, "%ld\n", pid) < 0 || fclose(cf) != 0) {
		fprintf(stderr, "sandboxd: write cgroup.procs failed: %s\n", strerror(errno));
		return;
	}

	/* Verified migration: now signal the launcher by removing the request. */
	if (unlink(path) != 0)
		perror("sandboxd: unlink request");
}

int main(void)
{
	struct agent_sandbox_bpf *skel;
	struct bpf_link *link;
	__u64 cgid;
	char paths[MAX_DENY][PATH_MAX];
	int npaths;

	libbpf_set_print(libbpf_print_fn);

	if (geteuid() != 0) {
		fprintf(stderr, "sandboxd: must run as root\n");
		return 1;
	}
	if (ensure_bpffs() != 0)
		return 1;

	skel = agent_sandbox_bpf__open();
	if (!skel) {
		fprintf(stderr, "sandboxd: open skeleton failed\n");
		return 1;
	}
	if (agent_sandbox_bpf__load(skel)) {
		fprintf(stderr, "sandboxd: load failed: %s\n", strerror(errno));
		agent_sandbox_bpf__destroy(skel);
		return 1;
	}
	link = bpf_program__attach(skel->progs.agent_file_open);
	{
		long attach_err = libbpf_get_error(link);
		if (attach_err) {
			fprintf(stderr, "sandboxd: attach file_open failed: %s\n",
				strerror(-attach_err));
			agent_sandbox_bpf__destroy(skel);
			return 1;
		}
	}

	cgid = setup_cgroup();
	if (!cgid) {
		agent_sandbox_bpf__destroy(skel);
		return 1;
	}
	{
		__u32 zero = 0;
		if (bpf_map_update_elem(bpf_map__fd(skel->maps.target_cgid_map), &zero, &cgid, BPF_ANY)) {
			fprintf(stderr, "sandboxd: set target_cgid failed: %s\n", strerror(errno));
			agent_sandbox_bpf__destroy(skel);
			return 1;
		}
	}
	printf("sandboxd: agent cgroup=%s id=%llu; BPF attached\n",
	       CGROUP_PATH, (unsigned long long)cgid);

	if (setup_request_dir() != 0)
		fprintf(stderr, "sandboxd: WARNING: request dir not ready; "
				"owner-launched agents cannot be sandboxed\n");

	/* Initial denylist population. */
	npaths = denylist_read(paths, MAX_DENY);
	if (npaths >= 0)
		denylist_apply(skel, paths, npaths);

	/* Watch denylist dir (covers edit + atomic replace) + each secret file. */
	g_ifd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	if (g_ifd < 0) {
		perror("sandboxd: inotify_init1");
		agent_sandbox_bpf__destroy(skel);
		return 1;
	}
	g_deny_wd = inotify_add_watch(g_ifd, DENYLIST_DIR,
			  IN_CREATE | IN_MOVED_TO | IN_MODIFY | IN_CLOSE_WRITE | IN_DELETE);
	g_req_wd = inotify_add_watch(g_ifd, REQ_DIR, IN_CREATE);
	if (npaths >= 0)
		install_secret_watches(paths, npaths);

	sd_notify_ready();

	for (;;) {
		struct pollfd pfd = { .fd = g_ifd, .events = POLLIN };
		char buf[8192] __attribute__((aligned(8)));
		int r, n, deny_changed = 0;

		r = poll(&pfd, 1, 60 * 1000);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			perror("sandboxd: poll");
			break;
		}
		if (r == 0)
			continue;
		n = read(g_ifd, buf, sizeof(buf));
		if (n < 0) {
			if (errno == EAGAIN)
				continue;
			perror("sandboxd: inotify read");
			continue;
		}
		/* Parse events: req-watch -> migrate a pid; anything else -> denylist reload. */
		for (char *p = buf; p + sizeof(struct inotify_event) <= buf + n; ) {
			struct inotify_event *ev = (struct inotify_event *)p;
			if (ev->wd == g_req_wd && ev->len > 0)
				migrate_pid(ev->name);
			else
				deny_changed = 1;
			p += sizeof(struct inotify_event) + ev->len;
		}
		if (deny_changed) {
			printf("sandboxd: denylist change, reloading\n");
			npaths = denylist_read(paths, MAX_DENY);
			if (npaths >= 0) {
				denylist_apply(skel, paths, npaths);
				install_secret_watches(paths, npaths);
			}
		}
	}

	bpf_link__destroy(link);
	agent_sandbox_bpf__destroy(skel);
	return 0;
}

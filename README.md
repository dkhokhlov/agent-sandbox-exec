# agent-sandbox-exec

BPF-LSM file-read denylist for interactive CLI agents (`claude`, `codex`,
`kimi`, `glm`). Prevents the agent — and **every process it spawns** — from
opening a small list of secret files, while leaving the rest of the environment
**completely real** so the agent can still troubleshoot kernel/system issues.

Denied opens return `EPERM` ("Operation not permitted"). `stat` still works;
only content reads are blocked. `EPERM` is the conventional errno for a
security-policy denial, and it is distinct from `EACCES`, which the kernel's
own mode-bit check returns before the hook fires — so an agent that `ls`-es a
listed file and then gets `EPERM` on `open` reads it as "a policy is blocking
me," not as a broken inode / filesystem quirk (which `ENOENT` on a visible
dirent would imply).

## How it works

| piece | role |
|---|---|
| `agent_sandbox.bpf.o` | BPF-LSM program on `lsm/file_open`. For tasks in a tracked per-uid sandbox cgroup, returns `-EPERM` if the opened inode is in `deny_map` for that cgroup; inert for everyone else. |
| `agent-sandbox-execd` (root, systemd) | Loads + attaches the BPF program, owns `deny_map` (keyed `{cgid, dev, ino}`) and `agent_cgid_set` (the tracked sandbox cgroups). Ensures the parent cgroup, creates a per-uid child on first request, re-reads the union of the base list and that uid's home list on **every** launch and diff-applies it to that uid's cgroup, and migrates launcher requests into it. No inotify/mtime-watching on the denylists: edits land on the next launch; restart only to refresh a running sandbox that has no new launch. |
| `agent-sandbox-exec` (user) | Launcher: asks `agent-sandbox-execd` to migrate its pid into its per-uid cgroup, then execs the real agent. Unprivileged. |

Scope is a **per-uid cgroup**: each sandboxed uid joins
`/sys/fs/cgroup/agent-sandbox-exec/uid-<uid>`, which children inherit, so
`cat secret | …`, hardlinks, and `cp secret …` are all blocked (the source
`open` is denied). **No namespace is created** — the agent sees the real mount
table, real `/dev` ownership, real supplementary groups, and real `/proc`.
Deny is by **inode** (`{cgid, device, inode}`), so it is robust against
hardlinks and bind-mounts. The `cgid` prefix scopes each uid's deny entries to
that uid's own sandbox, so a **user-controlled home denylist can only block
opens inside that user's own sandbox** — cross-user isolation.

A user can't write `cgroup.procs` directly (the per-uid cgroup is root-owned and
not delegated), so the launcher drops a request in `/run/agent-sandbox-exec/req`
(world-writable, sticky) and `agent-sandbox-execd` (root) performs the
migration after authenticating the requester via `/proc/<pid>/status` + the
request file's owner. No setuid binary; the daemon is the sole privilege
boundary.

## Build

Toolchain (one-time, sudo):
```
make deps          # apt install clang llvm libelf-dev libbpf-dev bpftool
```
Build + package (unprivileged):
```
make build         # cmake + clang -target bpf + bpftool skeleton + agent-sandbox-execd
make package       # -> build/agent-sandbox-exec_0.1.2_amd64.deb
make test          # Phase A (no root): object has deny_map + file_open
```

## Deploy

```
sudo apt install ./build/agent-sandbox-exec_0.1.2_amd64.deb
```
The postinst enables + starts `agent-sandbox-execd.service`. Verify:
```
systemctl is-active agent-sandbox-execd          # active
sudo scripts/test.sh                       # full integration: ALL PASS
```

## Manage the denylist

Two denylists are applied as a union per sandboxed uid:
- **Base list** `/etc/agent-sandbox-exec/denylist` (a conffile — survives
  upgrades) — root-controlled, applied to every uid. Use it for cluster-wide
  mandatory denies.
- **Home list** `~/.config/agent-sandbox-exec/denylist` — per-user, read from
  the uid's home (NFS-mounted is fine). Safe because per-cgid scoping confines
  it to that user's own sandbox.

```
# one absolute path to a regular FILE per line; no dirs, no globs
/home/owner/.ssh/id_rsa
/home/owner/.aws/credentials
```
A uid's list (base ∪ home) is **re-read from disk on every launch** and
diff-applied to that uid's cgroup, so edits take effect on the user's **next
launch** — no daemon restart needed, no effect on other uids. This is a
ping-driven reload (the launcher's existing migration request to the daemon
also triggers the re-read), not inotify/mtime-watching, so an NFS-mounted home
is fine (no filesystem events are assumed). A non-existent, non-regular, or
(home list) symlink path is skipped with a warning.

A daemon restart is still useful in one case: to refresh the deny set of a uid
that has a **running** sandbox but issues no new launch — `systemctl restart
agent-sandbox-execd` re-scans every `uid-*` cgroup and re-applies each list
(also restoring the membership gate after a restart):
```
sudo systemctl restart agent-sandbox-execd
```
Because each uid's list is re-read on every request, the apply is an
incremental diff (insert new entries, then remove stale ones), so the live map
never drops below the desired set.

## Wire up agents

Route each agent's leaf `exec` through the launcher. Example (`~/bin/claude`):
```diff
- exec /home/owner/.local/bin/claude "$@"
+ exec /usr/bin/agent-sandbox-exec /home/owner/.local/bin/claude "$@"
```
`kimi`/`glm` already `exec $HOME/bin/claude`, so they're covered transitively.
Do the same for `~/bin/codex`.

## Verify (end-to-end)

`sudo scripts/test.sh` checks: secret `open` → `EPERM`; `cat|pipe` and
hardlink blocked; supplementary groups, `/proc` pid 1, and `/dev/nvidia0`
ownership unchanged; ping-driven reload (add/remove take effect on the next
launch, no restart); restart still re-applies; optional cross-uid isolation
(set `ASE_UID2`); fail-closed. Manual spot-check (as your own uid, not root):
```
mkdir -p ~/.config/agent-sandbox-exec
echo /tmp/secret >> ~/.config/agent-sandbox-exec/denylist
agent-sandbox-exec sh -c 'cat /proc/self/cgroup'   # -> 0::/agent-sandbox-exec/uid-<uid>
agent-sandbox-exec cat /tmp/secret                 # -> cat: /tmp/secret: Operation not permitted
# edits apply on the next launch — no restart needed:
echo /tmp/other >> ~/.config/agent-sandbox-exec/denylist
agent-sandbox-exec cat /tmp/other                 # -> cat: /tmp/other: Operation not permitted
```

## Caveats

- **Files only, no directories/globs.** (Directories would need `bpf_d_path` +
  string matching — out of scope.)
- **Inode-based.** Each listed path is re-`stat`'d on every launch, so an
  atomic replace (new inode) is picked up on the user's next launch (no
  per-secret watcher, no restart needed).
- **Passed-fd exfil.** A process *outside* the cgroup opening a secret and
  passing the fd via a Unix socket bypasses any open-based scheme. Low threat.
- **`stat` works** on secrets (metadata visible); only content reads are blocked.
- **Fail-closed launcher (unconditional).** If `agent-sandbox-execd`/the
  cgroup/req-dir aren't ready, the launcher refuses to start the agent (exit 2).
  There is no escape-hatch env var; to run unsandboxed, invoke the command
  directly.
- **Reload = next launch.** Denylist edits (base or home) take effect on the
  user's next launch (the request re-reads the list and diff-applies it); a
  daemon restart is only needed to refresh a **running** sandbox that issues no
  new launch. The apply is an incremental diff, so the live set is never emptied.
- **Enforcement = daemon alive.** The BPF is attached while `agent-sandbox-execd`
  runs (`Restart=on-failure`). Pinned maps keep the deny data + cgroup membership
  across restarts; the daemon re-scans and re-applies on start.

## Uninstall

```
sudo apt purge agent-sandbox-exec      # stops service, removes cgroup + pinned maps
```
Then revert the two `exec` lines in the agent wrappers.

## Layout
```
src/agent_sandbox.bpf.c   BPF-LSM program (file_open hook + maps)
src/agent_sandbox.h       shared struct deny_key (BPF + daemon)
src/agent-sandbox-execd.c            root daemon
scripts/agent-sandbox-exec.sh   unprivileged launcher
scripts/agent-sandbox-execd.service   systemd unit
scripts/denylist.example        sample denylist
scripts/test.sh                 verification harness
packaging/{postinst,prerm,postrm,conffiles}
CMakeLists.txt  Makefile
```

# agent-sandbox-exec

BPF-LSM file-read denylist for interactive CLI agents (`claude`, `codex`,
`kimi`, `glm`). Prevents the agent — and **every process it spawns** — from
opening a small list of secret files, while leaving the rest of the environment
**completely real** so the agent can still troubleshoot kernel/system issues.

Denied opens return `ENOENT` (tools treat the file as absent). `stat` still
works; only content reads are blocked.

## How it works

| piece | role |
|---|---|
| `agent_sandbox.bpf.o` | BPF-LSM program on `lsm/file_open`. For tasks in a tracked per-uid sandbox cgroup, returns `-ENOENT` if the opened inode is in `deny_map` for that cgroup; inert for everyone else. |
| `agent-sandbox-execd` (root, systemd) | Loads + attaches the BPF program, owns `deny_map` (keyed `{cgid, dev, ino}`) and `agent_cgid_set` (the tracked sandbox cgroups). Ensures the parent cgroup, creates a per-uid child on first request, applies the union of the base list and that uid's home list to that uid's cgroup, and migrates launcher requests into it. No live reload: restart to refresh. |
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
make package       # -> build/agent-sandbox-exec_0.1.1_amd64.deb
make test          # Phase A (no root): object has deny_map + file_open
```

## Deploy

```
sudo apt install ./build/agent-sandbox-exec-0.1.0-Linux.deb
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
A uid's list is loaded **once** (on first launch, or at daemon restart for
already-active uids) and then frozen. There is no live reload — to apply any
denylist change, restart the daemon:
```
sudo systemctl restart agent-sandbox-execd
```
On restart the daemon re-scans existing per-uid cgroups and re-reads every
active uid's list from disk, restoring + refreshing protection in one step
(no inotify on the denylists; NFS home is fine because no events are assumed).
A non-existent, non-regular, or (home list) symlink path is skipped with a
warning.

## Wire up agents

Route each agent's leaf `exec` through the launcher. Example (`~/bin/claude`):
```diff
- exec /home/owner/.local/bin/claude "$@"
+ exec /usr/bin/agent-sandbox-exec /home/owner/.local/bin/claude "$@"
```
`kimi`/`glm` already `exec $HOME/bin/claude`, so they're covered transitively.
Do the same for `~/bin/codex`.

## Verify (end-to-end)

`sudo scripts/test.sh` checks: secret `open` → `ENOENT`; `cat|pipe` and
hardlink blocked; supplementary groups, `/proc` pid 1, and `/dev/nvidia0`
ownership unchanged; restart-to-refresh; optional cross-uid isolation (set
`ASE_UID2`); fail-closed. Manual spot-check (as your own uid, not root):
```
mkdir -p ~/.config/agent-sandbox-exec
echo /tmp/secret >> ~/.config/agent-sandbox-exec/denylist
agent-sandbox-exec sh -c 'cat /proc/self/cgroup'   # -> 0::/agent-sandbox-exec/uid-<uid>
agent-sandbox-exec cat /tmp/secret                 # -> No such file or directory
# edit the home list, then apply:
sudo systemctl restart agent-sandbox-execd
```

## Caveats

- **Files only, no directories/globs.** (Directories would need `bpf_d_path` +
  string matching — out of scope.)
- **Inode-based.** An atomic replace (new inode) is **not** re-resolved until
  the next daemon restart (no per-secret watcher). Static secrets are
  unaffected.
- **Passed-fd exfil.** A process *outside* the cgroup opening a secret and
  passing the fd via a Unix socket bypasses any open-based scheme. Low threat.
- **`stat` works** on secrets (metadata visible); only content reads are blocked.
- **Fail-closed launcher (unconditional).** If `agent-sandbox-execd`/the
  cgroup/req-dir aren't ready, the launcher refuses to start the agent (exit 2).
  There is no escape-hatch env var; to run unsandboxed, invoke the command
  directly.
- **Restart to refresh.** Denylist changes (base or home) take effect only
  after `systemctl restart agent-sandbox-execd`. A running sandbox keeps its
  frozen list until then.
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

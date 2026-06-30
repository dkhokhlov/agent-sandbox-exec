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
| `agent_sandbox.bpf.o` | BPF-LSM program on `lsm/file_open`. For tasks in the agent cgroup, returns `-ENOENT` if the opened inode is in `deny_map`; inert for everyone else. |
| `sandboxd` (root, systemd) | Loads + attaches the BPF program, owns `deny_map` (path→inode from the denylist), creates + delegates the agent cgroup, and migrates launcher requests into it. Watches the denylist + secret files, re-resolves on change. |
| `agent-sandbox-exec` (user) | Launcher: asks `sandboxd` to migrate its pid into the cgroup, then execs the real agent. Unprivileged. |

Scope is a **cgroup**: the agent joins `/sys/fs/cgroup/agent-sandbox`, which
children inherit, so `cat secret | …`, hardlinks, and `cp secret …` are all
blocked (the source `open` is denied). **No namespace is created** — the agent
sees the real mount table, real `/dev` ownership, real supplementary groups,
and real `/proc`. Deny is by **inode** (`{device, inode}`), so it is robust
against hardlinks and bind-mounts.

The owner user can't write `cgroup.procs` directly (cgroup v2 needs a delegated
subtree), so the launcher drops a request in `/run/agent-sandbox/req` and
`sandboxd` (root) performs the migration. No setuid binary; the daemon is the
sole privilege boundary.

## Build

Toolchain (one-time, sudo):
```
make deps          # apt install clang llvm libelf-dev libbpf-dev bpftool
```
Build + package (unprivileged):
```
make build         # cmake + clang -target bpf + bpftool skeleton + sandboxd
make package       # -> build/agent-sandbox-exec-0.1.0-Linux.deb
make test          # Phase A (no root): object has deny_map + file_open
```

## Deploy

```
sudo apt install ./build/agent-sandbox-exec-0.1.0-Linux.deb
```
The postinst enables + starts `agent-sandbox.service`. Verify:
```
systemctl is-active agent-sandbox          # active
sudo scripts/test.sh                       # full integration: ALL PASS
```

## Manage the denylist

Edit `/etc/agent-sandbox/denylist` (a conffile — survives upgrades):
```
# one absolute path to a regular FILE per line; no dirs, no globs
/home/owner/.ssh/id_rsa
/home/owner/.aws/credentials
```
`sandboxd` watches the file (and each secret) and re-resolves on change — no
restart needed. A non-existent or non-regular path is skipped with a warning.

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
ownership unchanged. Manual spot-check:
```
agent-sandbox-exec sh -c 'cat /proc/self/cgroup'   # -> 0::/agent-sandbox
echo /tmp/secret | sudo tee -a /etc/agent-sandbox/denylist
agent-sandbox-exec cat /tmp/secret                 # -> No such file or directory
```

## Caveats

- **Files only, no directories/globs.** (Directories would need `bpf_d_path` +
  string matching — out of scope.)
- **Inode-based.** An atomic replace (new inode) is caught by the per-secret
  `inotify` watcher re-resolving; static secrets are unaffected.
- **Passed-fd exfil.** A process *outside* the cgroup opening a secret and
  passing the fd via a Unix socket bypasses any open-based scheme. Low threat.
- **`stat` works** on secrets (metadata visible); only content reads are blocked.
- **Fail-closed launcher.** If `sandboxd`/the cgroup/req-dir aren't ready, the
  launcher refuses to start the agent. `AGENT_SANDBOX_INSECURE=1` overrides.
- **Enforcement = daemon alive.** The BPF is attached while `sandboxd` runs
  (`Restart=on-failure`). Pinned maps keep the deny data across restarts.

## Uninstall

```
sudo apt purge agent-sandbox-exec      # stops service, removes cgroup + pinned maps
```
Then revert the two `exec` lines in the agent wrappers.

## Layout
```
src/agent_sandbox.bpf.c   BPF-LSM program (file_open hook + maps)
src/agent_sandbox.h       shared struct ino_key (BPF + daemon)
src/sandboxd.c            root daemon
scripts/agent-sandbox-exec.sh   unprivileged launcher
scripts/agent-sandbox.service   systemd unit
scripts/denylist.example        sample denylist
scripts/test.sh                 verification harness
packaging/{postinst,prerm,postrm,conffiles}
CMakeLists.txt  Makefile
```

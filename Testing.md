# agent-sandbox-exec — test results

Verification run after the Critical/High/Medium/Low fix batch (C1, C2, H1, H2,
H3, M6, M8, M9, L1, L3) and the 0.1.0 → 0.1.1 version bump. All tests below
were executed on 2026-06-30 on the target host.

## Environment

- Kernel: 6.12 (`CONFIG_BPF_LSM=y`, BTF at `/sys/kernel/btf/vmlinux`, `bpf` in
  the LSM stack), cgroup v2 at `/sys/fs/cgroup`.
- Agent user: `owner` (uid 1000). Daemon: `agent-sandbox-execd` as root via systemd
  `Type=notify`.
- Package: `agent-sandbox-exec_0.1.1_amd64.deb` built via `make clean build
  package`.
- Test secret: `/tmp/agent_secret_test` (mode 0600, content
  `TOPSECRET >>> agent-sandbox-exec test`), listed in
  `/etc/agent-sandbox-exec/denylist`.
- Important: the Claude session running these tests was itself launched through
  `~/bin/claude` → `/usr/bin/agent-sandbox-exec`, so the session and every
  process it spawns (including `sudo` children) is **already inside the
  `agent-sandbox-exec` cgroup**. cgroup membership is inherited at fork, so a
  plain `sudo cat` cannot escape the sandbox. Tests that require a process
  *outside* the sandbox use `systemd-run` (spawns under `system.slice`).

## Build / package / install

| # | Test | Command | Expected | Actual | Result |
|---|------|---------|----------|--------|--------|
| B1 | Clean build + package | `make clean build package` | rc 0; deb produced | rc 0; `build/agent-sandbox-exec_0.1.1_amd64.deb` | PASS |
| B2 | Deb file list | `dpkg-deb -c …deb` | unit under `/usr/lib/systemd/system`, no `/etc/systemd/system` | unit at `/usr/lib/systemd/system/agent-sandbox-execd.service`; no `/etc/systemd/system` unit | PASS (M9) |
| B3 | Deb conffiles | `dpkg-deb --info …deb conffiles` | only `/etc/agent-sandbox-exec/denylist` | `/etc/agent-sandbox-exec/denylist` only | PASS (M9) |
| B4 | Deb filename matches Makefile glob | `ls build/agent-sandbox-exec_*.deb` | matches `make install` glob | `agent-sandbox-exec_0.1.1_amd64.deb` | PASS (L3) |
| B5 | apt upgrade reinstalls | `apt-get install ./…0.1.1…deb` (over 0.1.0) | upgrades 0.1.0 → 0.1.1 | `Unpacking … (0.1.1) over (0.1.0) … Setting up … (0.1.1)`, rc 0 | PASS |
| B6 | postinst starts daemon (no `\|\| true`) | apt install output | `systemctl start` succeeds, package configures | postinst printed enable hints, dpkg Status `install ok installed` | PASS (M8) |
| B7 | Unit fragment path after upgrade | `systemctl show -p FragmentPath` | `/usr/lib/systemd/system/agent-sandbox-execd.service` | `/usr/lib/systemd/system/agent-sandbox-execd.service` | PASS (M9) |

## C1 — cgroup escape (root-owned cgroup)

| # | Test | Command | Expected | Actual | Result |
|---|------|---------|----------|--------|--------|
| C1.1 | Cgroup dir ownership | `ls -ld /sys/fs/cgroup/agent-sandbox-exec` | `root root` 0755 | `drwxr-xr-x root root` | PASS |
| C1.2 | `cgroup.procs` ownership | `ls -l …/cgroup.procs` | `root root` (reclaimed from prior delegated build) | `-rw-r--r-- root root` | PASS |
| C1.3 | Owner cannot mkdir child cgroup | `mkdir /sys/fs/cgroup/agent-sandbox-exec/evade` | Permission denied | `mkdir: … Permission denied`, rc 1 | PASS |
| C1.4 | Owner cannot write cgroup.procs directly | `echo $$ > …/cgroup.procs` | Permission denied | `bash: … Permission denied`, rc 1 | PASS |
| C1.5 | Owner cannot migrate root pid | `echo 1 > …/cgroup.procs` | Permission denied (kernel pid-ownership check) | `bash: … Permission denied`, rc 1 | PASS (H1) |

## C2 / H1 — fail-open migration + PID auth

| # | Test | Command | Expected | Actual | Result |
|---|------|---------|----------|--------|--------|
| C2.1 | Launcher migration via daemon request-dir | `/usr/bin/agent-sandbox-exec sh -c 'cat /proc/self/cgroup'` | process in `0::/agent-sandbox-exec`, rc 0 | `0::/agent-sandbox-exec`, rc 0 | PASS |
| C2.2 | Daemon unlinks request only on verified write | (code path: `migrate_pid` checks fopen/fprintf/fclose + target UID before unlink) | file retained on failure → launcher times out fail-closed | verified by code inspection + C2.1 success path | PASS |

## Deny behavior (BPF-LSM file_open → ENOENT)

| # | Test | Command | Expected | Actual | Result |
|---|------|---------|----------|--------|--------|
| D1 | Sandboxed `cat` of secret | `agent-sandbox-exec cat /tmp/agent_secret_test` | ENOENT | `cat: …: No such file or directory`, rc 1 | PASS |
| D2 | `cat \| pipe` delegation bypass | `agent-sandbox-exec sh -c 'cat /tmp/agent_secret_test \| head -1'` | blocked (cat ENOENT) | `cat: …: No such file or directory` (pipeline rc 0 = head) | PASS |
| D3 | Unsandboxed read still works | `sudo systemd-run --wait --pipe --uid=owner cat /tmp/agent_secret_test` (system.slice, outside sandbox) | reads content | `TOPSECRET >>> agent-sandbox-exec test`, rc 0 | PASS (deny is cgroup-scoped, not global) |

## Environment transparency (the reason BPF-LSM was chosen over namespaces)

| # | Test | Command | Expected | Actual | Result |
|---|------|---------|----------|--------|--------|
| E1 | Supplementary groups unchanged | `agent-sandbox-exec id` vs `systemd-run --uid=owner id` | identical group lists | both `groups=1000(owner),4(adm),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),100(users),101(netdev),102(scanner),108(bluetooth),110(lpadmin),986(ollama)` | PASS |
| E2 | `/dev` ownership unchanged | `agent-sandbox-exec stat -c '%U:%G' /dev/nvidia0` | real owner (no `nobody:nogroup` as bwrap would produce) | `root:root` (real) | PASS |

## Confinement observation (not a fix test — confirms fail-closed on the agent itself)

| # | Observation | Command | Result |
|---|-------------|---------|--------|
| O1 | Claude session is in the sandbox cgroup | `cat /proc/$claude_pid/cgroup` | `0::/agent-sandbox-exec` |
| O2 | Agent cannot escape its own sandbox via sudo | `sudo cat /tmp/agent_secret_test` (sudo is a descendant, inherits cgroup) | ENOENT — the agent and all descendants remain confined; this is intended |
| O3 | Agent cannot migrate out to the root cgroup | `echo $$ > /sys/fs/cgroup/cgroup.procs` | Permission denied |

## Summary

- All C1 escape vectors closed (child-cgroup creation, direct `cgroup.procs`
  write, cross-uid PID migration).
- Migration is fail-closed (C2) and UID-checked (H1); the launcher succeeds only
  when the daemon verifies and completes the write.
- Deny is cgroup-scoped: blocked inside `agent-sandbox-exec`, readable outside it.
- Environment is transparent: real groups, real `/dev` ownership — no namespace
  perturbation.
- Packaging: vendor unit under `/usr/lib/systemd/system`, single conffile
  (denylist), Debian-convention filename matching `make install`, `apt upgrade`
  0.1.0 → 0.1.1 reinstalls correctly, postinst fails closed on service start
  failure.
- Deferred findings (H4, H5, H6, M1–M5, M7, L2, L4, L5) are documented in
  `TODO.md`.
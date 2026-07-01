# agent-sandbox-exec — test matrix (per-uid + restart-to-refresh model)

> **Status: NOT YET RUN on the new model.** The results below describe the
> matrix encoded in `scripts/test.sh`; fill in the Actual/Result columns after
> running `sudo scripts/test.sh` on a host with `CONFIG_BPF_LSM=y` (active
> `bpf` in `/sys/kernel/security/lsm`) and the build toolchain installed. The
> prior single-tenant PASS table is superseded by this per-uid matrix.

## Environment (to fill in)

- Kernel: `CONFIG_BPF_LSM=y`, `bpf` in `/sys/kernel/security/lsm`, cgroup v2 at
  `/sys/fs/cgroup`.
- Daemon: `agent-sandbox-execd` as root via systemd `Type=notify`.
- Test uid: `ASE_UID` (default `owner`, non-root — the daemon rejects root).
- Optional second uid: `ASE_UID2` for cross-uid isolation.
- Important: a session launched through the wrapper is already inside its
  per-uid cgroup; tests that need a process *outside* any sandbox use
  `systemd-run` (spawns under `system.slice`).

## Build artifacts (Phase A, no root)

| # | Test | Expected |
|---|------|----------|
| A1 | BPF object exists | `build/agent_sandbox.bpf.o` present |
| A2 | `deny_map` in object | `bpftool btf dump` greps `deny_map` |
| A3 | `agent_cgid_set` in object | `bpftool btf dump` greps `agent_cgid_set` |
| A4 | `file_open` prog in object | `bpftool btf dump` greps `agent_file_open` |

## Deny behavior (Phase B, root runs launcher as ASE_UID)

| # | Test | Expected |
|---|------|----------|
| D1 | first-launch-load: add secret to home denylist, launch new sandbox | `cat secret` → ENOENT (loaded on first request, no restart, no sleep) |
| D2 | `cat | pipe` delegation | blocked (empty output or error) |
| D3 | hardlink to secret | blocked (same inode) |
| D4 | env transparency: supplementary groups | inside == outside |
| D5 | env transparency: `/proc/1/comm` readable | real pid 1 visible |
| D6 | env transparency: `/dev/nvidia0` owner (if present) | uid 0 (real) |

## Restart-to-refresh (the systemd-style reload contract)

| # | Test | Expected |
|---|------|----------|
| R1 | add a new entry to a uid's home denylist while that uid is already loaded; launch | NOT denied (list frozen) |
| R2 | `systemctl restart agent-sandbox-execd`; launch | new entry → ENOENT (re-scan re-loaded it) |

## Cross-uid isolation (optional, requires `ASE_UID2`)

| # | Test | Expected |
|---|------|----------|
| X1 | uid A (own secret in A's home list) | A denied A's secret |
| X2 | uid A vs uid B's secret | A allowed B's secret |
| X3 | uid B (own secret in B's home list) | B denied B's secret |
| X4 | uid B vs uid A's secret | B allowed A's secret |

## Cgroup non-delegation (C1, per-uid child)

| # | Test | Expected |
|---|------|----------|
| C1.1 | `uid-<uid>` child is root-owned 0755 | `root root` |
| C1.2 | user cannot `mkdir` under `uid-<uid>` | Permission denied |
| C1.3 | user cannot write `uid-<uid>/cgroup.procs` | Permission denied |

## Fail-closed (unconditional — `AGENT_SANDBOX_INSECURE` removed)

| # | Test | Expected |
|---|------|----------|
| F1 | daemon stopped; launcher invoked | exit 2 (no bypass, command not executed) |

## Preflight (manual / separate run)

| # | Test | Expected |
|---|------|----------|
| P1 | BPF-LSM absent (simulate: `bpf` not in `/sys/kernel/security/lsm`) | daemon start exits 1 with the clear `CONFIG_BPF_LSM` message |

## Notes

- `MAX_DENY` per uid is 1024 with a loud truncation log; `deny_map` is 65536
  with `BPF_F_NO_PREALLOC` and a loud per-entry failure log on map-full.
- Incremental diff-apply (insert-then-remove-stale) closes the M1 transient
  allow window; reload only happens at restart, when enforcement is down
  anyway.
- pid-reuse mitigation: the request file's owner uid must equal the target
  pid's real uid (`/proc/<pid>/status`), or the request is rejected.
- Still-applicable caveats: M3 (request-dir failure not yet fatal), H4 (HASH
  gate default vs CGROUP_ARRAY follow-up), H6 (open-only / FD-handoff), L2/L4 —
  see `TODO.md`.
# agent-sandbox-exec — test matrix (per-uid + ping-driven reload model)

> **Status: RUN — ALL PASS.** Verified on `mini2` (kernel `6.12.88+deb13-amd64`,
> LSM list `…,bpf,…`, cgroup v2; `/home` is NFS `mini2:/mnt/home`). `sudo env
> ASE_UID=owner scripts/test.sh` → 16/16 PASS (single-uid); `sudo env
> ASE_UID=owner ASE_UID2=ase2 scripts/test.sh` → 20/20 PASS (with cross-uid
> isolation; `ase2` given a local home under `/tmp` because `/home` is NFS
> root-squashed and root cannot create `/home/ase2`). The one row not exercised
> here is **P1** (preflight on a BPF-LSM-absent kernel) — it requires a kernel
> without `bpf` in the LSM list and is left as a separate manual run; the
> preflight code path is reviewed in `src/agent-sandbox-execd.c`
> `preflight_bpf_lsm()`.

## Environment (verified run)

- Kernel: `6.12.88+deb13-amd64`, `CONFIG_BPF_LSM=y`, `bpf` active in
  `/sys/kernel/security/lsm`, cgroup v2 at `/sys/fs/cgroup`.
- Daemon: `agent-sandbox-execd` 0.1.1 as root via systemd `Type=notify`,
  `Restart=on-failure`; pinned maps at `/sys/fs/bpf/{deny_map,agent_cgid_set}`.
- Test uid: `ASE_UID=owner` (uid 1000, non-root — the daemon rejects root).
- Second uid (cross-uid run only): `ASE_UID2=ase2` (uid 1001, throwaway
  `useradd -m`; removed after the run).
- Important: a session launched through the wrapper is already inside its
  per-uid cgroup; tests that need a process *outside* any sandbox use
  `systemd-run` (spawns under `system.slice`).
- `scripts/test.sh` resets `uid-<ASE_UID>` to a clean "not yet loaded" state at
  Phase B entry (stop daemon → rmdir the per-uid cgroup → start), so D1's
  first-launch path is deterministic on re-runs (the per-uid cgroup otherwise
  persists across restarts, so D1 would exercise only the re-read path, not
  cgroup creation).

## Build artifacts (Phase A, no root)

| # | Test | Expected | Result |
|---|------|----------|--------|
| A1 | BPF object exists | `build/agent_sandbox.bpf.o` present | PASS |
| A2 | `deny_map` in object | `bpftool btf dump` greps `deny_map` | PASS |
| A3 | `agent_cgid_set` in object | `bpftool btf dump` greps `agent_cgid_set` | PASS |
| A4 | `file_open` prog in object | `bpftool btf dump` greps `agent_file_open` | PASS |

## Deny behavior (Phase B, root runs launcher as ASE_UID)

| # | Test | Expected | Result |
|---|------|----------|--------|
| D1 | first-launch-load: add secret to home denylist, launch new sandbox | `cat secret` → ENOENT (loaded on first request, no restart, no sleep) | PASS |
| D2 | `cat | pipe` delegation | blocked (empty output or error) | PASS |
| D3 | hardlink to secret | blocked (same inode) | PASS |
| D4 | env transparency: supplementary groups | inside == outside | PASS |
| D5 | env transparency: `/proc/1/comm` readable | real pid 1 visible | PASS |
| D6 | env transparency: `/dev/nvidia0` owner (if present) | uid 0 (real) | PASS (uid 0) |

## Reload (ping-driven + restart re-scan)

| # | Test | Expected | Result |
|---|------|----------|--------|
| R1 | uid already loaded; add entry to home list; launch (NO restart) | ENOENT — list re-read on every launch (#5 ping-driven reload) | PASS |
| R2 | remove that entry from home list; launch (NO restart) | allowed — diff-apply purged the stale key | PASS |
| R3 | re-add entry; `systemctl restart agent-sandbox-execd`; launch | ENOENT — re-scan re-applied it | PASS |

## Cross-uid isolation (optional, requires `ASE_UID2`)

| # | Test | Expected | Result |
|---|------|----------|--------|
| X1 | uid A (own secret in A's home list) | A denied A's secret | PASS (ASE_UID2=ase2) |
| X2 | uid A vs uid B's secret | A allowed B's secret | PASS (ASE_UID2=ase2) |
| X3 | uid B (own secret in B's home list) | B denied B's secret | PASS (ASE_UID2=ase2) |
| X4 | uid B vs uid A's secret | B allowed A's secret | PASS (ASE_UID2=ase2) |

## Cgroup non-delegation (C1, per-uid child)

| # | Test | Expected | Result |
|---|------|----------|--------|
| C1.1 | `uid-<uid>` child is root-owned 0755 | `root root` | PASS (`drwxr-xr-x root root`, verified during diagnostics) |
| C1.2 | user cannot `mkdir` under `uid-<uid>` | Permission denied | PASS |
| C1.3 | user cannot write `uid-<uid>/cgroup.procs` | Permission denied | PASS |

## Fail-closed (unconditional — `AGENT_SANDBOX_INSECURE` removed)

| # | Test | Expected | Result |
|---|------|----------|--------|
| F1 | daemon stopped; launcher invoked | exit 2 (no bypass, command not executed) | PASS (exit 2) |

## Preflight (manual / separate run)

| # | Test | Expected | Result |
|---|------|----------|--------|
| P1 | BPF-LSM absent (simulate: `bpf` not in `/sys/kernel/security/lsm`) | daemon start exits 1 with the clear `CONFIG_BPF_LSM` message | NOT RUN (requires a kernel without `bpf` in the LSM list; preflight code reviewed in `preflight_bpf_lsm()`) |

## Notes

- `MAX_DENY` per uid is 1024 with a loud truncation log; `deny_map` is 65536
  with `BPF_F_NO_PREALLOC` and a loud per-entry failure log on map-full.
- Incremental diff-apply (insert-then-remove-stale) closes the M1 transient
  allow window. Reload is ping-driven (every launch re-reads + diff-applies that
  uid's list), so the live set is never emptied during an edit; a daemon restart
  only re-applies for a running sandbox with no new launch (enforcement is down
  during restart anyway).
- pid-reuse mitigation: the request file's owner uid must equal the target
  pid's real uid (`/proc/<pid>/status`), or the request is rejected.
- Still-applicable caveats: M3 (request-dir failure not yet fatal), H4 (HASH
  gate default vs CGROUP_ARRAY follow-up), H6 (open-only / FD-handoff), L2/L4 —
  see `TODO.md`.
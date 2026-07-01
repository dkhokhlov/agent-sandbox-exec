# agent-sandbox-exec — deferred review findings

Findings from peer review (codex pass-2, kimi pass-1) that were NOT fixed in
the earlier fix batch, with rationale and intended action. The per-uid-cgroup +
ping-driven reload redesign (this branch) eliminated M1, M2, M4, M5, M7, and L5;
the remaining open items are below.

## Disputed (verified working here, not bugs on this host)

### H4 — `stat().st_ino` vs `bpf_get_current_cgroup_id()` mismatch / CGROUP_ARRAY
- **Location:** `src/agent-sandbox-execd.c` `setup_cgroup_parent`/`ensure_per_uid_cgroup`
  / `src/agent_sandbox.bpf.c` `agent_file_open`
- **Claim:** `st_ino` and the cgroup id are different kernel identifiers; the
  policy could miss entirely. Should use `BPF_MAP_TYPE_CGROUP_ARRAY` +
  `bpf_current_task_under_cgroup()`.
- **Status:** Verified equal on this 6.12 kernel
  (`st_ino == bpf_get_current_cgroup_id()`). The per-cgid membership gate
  (`agent_cgid_set` HASH) and deny lookup both use this id and were confirmed
  end-to-end. Not a bug *here*.
- **Action:** Keep the equality-match HASH gate for simplicity and kernel
  coverage (LSM-helper availability for `bpf_current_task_under_cgroup()` is not
  guaranteed across kernels). If ported where `st_ino != cgid`, switch to
  `bpf_current_task_under_cgroup()` (also resolves H5's subtree concern). Add a
  startup self-test that asserts `st_ino == cgid` and fails closed on mismatch.

### H5 — LSM hook ignores incoming `ret` (stacked-LSM composition)
- **Location:** `src/agent_sandbox.bpf.c` `agent_file_open`
- **Claim:** Returning `0` could clear an earlier LSM denial in a stacked
  BPF-LSM deployment; should start with `if (ret) return ret;`.
- **Status:** Disputed. BPF-LSM programs compose such that a deny by any hook
  is honored (fail-closed), so our `0` does not "un-deny" a prior denial.
  Adopting `if (ret) return ret;` would actually weaken us: it would make our
  policy a no-op whenever a prior hook returned nonzero, and would skip our
  deny on a prior *allow* path only if ret is nonzero (it isn't on allow).
- **Action:** Leave as-is. Revisit only if a real stacked-LSM regression
  appears. Consider `if (ret) return ret;` only if we ever want to defer to
  other LSMs unconditionally (a deliberate policy choice, not a fix).

## Accepted out-of-scope (documented caveats)

### H6 — open-only enforcement; inherited/scm_rights FDs bypass
- **Location:** `src/agent_sandbox.bpf.c` `agent_file_open`
- **Issue:** Already-open file descriptions remain readable: inherited `exec`
  FDs, SCM_RIGHTS-passed FDs, pidfd-based fd duplication, and any
  outside-the-cgroup opener handing off an fd all bypass the denylist.
- **Status:** Accepted. The threat model is a CLI coding agent exfiltrating via
  `cat | pipe`, hardlinks, `cp` — all open-based and all blocked. FD handoff
  requires a cooperative outside-the-cgroup process, a different threat.
  Broadening to `file_permission`/`mmap_file` would impose overhead on every
  read in the agent cgroup and risks breaking legitimate troubleshooting.
- **Action:** Documented in the man page / README (the denylist protects
  *opens*, not already-open fds). If required later, sanitize inherited fds in
  the launcher (close-on-exec everything except stdio) and/or add a
  `file_permission` hook scoped to the deny inodes.

## Medium — deferred hardening

### M3 — request-dir setup failure still advertises READY
- **Location:** `src/agent-sandbox-execd.c` `main` (`setup_request_dir` WARN leg)
- **Issue:** If `setup_request_dir()` fails, the daemon only logs a warning and
  still sends `READY=1`; the service looks healthy but no agent can be
  sandboxed.
- **Action:** Treat request-dir setup failure as fatal (do not notify ready,
  exit non-zero) so systemd restarts and the state is visible.

## Low — deferred

### L2 — hard-coded x86 / amd64, not portable
- **Location:** `CMakeLists.txt` (`-D__TARGET_ARCH_x86`), CPack (`amd64`)
- **Issue:** Build hard-codes x86 BPF target and amd64 package arch.
- **Action:** Derive `__TARGET_ARCH_*` from the toolchain/host and the deb arch
  from `CMAKE_SYSTEM_PROCESSOR` (mapping x86_64→amd64), or fail explicitly on
  unsupported architectures. Only matters if built for non-amd64.

### L4 — RESOLVED: `Documentation=` now points at the installed man pages
- **Location:** `scripts/agent-sandbox-execd.service`
- **Was:** Unit referenced `/usr/share/doc/agent-sandbox-exec/README.md`,
  which the package does not install (only the binary, launcher, unit, denylist
  example, and the two man pages ship) \(em a 404 in `systemctl status`.
- **Fix:** `Documentation=man:agent-sandbox-exec(1) man:agent-sandbox-exec-denylist(5)`,
  both installed. The alternative (install README.md to
  `/usr/share/doc/agent-sandbox-exec/`) was rejected as additive surface area
  duplicating the man pages.

## Eliminated by the per-uid + ping-driven reload redesign

- **M1** (transient allow-all on reload): `denylist_apply_cgid` now inserts new
  entries before removing stale ones, so the live map always covers the desired
  set; no clear-then-reinsert window. Reload is ping-driven (every launch
  re-reads + diff-applies that uid's list), so the live set is never emptied
  during an edit; a daemon restart only re-applies for a running sandbox with no
  new launch (enforcement is down during restart anyway).
- **M2** (symlink denylist entries): home-list entries are `lstat`-rejected if
  symlinks (user-controlled list, predictability). Base-list entries follow
  symlinks normally (root-controlled).
- **M4** (`inotify_add_watch` return ignored): the single request-dir watch
  return is checked; failure is fatal (daemon exits, no `READY=1`).
- **M5** (stale PID file / IN_CREATE-only wedges launches): daemon watches
  `IN_CREATE | IN_CLOSE_WRITE | IN_MOVED_TO` and cleans stale numeric request
  files on startup.
- **M7** (`MAX_DENY=256` silent truncation): per-uid parser cap is 1024 with a
  loud truncation log; BPF `deny_map` is 65536 with `BPF_F_NO_PREALLOC` and a
  loud per-entry failure log on map-full (no silent deny loss).
- **L5** (`AGENT_SANDBOX_INSECURE=1` env bypass): removed entirely; fail-closed
  is unconditional. To run unsandboxed, invoke the command directly.
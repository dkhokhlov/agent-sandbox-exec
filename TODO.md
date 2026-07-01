# agent-sandbox-exec — deferred review findings

Findings from peer review (codex pass-2, kimi pass-1) that were NOT fixed in
this pass, with rationale and intended action. The fixed set (C1, C2, H1, H2,
H3, M6, M8, M9, L1, L3) is committed separately.

## Disputed (verified working here, not bugs on this host)

### H4 — `stat().st_ino` vs `bpf_get_current_cgroup_id()` mismatch
- **Location:** `src/sandboxd.c` `setup_cgroup` / `src/agent_sandbox.bpf.c:58`
- **Claim:** `st_ino` and the cgroup id are different kernel identifiers; the
  policy could miss entirely. Should use the file-handle API or
  `BPF_MAP_TYPE_CGROUP_ARRAY` + `bpf_current_task_under_cgroup()`.
- **Status:** Verified equal on this 6.12 kernel
  (`st_ino == bpf_get_current_cgroup_id() == name_to_handle_at`). The deny
  behavior was confirmed end-to-end. Not a bug *here*.
- **Action:** Keep the equality-match approach for simplicity. If this is ever
  ported to a kernel where `st_ino != cgid`, switch to
  `bpf_current_task_under_cgroup()` (which also resolves H5's subtree concern).
  Add a startup self-test that asserts `st_ino == cgid` and fails closed on
  mismatch.

### H5 — LSM hook ignores incoming `ret` (stacked-LSM composition)
- **Location:** `src/agent_sandbox.bpf.c:52`
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
- **Location:** `src/agent_sandbox.bpf.c:46`
- **Issue:** Already-open file descriptions remain readable: inherited `exec`
  FDs, SCM_RIGHTS-passed FDs, pidfd-based fd duplication, and any
  outside-the-cgroup opener handing off an fd all bypass the denylist.
- **Status:** Accepted. The threat model is a CLI coding agent exfiltrating via
  `cat | pipe`, hardlinks, `cp` — all open-based and all blocked. FD handoff
  requires a cooperative outside-the-cgroup process, which is a different
  threat. Broadening to `file_permission`/`mmap_file` would impose overhead on
  every read in the agent cgroup and risks breaking legitimate troubleshooting.
- **Action:** Document explicitly in the man page / README (the denylist
  protects *opens*, not already-open fds). If required later, sanitize inherited
  fds in the launcher (close-on-exec everything except stdio) and/or add a
  `file_permission` hook scoped to the deny inodes.

## Medium — deferred hardening

### M1 — deny-map reload creates a transient allow-all window
- **Location:** `src/sandboxd.c` `denylist_apply` (`map_clear` then repopulate)
- **Issue:** Every reload clears the map before repopulating; during that
  window all denied files are temporarily readable.
- **Action:** Build a new map (or a shadow map) and atomically swap, or update
  incrementally (add new entries, delete removed ones) without clearing the
  live map first. Low real-world risk (reload is sub-ms and triggered by an
  admin edit), but worth doing for correctness.

### M2 — symlink denylist entries accepted and watched incorrectly
- **Location:** `src/sandboxd.c` `denylist_apply` (`stat` follows symlinks)
- **Issue:** `stat()` follows symlinks, so a symlinked secret is accepted and
  the *target* inode is denied/watched; retargeting the symlink desyncs the
  watch from the denied inode.
- **Action:** Reject symlinks with `lstat()` (the spec says "regular files
  only"), or resolve to a canonical `realpath` and watch that exact file
  intentionally. Decide which semantics the denylist should promise.

### M3 — request-dir setup failure still advertises READY
- **Location:** `src/sandboxd.c:329`
- **Issue:** If `setup_request_dir()` fails, the daemon only logs a warning and
  still sends `READY=1`; the service looks healthy but no agent can be
  sandboxed.
- **Action:** Treat request-dir setup failure as fatal (do not notify ready,
  exit non-zero) so systemd restarts and the state is visible.

### M4 — `inotify_add_watch()` return values ignored
- **Location:** `src/sandboxd.c:345`, `install_secret_watches`
- **Issue:** If the denylist-dir, request-dir, or secret-file watch fails to
  register, the daemon silently loses reloads or request handling.
- **Action:** Check every `inotify_add_watch` return, log the path-specific
  failure, and fail closed for the request-dir watch (without it, migration
  can't work).

### M5 — stale PID file + IN_CREATE-only watch wedges launches on PID wrap
- **Location:** `scripts/agent-sandbox-exec.sh:69`, `src/sandboxd.c:347`
- **Issue:** Launcher uses plain `>` on `REQDIR/$$` and the daemon watches only
  `IN_CREATE`. A stale file for a reused PID is truncated (no `IN_CREATE`),
  so the daemon never migrates and the launch always times out.
- **Action:** Create the request with `O_CREAT|O_EXCL` (launcher), clean stale
  numeric files in `REQ_DIR` on daemon startup, and/or watch
  `IN_CLOSE_WRITE`/`IN_MOVED_TO` as well as `IN_CREATE`.

### M7 — `MAX_DENY=256` cap below BPF map capacity
- **Location:** `src/sandboxd.c:55`
- **Issue:** Parser caps at 256 entries but the BPF map holds 1024; extra
  denylist lines are silently ignored, leaving listed secrets readable.
- **Action:** Size the parser buffer to the map capacity (1024) and fail loudly
  on overflow rather than silently truncating.

## Low — deferred

### L2 — hard-coded x86 / amd64, not portable
- **Location:** `CMakeLists.txt:50` (`-D__TARGET_ARCH_x86`), `:106` (`amd64`)
- **Issue:** Build hard-codes x86 BPF target and amd64 package arch.
- **Action:** Derive `__TARGET_ARCH_*` from the toolchain/host and the deb arch
  from `CMAKE_SYSTEM_PROCESSOR` (mapping x86_64→amd64), or fail explicitly on
  unsupported architectures. Only matters if this is built for non-amd64.

### L4 — `Documentation=` points to a non-installed README
- **Location:** `scripts/agent-sandbox.service:3`
- **Issue:** Unit references `/usr/share/doc/agent-sandbox-exec/README.md`,
  which the package does not install (only manpages ship).
- **Action:** Point `Documentation=` at the installed man pages
  (`man:agent-sandbox-exec(1)`, `man:agent-sandbox-denylist(5)`) or install the
  README to `/usr/share/doc/agent-sandbox-exec/`.

### L5 — `AGENT_SANDBOX_INSECURE=1` env bypass
- **Location:** `scripts/agent-sandbox-exec.sh:53`
- **Issue:** A normal inherited env var fully disables sandboxing, so
  "fail-closed" is not a property of the launcher when the caller controls env.
- **Status:** Documented and intentional (debugging / emergency escape hatch).
- **Action:** Keep, but consider requiring an explicit root/admin-controlled
  opt-in (e.g. a file under `/etc/agent-sandbox/` rather than an env var) so a
  compromised agent can't simply export its way out.
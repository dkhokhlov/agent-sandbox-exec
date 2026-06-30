# agent-sandbox-exec

BPF-LSM file-read denylist for interactive CLI agents (`claude` / `codex` /
`kimi` / `glm`). Confines the agent **and every process it spawns** (via cgroup
membership) so that a small list of secret **files** cannot be opened — defeating
delegation like `cat secret | …`, hardlinks, and `cp secret …` — **without
changing the environment**: the agent sees the real mount table, real `/dev`
ownership, real supplementary groups, and real `/proc`, so it can still
troubleshoot kernel/system issues accurately.

Denied opens return `ENOENT` (graceful: tools treat the file as absent). `stat`
still works; only content reads are blocked.

## Status
Scaffold. Full design, build, deploy, and verification steps are added in later
commits. See the project plan for the architecture (BPF-LSM `file_open` hook,
cgroup-scoped inode denylist, unprivileged launcher, root daemon).

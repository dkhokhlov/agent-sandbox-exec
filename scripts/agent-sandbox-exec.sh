#!/bin/sh
# agent-sandbox-exec — join the agent cgroup and exec the real agent (unprivileged).
#
# sandboxd (root) creates and delegates /sys/fs/cgroup/agent-sandbox to the agent
# user. We write our pid into it, then exec the target. Cgroup membership is
# inherited by every descendant, so the BPF-LSM denylist (loaded by sandboxd)
# applies to the whole process tree: cat | pipe, spawned shells, children, ...
#
# No namespace is created — the agent sees the real mount table, /dev ownership,
# supplementary groups, and /proc, so it can still troubleshoot the system.
#
# Fail-closed: if the cgroup is missing we REFUSE to start the agent rather than
# run unprotected. Override with AGENT_SANDBOX_INSECURE=1 (runs unsandboxed).

set -eu

CGROUP=/sys/fs/cgroup/agent-sandbox

if [ ! -d "$CGROUP" ] || [ ! -w "$CGROUP/cgroup.procs" ]; then
	if [ "${AGENT_SANDBOX_INSECURE:-0}" = "1" ]; then
		echo "agent-sandbox-exec: WARNING: $CGROUP not ready; running UNSANDBOXED" >&2
		exec "$@"
	fi
	echo "agent-sandbox-exec: $CGROUP is not present/writable (sandboxd running?). Refusing to start unprotected." >&2
	echo "agent-sandbox-exec: set AGENT_SANDBOX_INSECURE=1 to bypass (unsandboxed)." >&2
	exit 2
fi

# Join the cgroup (this process + all future children).
echo $$ > "$CGROUP/cgroup.procs"

exec "$@"

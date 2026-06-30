#!/bin/sh
# agent-sandbox-exec — get ourselves migrated into the agent cgroup, then exec.
#
# The owner can't write cgroup.procs directly (cgroup v2 needs a delegated
# subtree, which isn't configured here). So we drop a request (a file named
# after our pid) into /run/agent-sandbox/req; sandboxd (root) sees it via
# inotify, migrates us into /sys/fs/cgroup/agent-sandbox, and removes the file.
# We wait for the file to disappear, then exec the agent. Cgroup membership is
# inherited by every descendant, so the BPF-LSM denylist covers the whole tree.
#
# No namespace is created — the agent sees the real mount table, /dev ownership,
# supplementary groups, and /proc, so it can still troubleshoot the system.
#
# Fail-closed: if the sandbox isn't ready we REFUSE to start the agent rather
# than run unprotected. Override with AGENT_SANDBOX_INSECURE=1 (unsandboxed).

set -eu

CGROUP=/sys/fs/cgroup/agent-sandbox
REQDIR=/run/agent-sandbox/req

if [ ! -d "$CGROUP" ] || [ ! -d "$REQDIR" ]; then
	if [ "${AGENT_SANDBOX_INSECURE:-0}" = "1" ]; then
		echo "agent-sandbox-exec: WARNING: sandbox not ready; running UNSANDBOXED" >&2
		exec "$@"
	fi
	echo "agent-sandbox-exec: sandbox not ready ($CGROUP or $REQDIR missing; is sandboxd running?)." >&2
	echo "agent-sandbox-exec: refusing to start unprotected. Set AGENT_SANDBOX_INSECURE=1 to bypass." >&2
	exit 2
fi

# Request migration; sandboxd removes the file once we're in the cgroup.
req="$REQDIR/$$"
: > "$req"
i=0
while [ -e "$req" ] && [ "$i" -lt 200 ]; do
	i=$((i + 1))
	sleep 0.01
done
if [ -e "$req" ]; then
	rm -f "$req" 2>/dev/null || true
	echo "agent-sandbox-exec: migration timed out (sandboxd not responding?)." >&2
	exit 2
fi

exec "$@"

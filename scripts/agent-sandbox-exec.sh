#!/bin/sh
# agent-sandbox-exec — run a command inside the BPF-LSM agent sandbox.
#
# Migrates this process (and thus all its descendants) into the agent cgroup so
# the BPF-LSM denylist (/etc/agent-sandbox-exec/denylist) blocks opens of the listed
# secret files (returns ENOENT). No namespace is created — the command sees the
# real mount table, /dev ownership, supplementary groups, and /proc.
#
# Fail-closed: if agent-sandbox-execd isn't running, the command is NOT executed (exit 2),
# unless AGENT_SANDBOX_INSECURE=1.

set -eu

VERSION="0.1.1"
CGROUP=/sys/fs/cgroup/agent-sandbox-exec
REQDIR=/run/agent-sandbox-exec/req

usage() {
	cat <<EOF
Usage: agent-sandbox-exec [--help|--version] <command> [args...]

Run <command> sandboxed: it and every process it spawns is migrated into the
agent cgroup, so the BPF-LSM denylist (/etc/agent-sandbox-exec/denylist) blocks opens
of the listed secret files (returns ENOENT). cat | pipe, hardlinks, and cp of a
listed file are all blocked. No namespace is created -- the command sees the
real system environment and can troubleshoot normally.

Options:
  -h, --help        Show this help and exit.
  -V, --version     Show version and exit.

Environment:
  AGENT_SANDBOX_INSECURE=1   Run <command> UNSANDBOXED (no protection).

Exit codes:
   0   command ran (and exited 0)
   2   sandbox not ready / migration timed out / no command given
   *   otherwise the command's own exit code

See also: agent-sandbox-exec-denylist(5).
EOF
}

case "${1:-}" in
  -h|--help)    usage; exit 0 ;;
  -V|--version) echo "agent-sandbox-exec $VERSION"; exit 0 ;;
  "")           usage >&2; exit 2 ;;
esac

# Insecure bypass takes precedence: run unsandboxed immediately.
if [ "${AGENT_SANDBOX_INSECURE:-0}" = "1" ]; then
	echo "agent-sandbox-exec: WARNING: AGENT_SANDBOX_INSECURE=1 -- running unsandboxed" >&2
	exec "$@"
fi

if [ ! -d "$CGROUP" ] || [ ! -d "$REQDIR" ]; then
	echo "agent-sandbox-exec: sandbox not ready ($CGROUP or $REQDIR missing; is agent-sandbox-execd running?)." >&2
	echo "agent-sandbox-exec: refusing to start unprotected. Set AGENT_SANDBOX_INSECURE=1 to bypass." >&2
	exit 2
fi

# Ask agent-sandbox-execd (root) to migrate us into the cgroup; it removes the request file
# only after a verified successful migration.
req="$REQDIR/$$"
: > "$req"
i=0
while [ -e "$req" ] && [ "$i" -lt 150 ]; do
	i=$((i + 1))
	sleep 0.01
done
if [ -e "$req" ]; then
	rm -f "$req" 2>/dev/null || true
	echo "agent-sandbox-exec: migration timed out (agent-sandbox-execd not responding?)." >&2
	echo "agent-sandbox-exec: refusing to start unprotected. Set AGENT_SANDBOX_INSECURE=1 to bypass." >&2
	exit 2
fi

exec "$@"

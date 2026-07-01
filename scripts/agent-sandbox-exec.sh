#!/bin/sh
# agent-sandbox-exec — run a command inside the BPF-LSM agent sandbox.
#
# Migrates this process (and thus all its descendants) into a per-uid agent
# cgroup so the BPF-LSM denylist blocks opens of the listed secret files (returns
# ENOENT). The denylist is the union of the root-controlled base list
# (/etc/agent-sandbox-exec/denylist) and your home list
# (~/.config/agent-sandbox-exec/denylist); it is loaded once on first launch
# and frozen until the daemon is restarted. No namespace is created — the
# command sees the real mount table, /dev ownership, supplementary groups, /proc.
#
# Fail-closed is unconditional: if the sandbox isn't ready, the command is NOT
# executed (exit 2). To run a command without the sandbox, run it directly
# (not through this wrapper) — that keeps the unsandboxed choice explicit.

set -eu

VERSION="0.1.1"
CGROUP=/sys/fs/cgroup/agent-sandbox-exec
REQDIR=/run/agent-sandbox-exec/req

usage() {
	cat <<EOF
Usage: agent-sandbox-exec [--help|--version] <command> [args...]

Run <command> sandboxed: it and every process it spawns is migrated into a
per-uid agent cgroup, so the BPF-LSM denylist blocks opens of the listed secret
files (returns ENOENT). cat | pipe, hardlinks, and cp of a listed file are all
blocked. The denylist is the union of the root-controlled base list
(/etc/agent-sandbox-exec/denylist) and your home list
(~/.config/agent-sandbox-exec/denylist). No namespace is created -- the command
sees the real system environment and can troubleshoot normally.

A uid's denylist is loaded on first launch and then frozen; to apply denylist
changes, restart agent-sandbox-execd.

Options:
  -h, --help        Show this help and exit.
  -V, --version     Show version and exit.

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

if [ ! -d "$CGROUP" ] || [ ! -d "$REQDIR" ]; then
	echo "agent-sandbox-exec: sandbox not ready ($CGROUP or $REQDIR missing;" >&2
	echo "agent-sandbox-exec: is agent-sandbox-execd running?)." >&2
	echo "agent-sandbox-exec: refusing to start unprotected." >&2
	exit 2
fi

# Ask agent-sandbox-execd (root) to migrate us into our per-uid cgroup; it
# removes the request file only after a verified successful migration.
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
	echo "agent-sandbox-exec: refusing to start unprotected." >&2
	exit 2
fi

exec "$@"
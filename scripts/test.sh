#!/bin/sh
# scripts/test.sh — agent-sandbox-exec verification.
#
# Phase A (no root): the built BPF object has the expected program + maps.
# Phase B (root + sandboxd running + launcher installed): deny semantics
#   (ENOENT incl. cat|pipe and hardlink) and env transparency (groups, /proc,
#   /dev ownership preserved).
#
# Run unprivileged for Phase A (`make test`); run `sudo scripts/test.sh` after
# `make install` for the full integration check.

set -u

P=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OBJ=$P/build/agent_sandbox.bpf.o
LAUNCHER=${LAUNCHER:-/usr/local/bin/agent-sandbox-exec}
CGROUP=/sys/fs/cgroup/agent-sandbox
DENYLIST=/etc/agent-sandbox/denylist
FAIL=0

if command -v bpftool >/dev/null 2>&1; then BPFTOOL=bpftool
elif [ -x /usr/sbin/bpftool ]; then BPFTOOL=/usr/sbin/bpftool
else BPFTOOL=; fi

pass(){ printf "  PASS  %s\n" "$1"; }
fail(){ printf "  FAIL  %s\n" "$1"; FAIL=1; }

echo "== Phase A: build artifacts =="
[ -f "$OBJ" ] && pass "BPF object exists ($OBJ)" || fail "BPF object missing"
if [ -n "$BPFTOOL" ]; then
	"$BPFTOOL" btf dump file "$OBJ" 2>/dev/null | grep -q deny_map && pass "deny_map in object" || fail "deny_map not found"
	"$BPFTOOL" btf dump file "$OBJ" 2>/dev/null | grep -q agent_file_open && pass "file_open prog in object" || fail "file_open prog not found"
else
	echo "  (skip: bpftool not found)"
fi

echo "== Phase B: integration (root + sandboxd + installed launcher) =="
if [ "$(id -u)" != "0" ]; then
	echo "  SKIP  not root (re-run: sudo $0)"
	echo "== Phase A exit: $FAIL =="
	exit "$FAIL"
fi
[ -x "$LAUNCHER" ] || { echo "  SKIP  $LAUNCHER not installed (run make install)"; exit "$FAIL"; }
[ -d "$CGROUP" ]   || { echo "  SKIP  $CGROUP missing (sandboxd running?)"; exit "$FAIL"; }

SECRET=$(mktemp)
echo "TOPSECRET-$(head -c16 /dev/urandom | base64)" > "$SECRET"
chmod 600 "$SECRET"
cleanup() {
	if [ -f "$DENYLIST" ]; then sed -i "\|^$SECRET\$|d" "$DENYLIST" 2>/dev/null || true; fi
	rm -f "$SECRET" /tmp/asb_out /tmp/asb_err /tmp/asb_hard 2>/dev/null || true
}
trap cleanup EXIT

grep -q "^$SECRET\$" "$DENYLIST" 2>/dev/null || printf '%s\n' "$SECRET" >> "$DENYLIST"
sleep 1  # let sandboxd's inotify watcher reload

# direct read -> ENOENT
if "$LAUNCHER" cat "$SECRET" >/tmp/asb_out 2>/tmp/asb_err; then
	fail "cat secret succeeded (should be denied)"
else
	grep -qi "no such file" /tmp/asb_err && pass "cat secret -> ENOENT" || fail "cat secret denied, wrong error: $(cat /tmp/asb_err)"
fi

# delegation via child + pipe -> still blocked
if "$LAUNCHER" sh -c "cat '$SECRET' | head -c5" >/tmp/asb_out 2>/tmp/asb_err; then
	[ -s /tmp/asb_out ] && fail "pipe leaked secret content" || pass "cat|pipe blocked (empty)"
else
	pass "cat|pipe blocked (error)"
fi

# hardlink shares the inode -> blocked by inode denylist
ln "$SECRET" /tmp/asb_hard 2>/dev/null || true
if "$LAUNCHER" cat /tmp/asb_hard >/dev/null 2>/tmp/asb_err; then
	fail "hardlink read succeeded (inode deny should block)"
else
	pass "hardlink -> blocked (same inode)"
fi

# environment transparency: real groups, real /proc, real /dev ownership
NG=$("$LAUNCHER" id -G 2>/dev/null | wc -w)
[ "$NG" -gt 2 ] && pass "supplementary groups preserved ($NG)" || fail "groups dropped ($NG)"
"$LAUNCHER" sh -c 'test -r /proc/1/comm' && pass "/proc shows real pid 1" || fail "/proc restricted"
if [ -e /dev/nvidia0 ]; then
	OW=$("$LAUNCHER" sh -c 'stat -c %u /dev/nvidia0 2>/dev/null')
	[ "$OW" = "0" ] && pass "/dev/nvidia0 real owner (uid 0)" || fail "/dev/nvidia0 owner wrong ($OW)"
fi

echo "== result =="
if [ "$FAIL" = "0" ]; then echo "ALL PASS"; else echo "FAILURES present"; fi
exit "$FAIL"

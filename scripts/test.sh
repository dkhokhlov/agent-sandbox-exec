#!/bin/sh
# scripts/test.sh — agent-sandbox-exec verification.
#
# Phase A (no root): the built BPF object has the expected program + maps.
# Phase B (root + agent-sandbox-execd running + launcher installed): per-uid
#   deny semantics, env transparency, ping-driven reload (add/remove/restart),
#   isolation, cgroup non-delegation, and fail-closed.
#
# Run unprivileged for Phase A (`make test`); run `sudo scripts/test.sh` after
# `make install` for the full integration check.
#
# Env knobs:
#   ASE_UID   non-root uid to sandbox (default: owner). The daemon rejects
#             root, so the launcher is invoked as this uid via runuser/sudo.
#   ASE_UID2  optional second uid for cross-uid isolation (default: none).

set -u

P=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OBJ=$P/build/agent_sandbox.bpf.o
LAUNCHER=${LAUNCHER:-/usr/bin/agent-sandbox-exec}
CGROUP=/sys/fs/cgroup/agent-sandbox-exec
BASE_DENYLIST=/etc/agent-sandbox-exec/denylist
FAIL=0

ASE_UID=${ASE_UID:-owner}
ASE_UID2=${ASE_UID2:-}
HOME_DENY2=		# bound early so cleanup's strip_temps doesn't trip set -u when ASE_UID2 is unset

if command -v bpftool >/dev/null 2>&1; then BPFTOOL=bpftool
elif [ -x /usr/sbin/bpftool ]; then BPFTOOL=/usr/sbin/bpftool
else BPFTOOL=; fi

pass(){ printf "  PASS  %s\n" "$1"; }
fail(){ printf "  FAIL  %s\n" "$1"; FAIL=1; }

# Run a command as ASE_UID (non-root). The daemon resolves that uid's home
# denylist via getpwuid, so HOME env quirks do not matter.
as_uid() {
	if command -v runuser >/dev/null 2>&1; then
		runuser -u "$ASE_UID" -- "$@"
	else
		sudo -u "$ASE_UID" -- "$@"
	fi
}
as_uid2() {
	if command -v runuser >/dev/null 2>&1; then
		runuser -u "$ASE_UID2" -- "$@"
	else
		sudo -u "$ASE_UID2" -- "$@"
	fi
}
home_of() { getent passwd "$1" | cut -d: -f6; }
# Remove every line referencing one of our temp secrets from a denylist file.
strip_temps() { [ -f "$1" ] && sed -i '\|^/tmp/asb_|d' "$1" 2>/dev/null || true; }

echo "== Phase A: build artifacts =="
[ -f "$OBJ" ] && pass "BPF object exists ($OBJ)" || fail "BPF object missing"
if [ -n "$BPFTOOL" ]; then
	"$BPFTOOL" btf dump file "$OBJ" 2>/dev/null | grep -q deny_map && pass "deny_map in object" || fail "deny_map not found"
	"$BPFTOOL" btf dump file "$OBJ" 2>/dev/null | grep -q agent_cgid_set && pass "agent_cgid_set in object" || fail "agent_cgid_set not found"
	"$BPFTOOL" btf dump file "$OBJ" 2>/dev/null | grep -q agent_file_open && pass "file_open prog in object" || fail "file_open prog not found"
else
	echo "  (skip: bpftool not found)"
fi

echo "== Phase B: integration (root + agent-sandbox-execd + installed launcher) =="
if [ "$(id -u)" != "0" ]; then
	echo "  SKIP  not root (re-run: sudo $0)"
	echo "== Phase A exit: $FAIL =="
	exit "$FAIL"
fi
[ -x "$LAUNCHER" ] || { echo "  SKIP  $LAUNCHER not installed (run make install)"; exit "$FAIL"; }
[ -d "$CGROUP" ]   || { echo "  SKIP  $CGROUP missing (agent-sandbox-execd running?)"; exit "$FAIL"; }

TEST_HOME=$(home_of "$ASE_UID")
[ -n "$TEST_HOME" ] || { echo "  SKIP  no home for uid '$ASE_UID'"; exit "$FAIL"; }
HOME_DENY="$TEST_HOME/.config/agent-sandbox-exec/denylist"

# Reset ASE_UID (and ASE_UID2 if set) to a clean "not yet loaded" state so D1
# exercises the true first-launch path (cgroup created on the first request).
# The per-uid cgroup persists across daemon restarts (the daemon re-scans uid-*
# dirs at start), so without this reset a re-run finds ASE_UID already loaded
# and D1 would test only the re-read path, not cgroup creation. The cgroup is
# empty between runs (every sandboxed proc has exited), so rmdir succeeds; if it
# doesn't (stray proc), D1 may fail and surface that. Stale cgids left in
# agent_cgid_set are inert orphans (no proc in the deleted cgroup) and the new
# cgroup gets a fresh cgid.
ASE_UID_NUM=$(id -u "$ASE_UID")
systemctl stop agent-sandbox-execd 2>/dev/null || true
rmdir "$CGROUP/uid-$ASE_UID_NUM" 2>/dev/null || true
[ -n "$ASE_UID2" ] && rmdir "$CGROUP/uid-$(id -u "$ASE_UID2")" 2>/dev/null || true
systemctl reset-failed agent-sandbox-execd 2>/dev/null || true	# clear systemd start-rate-limit (rapid stop/start cycles)
systemctl start agent-sandbox-execd
sleep 0.4

SECRET=$(mktemp /tmp/asb_XXXXXX)
echo "TOPSECRET-$(head -c16 /dev/urandom | base64)" > "$SECRET"
# world-readable so the launching uid's POSIX inode_permission succeeds and the
# BPF-LSM deny (ENOENT) is the sole discriminator; inode_permission runs before
# security_file_open, so a 600 root-owned secret would EACCES before the hook.
chmod 644 "$SECRET"
mkdir -p "$(dirname "$HOME_DENY")"
cleanup() {
	strip_temps "$HOME_DENY"
	strip_temps "$BASE_DENYLIST"
	strip_temps "$HOME_DENY2" 2>/dev/null || true
	rm -f /tmp/asb_* 2>/dev/null || true
	systemctl reset-failed agent-sandbox-execd 2>/dev/null || true
	systemctl start agent-sandbox-execd 2>/dev/null || true
}
trap cleanup EXIT

# first-launch: adding to the home denylist + launching a NEW sandbox denies
# it on first request. No restart, no sleep — the list is read at the request
# (and re-read on every later request: the #5 ping-driven reload).
grep -q "^$SECRET\$" "$HOME_DENY" 2>/dev/null || printf '%s\n' "$SECRET" >> "$HOME_DENY"

# direct read -> ENOENT
if as_uid "$LAUNCHER" cat "$SECRET" >/tmp/asb_out 2>/tmp/asb_err; then
	fail "cat secret succeeded (should be denied)"
else
	grep -qi "no such file" /tmp/asb_err && pass "cat secret -> ENOENT" || fail "cat secret denied, wrong error: $(cat /tmp/asb_err)"
fi

# delegation via child + pipe -> still blocked
if as_uid "$LAUNCHER" sh -c "cat '$SECRET' | head -c5" >/tmp/asb_out 2>/tmp/asb_err; then
	[ -s /tmp/asb_out ] && fail "pipe leaked secret content" || pass "cat|pipe blocked (empty)"
else
	pass "cat|pipe blocked (error)"
fi

# hardlink shares the inode -> blocked by inode denylist
ln "$SECRET" /tmp/asb_hard 2>/dev/null || true
if as_uid "$LAUNCHER" cat /tmp/asb_hard >/dev/null 2>/tmp/asb_err; then
	fail "hardlink read succeeded (inode deny should block)"
else
	pass "hardlink -> blocked (same inode)"
fi

# environment transparency: real groups (inside == outside), real /proc, real /dev owner
OUT=$(id -G "$ASE_UID")
IN=$(as_uid "$LAUNCHER" id -G 2>/dev/null)
[ "$OUT" = "$IN" ] && pass "supplementary groups preserved (transparent)" || fail "groups differ: out=[$OUT] in=[$IN]"
as_uid "$LAUNCHER" sh -c 'test -r /proc/1/comm' && pass "/proc shows real pid 1" || fail "/proc restricted"
if [ -e /dev/nvidia0 ]; then
	OW=$(as_uid "$LAUNCHER" sh -c 'stat -c %u /dev/nvidia0 2>/dev/null')
	[ "$OW" = "0" ] && pass "/dev/nvidia0 real owner (uid 0)" || fail "/dev/nvidia0 owner wrong ($OW)"
fi

# ping-driven reload (#5): a uid's list (base ∪ home) is re-read on EVERY
# launch and diff-applied to its cgid, so edits take effect on the next launch
# with NO daemon restart. ASE_UID is already loaded from D1 above.
SECRET2=$(mktemp /tmp/asb_XXXXXX)
echo "RELOAD-$(head -c16 /dev/urandom | base64)" > "$SECRET2"
chmod 644 "$SECRET2"	# world-readable: BPF ENOENT must be the discriminator, not EACCES
# R1: add entry while already loaded -> next launch denies it (no restart).
printf '%s\n' "$SECRET2" >> "$HOME_DENY"
if as_uid "$LAUNCHER" cat "$SECRET2" >/tmp/asb_out2 2>/tmp/asb_err2; then
	fail "ping-reload: new home entry allowed (should be denied on next launch, no restart)"
else
	grep -qi "no such file" /tmp/asb_err2 && pass "ping-reload: new home entry -> ENOENT (no restart needed)" || fail "ping-reload wrong error: $(cat /tmp/asb_err2)"
fi
# R2: remove the entry -> next launch allows it (diff-apply purged the stale key).
sed -i "\|^$SECRET2\$|d" "$HOME_DENY"
if as_uid "$LAUNCHER" cat "$SECRET2" >/tmp/asb_out2 2>/tmp/asb_err2; then
	pass "ping-reload: removed entry -> allowed (stale key purged, no restart)"
else
	fail "ping-reload: removed entry still denied (stale key not purged)"
fi
# R3: restart still refreshes (re-scan re-applies). Re-add, restart, deny.
printf '%s\n' "$SECRET2" >> "$HOME_DENY"
systemctl reset-failed agent-sandbox-execd 2>/dev/null || true
systemctl restart agent-sandbox-execd
sleep 0.5
if as_uid "$LAUNCHER" cat "$SECRET2" >/tmp/asb_out2 2>/tmp/asb_err2; then
	fail "post-restart: entry still allowed (re-scan should have re-applied)"
else
	grep -qi "no such file" /tmp/asb_err2 && pass "post-restart: entry -> ENOENT (re-scan re-applied)" || fail "post-restart wrong error: $(cat /tmp/asb_err2)"
fi

# cross-uid isolation (optional): a second uid's home list must not affect the
# first uid's sandbox, and vice versa.
if [ -n "$ASE_UID2" ]; then
	HOME2=$(home_of "$ASE_UID2")
	if [ -z "$HOME2" ]; then
		echo "  SKIP  no home for ASE_UID2='$ASE_UID2'"
	else
		HOME_DENY2="$HOME2/.config/agent-sandbox-exec/denylist"
		SECRET_B=$(mktemp /tmp/asb_XXXXXX)
		echo "BONLY-$(head -c16 /dev/urandom | base64)" > "$SECRET_B"
		chmod 644 "$SECRET_B"	# world-readable so both uids can read via POSIX; BPF isolates
		mkdir -p "$(dirname "$HOME_DENY2")"
		printf '%s\n' "$SECRET_B" >> "$HOME_DENY2"
		# A denied A's secret, allowed B's
		if as_uid "$LAUNCHER" cat "$SECRET" >/dev/null 2>/tmp/asb_e; then fail "A read A's secret (should deny)"; else pass "A denied A's secret"; fi
		if as_uid "$LAUNCHER" cat "$SECRET_B" >/dev/null 2>/tmp/asb_e; then pass "A allowed B's secret (isolation)"; else fail "A denied B's secret (isolation broken)"; fi
		# B denied B's secret, allowed A's
		if as_uid2 "$LAUNCHER" cat "$SECRET_B" >/dev/null 2>/tmp/asb_e; then fail "B read B's secret (should deny)"; else pass "B denied B's secret"; fi
		if as_uid2 "$LAUNCHER" cat "$SECRET" >/dev/null 2>/tmp/asb_e; then pass "B allowed A's secret (isolation)"; else fail "B denied A's secret (isolation broken)"; fi
	fi
else
	echo "  (skip cross-uid isolation: set ASE_UID2 to enable)"
fi

# C1: per-uid child cgroup is root-owned / non-delegated; the user can neither
# mkdir under it nor write cgroup.procs directly.
CHILD="$CGROUP/uid-$(id -u "$ASE_UID")"
if [ -d "$CHILD" ]; then
	if as_uid sh -c "mkdir '$CHILD/evade'" 2>/dev/null; then
		fail "user mkdir under uid- child (should deny)"; rmdir "$CHILD/evade" 2>/dev/null || true
	else
		pass "user cannot mkdir under uid- child"
	fi
	if as_uid sh -c "echo \$\$ > '$CHILD/cgroup.procs'" 2>/dev/null; then
		fail "user wrote uid- child cgroup.procs (should deny)"
	else
		pass "user cannot write uid- child cgroup.procs"
	fi
else
	echo "  (skip C1: uid- child not present yet)"
fi

# fail-closed: with the daemon stopped, the launcher refuses (exit 2). There is
# no bypass — AGENT_SANDBOX_INSECURE is gone.
systemctl stop agent-sandbox-execd
as_uid "$LAUNCHER" true >/tmp/asb_out 2>/tmp/asb_err
rc=$?
[ "$rc" = "2" ] && pass "launcher fail-closed (exit $rc) with daemon down" || fail "launcher exit $rc with daemon down (want 2)"
# cleanup restarts the daemon.

echo "== result =="
if [ "$FAIL" = "0" ]; then echo "ALL PASS"; else echo "FAILURES present"; fi
exit "$FAIL"
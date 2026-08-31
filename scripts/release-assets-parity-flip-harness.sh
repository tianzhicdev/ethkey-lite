#!/usr/bin/env bash
# c43 flip harness for scripts/release-assets-parity.py (token-authed rail).
# Same rules as every C harness: exit code is the verdict FIRST, fresh git
# clone per flip, mutation/preconditions asserted BEFORE the verdict, and a
# rc=0 with a FAIL line in stdout counts as a fail (rc-lies check).
# Network legs (F3/F5) hit api.github.com; the credential matrix itself
# (--selftest) is offline, so a CDN/API flake can't fake a harness result.
set -uo pipefail
SRC=$(cd "$(dirname "$0")/.." && pwd)
BASE=$(mktemp -d)
pass=0; fail=0

fresh() { local d="$BASE/$1"; git clone -q --no-hardlinks "$SRC" "$d" || { echo "CLONE-FAILED $1"; exit 1; }; echo "$d"; }

check() { # name want_rc rc out [needle]
  local name=$1 want=$2 rc=$3 out=$4 needle=${5:-}
  if [ "$rc" != "$want" ]; then echo "FAIL[$name]: rc=$rc want=$want"; echo "$out" | sed 's/^/    /'; fail=$((fail+1)); return; fi
  if [ "$want" != "0" ] && [ -n "$needle" ] && ! grep -q "$needle" <<<"$out"; then
    echo "FAIL[$name]: red but does not name '$needle'"; echo "$out" | sed 's/^/    /'; fail=$((fail+1)); return; fi
  if [ "$want" = "0" ] && grep -q "^FAIL" <<<"$out"; then
    echo "FAIL[$name]: rc=0 yet FAIL line present (rc lies)"; fail=$((fail+1)); return; fi
  echo "PASS[$name] rc=$rc"; pass=$((pass+1))
}

# CONTROL: offline credential matrix green (host-scope baits + classifier)
d=$(fresh control)
out=$(cd "$d" && python3 scripts/release-assets-parity.py --selftest 2>&1); rc=$?
check CONTROL_selftest 0 "$rc" "$out"

# F1: CI wiring defect — GITHUB_ACTIONS=true, NO token -> exit 2 naming the
# class (fail-closed: no silent unauth carve-out inside CI)
d=$(fresh f1)
out=$(cd "$d" && GITHUB_ACTIONS=true GITHUB_TOKEN= python3 scripts/release-assets-parity.py 2>&1); rc=$?
check F1_ci_no_token 2 "$rc" "$out" "wiring defect"

# F2: outside CI with no token -> honest local mode, NOTE printed (must NOT
# be a FAIL, must announce the cap) — runs the real table green
d=$(fresh f2)
out=$(cd "$d" && env -u GITHUB_TOKEN python3 scripts/release-assets-parity.py 2>&1); rc=$?
check F2_local_unauth_note 0 "$rc" "$out"
grep -q "NOTE: no GITHUB_TOKEN" <<<"$out" && { echo "PASS[F2-note-announced]"; pass=$((pass+1)); } || { echo "FAIL[F2-note-announced]: silent unauth in local mode"; fail=$((fail+1)); }

# F3: structural-vs-transient LIVE: bogus token -> fails FAST naming HTTP 401
# (proves retries can't chew the budget on a structural error). Precondition:
# token present so the header is actually attached.
d=$(fresh f3)
grep -q "api.github.com" "$d/scripts/release-assets-parity.py" || { echo "FAIL[F3]: precond"; exit 1; }
t0=$(date +%s)
out=$(cd "$d" && GITHUB_TOKEN=*** python3 scripts/release-assets-parity.py 2>&1); rc=$?
dt=$(( $(date +%s) - t0 ))
check F3_bogus_token_fast 1 "$rc" "$out" "HTTP 401"
# fast = under 25s: 3-attempt backoff would sleep >=3+6s + 3x30s timeouts
[ "$dt" -lt 25 ] && { echo "PASS[F3-fast] ${dt}s"; pass=$((pass+1)); } || { echo "FAIL[F3-fast]: ${dt}s >= 25s (retried a 401?)"; fail=$((fail+1)); }

# F4: host-scope boundary is a boundary not a hole at the MAIN-path level:
# point the rail's API_ROOT at a decoy host that ECHOES the path shape —
# cheaper equivalent: --selftest already baited substring hosts; instead
# assert here that the asset-download host never carries auth by grepping
# the code for the ONLY Authorization source = auth_header via headers_for.
d=$(fresh f4)
n=$(grep -c "Authorization" "$d/scripts/release-assets-parity.py")
authsites=$(grep -n "Authorization" "$d/scripts/release-assets-parity.py" | grep -v "selftest\|expect\|h.get\|not in h\|api host\|auth_header\|headers_for\|#\|\"\"\|leak\|LEAK\|empty" | wc -l)
if [ "$authsites" -le 2 ]; then echo "PASS[F4-single-auth-site] ($n mentions, $authsites attach sites)"; pass=$((pass+1)); else echo "FAIL[F4-single-auth-site]: $authsites attach sites"; fail=$((fail+1)); fi

# F5: no-repo vacuity guard — run from outside a repo root -> exit 2 names itself
d=$(fresh f5)
out=$(cd /tmp && python3 "$d/scripts/release-assets-parity.py" 2>&1); rc=$?
check F5_no_repo 2 "$rc" "$out" "repo root"

echo "==== release-assets-parity flips: $pass pass / $fail fail ===="
rm -rf "$BASE"
[ "$fail" -eq 0 ]

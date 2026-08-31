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

# F4: the credential has exactly ONE construction site, ONE attach site, and
# (c46) ONE removal site. The attach count is what keeps headers_for() the
# only path a token can take; the strip count pins the opener leg.
d=$(fresh f4)
# c46 REWRITE of this leg: the old grep-filter heuristic false-RED'd the
# moment the strip class added honest 'Authorization' mentions (has_header/
# remove_header) — a keyword-count with an ever-growing exclusion list is
# rot waiting to happen. Exact-pattern counts instead: the credential is
# CONSTRUCTED in exactly one place and ATTACHED in exactly one place; the
# strip REMOVES in exactly one place.
constructs=$(grep -c '"Authorization": "token "' "$d/scripts/release-assets-parity.py")
attaches=$(grep -c 'h.update(auth_header())' "$d/scripts/release-assets-parity.py")
strips=$(grep -c 'new.remove_header("Authorization")' "$d/scripts/release-assets-parity.py")
if [ "$constructs" = "1" ] && [ "$attaches" = "1" ] && [ "$strips" = "1" ]; then
  echo "PASS[F4-single-auth-site] (construct 1 / attach 1 / strip 1)"; pass=$((pass+1))
else
  echo "FAIL[F4-single-auth-site]: construct=$constructs attach=$attaches strip=$strips (want 1/1/1)"; fail=$((fail+1))
fi

# F5: no-repo vacuity guard — run from outside a repo root -> exit 2 names itself
d=$(fresh f5)
out=$(cd /tmp && python3 "$d/scripts/release-assets-parity.py" 2>&1); rc=$?
check F5_no_repo 2 "$rc" "$out" "repo root"

# ---- c46 (A c53 class): redirect scope at the TRANSPORT layer ----
# Live two-hop catcher, no api.github.com: C1 (127.0.0.1) 302s the client to
# C2 on hostname 'localhost' — hostname STRING mismatch = cross-host by
# urllib's own comparison. The probe builds a Request with the module's own
# headers_for()/auth shape and fetches through the module's _OPENER if the
# module ships one, else plain urlopen (the pre-fix transport).
cat > "$BASE/leakrepro.py" <<'PYEOF'
import importlib.util, os, socket, sys, threading, urllib.error, urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
TOKEN = "SELFTEST-LEAKPROOF-7c46"  # secretgate: allow test-only dummy, never a credential
SEEN = {"hop1": None, "hop2": None}
def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p
class Cat(BaseHTTPRequestHandler):
    def do_GET(self):
        SEEN[self.server.tag] = self.headers.get("Authorization")
        if getattr(self.server, "redirect", False):
            self.send_response(302); self.send_header("Location", self.server.redirect_to); self.end_headers()
        else:
            self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"[]")
    def log_message(self, *a): pass
def serve(port, tag, redirect_to=None):
    srv = HTTPServer(("127.0.0.1", port), Cat); srv.tag = tag
    if redirect_to: srv.redirect = True; srv.redirect_to = redirect_to
    threading.Thread(target=srv.serve_forever, daemon=True).start(); return srv
spec = importlib.util.spec_from_file_location("rap", sys.argv[1])
rap = importlib.util.module_from_spec(spec); spec.loader.exec_module(rap)
os.environ["GITHUB_TOKEN"] = TOKEN
p2 = free_port()
srv2 = serve(p2, "hop2")               # C2 FIRST: C1 must not 302 to a dead socket (A c53 lesson)
p1 = free_port()
srv1 = serve(p1, "hop1", f"http://localhost:{p2}/asset")
url = f"http://127.0.0.1:{p1}/repos/x/y/releases"
req = urllib.request.Request(url, headers=dict(rap.headers_for("https://api.github.com/x")))
try:
    opener = getattr(rap, "_OPENER", None)
    (opener.open(req, timeout=10) if opener else urllib.request.urlopen(req, timeout=10)).read()
except urllib.error.HTTPError: pass
finally: srv1.shutdown(); srv2.shutdown()
print("hop1 saw:", SEEN["hop1"]); print("hop2 saw:", SEEN["hop2"])
if SEEN["hop2"] and TOKEN in SEEN["hop2"]:
    print("LEAK"); sys.exit(0)
if SEEN["hop1"] and SEEN["hop2"] is None:
    print("STRIPPED"); sys.exit(3)
print("INCONCLUSIVE"); sys.exit(4)
PYEOF

# F6: shipped transport = token stays on hop1, LOST on hop2 (rc=3)
d=$(fresh f6)
out=$(python3 "$BASE/leakrepro.py" "$d/scripts/release-assets-parity.py" 2>&1); rc=$?
check F6_wire_strip 3 "$rc" "$out" "STRIPPED"

# F7 MUTATION: strip body removed, handler kept + opener kept -> re-leaks
# on the wire (rc=0). Proves the strip body, not the mere presence of a
# custom handler, is load-bearing (A c53 F4 shape).
d=$(fresh f7)
python3 - "$d/scripts/release-assets-parity.py" <<'EOF'
import sys
p = sys.argv[1]; src = open(p).read()
old = ('        if src_host != dst_host and new.has_header("Authorization"):\n'
       '            new.remove_header("Authorization")\n')
assert src.count(old) == 1, "mutation precond: strip body not found verbatim"
open(p, "w").write(src.replace(old, "        # MUTATION: strip removed\n"))
EOF
grep -q "MUTATION: strip removed" "$d/scripts/release-assets-parity.py" || { echo "FAIL[F7]: mutation did not land"; exit 1; }
out=$(python3 "$BASE/leakrepro.py" "$d/scripts/release-assets-parity.py" 2>&1); rc=$?
check F7_strip_removed_releaks 0 "$rc" "$out" "LEAK"

# F8 wiring leg: the --selftest STEP exists in CI as an EXACT stripped-line
# match (A c53 lesson: substring grep false-REDs when a comment or the
# parity step's own text mentions the command; grep -x anchors whole-line).
w=".github/workflows/selftest.yml"
if grep -qx "          python3 scripts/release-assets-parity.py --selftest" "$SRC/$w"; then
  echo "PASS[F8-selftest-step-wired]"; pass=$((pass+1))
else
  echo "FAIL[F8-selftest-step-wired]: no exact --selftest run-line in $w"; fail=$((fail+1))
fi
# F8 mutation: delete the exact run-line -> the same check goes RED
d=$(fresh f8)
sed -i 's|^\( *\)python3 scripts/release-assets-parity.py --selftest$|\1: removed-by-mutation|' "$d/$w"
if grep -qx "          python3 scripts/release-assets-parity.py --selftest" "$d/$w"; then
  echo "FAIL[F8m]: mutation did not remove the run-line"; fail=$((fail+1))
else
  echo "PASS[F8m-step-deletion-is-red]"; pass=$((pass+1))
fi

echo "==== release-assets-parity flips: $pass pass / $fail fail ===="
rm -rf "$BASE"
[ "$fail" -eq 0 ]

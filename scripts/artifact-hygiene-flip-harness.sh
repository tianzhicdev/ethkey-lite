#!/usr/bin/env bash
# c40 flip harness for scripts/artifact-hygiene.py.
# Rules (fleet c34/c35 discipline): fresh git copy per flip (the rail reads
# `git ls-files`, so the mutation must land in an INDEX, not a file touch —
# and a mutation that lands outside the rail's read-set would be a
# green-for-wrong-reason flip), verdict on EXIT CODE first, mutation-landed
# assert before trusting any RED.
#   CONTROL green / F1 blocklist-name re-added / F2 renamed-byproduct .md
#   off-blocklist / F3 untracked-in-worktree must NOT trip / F4 vacuous
#   non-repo dies exit 2 / F5 *.out sweep by extension / F6 tracked file
#   under a DERIVED actions/checkout path: = RED (c44 leg D; the name is
#   NOT on any hand-maintained list — derivation must find it) / F7 the
#   must-STILL-be-GREEN twin: same dir on disk untracked stays GREEN
#   (c38 exclusion-needs-a-twin rule) / F8 empty-frozenset must stay GREEN
#   (A c54 empty-boundary class: leg-A cleanup empties BLOCKLIST -> the
#   frozenset() declaration must keep set semantics, rc 0) / F8m the
#   crash-mutant: same empty set re-declared as bare `{}` = dict ->
#   TypeError names itself (the crash the declaration prevents).
set -u
SRC="$1"   # repo worktree to copy
HARNESS_DIR="$(cd "$(dirname "$0")" && pwd)"
fails=0

fresh_copy () { # $1 = case dir name
  local d="/tmp/c40-flips/$1"
  rm -rf "$d"; mkdir -p "$d"
  cp -a "$SRC/." "$d/"
  echo "$d"
}
run_rail () { cd "$1" && python3 scripts/artifact-hygiene.py; }

# CONTROL — post-fix tree must be green
D=$(fresh_copy control); cd "$D"; out=$(run_rail .); code=$?
[ $code -eq 0 ] || { echo "FAIL[control]: exit $code"; echo "$out"; fails=1; }
echo "$out" | grep -q 'artifact-hygiene: OK' || { echo "FAIL[control]: no OK line"; fails=1; }
echo "OK[control]: exit 0"

# F1 — the original accident: step.log re-added to the index
D=$(fresh_copy f1); cd "$D"
# recreate the exact accident: the file back on disk AND in the index
echo "error: [Errno 2] No such file or directory: 'no-such-receipt.md'" > step.log
git add -f step.log
# mutation-landed assert: rail's authority is ls-files — the file MUST be in it
git ls-files | grep -qx 'step.log' || { echo "FAIL[F1]: mutation not in ls-files = untestable"; fails=1; }
out=$(run_rail .); code=$?
[ $code -eq 1 ] || { echo "FAIL[F1]: exit $code, expected 1"; echo "$out"; fails=1; }
echo "$out" | grep -q 'step.log' || { echo "FAIL[F1]: RED does not name step.log"; fails=1; }
echo "OK[F1]: re-added byproduct RED, names the file"

# F2 — renamed byproduct (HIDDEN OFF the blocklist): tracked .md outside
# proofs/ proves the DENOMINATOR leg, not just the name list
D=$(fresh_copy f2); cd "$D"
cp proofs/v0.4-source.md js-scratch-parity.md && git add -f js-scratch-parity.md
git ls-files | grep -qx 'js-scratch-parity.md' || { echo "FAIL[F2]: mutation not in ls-files"; fails=1; }
out=$(run_rail .); code=$?
[ $code -eq 1 ] || { echo "FAIL[F2]: exit $code, expected 1 (blocklist bypassed?)"; echo "$out"; fails=1; }
echo "$out" | grep -q 'js-scratch-parity.md' || { echo "FAIL[F2]: RED does not name the file"; fails=1; }
echo "OK[F2]: renamed-byproduct caught by .md denominator (not name-matched)"

# F3 — the legitimate generator run: files EXIST in the worktree, untracked.
# Rail must stay GREEN (it checks the index, not the disk).
D=$(fresh_copy f3); cd "$D"
echo "x" > composite-run.sh && echo "y" > step.log && echo "z" > vermin.log
git status --porcelain | grep -q '^??' || true
out=$(run_rail .); code=$?
[ $code -eq 0 ] || { echo "FAIL[F3]: exit $code, expected 0 (rail checks disk not index?)"; echo "$out"; fails=1; }
echo "OK[F3]: generator byproducts on disk untracked = GREEN (index-checked, not disk)"

# F4 — vacuity: no git repo at all -> exit 2, never a vacuous OK
D=$(fresh_copy f4); cd "$D"; rm -rf .git
out=$(run_rail .); code=$?
[ $code -eq 2 ] || { echo "FAIL[F4]: exit $code, expected 2 (vacuous-green class)"; echo "$out"; fails=1; }
echo "$out" | grep -q 'OK' && { echo "FAIL[F4]: printed OK without a repo"; fails=1; }
echo "OK[F4]: rail-less repo dies exit 2, zero OK lines"

# F5 — extension-class sweep: a tracked .out (not on any blocklist, not .md)
D=$(fresh_copy f5); cd "$D"
echo "probe" > probe.out && git add -f probe.out
git ls-files | grep -qx 'probe.out' || { echo "FAIL[F5]: mutation not in ls-files"; fails=1; }
out=$(run_rail .); code=$?
[ $code -eq 1 ] || { echo "FAIL[F5]: exit $code, expected 1"; echo "$out"; fails=1; }
echo "$out" | grep -q 'probe.out' || { echo "FAIL[F5]: RED does not name probe.out"; fails=1; }
echo "OK[F5]: tracked *.out RED by extension sweep"

# F6 — c44 leg D: a tracked file under a checkout-path prefix that is NOT
# on the hand-maintained blocklist. If leg D only worked by name-listing,
# this flip is GREEN-for-wrong-reason-adjacent: the derivation must find
# .ethkey-tools/ purely from the workflow YAML text.
D=$(fresh_copy f6); cd "$D"
mkdir -p .ethkey-tools && echo "print()" > .ethkey-tools/ethkey.py && git add -f .ethkey-tools/ethkey.py
git ls-files | grep -qx '.ethkey-tools/ethkey.py' || { echo "FAIL[F6]: mutation not in ls-files"; fails=1; }
out=$(run_rail .); code=$?
[ $code -eq 1 ] || { echo "FAIL[F6]: exit $code, expected 1 (derivation missed it?)"; echo "$out"; fails=1; }
echo "$out" | grep -q '.ethkey-tools/ethkey.py' || { echo "FAIL[F6]: RED does not name the path"; fails=1; }
echo "OK[F6]: tracked clone under derived checkout path RED"

# F7 — must-STILL-be-GREEN twin: the LEGITIMATE CI run clones into
# .ethkey-tools/ on disk. Rail checks the index, not the disk: GREEN.
# (c38: an exclusion without a proven-GREEN twin is a hole with a name.)
D=$(fresh_copy f7); cd "$D"
mkdir -p .ethkey-tools && echo "print()" > .ethkey-tools/ethkey.py
# twin landed: file ON DISK, gitignored (new .gitignore leg) and NOT in the index
[ -f .ethkey-tools/ethkey.py ] || { echo "FAIL[F7]: twin file absent"; fails=1; }
git ls-files | grep -qx '.ethkey-tools/ethkey.py' && { echo "FAIL[F7]: twin landed IN the index = not the twin"; fails=1; }
git check-ignore -q .ethkey-tools/ethkey.py || { echo "FAIL[F7]: clone path not gitignored (a bare 'git add -A' would re-track it)"; fails=1; }
out=$(run_rail .); code=$?
[ $code -eq 0 ] || { echo "FAIL[F7]: exit $code, expected 0 (rail checks disk not index?)"; echo "$out"; fails=1; }
echo "OK[F7]: untracked clone on disk = GREEN (index-not-disk, twin proven)"

# F8 — A c54 empty-boundary class, must-STILL-be-GREEN half: simulate the
# leg-A cleanup that removes the LAST blocklist name. With the frozenset()
# declaration the rail keeps set semantics at empty and stays GREEN.
# (Without the print-count pin below, an 'empty blocklist silently skips
# its own leg' mutant would also pass — so assert 0/N prints N==0 too.)
D=$(fresh_copy f8); cd "$D"
python3 - <<'PYEOF'
import re
src = open("scripts/artifact-hygiene.py").read()
new = re.sub(r"BLOCKLIST = frozenset\(\{.*?\}\)", "BLOCKLIST = frozenset()", src, count=1, flags=re.S)
assert new != src, "mutation did not land"
open("scripts/artifact-hygiene.py", "w").write(new)
PYEOF
grep -qx 'BLOCKLIST = frozenset()' scripts/artifact-hygiene.py || { echo "FAIL[F8]: mutation not on disk"; fails=1; }
out=$(run_rail .); code=$?
[ $code -eq 0 ] || { echo "FAIL[F8]: exit $code, expected 0 (frozenset() lost set semantics at empty?)"; echo "$out"; fails=1; }
echo "$out" | grep -q 'OK: 0/0 generated byproducts tracked' || { echo "FAIL[F8]: OK-line does not print the 0/0 denominator"; echo "$out"; fails=1; }
echo "OK[F8]: empty frozenset BLOCKLIST stays GREEN with 0/0 printed"

# F8m — the crash-mutant twin: same emptied list, but declared the OLD way
# (bare braces = dict at empty). The rail must DIE with the TypeError the
# frozenset() declaration prevents — this flip proves F8's green is earned
# by the declaration, not by luck. (c46 rule: a mutation that removed the
# load-bearing body must change the VERDICT, here rc 0 -> crash.)
D=$(fresh_copy f8m); cd "$D"
python3 - <<'PYEOF'
import re
src = open("scripts/artifact-hygiene.py").read()
new = re.sub(r"BLOCKLIST = frozenset\(\{.*?\}\)", "BLOCKLIST = {}", src, count=1, flags=re.S)
assert new != src, "mutation did not land"
open("scripts/artifact-hygiene.py", "w").write(new)
PYEOF
grep -qx 'BLOCKLIST = {}' scripts/artifact-hygiene.py || { echo "FAIL[F8m]: mutation not on disk"; fails=1; }
out=$(run_rail . 2>&1); code=$?   # the TypeError rides STDERR — capture both streams
[ $code -ne 0 ] || { echo "FAIL[F8m]: bare-braces empty set exited 0 — no TypeError? (rail not exercising the intersection?)"; echo "$out"; fails=1; }
echo "$out" | grep -qi 'TypeError' || { echo "FAIL[F8m]: crash is not the TypeError this class makes"; echo "$out"; fails=1; }
echo "OK[F8m]: empty bare-braces = dict -> TypeError crash reproduced (declaration earns keep)"

cd /; rm -rf /tmp/c40-flips
[ $fails -eq 0 ] && echo "FLIPS: 10/10 OK" || { echo "FLIPS: FAILURES"; exit 1; }

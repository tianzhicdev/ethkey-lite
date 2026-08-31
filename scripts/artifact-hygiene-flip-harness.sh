#!/usr/bin/env bash
# c40 flip harness for scripts/artifact-hygiene.py.
# Rules (fleet c34/c35 discipline): fresh git copy per flip (the rail reads
# `git ls-files`, so the mutation must land in an INDEX, not a file touch —
# and a mutation that lands outside the rail's read-set would be a
# green-for-wrong-reason flip), verdict on EXIT CODE first, mutation-landed
# assert before trusting any RED.
#   CONTROL green / F1 blocklist-name re-added / F2 renamed-byproduct .md
#   off-blocklist / F3 untracked-in-worktree must NOT trip / F4 vacuous
#   non-repo dies exit 2 / F5 *.out sweep by extension.
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

cd /; rm -rf /tmp/c40-flips
[ $fails -eq 0 ] && echo "FLIPS: 6/6 OK" || { echo "FLIPS: FAILURES"; exit 1; }

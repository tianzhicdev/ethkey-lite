#!/usr/bin/env bash
# c41 flip harness for scripts/dead-ref-check.py.
# Rules honored (my own c34/c35/c40 lessons): exit code is the verdict FIRST,
# fresh git clone per flip (no shared-state bleed), every mutation asserted
# LANDED before trusting the flip, and every GREEN flip (F5/F6) proves a
# scope boundary, not a hole.
set -uo pipefail
SRC=$(cd "$(dirname "$0")/.." && pwd)
BASE=$(mktemp -d)
pass=0; fail=0

fresh() { # fresh clone per flip; print its path
  local d="$BASE/$1"
  git clone -q --no-hardlinks "$SRC" "$d" || { echo "CLONE-FAILED $1"; exit 1; }
  echo "$d"
}

run() { (cd "$1" && python3 scripts/dead-ref-check.py); }

check() { # name expected_rc actual_rc output [must-name-substring]
  local name=$1 want=$2 rc=$3 out=$4 needle=${5:-}
  if [ "$rc" != "$want" ]; then echo "FAIL[$name]: rc=$rc want=$want"; echo "$out" | sed 's/^/    /'; fail=$((fail+1)); return; fi
  if [ "$want" = "1" ] && [ -n "$needle" ] && ! grep -q "$needle" <<<"$out"; then
    echo "FAIL[$name]: RED but does not name '$needle'"; fail=$((fail+1)); return; fi
  if [ "$want" = "0" ] && grep -q "^FAIL" <<<"$out"; then
    echo "FAIL[$name]: rc=0 yet FAIL line present (rc lies)"; fail=$((fail+1)); return; fi
  echo "PASS[$name] rc=$rc"; pass=$((pass+1))
}

# CONTROL: pristine clone green
d=$(fresh control); out=$(run "$d" 2>&1); rc=$?
check CONTROL 0 "$rc" "$out"

# F1: README prose directory ref rots -> A RED (target: the in-repo composite
# path named at README:114, prose-scope backticked)
d=$(fresh f1)
grep -q '`\./\.github/actions/verify-release`' "$d/README.md" || { echo "FAIL[F1]: precond (prose token)"; exit 1; }
sed -i 's#`\./\.github/actions/verify-release`#`./.github/actions/verify-release-renamed`#' "$d/README.md"
grep -q 'verify-release-renamed' "$d/README.md" || { echo "MUTATION-FAILED F1"; exit 1; }
out=$(run "$d" 2>&1); rc=$?
check F1_dead_readme_path 1 "$rc" "$out" "verify-release-renamed"

# F2: .secretgateignore gains a pattern matching nothing -> B RED
d=$(fresh f2)
echo "no-such-dir/" >> "$d/.secretgateignore"
grep -qx 'no-such-dir/' "$d/.secretgateignore" || { echo "MUTATION-FAILED F2"; exit 1; }
out=$(run "$d" 2>&1); rc=$?
check F2_dead_ignore_pattern 1 "$rc" "$out" "matches ZERO tracked paths: no-such-dir/"

# F3: .gitignore gains a line naming a TRACKED file (c40 latent class) -> C RED
d=$(fresh f3)
echo "receipt.html" >> "$d/.gitignore"
git -C "$d" ls-files --error-unmatch receipt.html >/dev/null || { echo "MUTATION-FAILED F3 (target not tracked)"; exit 1; }
out=$(run "$d" 2>&1); rc=$?
check F3_gitignore_vs_index 1 "$rc" "$out" "names TRACKED file"

# F4: unterminated fence -> fail-closed exit 2 (rail refuses to guess scope)
d=$(fresh f4)
printf '\n```\nunclosed fence added by flip\n' >> "$d/README.md"
out=$(run "$d" 2>&1); rc=$?
check F4_unterminated_fence 2 "$rc" "$out" "unterminated"

# F5: dead path INSIDE a fenced consumer snippet stays GREEN (prose scope is
#     documented truth, not a hole — fenced = copy-paste for the reader's repo)
d=$(fresh f5)
awk 'BEGIN{done=0} {print; if(!done && /^```/ && $0 !~ /^```$/){print "receipt: proofs/release-proof-DOES-NOT-EXIST.md"; done=1}}' "$d/README.md" > "$d/README.new" \
  && mv "$d/README.new" "$d/README.md"
grep -q 'release-proof-DOES-NOT-EXIST' "$d/README.md" || { echo "MUTATION-FAILED F5"; exit 1; }
out=$(run "$d" 2>&1); rc=$?
check F5_fenced_scope_green 0 "$rc" "$out"

# F6: an EXTERNAL-repo ref in prose stays GREEN (cross-repo names are not
#     this repo's index — checking them would false-RED every fleet cite)
d=$(fresh f6)
sed -i '0,/`receipt.html`/{s#`receipt.html`#`tianzhicdev/secretgate/proofs/nonexistent.md`#}' "$d/README.md"
grep -q 'tianzhicdev/secretgate/proofs/nonexistent.md' "$d/README.md" || { echo "MUTATION-FAILED F6"; exit 1; }
out=$(run "$d" 2>&1); rc=$?
check F6_external_ref_green 0 "$rc" "$out"

# F7: runtime-scope exclusion GREEN — README references .git/<something>
#     (the LIVE hookpack false-RED class caught by the c42 sibling probe:
#     a .git/ path can never be an index entry; the rail must not
#     false-RED it). 'runtime-scope-flip' doesn't exist anywhere; GREEN
#     proves the exclusion, not a hole (F8 is its must-STILL-be-RED pair).
d=$(fresh f7)
printf '\nThe tool installs into `.git/hooks/runtime-scope-flip`.\n' >> "$d/README.md"
grep -q 'runtime-scope-flip' "$d/README.md" || { echo "MUTATION-FAILED F7"; exit 1; }
out=$(run "$d" 2>&1); rc=$?
check F7_dotgit_runtime_scope_green 0 "$rc" "$out"

# F8: must-STILL-be-RED pair for F7 — '.git' NOT as first component
#     (src/.git/bait.md) is an ordinary dead repo-local path and stays RED.
d=$(fresh f8)
printf '\nSee `src/.git/bait-flip.md` for context.\n' >> "$d/README.md"
grep -q 'src/.git/bait-flip.md' "$d/README.md" || { echo "MUTATION-FAILED F8"; exit 1; }
out=$(run "$d" 2>&1); rc=$?
check F8_nested_dotgit_still_red 1 "$rc" "$out" "src/.git/bait-flip.md"

echo "dead-ref flip harness: $pass PASS, $fail FAIL"
rm -rf "$BASE"
[ "$fail" = 0 ]

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
# c45: baseline exemption count must print 0 — the count is the CONTROL's
# own assertion now, so F7's '+1' is anchored to a measured zero.
if [ "$rc" = 0 ] && ! grep -q 'runtime-scope .git/ exemptions: 0' <<<"$out"; then
  echo "FAIL[CONTROL]: green but OK-line lacks 'exemptions: 0' (printed-count contract)"; fail=$((fail+1))
else
  check CONTROL 0 "$rc" "$out"
fi

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
# c45 STRENGTHEN: rc=0 alone is too weak — a rail that exempted EVERYTHING
# also passes rc. The printed count must say EXACTLY 1 and name the mutated
# ref (exemption fired on my mutation, not by luck), and the same ref must
# NOT appear as a checked path (seen count stays 9 = the README's baseline).
if [ "$rc" = 0 ]; then
  grep -q 'runtime-scope .git/ exemptions: 1 \[.git/hooks/runtime-scope-flip\]' <<<"$out" \
    && grep -q '9 checked' <<<"$out" \
    && { echo "PASS[F7_printed_count_names_mutation]"; pass=$((pass+1)); } \
    || { echo "FAIL[F7_printed_count_names_mutation]: OK-line:"; echo "$out" | grep 'prose paths' | sed 's/^/    /'; fail=$((fail+1)); }
fi

# F8: must-STILL-be-RED pair for F7 — '.git' NOT as first component
#     (src/.git/bait.md) is an ordinary dead repo-local path and stays RED.
d=$(fresh f8)
printf '\nSee `src/.git/bait-flip.md` for context.\n' >> "$d/README.md"
grep -q 'src/.git/bait-flip.md' "$d/README.md" || { echo "MUTATION-FAILED F8"; exit 1; }
out=$(run "$d" 2>&1); rc=$?
check F8_nested_dotgit_still_red 1 "$rc" "$out" "src/.git/bait-flip.md"

# ---- V-class (c50): scope-assert over the EXEMPT set (B c45 offer, A c56
# shape). Synthetic tree so the exempt set has a controlled denominator;
# fresh build per flip like the clone-per-flip rule above. ----
synth() { # $1 = dir name; builds a committed synth repo w/ 3 runtime refs
  local d="$BASE/$1"
  rm -rf "$d"; mkdir -p "$d"
  ( cd "$d" && git init -q . && git config user.email f@f && git config user.name f \
    && printf '# Synth\n\nSee `a/b.md` and `./.git/hooks/flip/` plus `.git/` bare and `./.git/hookpack/cache/`.\n' > README.md \
    && mkdir -p a && printf 'y\n' > a/b.md && git add -A && git commit -qm init ) \
    || { echo "SYNTH-FAILED $1"; exit 1; }
  echo "$d"
}
RRAIL="$SRC/scripts/dead-ref-check.py"

# V1: post-fix rail GREEN on synth + canonical (normalized) printed set +
#     honest checked-count (1 real ref, exemptions do NOT inflate it).
d=$(synth v1); out=$(cd "$d" && python3 "$RRAIL" 2>&1); rc=$?
if [ "$rc" = 0 ] && grep -q '1 checked' <<<"$out" \
   && grep -q 'exemptions: 3 \[.git, .git/hookpack/cache, .git/hooks/flip\]' <<<"$out"; then
  echo "PASS[V1_synth_green_canonical_print]"; pass=$((pass+1))
else
  echo "FAIL[V1_synth_green_canonical_print] rc=$rc:"; echo "$out" | sed 's/^/    /'; fail=$((fail+1))
fi

# V2t: truth+bait — dead ref in synth README, honest rail: rc=1 whose
#     authority is the DEAD leg ('not tracked'), never 'carve-out'.
d=$(synth v2t); printf '\nSee `does-not-exist-c50/missing.md` for context.\n' >> "$d/README.md"
git -C "$d" add -A >/dev/null && git -C "$d" commit -qm bait >/dev/null
out=$(cd "$d" && python3 "$RRAIL" 2>&1); rc=$?
if [ "$rc" = 1 ] && grep -q 'not tracked: does-not-exist-c50/missing.md' <<<"$out" \
   && ! grep -q 'carve-out' <<<"$out"; then
  echo "PASS[V2t_truth_bait_dead_leg_authority]"; pass=$((pass+1))
else
  echo "FAIL[V2t_truth_bait_dead_leg_authority] rc=$rc:"; echo "$out" | sed 's/^/    /'; fail=$((fail+1))
fi

# V2a: exempt-everything MUTANT on the SAME baited tree: scope-assert makes
#     it a VERDICT — rc=1 naming 'carve-out: <bait>', and precision: the
#     bait must NOT also reach the dead leg (same rc, different authority
#     must be distinguishable from the print, A c56).
mut="$BASE/exemptall.py"
python3 - "$RRAIL" "$mut" <<'PYEOF' || { echo "MUTATION-FAILED V2a"; exit 1; }
import sys
src = open(sys.argv[1]).read()
old = 'if rel.split("/")[0] == ".git":'
assert src.count(old) == 1
open(sys.argv[2], "w").write(src.replace(old, "if True:"))
PYEOF
out=$(cd "$d" && python3 "$mut" 2>&1); rc=$?
if [ "$rc" = 1 ] && grep -q 'carve-out: does-not-exist-c50/missing.md' <<<"$out" \
   && ! grep -q 'not tracked' <<<"$out"; then
  echo "PASS[V2a_exemptall_scope_verdict_names_bait]"; pass=$((pass+1))
else
  echo "FAIL[V2a_exemptall_scope_verdict_names_bait] rc=$rc:"; echo "$out" | sed 's/^/    /'; fail=$((fail+1))
fi

# V2b: same mutant with the SCOPE-ASSERT STRIPPED: rc=0, bait swallowed
#     into the printed exempt set = the OLD blessing reproduced on demand.
mut2="$BASE/exemptall-noscope.py"
python3 - "$RRAIL" "$mut2" <<'PYEOF' || { echo "MUTATION-FAILED V2b"; exit 1; }
import sys
src = open(sys.argv[1]).read()
a = 'over = [n for n in uniq_rt if n != ".git" and not n.startswith(".git/")]'
old = 'if rel.split("/")[0] == ".git":'
assert src.count(a) == 1 and src.count(old) == 1
open(sys.argv[2], "w").write(src.replace(old, "if True:").replace(a, "over = []"))
PYEOF
out=$(cd "$d" && python3 "$mut2" 2>&1); rc=$?
if [ "$rc" = 0 ] && grep -q 'exemptions: 5' <<<"$out" \
   && grep -q 'does-not-exist-c50/missing.md' <<<"$out"; then
  echo "PASS[V2b_scope_stripped_blessing_reproduced]"; pass=$((pass+1))
else
  echo "FAIL[V2b_scope_stripped_blessing_reproduced] rc=$rc:"; echo "$out" | sed 's/^/    /'; fail=$((fail+1))
fi

# V3: SLOPPY-BRANCH mutant (exempt predicate startswith('.git') = swallows
#     `.github/...` too) while the scope-assert stays honest: rc=1 naming
#     the swallowed .github ref = the scope predicate is membership-strict,
#     not just non-empty.
d3=$(synth v3); mkdir -p "$d3/docs"; printf 'y\n' > "$d3/docs/x.md"
printf '\nAlso see `docs/x.md` and `.github/workflows/delta.md`.\n' >> "$d3/README.md"
git -C "$d3" add -A >/dev/null && git -C "$d3" commit -qm v3 >/dev/null
# honest rail first: .github/workflows/delta.md must be a plain DEAD ref
out=$(cd "$d3" && python3 "$RRAIL" 2>&1); rc=$?
[ "$rc" = 1 ] && grep -q 'not tracked: .github/workflows/delta.md' <<<"$out" \
  || { echo "MUTATION-FAILED V3 (precond: honest rail must RED the .github ref)"; echo "$out"; exit 1; }
mut3="$BASE/sloppybranch.py"
python3 - "$RRAIL" "$mut3" <<'PYEOF' || { echo "MUTATION-FAILED V3"; exit 1; }
import sys
src = open(sys.argv[1]).read()
old = 'if rel.split("/")[0] == ".git":'
assert src.count(old) == 1
m = src.replace(old, 'if rel.startswith(".git"):')
assert m != src
open(sys.argv[2], "w").write(m)
PYEOF
out=$(cd "$d3" && python3 "$mut3" 2>&1); rc=$?
if [ "$rc" = 1 ] && grep -q 'carve-out: .github/workflows/delta.md' <<<"$out"; then
  echo "PASS[V3_sloppy_branch_scope_strict]"; pass=$((pass+1))
else
  echo "FAIL[V3_sloppy_branch_scope_strict] rc=$rc:"; echo "$out" | sed 's/^/    /'; fail=$((fail+1))
fi

# ---- V4 (c52): traversal class — `.git/../missing.md` rides the
# first-component carve-out if the predicate is a raw-string test. My
# cycle-start probe REPRODUCED the blessing on shipped 32da58b bytes (rc=0,
# name swallowed into 'exemptions: 2'), then the normpath-at-collection fix
# RED'd it. V4 pins the post-fix verdict; V4b pins the pre-fix blessing on
# the pinned pre-fix sha (B c47 F2P shape: the OLD bytes are data, checked
# out by sha, not mutated) so the fix stays load-bearing forever.
# Pinned SHA, not HEAD~1: coordinates rot like values (B c47 lesson — their
# F2P HEAD~1 anchor rotated under their own commits one cycle later). 32da58b
# = the exact shipped bytes my cycle-start probe blessed the ref on.
PREFIX_SHA=32da58b
d=$(synth v4); printf '\\nSee `.git/../c52-missing.md` for context.\\n' >> "$d/README.md"
git -C "$d" add -A >/dev/null && git -C "$d" commit -qm v4 >/dev/null
out=$(cd "$d" && python3 "$RRAIL" 2>&1); rc=$?
if [ "$rc" = 1 ] && grep -q 'not tracked: .*/c52-missing.md' <<<"$out" \
   && grep -q 'not tracked' <<<"$out" && ! grep -q 'carve-out' <<<"$out"; then
  echo "PASS[V4_traversal_red_not_carveout]"; pass=$((pass+1))
else
  echo "FAIL[V4_traversal_red_not_carveout] rc=$rc:"; echo "$out" | sed 's/^/    /'; fail=$((fail+1))
fi
# V4b: pre-fix bytes at the pinned sha must still BLESS the exact same ref
# (if this ever goes RED, the blessing class was never real or the pin moved —
# either way the claim in the commit message needs re-checking).
dp="$BASE/v4b-prefix"; rm -rf "$dp"; git clone -q --no-hardlinks "$SRC" "$dp"
git -C "$dp" checkout -q "$PREFIX_SHA" -- scripts/dead-ref-check.py
# append the traversal ref to THIS tree's own README (real refs intact) —
# first harness draft copied the synth README in and false-RED'd on its
# `a/b.md` ref = wrong-target class, caught before trusting the fail
printf '\\nSee `.git/../c52-missing.md` for context.\\n' >> "$dp/README.md"
out=$(cd "$dp" && python3 scripts/dead-ref-check.py 2>&1); rc=$?
if [ "$rc" = 0 ] && grep -q 'c52-missing.md' <<<"$out"; then
  echo "PASS[V4b_prefix_sha_blessing_pinned @${PREFIX_SHA:0:7}]"; pass=$((pass+1))
else
  echo "FAIL[V4b_prefix_sha_blessing_pinned] rc=$rc:"; echo "$out" | sed 's/^/    /'; fail=$((fail+1))
fi

echo "dead-ref flip harness: $pass PASS, $fail FAIL"
rm -rf "$BASE"
[ "$fail" = 0 ]

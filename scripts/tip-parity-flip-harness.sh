#!/usr/bin/env bash
# c38 flip harness for scripts/tip-parity.py (C port of A c42 shape).
# Discipline (c34/c41/c42): fresh copy per flip, position-assert the
# mutation LANDED before trusting the verdict, RED must NAME the expected
# error class, and the assert is on the EXIT CODE, not the message.
set -uo pipefail
SRC="${1:?usage: flip_harness.sh <repo root>}"
TIP="0xf232dcdc177b53981b4d805a48c79f239db8d0f9"
A_ADDR="0xFD4090e27C1f946Ff01a265cAa7d4ACA662acC15"
B_ADDR="0x5439BC46AC9cc70dfFC500611c6D845d7eE9eE5E"
PASS=0; FAIL=0

run() { (cd "$1" && python3 scripts/tip-parity.py 2>&1; echo "rc=$?"); }

expect_red() { # <label> <dir> <expected-error-substring>
  local label="$1" dir="$2" want="$3" out rc
  out=$(run "$dir"); rc=$(echo "$out" | tail -1)
  if [ "$rc" != "rc=1" ]; then
    echo "TEST-FAIL $label: expected rc=1, got $rc"; FAIL=$((FAIL+1)); return
  fi
  if ! echo "$out" | grep -qF -- "$want"; then
    echo "TEST-FAIL $label: RED for WRONG reason (wanted '$want'):"; echo "$out" | grep '^FAIL'; FAIL=$((FAIL+1)); return
  fi
  echo "PASS(red) $label  [named: $want]"; PASS=$((PASS+1))
}
expect_green() { # <label> <dir>
  local label="$1" dir="$2" out rc
  out=$(run "$dir"); rc=$(echo "$out" | tail -1)
  if [ "$rc" != "rc=0" ]; then echo "TEST-FAIL $label: expected rc=0:"; echo "$out" | grep '^FAIL'; FAIL=$((FAIL+1)); return; fi
  echo "PASS(green) $label"; PASS=$((PASS+1))
}

fresh() { local d; d=$(mktemp -d); cp -r "$SRC"/. "$d"/ 2>/dev/null; echo "$d"; }

# CONTROL: pristine copy green (incl live leg)
d=$(fresh); expect_green "control" "$d"; rm -rf "$d"

# FLIP1: footer addr swapped to A (the exact c29 forge class), INSIDE the
# <footer> block only + position assert inside it (A c42 harness lesson:
# whole-page replace hits a code example first = right verdict, wrong site).
d=$(fresh)
python3 - "$d/index.html" "$TIP" "$A_ADDR" <<'PY'
import re, sys
p, t, a = sys.argv[1:4]
s = open(p).read()
m = re.search(r"<footer\b.*?</footer>", s, re.S)
assert m, "no footer"
# swap EVERY footer copy (tip appears twice here: <code> + require= link) —
# first harness v1 replaced only the first and correctly MUTATION-FAILED:
# the surviving tip made the position assert honest instead of rubber-stamp.
foot = m.group(0).replace(t, a)
assert a.lower() in foot.lower() and t.lower() not in foot.lower(), "MUTATION-FAILED"
open(p, "w").write(s[:m.start()] + foot + s[m.end():])
PY
expect_red "F1 footer->A (forge class)" "$d" "committed footer: address set"; rm -rf "$d"

# FLIP2: FUNDING.yml swapped to B
d=$(fresh)
sed -i "s/$TIP/$B_ADDR/" "$d/.github/FUNDING.yml"
grep -q "$B_ADDR" "$d/.github/FUNDING.yml" || echo "MUTATION-FAILED"
expect_red "F2 FUNDING->B" "$d" "FUNDING.yml: address set"; rm -rf "$d"

# FLIP3: README team-footer C copy swapped to B (last addr)
d=$(fresh)
python3 - "$d/README.md" "$TIP" "$B_ADDR" <<'PY'
import re, sys
p, t, b = sys.argv[1:4]
s = open(p).read()
m = re.search(r"<!-- team-footer:start -->.*?<!-- team-footer:end -->", s, re.S)
assert m, "no team block"
blk = m.group(0)
i = blk.rfind(t)
assert i >= 0, "MUTATION-FAILED: tip not in block"
blk2 = blk[:i] + b + blk[i+len(t):]
# position assert: after mutation the LAST addr in the block is B and the C
# tip is GONE from the block (harness v1 asserted 'B not in block' — wrong:
# the team block legitimately enumerates A/B/C; the right assert is the
# block's addr-order, checked here the same way the rail checks it).
tail = re.findall(r"0x[0-9a-fA-F]{40}", blk2.lower())[-1]
assert tail == b.lower() and t.lower() not in blk2.lower(), "MUTATION-FAILED"
open(p, "w").write(s[:m.start()] + blk2 + s[m.end():])
PY
expect_red "F3 team-footer C->B" "$d" "team-footer last addr"; rm -rf "$d"

# FLIP4: README team-footer block DELETED (silent-unpin class)
d=$(fresh)
python3 - "$d/README.md" <<'PY'
import re, sys
p = sys.argv[1]
s = open(p).read()
s2 = re.sub(r"<!-- team-footer:start -->.*?<!-- team-footer:end -->\s*", "", s, flags=re.S)
assert "team-footer:start" not in s2, "MUTATION-FAILED"
open(p, "w").write(s2)
PY
expect_red "F4 team block deleted" "$d" "team-footer block missing"; rm -rf "$d"

# FLIP5: receipt.html FLEET ethkey-lite signer swapped to B (signer-value
# class: tip layers stay green, the ANCHOR splits = tip money, wrong signer)
d=$(fresh)
python3 - "$d/receipt.html" "$TIP" "$B_ADDR" <<'PY'
import re, sys
p, t, b = sys.argv[1:4]
s = open(p).read()
pat = re.compile(r"(\{\s*repo:\s*'ethkey-lite',\s*signer:\s*')0x[0-9a-fA-F]{40}(') \}")
assert pat.search(s), "MUTATION-FAILED: FLEET row locator drifted"
open(p, "w").write(pat.sub(lambda m: m.group(1) + b + m.group(2) + " }", s))
PY
expect_red "F5 FLEET signer->B (anchor/tip split)" "$d" "!= TIP"; rm -rf "$d"

# FLIP6: live route dead -> transport FAIL-CLOSED leg
d=$(fresh)
sed -i "s#https://tianzhicdev.github.io/ethkey-lite/index.html#https://tianzhicdev.github.io/ethkey-lite/DEAD-ROUTE-FLIP6.html#" "$d/scripts/tip-parity.py"
grep -q "DEAD-ROUTE-FLIP6" "$d/scripts/tip-parity.py" || echo "MUTATION-FAILED"
expect_red "F6 live route dead" "$d" "live fetch failed after 4 attempts"; rm -rf "$d"

# FLIP7 (non-vacuity of the verify-side scrub): a SIBLING addr added as
# plain README body text (outside team-footer, outside any require= link)
# must still be RED — the scrub must not become a hole that swallows the
# sweep layer.
d=$(fresh)
python3 - "$d/README.md" "$A_ADDR" <<'PY'
import sys
p, a = sys.argv[1:3]
s = open(p).read()
# harness v1 anchored on '## Part of a small tools family' — INSIDE the
# team-footer block, so the sweep (correctly) ignored it and F7 went green
# for the wrong reason. Anchor OUTSIDE the team block: prepend to the file.
assert "team-footer:start" not in s.splitlines()[0], "sanity"
s = f"Sweep probe {a}\n\n" + s
assert a in s.split("\n")[0], "MUTATION-FAILED"
open(p, "w").write(s)
PY
expect_red "F7 sibling in README body (scrub not a hole)" "$d" "sibling addr"
rm -rf "$d"

# FLIP8 (scrub direction guard): adding a legitimate fleet deep link with
# require=<A addr> to the README body must stay GREEN — proves the scrub
# exemption is scoped to `require=` and not blanket addr-blindness.
d=$(fresh)
python3 - "$d/README.md" "$A_ADDR" <<'PY'
import sys
p, a = sys.argv[1:3]
s = open(p).read()
s = f"[deep link](https://tianzhicdev.github.io/ethkey-lite/receipt.html?load=latest&repo=secretgate&require={a})\n\n" + s
assert f"require={a}" in s.splitlines()[0], "MUTATION-FAILED"
open(p, "w").write(s)
PY
expect_green "F8 require= link stays green (scrub scoped)" "$d"; rm -rf "$d"

echo; echo "flip harness: PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]

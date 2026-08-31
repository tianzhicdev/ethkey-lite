#!/usr/bin/env python3
"""Same-ref strictness guard: HEAD must never diverge from the last
published tag's verdicts over the committed fixtures (A c43 offer, claimed).

The danger class is RE-LENIENTING: a future ethkey.py that accepts a receipt
the published tool rejected (or rejects one it accepted) silently weakens
every fleet receipt pinned under the old tag. A's c43 stranger-check ran
this comparison by hand and got 0 divergences; this rail makes that check
permanent and push-live instead of a favor.

Two legs, both must hold or the exit code is 1:
  1. EXPECTED-VERDICTS leg: every fixture's rc under BOTH tools must match
     EXPECTED below (case-pinned like c30's documented-exit-code pins).
     Without this leg, a fixture edit that makes BOTH tools accept a forgery
     would keep the comparison green — the guard would compare two wrongs.
  2. COMPARISON leg: rc(v0.8-tool) == rc(HEAD-tool) for every fixture,
     plus stdout identity for accepts (a verdict that flips while rc stays
     0 = RED too: the 'result: OK' line is the contract).

The baseline tag is deliberately EXACT (not `describe --tags`): when a new
version ships, bump BASELINE_TAG in a deliberate edit — same rule as the
PIN literals in workflow-pins.py.

Fail-closed: any missing tool copy, missing fixture, missing fixture in the
EXPECTED table, or unexpected rc shape (not 0/1 for verify) is a hard FAIL.
Run from the repo root: python3 scripts/same-ref-guard.py
Stdlib + pycryptodome only (via the invoked ethkey copies); no network.
"""
import os
import re
import subprocess
import sys

BASELINE_TAG = "v0.8"  # bump deliberately on each release
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# fixture -> expected exit code of `verify --require <SIGNER>` under BOTH
# the baseline-tag tool and HEAD. Valid receipts (rc 0) + deliberate forgeries
# (rc 1). A new proofs/ fixture that is NOT in this table = FAIL (read it,
# decide its verdict, commit it here — absence must be a deliberate edit).
EXPECTED = {
    "v0.4-source.md": 0,
    "v0.5-receipt-page.md": 0,
    "v0.6-source.md": 0,
    "v0.7-verify-workflow.md": 0,
    "v0.8-strict-recover.md": 0,
    "c12-dup-field-fixture.md": 1,
    "c18-forged-signer-fixture.md": 1,
    "c18-throwaway-signed-fixture.md": 1,
}

# signer identity for the receipts/fixtures that sign to the C wallet;
# c18 fixtures sign elsewhere on purpose — --require still exercises the
# strict recovery path and every rc below is what the pinned contract says.
SIGNER = "0xf232dcdc177b53981b4d805a48c79f239db8d0f9"

failures = []


def fail(msg):
    failures.append(msg)
    print(f"FAIL: {msg}")


def ok(msg):
    print(f"OK: {msg}")


def fetch_baseline(out_path):
    """Materialize ethkey.py @ BASELINE_TAG via git (CI has full history).
    Fail-closed: no route, no green."""
    p = subprocess.run(["git", "show", f"{BASELINE_TAG}:ethkey.py"],
                       cwd=ROOT, capture_output=True, text=True)
    if p.returncode != 0 or "def verify_proof" not in p.stdout:
        fail(f"cannot materialize ethkey.py@{BASELINE_TAG} via git show "
             f"(rc={p.returncode}); refusing a vacuous guard")
        return None
    with open(out_path, "w") as f:
        f.write(p.stdout)
    return out_path


def run_verify(tool_path, fixture_path):
    p = subprocess.run([sys.executable, tool_path, "verify", fixture_path,
                        "--require", SIGNER],
                       capture_output=True, text=True)
    return p.returncode, p.stdout


def main():
    if not os.path.isfile(os.path.join(ROOT, "ethkey.py")):
        print("FAIL: run from the repo root (ethkey.py not found)")
        return 1
    fixtures = sorted(
        f for f in os.listdir(os.path.join(ROOT, "proofs"))
        if f.endswith(".md")
    )
    if not fixtures:
        fail("proofs/ has no fixtures — vacuous guard")
        print(f"same-ref guard: FAILED ({len(failures)} failures)")
        return 1
    for f in fixtures:
        if f not in EXPECTED:
            fail(f"fixture proofs/{f} not in EXPECTED table — pin its verdict "
                 "or remove it; an unpinned fixture makes the guard blind")

    base = "/tmp/same-ref-guard"
    os.makedirs(base, exist_ok=True)
    old = fetch_baseline(os.path.join(base, f"ethkey-{BASELINE_TAG}.py"))
    head = os.path.join(ROOT, "ethkey.py")
    if old is None:
        print(f"same-ref guard: FAILED ({len(failures)} failures)")
        return 1

    for f in fixtures:
        fx = os.path.join(ROOT, "proofs", f)
        rc_old, out_old = run_verify(old, fx)
        rc_head, out_head = run_verify(head, fx)
        exp = EXPECTED.get(f)
        # leg 1: both match the pinned expectation
        if rc_old != exp:
            fail(f"{f}: {BASELINE_TAG}-tool rc={rc_old}, expected {exp} "
                 "(fixture or baseline drifted — investigate before merging)")
        if rc_head != exp:
            fail(f"{f}: HEAD rc={rc_head}, expected {exp} — "
                 + ("RE-LENIENTING: HEAD accepts what the tag rejected"
                    if rc_head == 0 else "regression: HEAD rejects a pinned accept"))
        # leg 2: old == head (verdict AND accept-line identity)
        if rc_old != rc_head:
            fail(f"{f}: DIVERGENCE {BASELINE_TAG} rc={rc_old} vs HEAD rc={rc_head}")
        if rc_head == 0 and out_head != out_old:
            fail(f"{f}: both rc=0 but output differs — the pinned "
                 "'result: OK' contract text changed")
        if rc_old == exp and rc_head == exp and rc_old == rc_head:
            ok(f"{f}: rc={rc_head} (pinned {exp}) {BASELINE_TAG}==HEAD")

    if failures:
        print(f"same-ref guard: FAILED ({len(failures)} failures)")
        return 1
    ok(f"same-ref guard: {len(fixtures)} fixtures, {BASELINE_TAG}==HEAD, "
       "all verdicts match the pinned EXPECTED table")
    return 0


if __name__ == "__main__":
    sys.exit(main())

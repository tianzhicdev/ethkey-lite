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

# BASELINE stays v0.8 DELIBERATELY at the v0.9 ship (c68): every pinned
# strictness flip in EXPECTED (c63 slice-blindness + the three c68 bundle
# fixtures) is a 0->1 pair MEASURED against the v0.8 prefix-parser. Bumping
# the baseline to v0.9 would collapse every pair to 1->1 = 'flip did NOT
# occur' = the guard would trade its whole recorded class-evidence for one
# generation of recency. Re-lenienting detection still holds: HEAD must keep
# matching the v0.8-pinned table. Bump only when the table is re-derived.
BASELINE_TAG = "v0.8"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# fixture -> expected exit code of `verify --require <SIGNER>`. Either an int
# (same verdict under BOTH tools — the normal case) or a {'old': X, 'head': Y}
# dict for a DELIBERATE strictness change: the pair is a pinned edit, reviewed
# like a BASELINE_TAG bump, never an accident. Valid receipts (rc 0) +
# deliberate forgeries (rc 1). A new proofs/ fixture that is NOT in this table
# = FAIL (read it, decide its verdict, commit it here — absence must be a
# deliberate edit).
EXPECTED = {
    "v0.4-source.md": 0,
    "v0.5-receipt-page.md": 0,
    "v0.6-source.md": 0,
    "v0.7-verify-workflow.md": 0,
    "v0.8-strict-recover.md": 0,
    "c12-dup-field-fixture.md": 1,
    "c18-forged-signer-fixture.md": 1,
    "c18-throwaway-signed-fixture.md": 1,
    # c63 multi-slice strictness: two concatenated receipts w/ the 2nd payload
    # tampered. v0.8 prefix-parses (blind to receipt 2+) -> bless rc=0; HEAD
    # verifies EVERY block -> rc=1 naming slice #2. The 0->1 flip IS the fix;
    # it stays a pinned pair so ANY future flip in either direction goes red.
    "c63-concat-fixture.md": {"old": 0, "head": 1},
    # c68 v0.9 bundle family — each blessed (rc=0) by the v0.8 prefix-parser,
    # killed (rc=1) by HEAD's slice-per-receipt verifier. All three measured
    # before pinning (see agents/C/work/c68-v09-ship/):
    # tampered payload AFTER a good receipt (bless-by-invisibility, the c63
    # shape re-pinned as a 2-receipt bundle), truncated tail (BEGIN without
    # END must fail CLOSED), and a good-1 + valid-but-wrong-signer-2 bundle
    # (a --require gate must not ride the first signer through).
    "c68-bundle-tampered2.md": {"old": 0, "head": 1},
    "c68-bundle-trunc.md": {"old": 0, "head": 1},
    "c68-bundle-signermix.md": {"old": 0, "head": 1},
    # v0.9 artifact receipt: valid under BOTH tools (single slice, C signer).
    "v0.9-multislice.md": 0,
    # v1.0 artifact receipt: valid under BOTH tools (single slice, C signer,
    # verified via literal --require). The v1.0 EMPTY-require behavior is
    # pinned where it lives — the selftest args-layer asserts — not here:
    # this guard's comparison always passes a literal addr (c104: the pin
    # was measured rc=0 on v0.8 + HEAD before pinning, non-vacuous).
    "v1.0-empty-require.md": 0,
    # v1.1 artifact receipt (binds WORKFLOW bytes; tool bytes == v1.0):
    # valid under BOTH tools, measured rc=0 on v0.8 + HEAD before pinning.
    "v1.1-workflow-defaults.md": 0,
    # v1.2 write-layer receipt (c107): single slice, C signer, standard format —
    # measured rc=0 under BOTH v0.8 and HEAD tools before pinning (the v1.2 fix
    # is args-layer only; parse/verify bytes are strictness-additive).
    "v1.2-write-empty.md": 0,
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
    try:  # hang-door guard (c113): wedged git child would freeze the guard
        p = subprocess.run(["git", "show", f"{BASELINE_TAG}:ethkey.py"],
                           cwd=ROOT, capture_output=True, text=True,
                           timeout=60)
    except subprocess.TimeoutExpired:
        fail(f"git show timed out after 60s (wedged git child?)")
        return None
    if p.returncode != 0 or "def verify_proof" not in p.stdout:
        fail(f"cannot materialize ethkey.py@{BASELINE_TAG} via git show "
             f"(rc={p.returncode}); refusing a vacuous guard")
        return None
    with open(out_path, "w") as f:
        f.write(p.stdout)
    return out_path


def run_verify(tool_path, fixture_path):
    # 120s: this child is the TOOL itself — a tool-side hang (c111 class)
    # must surface as a loud guard failure, not a frozen CI job.
    try:
        p = subprocess.run([sys.executable, tool_path, "verify", fixture_path,
                            "--require", SIGNER],
                           capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        fail(f"tool verify child timed out after 120s (tool hang?)")
        return 2, ""
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
        exp_old = exp.get("old") if isinstance(exp, dict) else exp
        exp_head = exp.get("head") if isinstance(exp, dict) else exp
        # leg 1: both match the pinned expectation (pair = deliberate flip)
        if rc_old != exp_old:
            fail(f"{f}: {BASELINE_TAG}-tool rc={rc_old}, expected {exp_old} "
                 "(fixture or baseline drifted — investigate before merging)")
        if rc_head != exp_head:
            fail(f"{f}: HEAD rc={rc_head}, expected {exp_head} — "
                 + ("RE-LENIENTING: HEAD accepts what the pin demands it reject"
                    if rc_head == 0 else "regression: HEAD rejects a pinned accept"))
        # leg 2: old == head UNLESS the EXPECTED pair declares a deliberate
        # strictness change (dict form); an undeclared flip is still RED.
        if isinstance(exp, dict):
            if rc_old == rc_head:
                fail(f"{f}: pinned {exp_old}->{exp_head} deliberate flip did NOT "
                     f"occur (both rc={rc_old}) — fixture or fix rotted")
        elif rc_old != rc_head:
            fail(f"{f}: DIVERGENCE {BASELINE_TAG} rc={rc_old} vs HEAD rc={rc_head}")
        if rc_head == 0 and out_head != out_old:
            fail(f"{f}: both rc=0 but output differs — the pinned "
                 "'result: OK' contract text changed")
        if rc_old == exp_old and rc_head == exp_head and (isinstance(exp, dict) or rc_old == rc_head):
            ok(f"{f}: rc={rc_head} (pinned {exp}) {BASELINE_TAG}==HEAD" if not isinstance(exp, dict)
               else f"{f}: deliberate pin {exp_old}->{exp_head} held ({BASELINE_TAG} rc={rc_old}, HEAD rc={rc_head})")

    if failures:
        print(f"same-ref guard: FAILED ({len(failures)} failures)")
        return 1
    ok(f"same-ref guard: {len(fixtures)} fixtures, {BASELINE_TAG}==HEAD, "
       "all verdicts match the pinned EXPECTED table")
    return 0


if __name__ == "__main__":
    sys.exit(main())

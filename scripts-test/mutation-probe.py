#!/usr/bin/env python3
"""c32 mutation probe: stranger-side parity check for ethkey-lite's verifier.

Why: C's c25 fixed a lenient recovery-id parser that existed AT tag v0.7
(the exact ref every fleet consumer CI pins). C proved the fix on `main`.
This probe proves it from the OUTSIDE, fixture-driven, no code assumptions:

  1. fetch ethkey.py at two refs (default: v0.7 tag vs main),
  2. take ANY signed fixture/receipt, mutate ONLY trust-critical fields
     (v byte -> 1a/1d/05, r -> 0),
  3. run BOTH tools over the whole set,
  4. print the DIFF rows: mutants the pinned tool ACCEPTS that the strict
     tool rejects = live leniency surface.

Exit 0 = zero divergence rows (pinned tool is as strict as the strict ref).
Exit 1 = divergence found (pinned ref accepts malformed sigs).
Exit 2 = harness/environment error (loud, never vacuous — assert-first).

Usage:
  python3 mutation-probe.py [--old PATH] [--new PATH] [--fixture F]...
Defaults: fetches v0.7 + main ethkey.py over HTTPS, uses the 3 public
fixtures in --fixture-dir (default ./). Requires pycryptodome.

Ported to: C (offer, c32) — portability notes in RESULT.md.
"""
import argparse, os, re, subprocess, sys, tempfile, urllib.request

MUTATIONS = {
    # name -> (transform on 130-hex sig)
    'v=1a(26)':  lambda s: s[:-2] + '1a',   # the exact c25 defect byte
    'v=1d(29)':  lambda s: s[:-2] + '1d',
    'v=05':      lambda s: s[:-2] + '05',
    'v=ff(255)': lambda s: s[:-2] + 'ff',   # C's c27 addition: rec_id 228,
                                             # parity 0 — accepts every true
                                             # rec_id-0 receipt; a THIRD live
                                             # variant of the same class
    'r=0':       lambda s: '0' * 64 + s[64:],
}

def fetch(url, dest):
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    data = urllib.request.urlopen(req, timeout=30).read()
    open(dest, 'wb').write(data)
    return data

def sig_of(text):
    m = re.search(r'signature: 0x([0-9a-fA-F]{130})', text)
    if not m:
        sys.exit(2)  # assert-first: fixture shape wrong -> die loud, not vacuous
    return m.group(1)

def run(tool, proof, require=None):
    cmd = ['python3', tool, 'verify', proof] + (['--require', require] if require else [])
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--old', default=None, help='pinned/lenient ethkey.py path (default: fetch v0.7)')
    ap.add_argument('--new', default=None, help='strict ethkey.py path (default: fetch main)')
    ap.add_argument('--fixture-dir', default='.')
    ap.add_argument('--fixtures', nargs='*', default=None)
    a = ap.parse_args()

    tmp = tempfile.mkdtemp(prefix='c32-probe.')
    old = a.old or fetch('https://raw.githubusercontent.com/tianzhicdev/ethkey-lite/v0.7/ethkey.py',
                         os.path.join(tmp, 'ethkey_old.py'))
    if a.old is None:
        old = os.path.join(tmp, 'ethkey_old.py')
    new = a.new or fetch('https://raw.githubusercontent.com/tianzhicdev/ethkey-lite/main/ethkey.py',
                         os.path.join(tmp, 'ethkey_new.py'))
    if a.new is None:
        new = os.path.join(tmp, 'ethkey_new.py')

    fixtures = a.fixtures or sorted(
        f for f in os.listdir(a.fixture_dir)
        if f.endswith('.md') and 'fixture' in f)
    if not fixtures:
        sys.exit(2)  # no fixtures = vacuous probe = failure, not success

    divergences = []
    for fname in fixtures:
        text = open(os.path.join(a.fixture_dir, fname)).read()
        sig = sig_of(text)
        cases = [('baseline', text)] + [(m, text.replace(sig, fn(sig))) for m, fn in MUTATIONS.items()]
        for mname, mutated in cases:
            pf = os.path.join(tmp, f'{fname}-{mname}.md'.replace('=', '').replace('(', '_').replace(')', ''))
            open(pf, 'w').write(mutated)
            rc_old = run(old, pf)
            rc_new = run(new, pf)
            tag = f'{fname} {mname}'
            if rc_old == 0 and rc_new != 0:
                divergences.append(tag)
                print(f'DIVERGE: pinned accepts, strict rejects: {tag}')
            elif rc_old != rc_new:
                # both reject but differently (e.g. traceback vs clean exit) — still report
                print(f'NOTE: verdict-shape differs: {tag} (old rc={rc_old}, new rc={rc_new})')
            else:
                print(f'agree: {tag} (rc={rc_old})')

    print(f'---\nfixtures={len(fixtures)} cases={len(fixtures)*(len(MUTATIONS)+1)} divergences={len(divergences)}')
    sys.exit(1 if divergences else 0)

if __name__ == '__main__':
    main()

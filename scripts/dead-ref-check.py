#!/usr/bin/env python3
"""Dead-reference rail (c41, own-lane plan-(d) candidate): names that no
longer name a file.

The artifact-hygiene rail (c40) checks that no TRACKED file lacks a referrer.
This rail walks the inverse arrow: every REFERENCE a stranger or a CI step
follows must still name something that exists. A stale exclusion file, a
gitignore line that names a tracked file, or a README path that rotted after
a rename are all SILENT lies: nothing crashes, the reader just 404s or the
guard watches nothing. Same index-authority convention as c40 (git ls-files
is the truth of what exists; the disk is not).

Checks (exit 1 on any violation, exit 2 on missing inputs — fail-closed):
  A. README prose paths. Outside ``` fences, every inline-code token that is
     a path (contains '/', no '@', no leading 'tianzhicdev/' = external-repo
     ref) and every RELATIVE markdown link ](path) must resolve to a tracked
     FILE or a tracked-directory prefix. Fenced blocks are copy-paste
     snippets for the CONSUMER's repo (proofs/release-proof.md = "in YOUR
     repo"), so prose-scope is the honest boundary — documented, not guessed.
     RUNTIME-SCOPE exclusion: a reference whose FIRST path component is
     `.git` names git's own private dir in whichever working tree it lives
     in — git never tracks `.git/`, so such a path can NEVER be an index
     entry and checking it is a category error. (Found by running this rail
     over sibling repos 2026-08-31: hookpack's README honestly references
     `.git/hooks/pre-commit` / `.git/hookpack/cache/` — its whole product
     installs INTO .git — and the rail false-RED'd them. The exclusion is
     FIRST-component-only: `src/.git/bait.md` still goes RED, flip F8.)
  B. .secretgateignore liveness (if present): every non-comment pattern must
     match >=1 tracked path, using secretgate's real semantics (exact path,
     'dir/' prefix, or fnmatch). A pattern matching NOTHING is a dead
     exclusion — config drift that will silently stop meaning anything, and
     the day proofs/ is renamed it masks the fact the ignore no longer
     covers what it was written for.
  C. .gitignore vs INDEX (if present): no TRACKED path may match an active
     (un-negated) pattern — a gitignore line naming a tracked file is the
     c40 accident in its latent form: the ignore rule LIES because
     gitignore never untracks, and the file stays tracked + public while the
     config claims otherwise.

Stdlib only; git via subprocess; run from the repo root.
"""
import fnmatch
import subprocess
import sys
from pathlib import Path

README = "README.md"
EXCLUDES = ".secretgateignore"
GITIGNORE = ".gitignore"
EXTERNAL_PREFIX = "tianzhicdev/"  # cross-repo refs, not repo-local paths


def die(msg, code=1):
    print(f"FAIL: {msg}")
    sys.exit(code)


def ok(msg):
    print(f"OK: {msg}")


def tracked_files():
    r = subprocess.run(["git", "ls-files"], capture_output=True, text=True)
    if r.returncode != 0:
        die("git ls-files failed: " + r.stderr.strip(), 2)
    files = r.stdout.split()
    if not files:
        die("git ls-files returned zero paths (empty index? vacuous rail)", 2)
    return files


def tracked_dirs(files):
    dirs = set()
    for f in files:
        parts = f.split("/")[:-1]
        for i in range(1, len(parts) + 1):
            dirs.add("/".join(parts[:i]))
    return dirs


def read(path):
    p = Path(path)
    if not p.is_file():
        return None
    return p.read_text(encoding="utf-8")


def readme_prose(text):
    """README with ``` fenced blocks removed (odd-count fences are malformed
    -> fail-closed: a rail that guesses fence state is a rail that goes blind
    on the day someone forgets to close one)."""
    if text.count("```") % 2 != 0:
        die("README has an unterminated ``` fence — refusing to guess prose scope", 2)
    out, in_fence = [], False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence:
            out.append(line)
    return "\n".join(out)


def ignore_patterns(text):
    return [l.strip() for l in text.splitlines()
            if l.strip() and not l.strip().startswith("#")]


def matches_ignore_pattern(pat, path):
    """Simplified gitignore/secretgate matching: exact, dir-prefix, or
    fnmatch on full path / basename ('*' does not cross '/')."""
    if pat.startswith("!"):
        return None  # negation: skip conservatively (none in use; documented)
    p = pat.rstrip("/")
    if path == p or path.startswith(p + "/"):
        return True
    base = path.split("/")[-1]
    if fnmatch.fnmatch(path, pat) or fnmatch.fnmatch(base, pat):
        return True
    return False


def main():
    files = tracked_files()
    dirs = tracked_dirs(files)
    fails = 0

    # --- A. README prose paths -------------------------------------------
    readme = read(README)
    if readme is None:
        die(f"{README} missing (this rail's primary surface — refusing vacuous OK)", 2)
    prose = readme_prose(readme)
    refs = []
    import re
    for m in re.finditer(r"`([^`\n]+)`", prose):
        s = m.group(1).strip()
        if "/" not in s or "@" in s or " " in s or s.startswith(EXTERNAL_PREFIX):
            continue
        if re.fullmatch(r"\.{0,2}/?[\w.\-]+(/[\w.\-]+)*/?", s):
            refs.append(s)
    for m in re.finditer(r"\]\((?!https?://|mailto:|#|/)([^)#\s]+)", prose):
        refs.append(m.group(1))
    seen, dead = set(), []
    for r_ in refs:
        rel = r_[2:] if r_.startswith("./") else (r_[1:] if r_.startswith("/") else r_)
        rel = rel.rstrip("/")
        if rel.split("/")[0] == ".git":
            continue  # runtime-scope: git's own dir, never indexable (see docstring)
        if rel in seen:
            continue
        seen.add(rel)
        if rel not in files and rel not in dirs:
            dead.append(r_)
    for d in dead:
        print(f"FAIL: README references a path that is not tracked: {d}")
        fails += 1
    if not dead:
        ok(f"README prose paths all resolve ({len(seen)} checked: files + dirs)")

    # --- B. .secretgateignore liveness ------------------------------------
    ex = read(EXCLUDES)
    if ex is None:
        ok(f"{EXCLUDES} absent — layer skipped by design (scan strict by default)")
    else:
        pats = ignore_patterns(ex)
        dead_pats = [p for p in pats
                     if not any(matches_ignore_pattern(p, f) for f in files)]
        for p in dead_pats:
            print(f"FAIL: {EXCLUDES} pattern matches ZERO tracked paths: {p}")
            fails += 1
        if not dead_pats:
            ok(f"{EXCLUDES}: all {len(pats)} exclusions match >=1 tracked path")

    # --- C. .gitignore vs INDEX --------------------------------------------
    gi = read(GITIGNORE)
    if gi is None:
        ok(f"{GITIGNORE} absent — layer skipped by design")
    else:
        pats = ignore_patterns(gi)
        conflicts = []
        for p in pats:
            if p.endswith("/"):
                continue  # dir-only pattern can't match an index entry
            hits = [f for f in files if matches_ignore_pattern(p, f)]
            if hits:
                conflicts.append((p, hits))
        for p, hits in conflicts:
            print(f"FAIL: {GITIGNORE} pattern '{p}' names TRACKED file(s) "
                  f"(gitignore never untracks — c40 class): {', '.join(sorted(hits)[:5])}")
            fails += 1
        if not conflicts:
            ok(f"{GITIGNORE}: no pattern conflicts with the index ({len(pats)} patterns)")

    if fails:
        print(f"dead-ref-check: {fails} violation(s)")
        return 1
    print("dead-ref-check: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())

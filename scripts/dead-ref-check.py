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
     The predicate runs on the CANONICALIZED form (`posixpath.normpath` at
     collection, c52): a prefix-string carve-out is a path test — resolve
     before you match. `.git/../real.md` resolves OUT of .git and is checked
     like any repo-local ref (riding the carve-out un-normalized was the
     traversal class B c47 measured and my own probe reproduced here);
     `../out.md` never normalizes into the index and goes RED honestly.
     The exemption PRINTS its count on the OK line (A c51 F7 rule, turned on
     my own rail c45): a silent carve-out is a hole with a name, and the
     count is what lets the flip harness assert the exemption fired on
     EXACTLY the mutated ref. A c52 asked whether a TRACKED `.git/...` path
     would ride this exemption; measured (c45, git 2.43): no such index entry
     is constructible — `git add`/`add -f` silently ignore `.git/` paths
     (rc=0, zero entries), `update-index` prints 'Ignoring path', and
     `read-tree`/`reset --hard` of a plumbing-crafted tree fail
     'invalid path .git/...'. The exemption can never mask a tracked file
     because the tracked file cannot exist; tracked-first ORDER is therefore
     not needed here (documented, not assumed).
     SCOPE-ASSERT (B c45 offer, shipped A-shape via A c56): the exemption
     set itself is audited — every exempted name must be `.git` or start
     with `.git/` (canonical, normalized-at-collection form), else it is a
     DEAD REF R IDING THE CARVE-OUT and the run goes RED naming each such
     name as 'carve-out: <name>'. Without this, the exempt-everything
     mutant (branch condition -> always true) swallowed every dead ref and
     still printed rc=0; only the flip harness knew. Now the VERDICT knows:
     same rc=1, different authority — the RED names 'carve-out', never
     'not tracked', so a reader can tell which leg killed it (A c56
     precision lesson). The predicate is membership-strict (== '.git' or
     startswith '.git/'): a startswith('.git') mutant would exempt
     `.github/workflows/x` and still pass a sloppy scope test — measured
     before shipped.
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
import posixpath
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
    runtime_skipped = []
    for r_ in refs:
        rel = r_[2:] if r_.startswith("./") else (r_[1:] if r_.startswith("/") else r_)
        # NORMALIZE ONCE at collection (B c47 lesson, traversal half from my
        # own probe): `.git/../c52-missing.md` has first component `.git` and
        # rides the carve-out rc=0 while it ACTUALLY resolves to a repo-local
        # path. Resolve before you match — a prefix-string carve-out is a path
        # test. After normpath, `.git` is only exempt if the path really is
        # under git's dir; `../x` keeps its leading `..` (never an index
        # entry -> plain dead ref, honest RED).
        rel = posixpath.normpath(rel)
        if rel.split("/")[0] == ".git":
            runtime_skipped.append(rel)  # runtime-scope, never indexable (docstring)
            continue
        if rel in seen:
            continue
        seen.add(rel)
        if rel not in files and rel not in dirs:
            dead.append(r_)
    for d in dead:
        print(f"FAIL: README references a path that is not tracked: {d}")
        fails += 1
    # SCOPE-ASSERT (B c45 offer, A c56 shape): the exemption set is audited
    # INDEPENDENTLY of the branch that filled it. The branch predicate above
    # can be mutated (exempt-everything) while this predicate stays honest —
    # two sites, same truth, and a mutant that edits one is caught by the
    # other. Membership-strict on the CANONICAL (normalized-at-collection)
    # form: `== ".git"` or `.git/` prefix. A sloppier startswith(".git")
    # scope test would bless a `.github/...` swallow — measured, see V-class
    # flips in dead-ref-flip-harness.sh.
    uniq_rt = sorted(set(runtime_skipped))
    over = [n for n in uniq_rt if n != ".git" and not n.startswith(".git/")]
    for n in over:
        print(f"FAIL: exemption outside .git/ carve-out: {n}")
        fails += 1
    if not dead and not over:
        # printed exemption count (A c51 rule): the carve-out never skips
        # silently, and a flip can assert it fired on EXACTLY its mutation.
        ok(f"README prose paths all resolve ({len(seen)} checked: files + dirs; "
           f"runtime-scope .git/ exemptions: {len(uniq_rt)}"
           + (f" [{', '.join(uniq_rt)}]" if uniq_rt else "") + ")")

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

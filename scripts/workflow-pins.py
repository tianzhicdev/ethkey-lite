#!/usr/bin/env python3
"""Tripwire: every `uses:` step this repo's CI executes is a content address.

B's railsite c31 class (docpins mode 'workflow'), ported and hardened: the
frozen-engine-default defect (B c30 / C c31) was pin-by-REFERENCE biting from
one layer in; a movable `@vN` tag is the same float class one layer OUT — the
v4 tag on actions/checkout is the head of a force-movable backport branch, so
a supplier force-move swaps the code our gates execute with zero commits on
our side.

Method: a PURPOSE-BUILT indent walk (pure stdlib — the runner's dogfood job
has pycryptodome only, PyYAML absent; C c21 blind-spot lesson: never let the
host's package set masquerade as the runner's). It tracks the indent column
of a 'jobs:' block and only treats `uses:` as a step/job ref while inside
that subtree, so `run:` block scalars and `# comment: uses: ...` prose are
structurally invisible (B's c30 vacuous-assert lesson, achieved without a
YAML parser). Job-level `uses:` (workflow_call) and composite `runs:` steps
are inside the tracked subtree and get collected.

Allowed shapes:
  - 40-hex commit sha            (content address)
  - './...'                      (local, same commit)
  - same-repo workflow_call ref  (own tag; author's own force-move is an
                                  authored action, and the tag value is
                                  cross-pinned by the 4-surface step)
Anything else (notably a bare @vN third-party/cross-repo tag) FAILS.

Anti-vacuous legs (c27 class): zero collected uses: steps FAIL, and a
cross-repo secretgate-action ref must agree with the secrets.yml PIN_ACTION_REF
env (leg 1 pins the bytes of the ref that EXECUTES — if the two ever diverge,
the pin proves the wrong bytes).

Exit codes: 0 all refs content-addressed, 1 a ref or rail is red, 2 bad usage.
"""
import os
import re
import sys

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
OWN_REPO = "tianzhicdev/ethkey-lite"
SECRETGATE_ACTION = "tianzhicdev/secretgate-action"
KEY_RE = re.compile(r"^([A-Za-z0-9_.-]+):\s*(.*)$")


def strip_comment(line):
    # naive but sufficient for our own files: '#' outside quotes starts a comment
    in_s = in_d = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s:
            in_d = not in_d
        elif ch == "#" and not in_s and not in_d:
            return line[:i]
    return line


def walk_yaml(path):
    """Yield (indent, key, value) for plain `key: value` lines that are OUTSIDE
    block scalars ('|' / '>') and not inside a block scalar's indented body.
    Also yield ('- uses', indent_of_dash, value) for '- uses: value' items."""
    out = []
    block_scalar_indent = None  # lines with indent >= this are opaque
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            stripped = line.strip()
            indent = len(line) - len(line.lstrip(" "))
            if not stripped:
                continue
            if block_scalar_indent is not None:
                if indent >= block_scalar_indent:
                    continue  # opaque body
                block_scalar_indent = None
            content = strip_comment(line).rstrip()
            body = content.lstrip(" ")
            if not body:
                continue
            ind = len(content) - len(body)
            # list item form: "- key: value" (treat the dash as +2 indent)
            if body.startswith("- "):
                m = KEY_RE.match(body[2:].strip())
                if m:
                    key, val = m.group(1), m.group(2).strip()
                    # dash-prefix EVERY first key of a list item: the walker
                    # can't know which key opens the item ('- name:' opens most
                    # steps, '- uses:' opens some), and collect_uses needs the
                    # marker to know an item BEGAN at this indent.
                    out.append((ind + 2, "-" + key, val))
                    if val in ("|", ">", "|-", ">-", "|+", ">+"):
                        block_scalar_indent = ind + 2
                continue
            m = KEY_RE.match(body)
            if m:
                key, val = m.group(1), m.group(2).strip()
                out.append((ind, key, val))
                if val in ("|", ">", "|-", ">-", "|+", ">+"):
                    block_scalar_indent = ind + 1
    return out


def collect_uses(path):
    """Return list of (label, uses_value) from the jobs: subtree + top-level
    runs: (composite action.yml)."""
    lines = walk_yaml(path)
    out = []
    # find the indent of 'jobs:' (top level) and 'runs:' for composites
    def subtree_lines(root_key):
        root = [ind for (ind, k, v) in lines if k == root_key and ind == 0]
        if not root:
            return []
        ri = root[0]
        sub = []
        seen = False
        for (i, k, v) in lines:
            if not seen:                      # only AFTER the root key line
                if (i, k) == (ri, root_key):
                    seen = True
                continue
            if i > ri:
                sub.append((i, k, v))
            else:
                break
        return sub

    labels = []
    jobs = subtree_lines("jobs")
    if jobs:
        depth2 = min(x for (x, _k, _v) in jobs)          # job-name indent
        job_name = "<job>"
        in_steps = False
        steps_indent = None
        step_item = None    # (indent_of_dash, name) of current '- ' list item
        for (i, k, v) in jobs:
            if i == depth2:                              # new job starts
                job_name, in_steps, steps_indent, step_item = k, False, None, None
            if k == "steps":
                in_steps, steps_indent = True, i
                continue
            if in_steps and steps_indent is not None and i <= steps_indent:
                in_steps, step_item = False, None        # left the steps block
            if k.startswith("-"):                        # new list item starts
                step_item = (i, None)
                if k == "-name":
                    step_item = (i, v.strip("'"))
            elif step_item is not None and i >= step_item[0]:
                # continuation key of the current '- ' item (YAML allows the
                # item's own keys at the dash's own indent, e.g. '- name:' then
                # a sibling 'uses:' at the SAME column — verified-release.yml
                # has exactly that shape; strict '>' missed a real step)
                if k == "name":
                    step_item = (step_item[0], v.strip("'"))
                elif k == "uses":
                    labels.append((f"{job_name}: {step_item[1] or 'step'}", v))
                    continue
            if k == "-uses" and in_steps:
                nm = step_item[1] if step_item else None
                labels.append((f"{job_name}: {nm or 'step'}", v))
            elif k == "uses" and not in_steps:
                labels.append((f"job {job_name}", v))
    else:
        # composite action.yml: runs: -> steps: -> list items
        runs = subtree_lines("runs")
        in_steps = False
        steps_indent = None
        step_item = None
        for (i, k, v) in runs:
            if k == "steps":
                in_steps, steps_indent = True, i
                continue
            if in_steps and steps_indent is not None and i <= steps_indent:
                in_steps, step_item = False, None
            if k.startswith("-"):
                step_item = (i, v.strip("'") if k == "-name" else None)
            elif step_item is not None and i >= step_item[0] and k == "uses":
                labels.append((f"composite: {step_item[1] or 'step'}", v))
                continue
            if k == "-uses" and in_steps:
                nm = step_item[1] if step_item else None
                labels.append((f"composite: {nm or 'step'}", v))
    for label, v in labels:
        out.append((label, v.strip("'")))
    return out


def allowed(value):
    base = value.split("@", 1)
    target = base[0]
    if value.startswith("./"):
        return True
    if len(base) == 2 and SHA_RE.match(base[1]):
        return True
    if target == f"{OWN_REPO}/.github/workflows/verify-release.yml":
        return True  # same-repo workflow_call; tag value cross-pinned elsewhere
    return False


def main() -> int:
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    if len(sys.argv) > 2:
        print("usage: workflow-pins.py [repo-root]", file=sys.stderr)
        return 2
    targets = []
    gh = os.path.join(root, ".github")
    for dirpath, _dirs, files in os.walk(gh):
        for f in files:
            if f.endswith((".yml", ".yaml")):
                targets.append(os.path.join(dirpath, f))
    if not targets:
        print("::error::no workflow/action YAML found — vacuous, failing.",
              file=sys.stderr)
        return 1
    collected = []
    secrets_pin_env = set()
    for path in sorted(targets):
        uses = collect_uses(path)
        collected += [(path, label, v) for (label, v) in uses]
        if os.path.basename(path) == "secrets.yml":
            for (_i, k, v) in walk_yaml(path):
                if k == "PIN_ACTION_REF":
                    secrets_pin_env.add(v.strip("'\"").split(" #")[0].strip())
    if not collected:
        print("::error::ZERO uses: steps found across the parsed YAML — a "
              "vacuous green tripwire is worse than none; failing.",
              file=sys.stderr)
        return 1
    # cross-check vs grep: any raw 'uses:' line with a value that the walk
    # never collected = walker bug (or prose in a file we should trust less);
    # prose is allowed to differ ONLY inside comments — count non-comment hits.
    bad = 0
    for path, label, value in collected:
        if allowed(value):
            short = value if len(value) < 60 else value[:52] + ".."
            print(f"ok: {os.path.relpath(path, root)} [{label}] -> {short}")
        else:
            print(f"::error::{os.path.relpath(path, root)} [{label}] uses "
                  f"{value!r} — a movable tag. Replace with the exact commit "
                  "sha (gh api repos/<owner>/<repo>/git/ref/tags/<tag>), "
                  "comment the version, repoint any matching PIN_* env.",
                  file=sys.stderr)
            bad = 1
    # consistency rail: leg 1 must pin the bytes of the EXECUTING ref.
    sg_refs = {v.split("@", 1)[1] for _p, _l, v in collected
               if v.startswith(SECRETGATE_ACTION + "@")}
    if sg_refs:
        if sg_refs != secrets_pin_env:
            print(f"::error::secrets.yml uses secretgate-action@{sorted(sg_refs)} "
                  f"but PIN_ACTION_REF = {sorted(secrets_pin_env)} — leg 1 "
                  "would pin bytes other than the ones that execute.",
                  file=sys.stderr)
            bad = 1
        else:
            print(f"ok: PIN_ACTION_REF agrees with the executing "
                  f"secretgate-action ref ({sorted(sg_refs)[0][:8]}..)")
    if bad:
        return 1
    print(f"OK: all {len(collected)} uses: refs content-addressed "
          "(sha / local ./ / same-repo)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

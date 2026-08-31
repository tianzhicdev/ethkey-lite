#!/usr/bin/env python3
"""Tripwire: every `uses:` step this repo's CI executes is a content address.

B's railsite c31 class (docpins mode 'workflow'), ported and hardened: the
frozen-engine-default defect (B c30 / C c31) was pin-by-REFERENCE biting from
one layer in; a movable `@vN` tag is the same float class one layer OUT — the
v4 tag on actions/checkout is the head of a force-movable backport branch, so
a supplier force-move swaps the code our gates execute with zero commits on
our side.

Method (parsed YAML, NOT line-grep — B's own c30 prose lesson: comment text
can contain 'uses:' = vacuous assert bait): load each workflow/action with a
YAML parser and walk every `uses` value at step level AND job level
(workflow_call jobs carry a job-level uses). Comment prose is structurally
invisible to this walk.

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

import yaml

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
OWN_REPO = "tianzhicdev/ethkey-lite"
SECRETGATE_ACTION = "tianzhicdev/secretgate-action"


def collect_uses(doc, path):
    """Yield (path, job_or_step_label, uses_value) from a parsed workflow/action."""
    out = []
    if not isinstance(doc, dict):
        return out
    jobs = doc.get("jobs")
    if isinstance(jobs, dict):
        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            if isinstance(job.get("uses"), str):
                out.append((path, f"job {job_name}", job["uses"]))
            steps = job.get("steps")
            if isinstance(steps, list):
                for i, step in enumerate(steps):
                    if isinstance(step, dict) and isinstance(step.get("uses"), str):
                        label = step.get("name") or f"step#{i}"
                        out.append((path, f"job {job_name}: {label}", step["uses"]))
    # composite action.yml shape: steps live under runs:
    runs = doc.get("runs")
    steps = runs.get("steps") if isinstance(runs, dict) else None
    if isinstance(steps, list):
        for i, step in enumerate(steps):
            if isinstance(step, dict) and isinstance(step.get("uses"), str):
                label = step.get("name") or f"step#{i}"
                out.append((path, f"composite: {label}", step["uses"]))
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
    for dirpath, _dirs, files in os.walk(os.path.join(root, ".github")):
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
        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        collected += collect_uses(doc, path)
        # remember PIN_ACTION_REF values declared in the secrets workflow
        if os.path.basename(path) == "secrets.yml" and isinstance(doc, dict):
            for job in (doc.get("jobs") or {}).values():
                for step in (job or {}).get("steps", []) or []:
                    env = step.get("env") or {}
                    v = env.get("PIN_ACTION_REF")
                    if isinstance(v, str):
                        secrets_pin_env.add(v)
    if not collected:
        print("::error::ZERO uses: steps found across the parsed YAML — a "
              "vacuous green tripwire is worse than none; failing.",
              file=sys.stderr)
        return 1
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

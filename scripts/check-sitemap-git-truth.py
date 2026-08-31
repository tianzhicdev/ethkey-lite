#!/usr/bin/env python3
"""Multi-page sitemap lastmod freshness contract (A c28 script generalized).

A's secretgate port handles a single-URL sitemap. ethkey-lite's sitemap lists
three pages (/, receipt.html, verify.html), so the pin is per-URL: every
<loc> maps to a committed page file, and every <lastmod> must equal the
committer date (short) of the most recent commit touching THAT page. Page
edited without its sitemap row updated = red (B c22 stale-companion class,
the strongest form for a hand-written site: lastmod == git truth, not
generator-emitted truth).

Checks (all must hold or exit 1):
  1. sitemap.xml parses (minidom), root <urlset>.
  2. Every <url> has exactly one <loc> + one <lastmod>; loc set == EXPECTED.
  3. loc -> committed page file (BASE root maps to index.html).
  4. lastmod is a valid ISO date AND == `git log -1 --date=short -- <page>`.

No third-party imports; git via subprocess. Run from the repo root (CI must
checkout with fetch-depth: 0 so full history is available).
"""
import datetime
import subprocess
import sys
from pathlib import Path
from xml.dom import minidom

BASE = "https://tianzhicdev.github.io/ethkey-lite"
SITEMAP = "sitemap.xml"
EXPECTED = {f"{BASE}/", f"{BASE}/receipt.html", f"{BASE}/verify.html"}


def die(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def ok(msg):
    print(f"OK: {msg}")


def page_for(loc):
    """Map a <loc> URL to its committed repo path."""
    rel = loc[len(BASE):].lstrip("/") if loc.startswith(BASE) else None
    if rel is None:
        die(f"<loc> {loc!r} is not under {BASE}")
    return rel if rel else "index.html"


def main():
    root = Path(__file__).resolve().parent.parent
    sm = root / SITEMAP
    if not sm.is_file():
        die(f"{SITEMAP} missing")
    try:
        dom = minidom.parseString(sm.read_bytes())
    except Exception as e:  # noqa: BLE001 - report any parse failure
        die(f"{SITEMAP} does not parse: {e}")
    if dom.documentElement.tagName != "urlset":
        die(f"root element is <{dom.documentElement.tagName}>, expected <urlset>")

    urls = dom.getElementsByTagName("url")
    if not urls:
        die("sitemap has no <url> entries")
    seen = set()
    for u in urls:
        locs = u.getElementsByTagName("loc")
        mods = u.getElementsByTagName("lastmod")
        if len(locs) != 1 or len(mods) != 1:
            die(f"every <url> needs exactly one loc + one lastmod, got "
                f"{len(locs)} loc / {len(mods)} lastmod")
        loc = locs[0].firstChild.data.strip()
        lastmod = mods[0].firstChild.data.strip()
        seen.add(loc)
        page = page_for(loc)
        if not (root / page).is_file():
            die(f"<loc> {loc} maps to {page}, not committed")
        try:
            datetime.date.fromisoformat(lastmod)
        except ValueError:
            die(f"<lastmod> '{lastmod}' for {page} is not an ISO date")
        try:  # hang-door guard (c113): wedged git child would freeze the check
            git = subprocess.run(
                ["git", "log", "-1", "--format=%cd", "--date=short", "--", page],
                cwd=root, capture_output=True, text=True, timeout=60,
            )
        except subprocess.TimeoutExpired:
            print(f"FAIL: git log timed out after 60s for {page}")
            sys.exit(2)
        if git.returncode != 0:
            die(f"git log failed for {page}: {git.stderr.strip()}")
        truth = git.stdout.strip()
        if not truth:
            die(f"git log found no commit touching {page} "
                "(shallow checkout? CI must use fetch-depth: 0)")
        if lastmod != truth:
            die(f"sitemap lastmod '{lastmod}' for {page} != last commit date "
                f"'{truth}' — update {SITEMAP} in this commit (stale "
                f"companion, B c22 class)")
        ok(f"{page}: lastmod tracks git truth ({truth})")
    if seen != EXPECTED:
        die(f"sitemap loc set {sorted(seen)} != expected {sorted(EXPECTED)}")
    print(f"PASS: {len(urls)} sitemap rows, loc set exact, lastmod == git truth")


if __name__ == "__main__":
    main()

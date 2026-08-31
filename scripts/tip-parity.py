#!/usr/bin/env python3
"""Tip-address parity contract (B c29 rail shape, A c42 port, C c38 layers).

Every copy of THIS repo's tip address must be the one address, and the
footer of the DEPLOYED page must equal the committed one. B's c29 audit
proved the danger class: a whole-page membership test on a page that
legitimately carries SIBLING fleet addresses (fleet deep links, team
footers) is forge-friendly — mutating the tip to a sibling addr stayed
green. So: compare footer-scoped SETS with exactly-one semantics, never
page-wide membership, and include the sibling addresses in a reject list.

A's port (c42) pinned the RECEIVE side of HIS pages; this is the mirrored
port for ethkey-lite — the repo whose tip addr doubles as the fleet's
signer anchor, so the signer==tip identity leg here reads the FLEET
trust-anchor table itself (A's layer-6 read his verify-release values;
mine read receipt.html, the page the whole fleet deep-links into).

Layers checked (all must hold or exit 1):
  1. index.html <footer> region carries EXACTLY ONE distinct EVM address
     and it == TIP_ADDR; A/B fleet addrs in the footer are a hard FAIL.
  2. Deployed Pages footer (live urllib fetch, browser UA, no-cache) has
     the same footer address set AND its address-bearing lines byte-match
     the committed footer's (B c29 live leg; c32 retry shape: 4 attempts,
     2/4/6s backoff, fail-closed at the cap).
  3. .github/FUNDING.yml custom list == {TIP} (exactly-one semantics).
  4. README team-footer block: the LAST (C-labelled) addr == TIP.
     (A's shape asserted the FIRST addr there = his tip; the team-footer
     line enumerates A/B/C in order, so C's copy is the last one.)
  5. receipt.html FLEET table: the ethkey-lite row's signer == TIP —
     signer==tip identity split now needs a deliberate edit, silent
     drift = RED (A's c42 layer-6 class, applied to the verify-side
     anchor because on THIS repo the anchor IS the tip).
  6. SECURITY.md (if present): every addr == TIP (single-mailbox rule).
  7. REJECT sweep: A's and B's fleet addrs must never appear in a
     RECEIVE-side layer (footer, FUNDING, README body outside the
     team-footer) — EXCEPT inside `require=` deep-link values, which are
     verify-side links the c20 mismatch rule already governs. A receive-
     side copy swapped to a sibling is the c29 forge class.

No third-party imports (stdlib urllib only). Run from the repo root.
"""
import re
import sys
import time
import urllib.request

TIP_ADDR = "0xf232dcdc177b53981b4d805a48c79f239db8d0f9"  # secretgate: allow public tip addr
SITE_PAGE = "https://tianzhicdev.github.io/ethkey-lite/index.html"
FLEET_OTHERS = {  # sibling fleet addrs: a tip copy swapped to one of these = forgery class
    "0xfd4090e27c1f946ff01a265caa7d4aca662acc15": "A",
    "0x5439bc46ac9cc70dfffc500611c6d845d7ee9ee5e": "B",
}

ADDR_RE = re.compile(r"0x[0-9a-fA-F]{40}")
failures = []


def die(msg):
    failures.append(msg)
    print(f"FAIL: {msg}")


def ok(msg):
    print(f"OK: {msg}")


def addrs(text):
    """Distinct addresses in text, lower-cased, document order."""
    seen, out = set(), []
    for m in ADDR_RE.findall(text):
        k = m.lower()
        if k not in seen:
            seen.add(k)
            out.append(k)
    return out


def check_receive_side(layer, text):
    """Address set of a receive-side layer must be exactly {TIP}."""
    a = addrs(text)
    if a == [TIP_ADDR.lower()]:
        ok(f"{layer}: exactly one addr, == TIP")
    else:
        die(f"{layer}: address set {a} != [TIP {TIP_ADDR}] "
            f"(sibling/fleet addr in receive-side layer = B c29 forge class)")


def footer_of(page_html):
    m = re.search(r"<footer\b.*?</footer>", page_html, re.S)
    if not m:
        die("no <footer> region found")
        return ""
    return m.group(0)


def fetch_live(url):
    """urllib + browser UA + no-cache (B c17 CDN-read class), 4-attempt
    backoff (A c32/B c32 retry class) so a mid-deploy or CDN flake retries
    but a real mismatch — or a dead route — fails closed at the cap."""
    last = None
    for i in range(1, 5):
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) tip-parity/1",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
            })
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.read().decode("utf-8")
        except Exception as e:  # noqa: BLE001 — retry any transport error, fail closed at cap
            last = e
            if i < 4:
                time.sleep(2 * i)
    die(f"live fetch failed after 4 attempts ({url}): {last}")
    return None


def main():
    page = open("index.html", encoding="utf-8").read()

    # 1. committed footer: exactly-one addr set, == TIP
    foot = footer_of(page)
    if foot:
        check_receive_side("committed footer", foot)

    # 2. live footer: same addr set AND same addr-bearing lines byte-match
    live = fetch_live(SITE_PAGE)
    if live is not None:
        live_foot = footer_of(live)
        if live_foot:
            check_receive_side("live footer", live_foot)
            committed_lines = sorted(
                ln.strip() for ln in foot.splitlines() if ADDR_RE.search(ln))
            live_lines = sorted(
                ln.strip() for ln in live_foot.splitlines() if ADDR_RE.search(ln))
            if committed_lines == live_lines:
                ok(f"live footer == committed footer ({len(committed_lines)} addr-bearing lines byte-match)")
            else:
                die("live footer != committed footer (deployed artifact drifted "
                    "from git — B c29 live-leg class)")

    # 3. FUNDING.yml
    funding = open(".github/FUNDING.yml", encoding="utf-8").read()
    check_receive_side("FUNDING.yml", funding)

    # 4. README team-footer block: C-labelled (last) addr == TIP
    readme = open("README.md", encoding="utf-8").read()
    team = re.search(r"<!-- team-footer:start -->.*?<!-- team-footer:end -->",
                     readme, re.S)
    body = re.sub(r"<!-- team-footer:start -->.*?<!-- team-footer:end -->",
                  "", readme, flags=re.S)
    if not team:
        die("README team-footer block missing (silent-unpin class, c27)")
    else:
        last = addrs(team.group(0))[-1:]
        if last == [TIP_ADDR.lower()]:
            ok("README team-footer: last (C-labelled) addr == TIP")
        else:
            die(f"README team-footer last addr {last} != TIP "
                "(fleet line order changed or C's copy swapped)")

    # 5. receipt.html FLEET table: ethkey-lite signer == TIP (signer==tip)
    fleet_html = open("receipt.html", encoding="utf-8").read()
    own = re.search(r"\{\s*repo:\s*'ethkey-lite',\s*signer:\s*'(0x[0-9a-fA-F]{40})'\s*\}",
                    fleet_html)
    if not own:
        die("receipt.html: FLEET ethkey-lite row not found (locator drifted "
            "= silent-skip class)")
    elif own.group(1).lower() != TIP_ADDR.lower():
        die(f"receipt.html FLEET ethkey-lite signer {own.group(1)} != TIP "
            "(verify-side anchor and receive-side tip split = A c42 "
            "signer-value class)")
    else:
        ok("receipt.html FLEET: ethkey-lite signer == TIP (anchor==tip identity pinned)")

    # 6. SECURITY.md if present
    try:
        sec = open("SECURITY.md", encoding="utf-8").read()
        check_receive_side("SECURITY.md", sec)
    except FileNotFoundError:
        ok("SECURITY.md absent — layer skipped by design")

    # 7. REJECT sweep: sibling fleet addrs must never appear in a
    #    RECEIVE-side layer. Verify-side `require=` deep-link values are
    #    scrubbed FIRST — they legitimately carry sibling addrs (fleet
    #    deep links), and the c20 mismatch rule already governs them.
    def scrub_verify_side(text):
        return re.sub(r"require=0x[0-9a-fA-F]{40}", "require=<verify-side>", text)

    for name, txt in [("index.html", page),
                      (".github/FUNDING.yml", funding),
                      ("README.md (outside team-footer)", scrub_verify_side(body))]:
        for a in addrs(scrub_verify_side(txt)):
            if a in FLEET_OTHERS:
                die(f"{name}: sibling addr {a} ({FLEET_OTHERS[a]}) present — "
                    "tip copy swapped to a fleet sibling")
    ok("REJECT sweep: no sibling fleet addr in any receive-side layer")

    if failures:
        print(f"\n{len(failures)} failure(s)")
        sys.exit(1)
    ok("tip parity: every layer agrees on one address, live == committed")


if __name__ == "__main__":
    main()

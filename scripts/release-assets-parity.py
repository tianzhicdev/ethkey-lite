#!/usr/bin/env python3
"""Release assets <-> committed proofs parity (c28 rail, extracted + token-authed c43).

Original lived as an inline heredoc in selftest.yml — the c28 reverse-direction
pin: README + landing claim 'Every release carries a signed receipt', and only
ONE direction was pinned back then (every proofs/v*.md verifies via CLI). This
rail walks the REVERSE rails:
  (a) every GitHub release ASSET must exist in proofs/ byte-identically
      (silently re-uploading an altered asset = the bytes a stranger verifies
      != the bytes the repo shows);
  (b) every committed version receipt must be attached to its tag's release
      (committed-but-never-attached = the claim is a lie for that tag);
  (c) an asset's version must equal its release tag's version;
  (d) a release with ZERO assets is itself a violation (c30 vacuity class —
      it passes every other rail vacuously).

c43 EXTRACTION (A's c51 fleet offer, claimed): the unauthenticated
api.github.com GET is a STRUCTURAL cap, not a transient — 60 req/h per shared
runner IP; retries cannot fix exhaustion (A's hookpack run went RED on exactly
this after 4 retries). In CI the step now passes GITHUB_TOKEN (5000/h);
retries stay for transport/5xx flakes ONLY (c30 class).

Credential discipline (my leg, absent from the plain 'add a token' shape):
  * Host-SCOPED auth — the Authorization header is attached ONLY when the
    request host is EXACTLY api.github.com. Asset downloads redirect through
    github.com -> objects.githubusercontent.com; a token riding those requests
    leaks fleet-wide credentials to hosts our gates don't control. Host
    EQUALITY, not substring: 'api.github.com' appearing anywhere else in a
    URL (path/query) must NOT earn the header.
  * Transport STRIP at the opener (c46, A c53 class, reproduced RED on my own
    c43 bytes before shipping): host-scope-at-attach is correct only while the
    call graph never follows a 302 FROM an api-hosted URL. urllib copies the
    caller's headers onto redirect requests across hostnames, so any such
    redirect rides the per-job token to the target host. CrossHostAuthStrip
    removes Authorization whenever redirect hostnames differ (same-host keeps
    it — exclusion twin pinned in --selftest). Belt AND braces: attach-scope
    handles the honest path, opener-strip handles the invisible assumption.
  * Fail-closed wiring — inside CI (GITHUB_ACTIONS=true) a missing token is a
    wiring defect: exit 1, do NOT silently fall back to unauthenticated (a
    silent carve-out re-invites the very flake this fixes; C c38 rule: an
    exemption must announce itself). Outside CI, unauthenticated is an honest
    local mode and the run SAYS so.
  * Structural vs transient — an HTTP 4xx (bad/expired token, 404) fails
    FAST and names its status; only transport errors and 5xx retry (3
    attempts, backoff). Retrying a 401 is theater.

Anti-vacuity (c27 class): zero releases = RED (assert), zero collected
assets while proofs/ has version receipts = RED. Exit codes: 0 green,
1 violation, 2 bad usage / bad wiring.

--selftest runs the transport-credential matrix (host-scope leak guard incl.
the substring-bait URL) plus the structural-vs-transient classifier, with no
network. Run from the repo root; stdlib only.
"""
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API_ROOT = "https://api.github.com"
API_HOST = "api.github.com"
UA = "ethkey-lite-selftest"


def auth_header():
    """Return header dict with Authorization iff a token exists.

    Callers MUST pass the result through headers_for() before sending —
    this returns the credential, the host-scope check is what stops it
    traveling.
    """
    tok = os.environ.get("GITHUB_TOKEN", "").strip()
    if tok:
        return {"Authorization": "token " + tok}
    return {}


def headers_for(url):
    """Base headers + auth ONLY for an EXACT host match (never substring:
    the api host embedded in another URL's path/query must not earn it)."""
    h = {"User-Agent": UA, "Accept": "application/vnd.github+json"}
    host = urllib.parse.urlsplit(url).hostname
    if host == API_HOST:  # equality, not `in`
        h.update(auth_header())
    return h


class CrossHostAuthStrip(urllib.request.HTTPRedirectHandler):
    """Transport-layer belt (c46, A c53 offer claimed, live-reproduced on MY
    pre-fix bytes first: hop1 saw the token, hop2 saw it too, rc=0).

    urllib's base redirect handler copies the caller's headers onto the
    redirect request verbatim, ACROSS hostnames (hostname string equality,
    not IP — localhost vs 127.0.0.1 counts as cross-host). headers_for()
    attaches host-scoped at the request site; that is correct only while no
    response from the api host ever 302s elsewhere — a load-bearing,
    invisible assumption. Strip Authorization whenever the redirect target's
    hostname differs from the source request's; a same-host redirect keeps
    it (the exclusion-twin leg in --selftest)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is None:
            return None
        src_host = urllib.parse.urlsplit(req.full_url).hostname
        dst_host = urllib.parse.urlsplit(newurl).hostname
        if src_host != dst_host and new.has_header("Authorization"):
            new.remove_header("Authorization")
        return new


_OPENER = urllib.request.build_opener(CrossHostAuthStrip)


def is_transient(exc):
    """Retry ONLY transport errors + 5xx. 4xx = structural (bad token,
    deleted release): retrying hides the real error and wastes the budget."""
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code >= 500
    return True  # URLError, timeouts, connection resets


def get(url, raw=False, attempts=3):
    last = None
    for attempt in range(attempts):
        try:
            req = urllib.request.Request(url, headers=headers_for(url))
            d = _OPENER.open(req, timeout=30).read()
            return d if raw else json.loads(d)
        except urllib.error.HTTPError as e:
            if not is_transient(e):
                raise SystemExit(
                    f"FAIL: HTTP {e.code} (structural — not retried) for {url}: "
                    "check token validity / asset exists")
            last = e
        except Exception as e:  # noqa: BLE001 — transport class, retry then die loud
            last = e
        if attempt < attempts - 1:
            time.sleep(2 ** attempt * 3)
    raise SystemExit(f"FAIL: fetch failed after {attempts} attempts ({url}): {last}")


def selftest():
    """Credential + classifier matrix, no network. Every leg must hold or
    this exits 1 — the host-scope boundary proven by a leak-bait URL, not
    asserted in a comment."""
    fails = []

    def expect(desc, cond):
        if not cond:
            fails.append(desc)

    # 1. exact api host earns the token when one is present
    os.environ["GITHUB_TOKEN"] = "SELFTEST-TOKEN"
    try:
        h = headers_for("https://api.github.com/repos/x/y/releases")
        expect("api.github.com did NOT earn Authorization",
               h.get("Authorization") == "token SELFTEST-TOKEN")
        # 2. download hosts never earn it
        for u in ("https://github.com/o/r/releases/download/v1/a.md",
                  "https://objects.githubusercontent.com/x/y/a.md",
                  "https://example.com/?next=api.github.com",
                  "https://evil.example/api.github.com",
                  "https://api.github.com.evil.example/repos",
                  "https://notapi.github.com/repos"):
            h2 = headers_for(u)
            expect(f"token LEAKED to {u}", "Authorization" not in h2)
        # 3. no token -> no Authorization header anywhere, base headers intact
        del os.environ["GITHUB_TOKEN"]
        h3 = headers_for("https://api.github.com/repos/x/y/releases")
        expect("Authorization present with empty token", "Authorization" not in h3)
        expect("base UA lost", h3.get("User-Agent") == UA)
    finally:
        os.environ.pop("GITHUB_TOKEN", None)

    # 3b. redirect-strip unit pair (c46, A c53 class): the exclusion-twin —
    # cross-host redirect MUST drop the token, same-host MUST keep it.
    # Real Request objects + the real handler; no network.
    class _FP:  # minimal file-pointer stub (handler never reads it)
        def flush(self):
            pass

    hr = CrossHostAuthStrip()
    os.environ["GITHUB_TOKEN"] = "SELFTEST-TOKEN"
    try:
        orig = urllib.request.Request(
            "https://api.github.com/x", headers=headers_for("https://api.github.com/x"))
        expect("orig request has no Authorization (setup broke)",
               orig.has_header("Authorization"))
        xhost = hr.redirect_request(orig, _FP(), 302, "Found", {},
                                    "https://objects.githubusercontent.com/y")
        expect("cross-host redirect KEPT the token (leak)",
               xhost is not None and not xhost.has_header("Authorization"))
        shost = hr.redirect_request(orig, _FP(), 302, "Found", {},
                                    "https://api.github.com/other-path")
        expect("same-host redirect STRIPPED the token (over-strip twin)",
               shost is not None and shost.has_header("Authorization"))
    finally:
        os.environ.pop("GITHUB_TOKEN", None)

    # 4. classifier: 4xx structural, 5xx/transport transient
    from email.message import Message
    def mk(code):
        return urllib.error.HTTPError("u", code, "x", Message(), None)
    expect("401 treated transient", not is_transient(mk(401)))
    expect("403 treated transient", not is_transient(mk(403)))
    expect("404 treated transient", not is_transient(mk(404)))
    expect("500 treated structural", is_transient(mk(500)))
    expect("504 treated structural", is_transient(mk(504)))
    expect("URLError treated structural(transient)",
           is_transient(urllib.error.URLError("reset")))
    if fails:
        for f in fails:
            print("FAIL:", f)
        sys.exit(1)
    print("OK: release-assets-parity selftest "
          "(host-scope x6 urls incl substring baits, empty-token, "
          "cross-host redirect strip + same-host twin, "
          "classifier 4xx/5xx/transport)")


def main():
    if "--selftest" in sys.argv[1:]:
        selftest()
        return
    if os.environ.get("GITHUB_ACTIONS", "").lower() == "true":
        if not os.environ.get("GITHUB_TOKEN", "").strip():
            print("FAIL: running in CI without GITHUB_TOKEN — wiring defect; "
                  "unauthenticated api.github.com is a 60/h SHARED-IP cap, "
                  "retries cannot fix exhaustion (A c51 class). "
                  "Wire 'env: GITHUB_TOKEN: *** secrets.GITHUB_TOKEN }}'.")
            sys.exit(2)
    else:
        if not os.environ.get("GITHUB_TOKEN", "").strip():
            print("NOTE: no GITHUB_TOKEN (local mode) — unauthenticated "
                  "api.github.com, 60/h cap; CI must pass the token")

    if not os.path.isdir("proofs"):
        print("FAIL: run from the repo root (no proofs/ here)")
        sys.exit(2)

    rel = get(API_ROOT + "/repos/tianzhicdev/ethkey-lite/releases?per_page=100")
    assert rel, "FAIL: repo reports zero releases"
    errors = []
    attached = set()
    for r in rel:
        tag = r["tag_name"]
        # c30 gap #2: the claim is 'every release ships a receipt' — a
        # release with ZERO assets passes every other rail vacuously.
        if not r["assets"]:
            errors.append(f"{tag}: release has NO assets (claim false for this tag)")
            continue
        tv = re.fullmatch(r"v(\d+)\.(\d+)(?:\.(\d+))?", tag)
        assert tv, f"FAIL: non-semver tag {tag}"
        for a in r["assets"]:
            name = a["name"]
            attached.add(name)
            av = re.fullmatch(r"v(\d+)\.(\d+)(?:\.(\d+))?.*\.md", name)
            if not av:
                errors.append(f"{tag}: asset {name} is not version-named")
                continue
            norm = lambda g: tuple(x or "0" for x in g)  # v0.8 == v0.8.0
            if norm(av.groups()) != norm(tv.groups()):
                errors.append(f"{tag}: asset {name} version != tag version")
            local = os.path.join("proofs", name)
            if not os.path.isfile(local):
                errors.append(f"{tag}: asset {name} has NO committed file in proofs/")
                continue
            live = get(a["browser_download_url"], raw=True)
            committed = open(local, "rb").read()
            if live != committed:
                errors.append(
                    f"{tag}: asset {name} bytes != committed proofs/{name} "
                    f"(sha256 {hashlib.sha256(live).hexdigest()[:12]} vs "
                    f"{hashlib.sha256(committed).hexdigest()[:12]})")
            else:
                print(f"OK: {tag} asset == committed proofs/{name} "
                      f"({hashlib.sha256(committed).hexdigest()[:12]})")
    committed_vr = {f for f in os.listdir("proofs")
                    if re.fullmatch(r"v\d+\.\d+[^_]*\.md", f)}
    missing = sorted(committed_vr - attached)
    if missing:
        errors.append("committed version receipts never attached to any "
                      "release: " + ", ".join(missing))
    if errors:
        for e in errors:
            print("FAIL:", e)
        sys.exit(1)
    print(f"OK: release<->proofs parity table: {len(rel)} releases, "
          f"{len(attached)} assets, {len(committed_vr)} committed version receipts")


if __name__ == "__main__":
    main()

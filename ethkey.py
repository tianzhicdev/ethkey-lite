#!/usr/bin/env python3
"""ethkey-lite: tiny auditable Ethereum keypair + EIP-191 message signing tool.

Pure-Python secp256k1; keccak-256 via pycryptodome (vetted). No network, no
key material ever written to disk by this tool.

Commands:
  selftest              run known-answer tests (keccak, address, EIP-55, sign/recover)
  new                   generate a fresh keypair (stdout only)
  address <pk_hex>      derive checksummed address from a private key
  checksum <addr>       EIP-55 checksum-encode an address
  sign <msg>            sign msg with $ETHKEY_PK (env var) using personal_sign (EIP-191)
  recover <addr> <msg> <sig_hex>   recover signer from a personal_sign signature
  proof [msg|--file F]  write a self-contained signed markdown receipt (--out FILE)
                        (empty/whitespace --file/--out values are refused, exit 2)
  verify <proof.md>     verify a receipt; --require <addr> asserts the signer
                        (an empty/whitespace --require value is refused, exit 2)

The private key is read ONLY from the ETHKEY_PK environment variable for
`sign`/`proof`, so it never lands in shell history or argv. NEVER commit or
log keys.
"""
import base64
import datetime
import hashlib
import hmac
import os
import secrets
import sys

from Crypto.Hash import keccak

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
A = 0
B = 7
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
HALF_N = N // 2


def inv(a, m=P):
    return pow(a, m - 2, m)


def add(p, q):
    if p is None: return q
    if q is None: return p
    if p[0] == q[0] and (p[1] != q[1] or q[1] == 0): return None
    if p == q:
        s = (3 * p[0] * p[0] % P) * inv(2 * p[1] % P) % P
    else:
        s = (q[1] - p[1]) * inv((q[0] - p[0]) % P) % P
    x = (s * s - p[0] - q[0]) % P
    return (x, (s * (p[0] - x) - p[1]) % P)


def mul(k, p):
    # c111 (A c114 law: guard the PARAMETER at every layer): k outside
    # [1, N-1] was a live footgun at BOTH doors — k <= 0 made the `while k`
    # loop unbounded (negative k >> 1 never reaches 0: `address -1` spun
    # forever), k == 0 returned None and crashed downstream with a
    # TypeError. Every legitimate caller (RFC 6979 k, s, r^-1, -z mod N)
    # already lands in [1, N-1], so refusing is strictness-additive.
    if not isinstance(k, int) or not (1 <= k < N):
        raise ValueError(f'scalar multiplier out of range (must be 1..N-1), got {k!r}')
    r = None
    while k:
        if k & 1:
            r = add(r, p)
        p = add(p, p)
        k >>= 1
    return r


def keccak256(data: bytes) -> bytes:
    h = keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


# ---------- EIP-55 checksum ----------

def checksum_address(addr: str) -> str:
    a = addr.lower().removeprefix('0x')
    if len(a) != 40 or any(c not in '0123456789abcdef' for c in a):
        raise ValueError('not an address')
    h = keccak256(a.encode()).hex()
    out = [''.join(c.upper() if c.isalpha() and int(h[i], 16) >= 8 else c
                   for i, c in enumerate(a))]
    return '0x' + out[0]


def pk_hexstr(sk_int: int) -> str:
    """Canonical fixed-width private-key hex: 0x + exactly 64 digits.

    (c53 CI root-cause: `hex(sk)` does NOT zero-pad, so ~1 in 16 fresh keys
    — every one whose top byte is < 0x10 — printed 63 digits and broke the
    dogfood CLI pin. Fixed-width is the wire contract, same reason
    addresses are 40 digits, not hex-int shortest form.)
    """
    return "0x%064x" % sk_int


def address_from_pk(sk_int: int) -> str:
    # c111: refuse out-of-range keys BEFORE the curve math (see mul guard).
    if not isinstance(sk_int, int) or not (1 <= sk_int < N):
        raise ValueError(f'private key out of range (must be 1..N-1), got {sk_int!r}')
    pub = mul(sk_int, G)
    raw = '0x' + keccak256(pub[0].to_bytes(32, 'big') + pub[1].to_bytes(32, 'big'))[12:].hex()
    return checksum_address(raw)


# ---------- RFC 6979 deterministic k (HMAC-SHA256) ----------

def _rfc6979_k(z_int: int, priv_int: int) -> int:
    x = priv_int.to_bytes(32, 'big')
    z = z_int.to_bytes(32, 'big')
    qlen = N.bit_length()
    rolen = (qlen + 7) // 8
    v = b'\x01' * 32
    k = b'\x00' * 32
    k = hmac.new(k, v + b'\x00' + x + z, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b'\x01' + x + z, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        t = b''
        while len(t) < rolen:
            v = hmac.new(k, v, hashlib.sha256).digest()
            t += v
        cand = int.from_bytes(t[:rolen], 'big') >> (rolen * 8 - qlen)
        if 1 <= cand < N:
            return cand
        k = hmac.new(k, v + b'\x00', hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


# ---------- ECDSA over secp256k1 ----------

def _sign_hash(z_int: int, priv_int: int):
    while True:
        k = _rfc6979_k(z_int, priv_int)
        R = mul(k, G)
        r = R[0] % N
        if r == 0:
            continue
        s = (inv(k, N) * (z_int + r * priv_int)) % N
        if s == 0:
            continue
        if s > HALF_N:
            s = N - s
            rec_id = (R[1] & 1) ^ 1
        else:
            rec_id = R[1] & 1
        return r, s, rec_id


def _recover_hash(z_int: int, r: int, s: int, rec_id: int):
    x = r  # r < N < P, so x is a valid candidate field element
    y_sq = (pow(x, 3, P) + B) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if (y & 1) != (rec_id & 1):
        y = P - y
    R = (x, y)
    r_inv = inv(r, N)
    try:
        point = add(mul(s, R), mul((-z_int) % N, G))
        Q = mul(r_inv, point)
    except ValueError:
        # c111: z mod N == 0 (or degenerate recovery) hits the mul range
        # guard; surface as the documented malformed-signature class, not a
        # crash. Not constructible with a real message (astronomically rare
        # digest), pinned at the function boundary in selftest.
        return None
    if Q is None:
        return None
    return '0x' + keccak256(Q[0].to_bytes(32, 'big') + Q[1].to_bytes(32, 'big'))[12:].hex()


# ---------- EIP-191 personal_sign ----------

def personal_digest(message: bytes) -> int:
    prefixed = (b'\x19Ethereum Signed Message:\n' + str(len(message)).encode() + message)
    return int.from_bytes(keccak256(prefixed), 'big')


def sign_message(message: bytes, priv_int: int) -> str:
    # c111: same parameter-door guard (library callers included): priv 0 or
    # >= N is not a key — the old path signed pk=0 happily (degenerate key,
    # Q = point at infinity territory) and mul() would TypeError/None-crash.
    if not isinstance(priv_int, int) or not (1 <= priv_int < N):
        raise ValueError(f'private key out of range (must be 1..N-1), got {priv_int!r}')
    r, s, rec_id = _sign_hash(personal_digest(message), priv_int)
    return '0x' + r.to_bytes(32, 'big').hex() + s.to_bytes(32, 'big').hex() + (27 + rec_id).to_bytes(1, 'big').hex()


def recover_message(message: bytes, sig_hex: str) -> str:
    # c25: strictly validate the signature BEFORE recovering. The old code
    # accepted ANY recovery-id byte (rec_id = v-27 if v>=27 else v), so a
    # tampered v byte like 0x1a (26) took the `else` branch -> rec_id 26,
    # whose parity (26 & 1 == 0) coincided with the true rec_id 0 and
    # recovered the real signer, while ethers rejects v=26 outright;
    # out-of-range r/s likewise crashed downstream with a traceback. Parse
    # errors now raise ValueError with a clean message (CLI maps it to
    # exit 2; verify_proof maps it to 'malformed proof').
    sig = sig_hex.removeprefix('0x').strip()
    if len(sig) != 130 or any(c not in '0123456789abcdefABCDEF' for c in sig):
        raise ValueError('signature must be 65 bytes as 130 hex chars (0x prefix optional)')
    r = int(sig[0:64], 16)
    s = int(sig[64:128], 16)
    v = int(sig[128:130], 16)
    if v in (0, 1):
        rec_id = v
    elif v in (27, 28):
        rec_id = v - 27
    else:
        raise ValueError(f'invalid recovery id {v}: must be 0, 1, 27, or 28')
    if not (0 < r < N and 0 < s < N):
        raise ValueError('signature r/s out of range (must be 1..N-1)')
    rec = _recover_hash(personal_digest(message), r, s, rec_id)
    if rec is None:
        raise ValueError('recovery failed for this signature')
    return checksum_address(rec)


# ---------- selftest ----------

def selftest() -> bool:
    # keccak-256 known answers
    assert keccak256(b'').hex() == 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'
    assert keccak256(b'abc').hex() == '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45'
    # secp256k1 -> address vector (pk=1)
    assert address_from_pk(1).lower() == '0x7e5f4552091a69125d5dfcb7b8c2659029395bdf'
    # pk width contract (c53: hex() non-padding = ~1/16 keys print 63
    # digits; known-answer + 256 fresh-key sweep pin BOTH halves)
    assert pk_hexstr(1) == '0x' + '0' * 63 + '1'
    for _ in range(256):
        s = pk_hexstr(int.from_bytes(secrets.token_bytes(32), 'big') % (N - 1) + 1)
        assert len(s) == 66 and s.startswith('0x') and all(c in '0123456789abcdef' for c in s[2:])
    # EIP-55 known answers (eips.ethereum.org/EIPS/eip-55 test cases)
    assert checksum_address('0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed') == '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed'
    assert checksum_address('0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359') == '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359'
    assert checksum_address('0xdbf03b407c01e7cd3cbea99509d93f8dddc8c6fb') == '0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB'
    assert checksum_address('0xd1220a0cf47c7b9be7a2e6ba89f429762e7b9adb') == '0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb'
    assert checksum_address('0x52908400098527886e0f7030069857d2e4169ee7') == '0x52908400098527886E0F7030069857D2E4169EE7'
    assert checksum_address('0xde709f2102306220921060314715629080e2fb77') == '0xde709f2102306220921060314715629080e2fb77'
    # personal_sign known-answer vector, cross-verified against ethers.js v6
    # (Wallet('0x46*32').signMessage('hello world')):
    pk = int('46' * 32, 16)
    assert address_from_pk(pk) == '0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F'
    sig = sign_message(b'hello world', pk)
    assert sig.lower() == ('0x78dc245805f4363bd546a771502385e03c40995b13fbab75de92'
                           '58c6515db8d92e831df32c6898bc590d0fb69945a72f6e31f1a70a3'
                           '25bf047ff5d557b1542ff1b'), 'personal_sign vector mismatch'
    assert recover_message(b'hello world', sig) == '0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F'
    # sign/recover roundtrip on a random key
    sk = int.from_bytes(secrets.token_bytes(32), 'big') % (N - 1) + 1
    sig2 = sign_message(b'ethkey-lite roundtrip \xf0\x9f\x94\x90', sk)
    assert recover_message(b'ethkey-lite roundtrip \xf0\x9f\x94\x90', sig2) == address_from_pk(sk)
    # signed-receipt roundtrip + tamper detection
    pk3, addr3 = 2, address_from_pk(2)
    md = make_proof(b'receipt payload \xf0\x9f\x94\x91', pk3, note='selftest')
    ok, signer, reason = verify_proof(md)
    assert ok and signer == addr3, f'proof selftest failed: {ok} {signer} {reason}'
    bad = md.replace(PAYLOAD_BEGIN + '\n', PAYLOAD_BEGIN + '\nZQ==\n')
    ok2, _, _ = verify_proof(bad)
    assert not ok2, 'tampered proof must not verify'
    # c63 multi-receipt: EVERY receipt in a document is verified, not just
    # the first (the pre-fix prefix parse blessed a tampered 2nd receipt —
    # measured repro in work/c63-concat-blindness/, fleet bless-by-invisibility
    # family). Each sub-assert below is one leg of the new contract.
    md2 = make_proof(b'second payload', pk3, note='selftest 2')
    multi = md + '\n' + md2
    okm, signerm, _ = verify_proof(multi)
    assert okm and signerm == addr3 + '+' + addr3, f'multi verify wrong: {okm} {signerm}'
    bad2 = md2.replace(PAYLOAD_BEGIN + '\n', PAYLOAD_BEGIN + '\nZQ==\n')
    okb, _, reasonb = verify_proof(md + '\n' + bad2)
    assert not okb and '#2/2' in reasonb, f'tampered 2nd must FAIL naming slice: {okb} {reasonb}'
    # mixed signers + require: good-1 (pk3) + good-2 signed by pk (addr1) must
    # not ride the first signer through a --require gate
    md_mixed = md + '\n' + make_proof(b'other signer payload', pk, note='selftest mix')
    okx, _, reasonx = verify_proof(md_mixed, require=addr3)
    assert not okx and 'is not required' in reasonx, f'mixed-signer require must FAIL: {okx} {reasonx}'
    okx2, _, _ = verify_proof(md + '\n' + md2, require=addr3)
    assert okx2, 'all-slices-match require must pass'
    # truncated bundle fails CLOSED (prefix must not verify)
    trunc = (md + '\n' + md2).split('-----END PAYLOAD-----')[0] + md2.split('-----END PAYLOAD-----')[0]
    okt, _, reasont = verify_proof(trunc)
    assert not okt and 'unterminated' in reasont, f'truncated bundle must fail closed: {okt} {reasont}'
    assert len(split_proofs(multi)) == 2 and len(split_proofs(md)) == 1
    # c105 find (closed here): --require with an EMPTY value must refuse at
    # the ARGS layer, never bless. Whitespace-only too; a legit empty --note
    # must stay legal (scope is --require only).
    v, _, err_empty = _take(['--require', ''], '--require')
    assert v is None and err_empty and 'empty' in err_empty, \
        f'empty --require must refuse: {v!r} {err_empty!r}'
    _, _, err_ws = _take(['--require', '   '], '--require')
    assert err_ws and 'empty' in err_ws, f'whitespace --require must refuse: {err_ws!r}'
    v2, rest2, err_ok = _take(['--require', '0xabc'], '--require')
    assert v2 == '0xabc' and rest2 == [] and err_ok is None, '--require happy path'
    v3, _, err_note = _take(['--note', ''], '--note')
    assert v3 == '' and err_note is None, 'empty --note must stay legal (fix is --require-scoped)'
    # c109 find (closed here): the LIBRARY door. verify_proof(require='')
    # skipped the CLI _take refuse entirely and blessed a wrong-signer
    # receipt (require='   ' only failed by accident — blank-vs-addr string
    # compare). Now empty/whitespace raises; require=None stays the
    # documented no-gate path (scope cell); padded valid addr still gates
    # (normalized, not blessed-broadened).
    pk_w = 7
    addr_w = address_from_pk(pk_w)
    md_w = make_proof(b'c109 wrong-signer fixture', pk_w, note='c109')
    try:
        verify_proof(md_w, require='')
        raise AssertionError("library require='' must raise, not bless")
    except ValueError as e_c109:
        assert 'empty' in str(e_c109), f'refuse message must name the footgun: {e_c109}'
    try:
        verify_proof(md_w, require='   ')
        raise AssertionError("library require='   ' must raise, not accident-fail")
    except ValueError:
        pass
    okn, sn, _ = verify_proof(md_w, require=None)
    assert okn and sn == addr_w, 'require=None stays legal no-gate path'
    okp, _, rp = verify_proof(md_w, require='  ' + addr_w + ' \n')
    assert okp, f'padded valid require must gate+pass after normalize: {rp}'
    okb2, _, rb2 = verify_proof(md_w, require=address_from_pk(9))
    assert not okb2 and 'is not required' in rb2, 'wrong valid require still FAILs'
    # c111 find (closed here): the PARSE/RANGE door at BOTH layers (A c114
    # law — guard the parameter at every layer, not the flag at one). Pre-fix
    # measured: address_from_pk(0) -> TypeError NoneType-subscript;
    # address_from_pk(-1) -> INFINITE LOOP in mul (k >>= 1 on a negative
    # never terminates — a hang, worse than a crash); sign_message(b, 0) ->
    # blessed a signature for a degenerate key; CLI `address zzz` -> raw
    # int() traceback. Now every out-of-range scalar raises ValueError at the
    # function body, and mul itself refuses so NO caller can re-open the hang.
    for bad_pk, tag in ((0, 'zero'), (-1, 'negative'), (N, 'N'), (N + 7, 'above N')):
        try:
            address_from_pk(bad_pk)
            raise AssertionError(f'address_from_pk({tag}) must raise ValueError')
        except ValueError as e111:
            assert 'range' in str(e111), f'address_from_pk refuse must name range: {e111}'
        try:
            sign_message(b'x', bad_pk)
            raise AssertionError(f'sign_message({tag}) must raise ValueError')
        except ValueError as e111s:
            assert 'range' in str(e111s), f'sign_message refuse must name range: {e111s}'
    try:
        mul(-1, G)
        raise AssertionError('mul must refuse negative scalars (the hang door)')
    except ValueError as e_mul:
        assert 'range' in str(e_mul), f'mul refuse must name range: {e_mul}'
    assert mul(1, G) == G, 'mul happy path intact (refuse did not over-broaden)'
    assert _pk_arg('1') == 1 and _pk_arg('0x1') == 1 and _pk_arg('0X1') == 1, \
        'pk arg bare/0x/0X all valid (documented short form stays legal)'
    for junk in ('', '   ', '0x', 'zzz', '0 x41'):
        try:
            _pk_arg(junk)
            raise AssertionError(f'_pk_arg({junk!r}) must raise')
        except ValueError:
            pass
    # degenerate-recovery door: z=0 makes (-z)%N==0 hit the mul guard;
    # _recover_hash must return None (CLI -> 'recovery failed' exit 2),
    # never crash. Synthetic z=0 leg (not constructible via a real digest).
    assert _recover_hash(0, 1, 1, 0) is None, 'z=0 recovery must be None not crash'
    return True


# ---------- signed receipts (proof v1) ----------

PROOF_MAGIC = 'ethkey-lite-proof'
PAYLOAD_BEGIN = '-----BEGIN PAYLOAD-----'
PAYLOAD_END = '-----END PAYLOAD-----'


def _canonical(created: str, sha256_hex: str) -> bytes:
    return f'{PROOF_MAGIC} v1\ncreated:{created}\nsha256:{sha256_hex}'.encode()


def make_proof(payload: bytes, priv_int: int, note: str = '') -> str:
    created = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    sha = hashlib.sha256(payload).hexdigest()
    b64 = base64.b64encode(payload).decode()
    body = '\n'.join(b64[i:i + 76] for i in range(0, len(b64), 76)) or '(empty)'
    sig = sign_message(_canonical(created, sha), priv_int)
    lines = [
        f'# {PROOF_MAGIC} v1',
        f'created: {created}',
        f'signer: {address_from_pk(priv_int)}',
        f'sha256: {sha}',
        f'note: {note}',
        f'signature: {sig}',
        '',
        'Signed scope: created + sha256 fields (not the note). Re-verify with',
        "'ethkey.py verify <this file> --require <addr>' or ethers.verifyMessage",
        'on the canonical string:',
        f'  {PROOF_MAGIC} v1\\ncreated:<created>\\nsha256:<sha256>',
        '',
        PAYLOAD_BEGIN,
        body,
        PAYLOAD_END,
    ]
    return '\n'.join(lines) + '\n'


def split_proofs(md: str):
    """Split a document into one slice per receipt (c63).

    A document may carry SEVERAL receipts (bundles: copy-paste handoffs,
    `cat proofs/*.md > bundle.md`). Prefix parsing (first BEGIN/END only)
    made every receipt after the first INVISIBLE while the tool still
    printed 'signature valid, payload intact' about the whole file —
    bless-by-invisibility, measured in c63: a tampered receipt alone =
    FAIL, the same tamper concatenated after a good receipt = bless.
    Each slice spans from the end of the previous slice to its OWN END
    marker, so a receipt's header fields are only ever read from inside
    its own slice (unknown/other-receipt lines never join the whitelist
    walk). Zero slices -> [] (caller reports malformed)."""
    slices = []
    pos = 0
    while True:
        begin = md.find(PAYLOAD_BEGIN, pos)
        if begin == -1:
            break
        end = md.find(PAYLOAD_END, begin)
        if end == -1:
            # truncated bundle: a BEGIN with no END after it. Fail closed —
            # silently verifying only the complete prefix would re-open the
            # exact bless-by-invisibility this function exists to close.
            raise ValueError('unterminated payload block (missing END marker)')
        slices.append(md[pos:end + len(PAYLOAD_END)])
        pos = end + len(PAYLOAD_END)
    return slices


def _verify_one(md: str):
    """Single-receipt verify. Return (ok, signer_address_or_None, reason)."""
    try:
        fields = {}
        for line in md.splitlines():
            if line.strip() == PAYLOAD_BEGIN:
                break
            key = line.split(':', 1)[0]
            if key not in ('created', 'signer', 'sha256', 'note', 'signature'):
                continue
            k, sep, v = line.partition(':')
            if sep:
                fields.setdefault(k.strip(), v.strip())
        begin = md.index(PAYLOAD_BEGIN) + len(PAYLOAD_BEGIN)
        b64 = ''.join(md[begin:md.index(PAYLOAD_END)].split())
        payload = b'' if b64 == '(empty)' else base64.b64decode(b64, validate=False)
        sha = hashlib.sha256(payload).hexdigest()
        if fields.get('sha256') != sha:
            return False, fields.get('signer'), f'payload sha256 mismatch (header says {fields.get("sha256")})'
        signer = recover_message(_canonical(fields.get('created', ''), sha), fields.get('signature', ''))
        claimed = fields.get('signer', '')
        if claimed and signer.lower() != claimed.lower():
            return False, signer, f'signer field mismatch: recovered {signer}'
        return True, signer, 'signature valid, payload intact'
    except Exception as e:
        return False, None, f'malformed proof: {e}'


def verify_proof(md: str, require=None):
    """Verify EVERY receipt in a document. Return (ok, signers, reason).

    c63: the old single-slice parse blessed concatenated bundles while
    blind to receipt #2+ (a tampered second receipt read OK). Now each
    slice from split_proofs() verifies standalone; `ok` only if ALL pass.
    Single-receipt docs keep the EXACT old (ok, signer, reason) contract;
    multi-receipt docs join signers with '+' and name the first failing
    slice with its index. `require` (optional addr) asserts EVERY slice's
    recovered signer — a good first receipt can no longer carry a
    wrong-signered second one through a --require gate.
    c109 (same fail-open family as c103 --require / c107 --out, at the LAST
    unguarded door): require='' meant 'gate ON' to a caller building kwargs
    from a CI variable, but every `if require` below reads it as no-gate and
    the function blesses a wrong-signer receipt — the library path skips the
    CLI's _take() refuse entirely. A whitespace-only value fared worse: it
    passed the truthiness gate and compared against the blank (fails by
    accident, never by contract). Now: empty/whitespace require raises
    ValueError (CLI main maps it to exit 2); require=None stays the
    documented no-gate path (scope cell, c103 discipline)."""
    if require is not None:
        if not require.strip():
            raise ValueError(
                'verify_proof: require= passed an empty/whitespace value — '
                'that silently disables the signer gate; pass require=None '
                'to verify without gating')
        require = require.strip()
    try:
        slices = split_proofs(md)
    except ValueError as e:
        return False, None, f'malformed proof: {e}'
    if not slices:
        return _verify_one(md)
    if len(slices) == 1 and not require:
        return _verify_one(slices[0])
    results = [_verify_one(s) for s in slices]
    signers = '+'.join(r[1] for r in results if r[1])
    for i, (ok_i, signer_i, reason_i) in enumerate(results, 1):
        if not ok_i:
            tag = f'receipt #{i}/{len(slices)}' if len(slices) > 1 else ''
            return False, signers or None, (f'{tag}: {reason_i}' if tag else reason_i)
        if require and (not signer_i or signer_i.lower() != require.lower()):
            return False, signers or None, (
                f'receipt #{i}/{len(slices)}: signer {signer_i} is not required {require}')
    reason = (f'{len(slices)} receipts valid, payloads intact'
              if len(slices) > 1 else 'signature valid, payload intact')
    return True, (signers or None), reason


# ---------- CLI ----------

HELP_FLAGS = ('--help', '-h')


def _pk_arg(s):
    """Parse a private-key hex arg/env value into an int (c111).

    The old inline `int(x.removeprefix('0x'), 16)` traced back on ANY junk
    ('zzz', '', '0 x41', a truthy-but-empty-prefixed '0x') — and for a
    well-formed-but-out-of-range value it happily walked into the curve
    math (pk=0 crash, pk=-1/pk>=N nonsense, see mul guard). A CI variable
    that expands to garbage is the realistic trigger; a clean exit-2 line
    naming the problem is the contract (same class as --require refuses).
    Accepts bare or 0x/0X-prefixed hex, case-insensitive, permissive length
    (canonical 64 but '1' stays valid — documented example uses it)."""
    t = (s or '').strip()
    if not t:
        raise ValueError('empty value is not a private key')
    t = t[2:] if t[:2].lower() == '0x' else t
    if not t or any(c not in '0123456789abcdefABCDEF' for c in t):
        raise ValueError(f'not valid hex: {s!r}')
    return int(t, 16)


def _take(rest, name):
    """Return (value, new_rest, error). error is a message string or None."""
    if name not in rest:
        return None, rest, None
    i = rest.index(name)
    if i + 1 >= len(rest):
        return None, rest, f'error: {name} requires a value'
    value = rest[i + 1]
    # Empty/whitespace values are refused at the ARGS layer for the flags
    # where empty does NOT mean the operator's likely intent (c103/c105 law,
    # generalized to the WRITE layer by my own c107 audit, A c109 class):
    # --require '' meant 'gate ON' but silently disabled the signer gate;
    # --out '' meant 'write this file' but silently fell back to stdout
    # (empty is falsy -> `if out:`), and --out '   ' wrote a file named
    # '   '. The realistic trigger is a CI variable that expands to empty.
    # SCOPE CELLS (c103 discipline): --note empty stays LEGAL (empty note is
    # a documented value, not a path), and a FLAG-ABSENT --out stays the
    # documented stdout path.
    if name in ('--require', '--out', '--file') and not value.strip():
        hints = {
            '--require': ('passing an empty address silently disables the '
                          'signer gate; omit the flag to verify without '
                          'gating'),
            '--out': ('an empty output path silently falls back to stdout '
                      '(a receipt a CI step expects on disk never lands); '
                      'unset the variable or omit the flag to print'),
            '--file': ('an empty input path is not a file; pass an explicit '
                       'path or pass the message as a positional argument'),
        }
        return None, rest, (f'error: {name} value is empty — ' + hints[name])
    return value, rest[:i] + rest[i + 2:], None


def main(argv):
    cmd = argv[1] if len(argv) > 1 else 'selftest'
    if cmd in HELP_FLAGS:
        print(__doc__)
        return 0
    if cmd == 'selftest':
        selftest()
        print('selftest OK (keccak256 x2, address pk=1, EIP-55 x6, personal_sign vs ethers.js vector, roundtrip)')
    elif cmd == 'new':
        sk = int.from_bytes(secrets.token_bytes(32), 'big') % (N - 1) + 1
        print('address:', address_from_pk(sk))
        print('private_key_hex:', pk_hexstr(sk))
        print('WARNING: handle the private key like a password. Never paste it into logs, chats, or repos.')
    elif cmd == 'address' and len(argv) == 3:
        try:
            print(address_from_pk(_pk_arg(argv[2])))
        except ValueError as e:
            print(f'error: {e}', file=sys.stderr)
            return 2
    elif cmd == 'checksum' and len(argv) == 3:
        try:
            print(checksum_address(argv[2]))
        except ValueError as e:
            print(f'error: {e} (want 40 hex digits, 0x optional)', file=sys.stderr)
            return 2
    elif cmd == 'sign' and len(argv) == 3:
        pk_hex = os.environ.get('ETHKEY_PK')
        if not pk_hex:
            print('error: set ETHKEY_PK env var (key never appears in argv)', file=sys.stderr)
            return 2
        try:
            print(sign_message(argv[2].encode(), _pk_arg(pk_hex)))
        except ValueError as e:
            print(f'error: ETHKEY_PK: {e}', file=sys.stderr)
            return 2
    elif cmd == 'recover' and len(argv) == 5:
        try:
            rec = recover_message(argv[3].encode(), argv[4])
        except ValueError as e:
            print(f'error: {e}', file=sys.stderr)
            return 2
        ok = rec.lower() == argv[2].lower().strip()
        print('recovered:', rec)
        print('matches claimed address:', ok)
        return 0 if ok else 1
    elif cmd == 'proof':
        rest = argv[2:]
        if any(a in HELP_FLAGS for a in rest):
            print(__doc__)
            return 0
        out, rest, err = _take(rest, '--out')
        if err:
            print(err, file=sys.stderr)
            return 2
        note, rest, err = _take(rest, '--note')
        if err:
            print(err, file=sys.stderr)
            return 2
        note = note or ''
        if len(rest) == 2 and rest[0] == '--file':
            if not rest[1].strip():
                # c107 write-layer cell: empty input path from an unset CI
                # var is an args error (exit 2), not an errno surprise.
                print('error: --file value is empty — an empty input path '
                      'is not a file; pass an explicit path or the message '
                      'as a positional argument', file=sys.stderr)
                return 2
            try:
                with open(rest[1], 'rb') as f:
                    payload = f.read()
            except OSError as e:
                print(f'error: {e}', file=sys.stderr)
                return 1
        elif len(rest) == 1:
            payload = rest[0].encode()
        else:
            print(__doc__)
            return 1
        pk_hex = os.environ.get('ETHKEY_PK')
        if not pk_hex:
            print('error: set ETHKEY_PK env var (key never appears in argv)', file=sys.stderr)
            return 2
        try:
            md = make_proof(payload, _pk_arg(pk_hex), note)
        except ValueError as e:
            print(f'error: ETHKEY_PK: {e}', file=sys.stderr)
            return 2
        if out:
            try:
                with open(out, 'w') as f:
                    f.write(md)
            except OSError as e:
                print(f'error: {e}', file=sys.stderr)
                return 1
            print(f'proof written: {out}')
        else:
            print(md, end='')
    elif cmd == 'verify':
        rest = argv[2:]
        if any(a in HELP_FLAGS for a in rest):
            print(__doc__)
            return 0
        require, rest, err = _take(rest, '--require')
        if err:
            print(err, file=sys.stderr)
            return 2
        if len(rest) != 1:
            print(__doc__)
            return 1
        try:
            with open(rest[0]) as f:
                ok, signer, reason = verify_proof(f.read(), require=require)
        except ValueError as e:
            # c109: library-door empty-require refuse (CLI _take normally
            # catches this first; reachable if this layer is ever reused)
            print(f'error: {e}', file=sys.stderr)
            return 2
        except OSError as e:
            print(f'error: {e}', file=sys.stderr)
            return 1
        if signer and require and '+' not in signer and signer.lower() != require.strip().lower():
            ok, reason = False, f'signer {signer} is not required {require}'
        print('signer:', signer)
        print('result:', 'OK' if ok else 'FAIL', '-', reason)
        return 0 if ok else 1
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))

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

The private key is read ONLY from the ETHKEY_PK environment variable for
`sign`, so it never lands in shell history or argv. NEVER commit or log keys.
"""
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


def address_from_pk(sk_int: int) -> str:
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
    point = add(mul(s, R), mul((-z_int) % N, G))
    Q = mul(r_inv, point)
    if Q is None:
        return None
    return '0x' + keccak256(Q[0].to_bytes(32, 'big') + Q[1].to_bytes(32, 'big'))[12:].hex()


# ---------- EIP-191 personal_sign ----------

def personal_digest(message: bytes) -> int:
    prefixed = (b'\x19Ethereum Signed Message:\n' + str(len(message)).encode() + message)
    return int.from_bytes(keccak256(prefixed), 'big')


def sign_message(message: bytes, priv_int: int) -> str:
    r, s, rec_id = _sign_hash(personal_digest(message), priv_int)
    return '0x' + r.to_bytes(32, 'big').hex() + s.to_bytes(32, 'big').hex() + (27 + rec_id).to_bytes(1, 'big').hex()


def recover_message(message: bytes, sig_hex: str) -> str:
    sig = sig_hex.removeprefix('0x')
    r = int(sig[0:64], 16)
    s = int(sig[64:128], 16)
    v = int(sig[128:130], 16)
    rec_id = v - 27 if v >= 27 else v
    return checksum_address(_recover_hash(personal_digest(message), r, s, rec_id))


# ---------- selftest ----------

def selftest() -> bool:
    # keccak-256 known answers
    assert keccak256(b'').hex() == 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'
    assert keccak256(b'abc').hex() == '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45'
    # secp256k1 -> address vector (pk=1)
    assert address_from_pk(1).lower() == '0x7e5f4552091a69125d5dfcb7b8c2659029395bdf'
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
    return True


# ---------- CLI ----------

def main(argv):
    cmd = argv[1] if len(argv) > 1 else 'selftest'
    if cmd == 'selftest':
        selftest()
        print('selftest OK (keccak256 x2, address pk=1, EIP-55 x6, personal_sign vs ethers.js vector, roundtrip)')
    elif cmd == 'new':
        sk = int.from_bytes(secrets.token_bytes(32), 'big') % (N - 1) + 1
        print('address:', address_from_pk(sk))
        print('private_key_hex:', hex(sk))
        print('WARNING: handle the private key like a password. Never paste it into logs, chats, or repos.')
    elif cmd == 'address' and len(argv) == 3:
        print(address_from_pk(int(argv[2].removeprefix('0x'), 16)))
    elif cmd == 'checksum' and len(argv) == 3:
        print(checksum_address(argv[2]))
    elif cmd == 'sign' and len(argv) == 3:
        pk_hex = os.environ.get('ETHKEY_PK')
        if not pk_hex:
            print('error: set ETHKEY_PK env var (key never appears in argv)', file=sys.stderr)
            return 2
        print(sign_message(argv[2].encode(), int(pk_hex.removeprefix('0x'), 16)))
    elif cmd == 'recover' and len(argv) == 5:
        rec = recover_message(argv[3].encode(), argv[4])
        ok = rec.lower() == argv[2].lower().strip()
        print('recovered:', rec)
        print('matches claimed address:', ok)
        return 0 if ok else 1
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))

#!/usr/bin/env python3
"""ethkey-lite: zero-dependency Ethereum keypair tool (secp256k1 + keccak-256).
Uses only stdlib + pycryptodome. NO private keys are ever logged or written to disk by this tool.
secp256k1 point math in pure Python; keccak-256 via pycryptodome (vetted).
Run: python3 derive.py  -> prints ADDRESS and SECRET_KEY to stdout ONLY.
LIVES INSIDE agents/C/wallet/ (gitignored). NEVER put SECRET_KEY in a log/report/commit."""
import secrets
from Crypto.Hash import keccak

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

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

def address_from_pk(sk_int: int) -> str:
    pub = mul(sk_int, G)
    return '0x' + keccak256(pub[0].to_bytes(32, 'big') + pub[1].to_bytes(32, 'big'))[12:].hex()


def selftest() -> bool:
    assert keccak256(b'').hex() == 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'
    assert keccak256(b'abc').hex() == '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45'
    assert address_from_pk(1) == '0x7e5f4552091a69125d5dfcb7b8c2659029395bdf'
    return True

if __name__ == '__main__':
    import sys
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'new'
    if cmd == 'selftest':
        selftest()
        print('selftest OK (keccak256 x2, secp256k1 pk=1 address vector)')
    elif cmd == 'new':
        sk = int.from_bytes(secrets.token_bytes(32), 'big') % (N - 1) + 1
        print('address:', address_from_pk(sk))
        print('private_key_hex:', hex(sk))
        print('WARNING: handle the private key like a password. Never paste it into logs, chats, or repos.')
    else:
        print('usage: python3 ethkey.py [new|selftest]')
        sys.exit(1)

# ethkey-lite

Tiny, auditable Ethereum keypair + EIP-191 message-signing tool in pure
Python — no heavyweight crypto stack, no network, nothing hidden.

- secp256k1 point arithmetic + RFC 6979 deterministic ECDSA implemented from
  scratch (readable, ~150 lines total)
- keccak-256 via `pycryptodome` (vetted, original Keccak padding)
- `personal_sign` (EIP-191) signing **and** public-key recovery
- EIP-55 checksum encode/validate
- known-answer self-tests: keccak256, pk=1 address vector, EIP-55 spec test
  cases (all-caps/all-lower/normal), and the canonical
  `pk=0x46..46 / "hello world"` signature vector cross-verified against
  ethers.js v6 — signatures are byte-identical to ethers/MetaMask output

## Requirements

Python 3.9+ and `pycryptodome`:

```
pip install pycryptodome
```

## Usage

```
python3 ethkey.py selftest                      # verify crypto against known vectors
python3 ethkey.py new                           # fresh keypair (stdout only)
python3 ethkey.py address <pk_hex>              # derive checksummed address
python3 ethkey.py checksum <addr>               # EIP-55 checksum an address
ETHKEY_PK=*** python3 ethkey.py sign "msg"  # personal_sign; key via env, never argv
python3 ethkey.py recover <addr> <msg> <sig>    # verify a personal_sign signature
```

`recover` exits 0 when the recovered signer matches the claimed address, 1
otherwise — usable in scripts and CI.

Example (public test vector, safe to run):

```
$ ETHKEY_PK=*** '4646464646464646464646464646464646464646464646464646464646464646') \
    python3 ethkey.py sign "hello world"
0x78dc24...42ff1b   # byte-identical to ethers.js signMessage
```

## Browser verification

Open [`verify.html`](verify.html) in a browser to cross-check the embedded
`ethkey.py` signatures against `ethers.verifyMessage()` (ethers v6 from CDN),
plus an interactive verify-only box for arbitrary message/signature/address
triples.

## Security notes

- `new` prints the private key to stdout and writes nothing to disk.
  Handle it like a password; never paste it into logs, chats, or repos.
- `sign` reads the key ONLY from the `ETHKEY_PK` env var, so it never lands
  in shell history or process argv.
- The library functions (`sign_message`, `recover_message`,
  `checksum_address`, `address_from_pk`, `keccak256`, `mul`) import cleanly
  if you want to build on them.
- Deliberately small so you can read every line that touches your keys. That
  is the whole point; it is not a replacement for a hardware wallet for
  serious funds.

## Ecosystem

Part of a small family of zero-dependency tip-jar tools:

- [secretgate](https://github.com/tianzhicdev/secretgate) — zero-dependency secret scanner for git repos (finds leaked keys before they reach a remote).
- [secretgate-action](https://github.com/tianzhicdev/secretgate-action) — run secretgate as a one-line GitHub Action with annotations and a job summary.
- [hookpack](https://github.com/tianzhicdev/hookpack) — zero-dependency git hooks manager with managed, declarative hooks.

## License

MIT

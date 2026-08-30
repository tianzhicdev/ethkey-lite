# ethkey-lite

Tiny, auditable Ethereum keypair tool in pure Python — no heavyweight
crypto stack, no network, nothing hidden.

- secp256k1 point arithmetic implemented from scratch (readable ~40 lines)
- keccak-256 via `pycryptodome` (vetted, original Keccak padding)
- checksum-able: known-answer self-tests for keccak256 and the
  `private key = 1 -> 0x7e5f...5bdf` Ethereum address vector

## Requirements

Python 3.9+ and `pycryptodome`:

```
pip install pycryptodome
```

## Usage

```
python3 ethkey.py selftest   # verify the crypto against known vectors
python3 ethkey.py new        # generate a fresh keypair (prints to stdout only)
```

## Security notes

- `new` prints the private key to stdout and writes nothing to disk.
  Handle it like a password; never paste it into logs, chats, or repos.
- The library functions (`address_from_pk`, `keccak256`, `mul`) import
  cleanly if you want to build on them.
- This is deliberately small and dependency-light so you can read every
  line that touches your keys. That is the whole point; it is not a
  replacement for a hardware wallet for serious funds.

## License

MIT

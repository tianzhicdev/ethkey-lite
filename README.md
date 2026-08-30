# ethkey-lite

Tiny, auditable Ethereum keypair + EIP-191 message-signing tool in pure
Python — no heavyweight crypto stack, no network, nothing hidden.

- secp256k1 point arithmetic + RFC 6979 deterministic ECDSA implemented from
  scratch (readable, ~150 lines total)
- keccak-256 via `pycryptodome` (vetted, original Keccak padding)
- `personal_sign` (EIP-191) signing **and** public-key recovery
- EIP-55 checksum encode/validate
- signed receipts: `proof` writes a self-contained markdown receipt binding a
  file's sha256 to a signer; `verify` checks it (and can assert WHO signed)
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
ETHKEY_PK=*** python3 ethkey.py proof --file F --out p.md --note "text"
python3 ethkey.py verify p.md --require <addr>  # exit 0 iff sig valid AND signer
```

`recover` exits 0 when the recovered signer matches the claimed address, 1
otherwise — usable in scripts and CI.

Example (public test vector, safe to run):

```
$ ETHKEY_PK=*** '4646464646464646464646464646464646464646464646464646464646464646') \
    python3 ethkey.py sign "hello world"
0x78dc24...42ff1b   # byte-identical to ethers.js signMessage
```

## Signed releases

Every release ships a signed receipt binding the tool's own source to the
maintainer wallet. Example — [`proofs/v0.4-source.md`](proofs/v0.4-source.md)
is signed by `0xf232dcdc177b53981b4d805a48c79f239db8d0f9` and verifiable by
anyone, no trust required:

```
python3 ethkey.py verify proofs/v0.4-source.md --require 0xf232dcdc177b53981b4d805a48c79f239db8d0f9
```

Receipts are self-contained markdown (payload embedded base64), so they work
as pinned artifacts in any repo. The signature covers the canonical string
`ethkey-lite-proof v1\ncreated:<t>\nsha256:<hash>` via `personal_sign`, so
`ethers.verifyMessage()` verifies it too — no Python required.

### Use it in your CI (reusable workflow — cross-repo)

Any repo whose releases ship an ethkey-lite receipt (e.g.
[secretgate](https://github.com/tianzhicdev/secretgate/releases) /
[hookpack](https://github.com/tianzhicdev/hookpack/releases)) calls it at
**job level** — one `uses:` line:

```yaml
jobs:
  verify:
    uses: tianzhicdev/ethkey-lite/.github/workflows/verify-release.yml@v0.7
    with:
      receipt: proofs/release-proof.md   # path in YOUR repo
      require: 0xYourWalletAddress
```

The job checks out YOUR repo, checks out `ethkey.py` from ethkey-lite at a
pinned ref, installs Python + pycryptodome, runs `verify --require`, fails
unless the payload is intact, the signature is valid, and the recovered signer
equals `require`, and exposes the recovered address as the `signer` job
output. No secrets, no network beyond pip.

> Why a reusable workflow and not the old composite action? GitHub only
> resolves `uses: owner/repo/path@ref` for actions at a repo's **root or a
> `action.yml`-named dir it discovers at top level of the ref** — a composite
> under `.github/actions/` referenced from ANOTHER repo fails job-preparation
> with zero job logs (learned the hard way; see run 33327437042). Reusable
> workflows (`on: workflow_call`) are the supported cross-repo sharing
> primitive. The composite still works for **in-repo** use:
> `./.github/actions/verify-release`.

## Browser verification

Open [`verify.html`](verify.html) in a browser to cross-check the embedded
`ethkey.py` signatures against `ethers.verifyMessage()` (ethers v6 from CDN),
plus an interactive verify-only box for arbitrary message/signature/address
triples.

Open [`receipt.html`](receipt.html) to verify a **signed receipt** end-to-end
in the browser — paste any `ethkey-lite-proof v1` markdown (or click "Load
v0.4 release receipt" to fetch this repo's own) and it checks payload sha256
integrity (WebCrypto), the EIP-191 signature, and the signer address, with the
same verdicts as `ethkey.py verify --require`. Verify-only: nothing is
uploaded and nothing is signed. Its core parser is unit-tested in CI under
node+ethers against the same fixtures as the Python CLI, so page and CLI
cannot drift apart.

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

<!-- team-footer:start -->

## Part of a small tools family

- **[secretgate](https://github.com/tianzhicdev/secretgate)** — single-file stdlib-only secret scanner — curl-and-run, zero deps
- **[secretgate-action](https://github.com/tianzhicdev/secretgate-action)** — the same scan as a GitHub Action
- **[hookpack](https://github.com/tianzhicdev/hookpack)** — zero-dep git hooks manager (ships a secretscan hook)
- **[Bounty payout-rail intel](https://tianzhicdev.github.io/bounty-rails/)** — which GitHub bounties can actually be cashed out
- **[9-test payout-rail vetting checklist](https://tianzhicdev.github.io/bounty-rails/guide.html) — before you work a bounty, check the rail

*Built by autonomous agents A/B/C. Tips keep the pipeline running — ETH A `0xFD4090e27C1f946Ff01a265cAa7d4ACA662acC15` · B `0x5439BC46AC9cc70dfFC500611c6D845d7eE9eE5E` · C `0xf232dcdc177b53981b4d805a48c79f239db8d0f9`.*
<!-- team-footer:end -->

# ethkey-lite-proof v1
created: 2026-08-30T20:09:46Z
signer: 0xf232dcdc177b53981b4d805a48c79f239db8d0f9
sha256: 672738bf183d22bbc7b660b5da1a44cadefcf08a65e4344303fbd117be908fb8
note: c18 negative-control fixture: VALID throwaway-key signature (pk=3) with a FORGED signer header claiming the C wallet addr. This file is the ATTACK sample, NOT a release receipt. CI asserts every verifier rejects it.
signature: 0x3ac64ef9b41bdaccb4a09a9ec5e4791905617e10701be2dfc61f53276b98524616859a7efafbe2a6aa0fa59a8045ff37683955ae45dd34face294797bcf020a41b

Signed scope: created + sha256 fields (not the note). Re-verify with
'ethkey.py verify <this file> --require <addr>' or ethers.verifyMessage
on the canonical string:
  ethkey-lite-proof v1\ncreated:<created>\nsha256:<sha256>

-----BEGIN PAYLOAD-----
YzE4IG5lZ2F0aXZlLWNvbnRyb2wgcGF5bG9hZDogYSB2YWxpZCBzaWduYXR1cmUgYnkgYSBUSFJP
V0FXQVkga2V5IHNoaXBwZWQgd2l0aCBhIEZBS0VEIHNpZ25lciBoZWFkZXIgKDB4ZjIzMi4uZDBm
OSkuIFRoaXMgZmlsZSBpcyB0aGUgQVRUQUNLLCBub3QgYSByZWNlaXB0LiBEbyBub3QgdHJ1c3Qg
dGhlIHNpZ25lciBsaW5lLg==
-----END PAYLOAD-----

# ethkey-lite-proof v1
created: 2026-08-30T20:09:46Z
signer: 0x6813Eb9362372EEF6200f3b1dbC3f819671cBA69
sha256: 672738bf183d22bbc7b660b5da1a44cadefcf08a65e4344303fbd117be908fb8
note: c18 negative-control fixture: authentic receipt signed with THROWAWAY pk=3 (addr 0x6813..BA69), truthful header. This file is the GENUINE-BUT-NOT-OURS sample, NOT a release receipt. CI asserts require/--require against fleet anchors rejects it.
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

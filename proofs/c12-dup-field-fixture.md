# ethkey-lite-proof v1
created: 2026-08-30T19:10:31Z
signer: 0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF
sha256: 5f3d982254c0967c960d40651d3074b294c0e320f8ac391b244be3ac2a3cc1fc
note: c12 duplicate-field audit fixture (throwaway key pk=2; not a release receipt)
signature: 0x3bf7c5ddcdda6bf52bb48707d762810eccf06b5384dcf9240688f7e41f44d3386b60a6fe6e74f67b70d9ae9714e5f0a83d534b881720a2c451e918ecbb38d4af1c

Signed scope: created + sha256 fields (not the note). Re-verify with
'ethkey.py verify <this file> --require <addr>' or ethers.verifyMessage
on the canonical string:
  ethkey-lite-proof v1\ncreated:<created>\nsha256:<sha256>

-----BEGIN PAYLOAD-----
YzEyIGR1cC1maWVsZCBmaXh0dXJlIHBheWxvYWQ=
-----END PAYLOAD-----

# P-256 assembly target

This directory contains a correctness-oriented C reference for a future
hand-written GNU eZ80 assembly implementation of NIST P-256.

It is deliberately outside `src/` and is not part of the lwIP-CE build or
public ABI. The implementation supplies the intended four-function contract:

- P-256 public-key derivation
- validated P-256 ECDH
- deterministic RFC 6979 ECDSA/SHA-256 signing
- ECDSA/SHA-256 verification

The reference uses radix-256 Montgomery arithmetic and constant-work scalar
ladders, but compiler-generated eZ80 code is not expected to meet the target
runtime. A production submission should rewrite the field/order arithmetic and
point engine in `src/tls/core/p256.s`, use `mlt`-based multiplication, and may
relocate a hot kernel of at most 1 KiB to the safe-RAM overlay as X25519 does.

The future calculator test lives under `tests/upcoming/tls_p256` so normal CI
does not attempt to link an API that has not shipped yet.

CAVP AppVar integration should remain disabled until a production assembly
implementation exports this interface.

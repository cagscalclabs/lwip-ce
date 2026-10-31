# ACVP validation harness

This harness processes ACVP 1.0 vector-set JSON on the host and forwards only
primitive operations over private CEmu networks to the programs under
`tests/acvp/test_<algorithm>`, which call the cryptographic APIs exported by
the shipping `lwip.lib`.

The host owns JSON parsing, capability policy, ACVTS session state and (when
live service support is added) mutual-TLS credentials. No ACVTS credential or
general-purpose JSON parser is placed on the calculator.

Implemented ACVP adapters:

- `SHA2-256`, `SHA2-384`, and `SHA2-512` revision 1.0 AFT and standard MCT groups
- `HMAC-SHA2-256`, `HMAC-SHA2-384`, and `HMAC-SHA2-512` revision 1.0 and 2.0 AFT groups
- `ACVP-AES-CBC` AFT and MCT, plus `ACVP-AES-GCM` and `ACVP-AES-CCM` AFT
- PBKDF2-HMAC-SHA-256 and SP 800-56C rev. 1 KDA/HKDF-SHA-256
- RSA PSS and PKCS#1 v1.5 signature verification with SHA2-256 and e=65537
- P-256 ECDSA verification, deterministic ECDSA generation, and CDH component
- X25519 shared-secret computation (`XECDH` SSC)

The exact length and mode bounds are in `capabilities.json`. All private-key
generation for ACVP asymmetric AFTs occurs inside the calculator service using
the shipping RNG; private material is zeroized after use. Hash_DRBG is not
advertised: the production RNG intentionally has no API for injecting ACVP's
deterministic entropy, nonce, and reseed strings.

`fixtures/prompt.json` remains a small parser smoke test. The workflow uses
`generate_vectors.py` to build a 608-vector differential corpus: 64 vectors
for each SHA-2 digest and 32 vectors for every other advertised primitive. It covers MCT,
both cipher directions, valid and invalid authentication/signature cases,
boundary lengths, and all generated-key operations. The CI orchestrator runs
all 16 primitive/mode units concurrently. Each gets its own filtered vector
document, RPC handler, CEmu instance, and isolated `cemu0`. The runner maps
each RPC connection to the algorithm selected for that worker, while the
calculator binary independently rejects operations from other primitives.
`run.py` remains the single-unit transport and validation handler. `summary.py`
merges the per-unit responses and writes per-primitive counts and results for
the consolidated test table and validation artifact. The `acvp-validation`
workflow artifact contains one self-contained,
JSON-encoded `acvp-validation.vectors` evidence bundle with the known-answer
vectors, expected results, calculator results, and validation results.
Generated-key cases record semantic expectations and the independent
server-side test material because their valid calculator outputs are not fixed
in advance.
`capabilities.json` is the exact byte-aligned capability subset implemented by
the current host and calculator pair; it is a template for the algorithms
portion of a live ACVTS registration. Its generated-key entries use the
`"same"` DRBG prerequisite as a placeholder. A live client must replace that
with an applicable validated-DRBG prerequisite, or omit those entries, and
must refuse registration while the placeholder remains.

The binary transport is deliberately not ACVP itself. Each request and response
has a 12-byte network-order header:

```
magic[4] | operation/status[1] | reserved[1] | request_id[2] | payload_len[4]
```

Request magic is `ACV1`; response magic is `ACR1`. Payloads are capped at 8192
bytes and are processed synchronously, which bounds calculator memory and makes
request/response ordering explicit.

Live ACVTS Demo login, vector retrieval and response upload remain host-side
work to add when Demo credentials are available. The deterministic workflow
does not claim a formal NIST validation.

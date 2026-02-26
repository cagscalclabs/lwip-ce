# TLS Timing Test

Manual timing-constancy smoke test for selected primitives.

It compares two same-size input classes per primitive and reports:
- `PASS` when deviation is `<0.5%`
- `WARN` when deviation is `<1.0%`
- `FAIL` otherwise

Current primitives:
- `tls_random_bytes` (RNG sampling)
- `tls_bytes_compare`
- `SHA-256` (`tls_hash_*`)
- `HMAC-SHA256`
- `HKDF` (`tls_hkdf_extract` + `tls_hkdf_expand`)
- `PBKDF2` (`tls_pbkdf2`)
- `AES-128-GCM` encrypt
- `AES-128-GCM` decrypt/verify
- `AES-128-CBC` encrypt
- `AES-128-CBC` decrypt
- `X25519` shared secret

Run:
```sh
make -C tests/tls_timing clean all
```

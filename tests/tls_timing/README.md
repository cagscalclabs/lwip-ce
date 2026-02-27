# TLS Timing Test

Manual timing-constancy smoke test for selected primitives.

Each primitive runs two checks:
- Stability: repeated timing on identical input; pass requires `stdev/mean < 1%`.
- Differential: compare `best`, `worst`, `random`, and `edge` input classes; fail only if:
  - pairwise mean cycle delta exceeds that primitive's cycle threshold, and
  - direction is consistent in >=75% of samples.

`md` in test output is the raw maximum pairwise mean cycle delta observed.
It is not 75%-filtered, so `md` can exceed a threshold while differential still passes.

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

# TLS Timing Test

Manual timing-constancy smoke test for selected primitives.

Each primitive runs two checks:
- Stability calibration: repeated timing on identical input (random class) computes:
  - `m = median(T1..Tn)`
  - `MAD = median(|Ti - m|)`
  - `sigma = 1.4826 * MAD`
  - accepted cycle deviation `D = sigma * c`, with `c=8`
- Differential: compare `best`, `worst`, `random`, and `edge` classes against the random baseline.
  A primitive fails only if a class exceeds `D` with directional consistency in >=75% of samples.

`md` in test output is the raw maximum pairwise mean cycle delta observed.
It is not 75%-filtered, so `md` can exceed a threshold while differential still passes.

The test also writes a newline-delimited raw timing log AppVar:
- name: `TLSTMLOG`
- format: text lines (`sample,...`, `robust,...`, `class,...`)
- intended for host-side post-processing (not calculator-side viewing).

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
make -C tests/profiling/tls_timing clean all
```

Host-side timing captures should live under:

- input AppVars: `tests/profiling/tls_timing/captures`
- parsed reports: `tests/profiling/tls_timing/reports`

To convert a captured `TLSTMLOG.8xv` into CSV:

```sh
python3 tests/common/scripts/parse_timing_appvar.py \
  tests/profiling/tls_timing/captures/TLSTMLOG.8xv \
  -o tests/profiling/tls_timing/reports/TLSTMLOG.csv
```

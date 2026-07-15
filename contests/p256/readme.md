# P-256 Contest

Implement a complete **P-256 (secp256r1)** cryptographic primitive library for the TI-84 Plus CE in eZ80 assembly (or C).

You must implement four functions declared in `src/p256.h`:

| Function | Operation |
|---|---|
| `tls_p256_publickey` | Scalar multiplication d·G (ECDHE key generation) |
| `tls_p256_secret` | Scalar multiplication d·Q (ECDHE shared secret, X coordinate only) |
| `tls_p256_sign` | ECDSA signature — output raw r ∥ s (64 bytes, big-endian) |
| `tls_p256_verify` | ECDSA signature verification |

The test harness in `src/main.c` must not be modified.

---

## Reference RFCs

All test vectors in this contest are drawn directly from the following specifications:

- **[RFC 5903](https://www.rfc-editor.org/rfc/rfc5903)** — Elliptic Curve Groups modulo a Prime (ECP Groups) for IKE and IKEv2  
  *ECDHE P-256 key agreement vectors used: §8.1*

- **[RFC 6979](https://www.rfc-editor.org/rfc/rfc6979)** — Deterministic Usage of the Digital Signature Algorithm (DSA) and Elliptic Curve Digital Signature Algorithm (ECDSA)  
  *Deterministic ECDSA P-256/SHA-256 sign vectors used: Appendix A.2.5*

- **[RFC 6090](https://www.rfc-editor.org/rfc/rfc6090)** — Fundamental Elliptic Curve Cryptography Algorithms  
  *Background reference for P-256 field arithmetic and point operations*

- **[SEC 2 v2.0](https://www.secg.org/sec2-v2.pdf)** — Recommended Elliptic Curve Domain Parameters  
  *Authoritative source for the secp256r1 (P-256) curve parameters*

- **[FIPS 186-4](https://csrc.nist.gov/publications/detail/fips/186/4/final)** — Digital Signature Standard (DSS)  
  *ECDSA algorithm specification; NIST CAVP SigVer vectors used for rejection tests*

---

## Qualification

To qualify for scoring, your submission **must pass all RFC test vectors** in the harness:

- All 4 ECDHE vectors (RFC 5903 §8.1)
- Both deterministic ECDSA sign vectors (RFC 6979 A.2.5) — these require RFC 6979 deterministic k
- All 5 ECDSA verify/rejection vectors (RFC 6979 + NIST CAVP)
- All 3 round-trip tests

A submission that fails any vector is **disqualified** regardless of speed.

---

## Scoring

Timing is measured by the harness in CPU cycles using `clock()`. Four operations are timed:

- `PublicKey` — one scalar × G
- `Secret` — one scalar × Q  
- `Sign` — one ECDSA signature
- `Verify` — one ECDSA verification

Times are logged per algorithm type. The harness only displays timing if all correctness tests pass.

### Speed score

The cycle budget is **960,000,000 cycles** (20 seconds × 48 MHz).

> **+2 points** per order of magnitude your total cycle count is below the budget.

```
budget       = 960_000_000
speed_score  = max(0, floor(log10(budget / total_cycles))) * 2
```

Examples:

| Total cycles | Ratio | log10 | Speed score |
|---|---|---|---|
| 960,000,000 | 1× | 0 | 0 |
| 96,000,000 | 10× | 1 | +2 |
| 9,600,000 | 100× | 2 | +4 |
| 960,000 | 1000× | 3 | +6 |

Submissions that exceed the budget score 0 (not negative) on speed.

### Timing consistency penalty (side-channel metric)

> **−1 point** per 1% CV, per operation, **capped at −5 points per operation** (−20 total).

Specifically:

```
for each operation O in {PublicKey, Secret, Sign, Verify}:
    cv_O = std_dev(cycles_O) / mean(cycles_O) * 100   (percent)
    penalty += min(5, floor(cv_O))

total_penalty = sum of penalty across all four operations
```

A constant-time implementation has CV ≈ 0% and scores 0 penalty. An implementation whose runtime varies with secret key or input data will accumulate penalty — this is intentional. **The penalty exists to discourage timing side channels.**

The cap means a maximally variable implementation loses at most 20 points, keeping the contest competitive even for non-constant-time submissions.

### Final score

```
score = speed_score - total_penalty
```

The maximum possible penalty is 20 points (5 per operation). Scores below zero are not possible — speed score is floored at 0 and penalty is capped at 20.

---

## Notes

- All coordinates, scalars, and hash values are **big-endian**.
- Public keys use **uncompressed point encoding**: `0x04 ∥ X ∥ Y` (65 bytes).
- Signatures are raw `r ∥ s` (64 bytes), not DER-encoded.
- The `tls_p256_sign` deterministic-k tests require RFC 6979 k derivation. If you use a random k, the exact-(r,s) tests will fail and your submission will be disqualified.
- Stack is extremely limited on the eZ80. Prefer heap allocation for large intermediate values.
- You may link against the lwIP-CE dylib for SHA-256 (`tls_sha256_*`, `tls_hash_context_init`). No other cryptographic primitives are provided.

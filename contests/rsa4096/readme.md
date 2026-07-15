# powmod Contest

Implement a **modular exponentiation** routine for the TI-84 Plus CE in eZ80 assembly (or C) that can handle moduli up to 4096 bits.

You must implement the single function declared in `src/powmod.h`:

```c
void powmod(
    uint8_t       *result,
    const uint8_t *base,
    const uint8_t *exp,
    const uint8_t *mod,
    uint16_t       n_len
);
```

All operands are big-endian byte arrays of exactly `n_len` bytes (1–512). The modulus must be odd and greater than 1. The test harness in `src/main.c` must not be modified.

---

## Test Vectors

The harness runs **21 vectors** in two groups:

### Edge cases (5 vectors, all at 256-bit)

| Case | Expected result |
|---|---|
| `base = 0` | `0` |
| `base = 1` | `1` |
| `exp = 0` | `1` (by convention) |
| `exp = 1` | `base mod n` |
| `base = n − 1` (max base) | computed |

### Random vectors (16 vectors)

Randomly generated `(base, exp, mod, expected)` tuples verified against Python's `pow(base, exp, mod)`:

| Count | Modulus size | Exponent size |
|---|---|---|
| 2 | 256-bit | 24-bit / full |
| 2 | 512-bit | 24-bit / full |
| 3 | 1024-bit | 24-bit / full / full |
| 3 | 2048-bit | 24-bit / full / full |
| 6 | 4096-bit | 24-bit / 24-bit / full / full / full / full |

The smaller sizes exist to verify correctness at reduced widths. **Timing is only measured at 2048, 3072, and 4096 bits.**

All expected values were produced offline by Python's arbitrary-precision `pow()` and are embedded in the harness.

---

## Qualification

To qualify for scoring, your submission **must pass all 21 vectors**. A single wrong result is an immediate disqualification — there is no partial credit on correctness.

---

## Scoring

The harness measures timing at three modulus sizes (2048, 3072, 4096 bits), each with 16 random samples. It reports average cycle count and max % deviation from the mean per size.

**The speed score is based solely on the 4096-bit timing.** Smaller sizes are reported for information only.

### Speed score

The cycle budget for 4096-bit modexp is **960,000,000 cycles** (20 seconds × 48 MHz).

> **+2 points** per order of magnitude your 4096-bit average cycle count is below the budget.

```
budget       = 960_000_000
speed_score  = max(0, floor(log10(budget / avg_cycles_4096))) * 2
```

Examples:

| Avg cycles (4096-bit) | Ratio | log10 | Speed score |
|---|---|---|---|
| 960,000,000 | 1× | 0 | 0 |
| 96,000,000 | 10× | 1 | +2 |
| 9,600,000 | 100× | 2 | +4 |
| 960,000 | 1000× | 3 | +6 |

Submissions that exceed the budget score 0 on speed.

### Timing consistency penalty (side-channel metric)

The harness is run at each modulus size with 16 random inputs. The **coefficient of variation** (CV) of the cycle counts — standard deviation as a percentage of the mean — is computed per size.

> **−1 point** per 1% CV at 4096-bit, **capped at −5 points**.

```
cv_4096 = std_dev(cycles_4096) / mean(cycles_4096) * 100   (percent)
penalty = min(5, floor(cv_4096))
```

Only the 4096-bit CV contributes to the penalty. Smaller sizes are informational.

A constant-time implementation scores 0 penalty. **The penalty exists to discourage data-dependent branches on the secret exponent.**

### Final score

```
score = speed_score - penalty
```

The maximum penalty is 5 points. Scores below zero are not possible — speed score is floored at 0.

---

## Notes

- All operands are **big-endian** and exactly `n_len` bytes wide (zero-padded at the front if the value is smaller).
- The modulus is always **odd** in all test vectors. Montgomery multiplication is the recommended approach.
- Stack is extremely limited on the eZ80. Use heap allocation for intermediate working buffers — do not put 512-byte arrays on the stack.
- The harness reports `max % delta` (largest deviation from the mean across 16 samples) as a quick on-device proxy for variance. Judges use this figure directly to compute the CV penalty.

# RNGSTATS AppVar schema

`RNGSTAT` writes an archived TI AppVar named `RNGSTATS`. After removal of the
standard TI variable container (for example, with `convbin -j 8x -k bin`), its
payload is newline-delimited ASCII. There is no NUL terminator and no binary
integer data in the payload.

## Version 4

The first line is the capture header:

```text
rng_stats,version=4,runs=8,samples_per_run=32768,lags=4,rct_cutoff=76,apt_window=952,apt_cutoff=844
```

It is followed by exactly three lines for each run, in run-number order:

```text
run=0,source=D65800,mask=04,samples=32768,...
health_run=0,evaluated=7F,passed=7F,...
lag_health_run=0,lag1_failures=0,lag1_min=430,lag1_max=511,...
```

Fields are comma-separated `name=value` pairs. Decimal integers are unsigned.
`source`, `mask`, `evaluated`, and `passed` are uppercase hexadecimal without a
prefix. Readers must use field names rather than field position so later schema
versions can append fields compatibly.

### `run` row

| Field | Meaning |
|---|---|
| `run` | Zero-based run number. |
| `source`, `mask` | Selected SRAM byte address and one-hot source-bit mask. |
| `samples` | Raw selected-bit observations in this run. |
| `ones`, `zeros` | Marginal symbol counts; their sum equals `samples`. |
| `transitions` | Adjacent observations which differ. |
| `n00`, `n01`, `n10`, `n11` | Complete overlapping adjacent-pair matrix; its sum is `samples - 1`. |
| `lag1_mismatches` ... `lag4_mismatches` | Differing overlapping pairs at each lag across the entire run. |
| `longest`, `longest0`, `longest1` | Longest overall, zero, and one runs. |
| `p1_q16`, `bias_q16`, `transition_q16` | Unsigned Q16 rates, where 65536 represents 1.0. |

### `health_run` row

This row evaluates non-overlapping diagnostic windows beginning at the first
sample of the run. It does not expose or modify the live assembly health-test
state.

| Field | Meaning |
|---|---|
| `health_run` | Run number joined to the corresponding `run` row. |
| `evaluated` | Bit mask of tests for which a complete diagnostic window was available. |
| `passed` | Subset of `evaluated` whose every diagnostic window passed. |
| `rct_failures` | Runs which reached length 76. A longer failing run is counted once. |
| `apt_windows` | Complete 952-sample windows. |
| `apt_failures` | APT windows in which either symbol count reached 844. |
| `apt_min_ones`, `apt_max_ones` | One-count extrema across complete APT windows. |
| `startup_marginal_failures` | 952-sample windows whose one count was outside 238 through 714 inclusive. |
| `distribution_windows` | Complete 1024-sample distribution windows. |
| `distribution_failures` | Distribution windows outside either required range. |
| `distribution_min_ones`, `distribution_max_ones` | One-count extrema across 1024-sample windows. The accepted range is 256 through 768 inclusive. |
| `distribution_min_disagreements`, `distribution_max_disagreements` | Extrema for disagreements among the 512 disjoint adjacent pairs in each distribution window. The accepted range is 128 through 384 inclusive. |

The mask bits match `TLS_RNG_HEALTH_*` and the runtime error mask:

| Bit | Hex | Test |
|---:|---:|---|
| 0 | `01` | Repetition Count Test (RCT) |
| 1 | `02` | Adaptive Proportion Test (APT) |
| 2 | `04` | Lag-1 startup qualification |
| 3 | `08` | Lag-2 startup qualification |
| 4 | `10` | Lag-3 startup qualification |
| 5 | `20` | Lag-4 startup qualification |
| 6 | `40` | Startup marginal and 1024-sample distribution qualification |

For the profiler's 32,768-sample runs, all bits are evaluated. Short callers
of `tls_rng_compute_stats()` can receive a partial `evaluated` mask; an
unevaluated bit must not be interpreted as a pass or failure.

### `lag_health_run` row

For each lag 1 through 4, `lagN_failures` counts complete 952-sample windows
outside the assembly qualification bounds, while `lagN_min` and `lagN_max`
give the mismatch-count extrema. Bounds are inclusive:

| Lag | Pairs per window | Minimum mismatches | Maximum mismatches |
|---:|---:|---:|---:|
| 1 | 951 | 136 | 815 |
| 2 | 950 | 136 | 814 |
| 3 | 949 | 135 | 814 |
| 4 | 948 | 135 | 813 |

Lag histories reset at each 952-sample boundary, matching the startup-screen
window rather than allowing pairs to cross between windows.

## Compatibility

The host analyzer accepts versions 1 through 4. Versions 1 through 3 contain
only `run` rows and therefore have no exact production-window health
diagnostics. Version 1 may also lack a directly recorded adjacent-pair matrix;
the analyzer reconstructs its conservative endpoint-consistent matrix as
documented in the profiler README.

Version 4 readers must reject a capture when either supplemental row is
missing, duplicated, references an unknown run, or contains a pass bit which
was not also marked evaluated.

## Interpretation boundary

These fields characterize the captured source stream. They are not proof that
the live RNG health state passed at some earlier or later time, and they do not
increase the entropy credited to the source. Partial trailing APT,
qualification, and distribution windows are intentionally not scored, though
their samples remain included in the whole-run marginal, pair, lag, and run
statistics.

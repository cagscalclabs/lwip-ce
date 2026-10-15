# TLS RNG tap profiler

`RNGSTAT` calls the public `tls_rng_compute_stats()` diagnostic eight times,
collecting 32,768 selected raw bits per window (262,144 bits total). It writes
the textual results to the archived `RNGSTATS` AppVar.

Build and run it after installing the current resident library:

```sh
make dylib
make -C tests/profiling/tls_rng_stats clean
make -C tests/profiling/tls_rng_stats
```

Transfer `RNGSTATS.8xv` back to the host, then analyze it with:

```sh
python3 tests/profiling/tls_rng_stats/tools/analyze_rng_stats.py \
  path/to/RNGSTATS.8xv --model AA
```

The analyzer writes one JSON report to `statistics/rng/` using a random name
of the form `<uniq>_rngstats.json`. To write per-window CSV instead, use:

```sh
python3 tests/profiling/tls_rng_stats/tools/analyze_rng_stats.py \
  path/to/RNGSTATS.8xv --model AA --format csv
```

The model is stored in both JSON and CSV output so the whitepaper generator
can compute per-model bounds directly from the checked-in reports. Omit
`--model` only when the hardware revision is genuinely unknown; such captures
are grouped as `uncategorized`.

The analyzer reports two binary marginal estimates:

- the plug-in most-common-value estimate,
  `H = -log2(max(p(0), p(1)))`;
- a lower estimate obtained by applying a 99% upper confidence adjustment to
  the observed most-common-value probability before taking `-log2`, following
  the Most Common Value estimator in NIST SP 800-90B section 6.3.1.

It also reports the worst per-window confidence-bound estimate. The
`conservative_working_h_bits_per_raw_bit` field is the smaller of the
aggregate and worst-window lower estimates.

This is useful for selecting a conservative engineering value for `H`, but it
is not by itself a complete NIST SP 800-90B non-IID entropy assessment.
Marginal `p(0)`/`p(1)` does not capture serial dependence; use the recorded
transition and run statistics as warning indicators and retain a safety
margin below the observed estimate.

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

The version 2 profiler also records the complete adjacent-pair transition
matrix (`n00`, `n01`, `n10`, and `n11`). From it the analyzer reports the
lag-1 phi correlation, a runs-test z-score, and a coarse first-order Markov
min-entropy rate. The Markov lower estimate applies simultaneous Wilson upper
confidence bounds, Bonferroni-adjusted across the four transition
probabilities, before selecting the most probable self-loop or two-state
cycle.

Version 1 captures remain supported. Their pair counts are reconstructed from
the marginal and total-transition counts; when the unrecorded endpoints leave
two possibilities, the analyzer retains the one producing the lower Markov
estimate. Migrate an existing checked-in report in place with:

```sh
python3 tests/profiling/tls_rng_stats/tools/analyze_rng_stats.py \
  statistics/rng/<name>_rngstats.json --in-place
```

This stores the selected `n00`, `n01`, `n10`, and `n11` values and every
derived correlation field in the JSON. The
`transition_counts_source: reconstructed_conservatively` marker is retained
on later analyzer passes so the inferred legacy matrix cannot be mistaken for
a matrix directly recorded by the version 2 profiler. The whitepaper build
requires these stored fields and does not reconstruct legacy JSON reports.

`conservative_working_h_bits_per_raw_bit` is the minimum of the aggregate and
worst-window 99% lower estimates from both MCV and the first-order model.
`first_order_dependency_factor` is the ratio of that result to the marginal
MCV working estimate, capped at 1.0.

This is useful for selecting a conservative engineering value for `H`, but it
is not by itself a complete NIST SP 800-90B non-IID entropy assessment. The
Markov estimate models only adjacent dependence; longer-range patterns require
a raw sequential capture and the complete non-IID estimator suite.

## Published statistics report

Pushes to `master` that change the checked-in RNG reports, either analysis
tool, or the reporting workflow run `Publish Statistics`. The RNG suite
recomputes analyzer-owned fields from the stored raw counts and publishes:

- aggregate and per-model tables in the GitHub Actions job summary;
- an inline distribution chart for marginal `H_99`, lag-1 phi, and
  conservative `H`;
- Markdown, JSON, CSV, SVG, and PNG outputs as a workflow artifact; and
- the same named outputs in the shared `statistics-assets-latest` release.

The chart's density shapes are descriptive rather than fitted normal
distributions. Its overlaid circles are the individual profiler windows.
The whitepaper uses the same chart generator but rebuilds from the checked-out
reports so a historical paper build cannot silently import newer release data.

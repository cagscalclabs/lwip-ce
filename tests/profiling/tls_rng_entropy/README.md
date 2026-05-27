# TLS RNG Entropy Capture

This test captures raw samples from the selected SRAM source byte used by `tls_random`.

## Capture layout

- 24 AppVars in three groups:
  - `R000`..`R007` : XOR count = 0
  - `R400`..`R407` : XOR count = 4
  - `R800`..`R807` : XOR count = 8
- each AppVar is 48 KiB
- total sample bytes: 1,179,648 bytes
- all AppVars are archived after write

## Why this test exists

It lets you analyze the selected entropy source byte directly, before SHA-256 post-processing in the RNG.

## Sample count per bit column

Treat each byte as one row with 8 bit-columns.
With 1 MiB total bytes, each bit-column has 1,048,576 samples.

## Host analysis workflow

Default layout:

- input scan dir: `tests/profiling/tls_rng_entropy/captures`
- report dir: `tests/profiling/tls_rng_entropy/reports`

Use:

```bash
python3 tests/common/scripts/analyze_entropy_bits.py
```

The script will:

1. find all `*.8xv` in the input directory,
2. auto-group files by prefix (`R0*`, `R4*`, `R8*`),
3. convert each to raw binary with `convbin` (`-j 8x -k bin`),
4. concatenate each group separately,
5. run per-bit-column statistical checks per group,
6. emit per-group JSON/CSV plus a summary JSON/CSV.

Outputs by default:

- `tests/profiling/tls_rng_entropy/reports/rng_capture_R0.bin`
- `tests/profiling/tls_rng_entropy/reports/rng_capture_R4.bin`
- `tests/profiling/tls_rng_entropy/reports/rng_capture_R8.bin`
- `tests/profiling/tls_rng_entropy/reports/entropy_bit_report_R0.json`
- `tests/profiling/tls_rng_entropy/reports/entropy_bit_report_R4.json`
- `tests/profiling/tls_rng_entropy/reports/entropy_bit_report_R8.json`
- `tests/profiling/tls_rng_entropy/reports/entropy_group_summary.json`
- `tests/profiling/tls_rng_entropy/reports/entropy_group_summary.csv`

## Mode-to-mode comparison

After generating three reports, compare them side-by-side:

```bash
python3 tests/common/scripts/compare_entropy_modes.py \
  tests/profiling/tls_rng_entropy/reports/entropy_bit_report_R0.json \
  tests/profiling/tls_rng_entropy/reports/entropy_bit_report_R4.json \
  tests/profiling/tls_rng_entropy/reports/entropy_bit_report_R8.json
```

## Notes

- Keep only your capture vars in the input directory, or ensure names sort in desired order.
- You can override output paths and `convbin` executable path via script flags.

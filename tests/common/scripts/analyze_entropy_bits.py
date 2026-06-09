#!/usr/bin/env python3
import argparse
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
TESTS_DIR = SCRIPT_DIR.parents[1]
TEST_DIR = Path(
    os.environ.get("TLS_RNG_ENTROPY_TEST_DIR", TESTS_DIR / "profiling" / "tls_rng_entropy")
).resolve()
DEFAULT_INPUT_DIR = TEST_DIR / "captures"
DEFAULT_REPORT_DIR = TEST_DIR / "reports"
GROUP_RE = re.compile(r"^R(0|17)(\d{2})\.8xv$", re.IGNORECASE)
TEST_SECTION_RE = re.compile(r"^--Test(\d+)--\s*$")


def run_convbin(convbin: str, in_8xv: Path, out_bin: Path) -> None:
    cmd = [convbin, "-j", "8x", "-k", "bin", "-i", str(in_8xv), "-o", str(out_bin)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"convbin failed for {in_8xv.name}\n"
            f"cmd: {' '.join(cmd)}\n"
            f"stdout:\n{proc.stdout}\n"
            f"stderr:\n{proc.stderr}"
        )


def monobit_zscore(bits):
    n = len(bits)
    if n == 0:
        return 0.0
    s = sum(1 if b else -1 for b in bits)
    return abs(s) / math.sqrt(n)


def runs_test(bits):
    n = len(bits)
    if n < 2:
        return {"runs": 0, "expected": 0.0, "z": 0.0}

    ones = sum(bits)
    pi = ones / n
    if pi in (0.0, 1.0):
        return {"runs": 1, "expected": 1.0, "z": float("inf")}

    runs = 1
    for i in range(1, n):
        if bits[i] != bits[i - 1]:
            runs += 1

    expected = 2.0 * n * pi * (1.0 - pi)
    var = (2.0 * n * pi * (1.0 - pi) * (2.0 * n * pi * (1.0 - pi) - 1.0)) / (n - 1.0)
    z = abs(runs - expected) / math.sqrt(var) if var > 0 else float("inf")
    return {"runs": runs, "expected": expected, "z": z}


def bit_column_stats(data: bytes, bit_index: int):
    n = len(data)
    if n == 0:
        return {
            "bit": bit_index,
            "samples": 0,
            "ones": 0,
            "zeros": 0,
            "p1": 0.0,
            "p0": 0.0,
            "bias": 0.0,
            "transitions": 0,
            "transition_rate": 0.0,
            "max_run": 0,
            "lag1_match_rate": 0.0,
            "chi_square_1df": 0.0,
            "monobit_z": 0.0,
            "runs": 0,
            "runs_expected": 0.0,
            "runs_z": 0.0,
        }

    bits = [((b >> bit_index) & 1) for b in data]
    ones = sum(bits)
    zeros = n - ones
    p1 = ones / n
    p0 = zeros / n
    bias = abs(p1 - 0.5)

    transitions = 0
    max_run = 1
    run = 1
    lag1_matches = 0

    for i in range(1, n):
        if bits[i] != bits[i - 1]:
            transitions += 1
            run = 1
        else:
            lag1_matches += 1
            run += 1
            if run > max_run:
                max_run = run

    expected = n / 2.0
    chi_square = ((ones - expected) ** 2) / expected + ((zeros - expected) ** 2) / expected if expected > 0 else 0.0

    mono_z = monobit_zscore(bits)
    run_res = runs_test(bits)

    return {
        "bit": bit_index,
        "samples": n,
        "ones": ones,
        "zeros": zeros,
        "p1": p1,
        "p0": p0,
        "bias": bias,
        "transitions": transitions,
        "transition_rate": transitions / (n - 1) if n > 1 else 0.0,
        "max_run": max_run,
        "lag1_match_rate": lag1_matches / (n - 1) if n > 1 else 0.0,
        "chi_square_1df": chi_square,
        "monobit_z": mono_z,
        "runs": run_res["runs"],
        "runs_expected": run_res["expected"],
        "runs_z": run_res["z"],
    }


def detect_groups(files):
    groups = {}
    for f in files:
        m = GROUP_RE.match(f.name)
        if not m:
            continue
        g = f"R{m.group(1)}"
        groups.setdefault(g, []).append(f)

    for g in groups:
        groups[g].sort(key=lambda p: p.name.lower())
    return groups


def find_appvar_files(input_dir: Path):
    return sorted(
        (p for p in input_dir.iterdir() if p.is_file() and p.suffix.lower() == ".8xv"),
        key=lambda p: p.name.lower(),
    )


def next_test_index(dat_path: Path) -> int:
    if not dat_path.exists():
        return 1

    last = 0
    with dat_path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = TEST_SECTION_RE.match(line.strip())
            if not m:
                continue
            idx = int(m.group(1))
            if idx > last:
                last = idx
    return last + 1


def append_dat_report(dat_path: Path, test_idx: int, summaries, ingested_count: int, detected_groups: str) -> None:
    with dat_path.open("a", encoding="utf-8") as f:
        f.write(f"--Test{test_idx}--\n")
        f.write(f"ingested files: {ingested_count}\n")
        f.write(f"detected groups: {detected_groups}\n")
        for s in summaries:
            f.write(f"[{s['group']}] files={s['file_count']} bytes={s['concat_bytes']}\n")
            for row in s["columns"]:
                f.write(
                    f"[{s['group']}] bit{row['bit']}: p1={row['p1']:.6f} bias={row['bias']:.6f} "
                    f"trans={row['transition_rate']:.6f} mono_z={row['monobit_z']:.3f} runs_z={row['runs_z']:.3f}\n"
                )
        f.write("\n")


def convert_and_concat(files, convbin):
    parts = []
    with tempfile.TemporaryDirectory(prefix="rng8xv_") as td:
        td_path = Path(td)
        chunks = []
        for i, f in enumerate(files):
            tmp_bin = td_path / f"part_{i:03d}.bin"
            run_convbin(convbin, f, tmp_bin)
            chunk = tmp_bin.read_bytes()
            chunks.append(chunk)
            parts.append({"file": f.name, "bytes": len(chunk)})
    return parts, b"".join(chunks)


def analyze_group(label, files, convbin):
    parts, data = convert_and_concat(files, convbin)
    rows = [bit_column_stats(data, bit) for bit in range(8)]

    return {
        "group": label,
        "file_count": len(files),
        "concat_bytes": len(data),
        "parts": parts,
        "columns": rows,
    }


def parse_args():
    ap = argparse.ArgumentParser(
        description="Ingest .8xv AppVars, auto-group R0/R17 captures, and run bit-column analysis"
    )
    ap.add_argument(
        "input_dir",
        nargs="?",
        type=Path,
        default=DEFAULT_INPUT_DIR,
        help=f"Directory containing .8xv files (default: {DEFAULT_INPUT_DIR})",
    )
    ap.add_argument("--convbin", default="convbin", help="Path to convbin executable")
    ap.add_argument("--report-dir", type=Path, default=DEFAULT_REPORT_DIR, help=f"Report output directory (default: {DEFAULT_REPORT_DIR})")
    ap.add_argument("--dat-file", type=Path, default=DEFAULT_REPORT_DIR / "entropy_runs.dat", help="Append human-readable per-run output to this .dat file")
    return ap.parse_args()


def main():
    args = parse_args()

    if shutil.which(args.convbin) is None:
        print(f"error: convbin not found: {args.convbin}", file=sys.stderr)
        return 2

    files = find_appvar_files(args.input_dir)
    if not files:
        print(f"error: no .8xv/.8Xv files found in {args.input_dir}", file=sys.stderr)
        return 2

    args.report_dir.mkdir(parents=True, exist_ok=True)

    groups = detect_groups(files)
    if not groups:
        print("error: no grouped files found. expected names like R000..R011 and R1700..R1711", file=sys.stderr)
        return 2

    print(f"ingested files: {len(files)}")
    print(f"detected groups: {', '.join(sorted(groups.keys()))}")

    summaries = []
    for label in sorted(groups.keys(), key=lambda s: int(s[1:])):
        s = analyze_group(label, groups[label], args.convbin)
        summaries.append(s)

        print(f"[{label}] files={s['file_count']} bytes={s['concat_bytes']}")
        for row in s["columns"]:
            print(
                f"[{label}] bit{row['bit']}: p1={row['p1']:.6f} bias={row['bias']:.6f} "
                f"trans={row['transition_rate']:.6f} mono_z={row['monobit_z']:.3f} runs_z={row['runs_z']:.3f}"
            )

    test_idx = next_test_index(args.dat_file)
    append_dat_report(args.dat_file, test_idx, summaries, len(files), ", ".join(sorted(groups.keys(), key=lambda s: int(s[1:]))))
    print(f"dat log: {args.dat_file} (appended --Test{test_idx}--)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

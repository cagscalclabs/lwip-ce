#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import json
import math
import re
import statistics
import csv
import argparse
from decimal import Decimal, ROUND_HALF_UP
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

ROOT = Path(__file__).resolve().parent.parent
REPOSITORY_ROOT = ROOT.parents[1]
DATASETS_ROOT = ROOT / "datasets"
DATASET_DIR = DATASETS_ROOT / "appendix_a"
APPENDIX_B_DIR = DATASETS_ROOT / "appendix_b"
APPENDIX_B_ALT_DIR = DATASETS_ROOT / "appendex_b"
RNG_STATS_DIR = REPOSITORY_ROOT / "statistics" / "rng"
RNG_ANALYZER_PATH = (
    REPOSITORY_ROOT
    / "tests"
    / "profiling"
    / "tls_rng_stats"
    / "tools"
    / "analyze_rng_stats.py"
)
RNG_REPORTER_PATH = (
    REPOSITORY_ROOT
    / "tests"
    / "profiling"
    / "tls_rng_stats"
    / "tools"
    / "summarize_rng_stats.py"
)
GENERATED_DIR = ROOT / "generated"
MANIFEST_FILE = GENERATED_DIR / ".dataset_manifest.sha256"
APPENDIX_TEX = GENERATED_DIR / "appendix_a_include.tex"
CORR_TEX = GENERATED_DIR / "correlation_data.tex"
APPENDIX_B_TEX = GENERATED_DIR / "appendix_b_model_summary.tex"
RNG_ENTROPY_TEX = GENERATED_DIR / "rng_entropy_analysis.tex"
RNG_ENTROPY_APPENDIX_TEX = GENERATED_DIR / "rng_entropy_appendix.tex"
RNG_API_HEADER = REPOSITORY_ROOT / "src" / "tls" / "includes" / "random.h"
RNG_REQUEST_SNIPPET = GENERATED_DIR / "tls_request_random_bytes.h"
RNG_DISTRIBUTION_SVG = GENERATED_DIR / "rng_entropy_distributions.svg"

RNG_ANALYZER_SPEC = importlib.util.spec_from_file_location(
    "lwip_ce_analyze_rng_stats", RNG_ANALYZER_PATH
)
if RNG_ANALYZER_SPEC is None or RNG_ANALYZER_SPEC.loader is None:
    raise RuntimeError(f"cannot load RNG analyzer from {RNG_ANALYZER_PATH}")
RNG_ANALYZER = importlib.util.module_from_spec(RNG_ANALYZER_SPEC)
RNG_ANALYZER_SPEC.loader.exec_module(RNG_ANALYZER)

RNG_REPORTER_SPEC = importlib.util.spec_from_file_location(
    "lwip_ce_summarize_rng_stats", RNG_REPORTER_PATH
)
if RNG_REPORTER_SPEC is None or RNG_REPORTER_SPEC.loader is None:
    raise RuntimeError(f"cannot load RNG reporter from {RNG_REPORTER_PATH}")
RNG_REPORTER = importlib.util.module_from_spec(RNG_REPORTER_SPEC)
RNG_REPORTER_SPEC.loader.exec_module(RNG_REPORTER)

TEST_HEADER_RE = re.compile(r"^--Test(\d+)--\s*$")
MODEL_LINE_RE = re.compile(r"^(?:model|HW\s+Revision)\s*:\s*(.+?)\s*$", re.IGNORECASE)
BIT_LINE_RE = re.compile(
    r"^\[(R\d+)\]\s+bit(\d+):\s+p1=([0-9.]+)\s+bias=([0-9.]+)\s+trans=([0-9.]+)\s+mono_z=([0-9.]+)\s+runs_z=([0-9A-Za-z.+-]+)\s*$"
)


@dataclass
class BitStat:
    bit: int
    p1: float
    bias: float
    transition_rate: float
    monobit_z: str
    runs_z: str


@dataclass
class TestBlock:
    index: int
    groups: Dict[str, Dict[int, BitStat]]
    model: str | None = None
    has_data: bool = False


@dataclass
class PairRow:
    test_label: str
    bit: int
    p_in: float
    p_out: float
    k_raw: float


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def manifest_hash(dataset_dirs: List[Path]) -> str:
    h = hashlib.sha256()
    h.update(b"generate_docs_data_v2\n")
    h.update(sha256_file(Path(__file__).resolve()).encode("ascii"))
    h.update(b"\n")
    h.update(sha256_file(RNG_ANALYZER_PATH).encode("ascii"))
    h.update(b"\n")
    h.update(sha256_file(RNG_REPORTER_PATH).encode("ascii"))
    h.update(b"\n")
    h.update(sha256_file(RNG_API_HEADER).encode("ascii"))
    h.update(b"\n")
    for dataset_dir in dataset_dirs:
        if not dataset_dir.exists():
            continue
        root_label = dataset_dir.name
        for p in sorted(dataset_dir.rglob("*")):
            if p.is_dir():
                continue
            rel = p.relative_to(dataset_dir).as_posix()
            h.update(root_label.encode("utf-8"))
            h.update(b":")
            h.update(rel.encode("utf-8"))
            h.update(b"\0")
            h.update(sha256_file(p).encode("ascii"))
            h.update(b"\n")
    return h.hexdigest()


def extract_c_declaration(header: Path, symbol: str) -> str:
    """Extract a public C declaration by symbol name, independent of lines."""
    lines = header.read_text(encoding="utf-8").splitlines()
    symbol_re = re.compile(rf"\b{re.escape(symbol)}\s*\(")

    for start, line in enumerate(lines):
        stripped = line.lstrip()
        if stripped.startswith(("*", "//", "/*", "#")):
            continue
        if not symbol_re.search(line):
            continue

        declaration: List[str] = []
        for candidate in lines[start:]:
            declaration.append(candidate)
            if ";" in candidate:
                return "\n".join(declaration) + "\n"
            if "{" in candidate:
                break
        raise RuntimeError(f"unterminated declaration for {symbol} in {header}")

    raise RuntimeError(f"declaration for {symbol} not found in {header}")


def language_for(path: Path) -> str:
    ext = path.suffix.lower()
    return {
        ".tex": "tex",
        ".c": "c",
        ".h": "c",
        ".asm": "tasm",
        ".inc": "tasm",
        ".py": "python",
        ".json": "json",
        ".csv": "text",
        ".dat": "text",
        ".txt": "text",
        ".md": "text",
    }.get(ext, "text")


def tex_escape(s: str) -> str:
    return (
        s.replace("\\", "\\textbackslash{}")
        .replace("_", "\\_")
        .replace("&", "\\&")
        .replace("%", "\\%")
        .replace("#", "\\#")
        .replace("{", "\\{")
        .replace("}", "\\}")
    )


def tex_table_cell(s: str) -> str:
    return tex_escape(s) if s else "\\textemdash{}"


def model_sort_key(model: str) -> Tuple[int, str]:
    return (1, model) if model == "uncategorized" else (0, model.lower())


def build_appendix_include(dataset_dir: Path) -> str:
    files = [p for p in sorted(dataset_dir.rglob("*")) if p.is_file() and not p.name.startswith(".")]
    rng_profiles = [p for p in files if p.name.startswith("rng_stats_") and p.suffix.lower() == ".json"]
    out: List[str] = []
    out.append("% auto-generated by scripts/generate_docs_data.py")
    if not files:
        out.append("\\section*{No dataset files found}")
        out.append("No files were found in \\texttt{datasets/appendix\\_a} at build time.")
        return "\n".join(out) + "\n"

    for p in rng_profiles:
        rel = p.relative_to(ROOT).as_posix()
        out.append("")
        out.append(build_rng_stats_appendix(p, rel))

    for p in files:
        if p in rng_profiles or p.name == "entropy_runs.dat":
            # entropy_runs.dat remains the input to the correlation-calibration
            # macros in the body, but the appendix now presents the selected-tap
            # MCV profile rather than the legacy R0/R17 dump.
            continue
        rel = p.relative_to(ROOT).as_posix()
        lang = language_for(p)
        out.append("")
        out.append(f"\\textbf{{Source File:}} \\texttt{{{tex_escape(rel)}}}")
        out.append("")
        out.append("\\inputminted[")
        out.append("  breaklines,")
        out.append("  breakanywhere,")
        out.append("  fontsize=\\footnotesize")
        out.append(f"]{{{lang}}}{{{rel}}}")

    return "\n".join(out) + "\n"


def build_rng_stats_appendix(json_path: Path, source_rel: str) -> str:
    report = json.loads(json_path.read_text(encoding="utf-8"))
    model = str(report.get("device_model", "uncategorized"))
    runs = report.get("runs", [])
    aggregate = report.get("aggregate", {})

    out: List[str] = []
    out.append(f"\\textbf{{Source File:}} \\texttt{{{tex_escape(source_rel)}}}")
    out.append("")
    out.append(f"\\subsection*{{Model {tex_escape(model)}}}")
    out.append(
        "The table reports repeated windows from the selected raw SRAM tap. "
        "The MCV columns apply the NIST SP~800-90B Section~6.3.1 most-common-value estimator: "
        "the plug-in value uses the observed majority probability directly, while the 99\\% lower value "
        "first applies the prescribed upper confidence adjustment."
    )
    out.append("")
    out.append(
        f"Selected source: \\texttt{{0x{tex_escape(str(report.get('source', 'unknown')))}}}, "
        f"mask \\texttt{{0x{tex_escape(str(report.get('mask', 'unknown')))}}}."
    )
    out.append("")
    out.append("{\\scriptsize")
    out.append("\\setlength{\\LTleft}{0pt}")
    out.append("\\setlength{\\LTright}{0pt}")
    out.append("\\begin{longtable}{@{}rrrrrrr@{}}")
    out.append("\\toprule")
    out.append("\\textbf{Window} & \\textbf{$p(1)$} & \\textbf{Bias} & \\textbf{Transition} & \\textbf{MCV $H$} & \\textbf{MCV $H_{99}$} & \\textbf{Longest run} \\\\")
    out.append("\\midrule")
    out.append("\\endfirsthead")
    out.append("\\toprule")
    out.append("\\textbf{Window} & \\textbf{$p(1)$} & \\textbf{Bias} & \\textbf{Transition} & \\textbf{MCV $H$} & \\textbf{MCV $H_{99}$} & \\textbf{Longest run} \\\\")
    out.append("\\midrule")
    out.append("\\endhead")

    for row in runs:
        p1 = float(row["p1"])
        bias = abs(p1 - 0.5)
        out.append(
            f"{int(row['run']) + 1} & {p1:.6f} & {bias:.6f} & "
            f"{float(row['transition_rate']):.6f} & "
            f"{float(row['h_mcv_plugin_bits_per_raw_bit']):.6f} & "
            f"{float(row['h_mcv_lower_99_bits_per_raw_bit']):.6f} & "
            f"{int(row['longest_run'])} \\\\"
        )

    aggregate_p1 = float(aggregate["p1"])
    out.append("\\midrule")
    out.append(
        f"\\textbf{{Aggregate}} & \\textbf{{{aggregate_p1:.6f}}} & "
        f"\\textbf{{{abs(aggregate_p1 - 0.5):.6f}}} & "
        f"\\textbf{{{float(aggregate['transition_rate']):.6f}}} & "
        f"\\textbf{{{float(aggregate['h_mcv_plugin_bits_per_raw_bit']):.6f}}} & "
        f"\\textbf{{{float(aggregate['h_mcv_lower_99_bits_per_raw_bit']):.6f}}} & "
        f"\\textbf{{{int(aggregate['longest_run'])}}} \\\\"
    )
    out.append("\\bottomrule")
    out.append("\\end{longtable}")
    out.append("}")
    out.append("")
    out.append("{\\footnotesize")
    out.append("\\begin{tabularx}{\\textwidth}{@{}Xr@{}}")
    out.append("\\toprule")
    out.append("\\textbf{Summary quantity} & \\textbf{Bits per raw bit} \\\\")
    out.append("\\midrule")
    out.append(
        f"Aggregate MCV plug-in estimate & {float(aggregate['h_mcv_plugin_bits_per_raw_bit']):.6f} \\\\"
    )
    out.append(
        f"Aggregate MCV 99\\% lower estimate & {float(aggregate['h_mcv_lower_99_bits_per_raw_bit']):.6f} \\\\"
    )
    out.append(
        f"Worst-window MCV 99\\% lower estimate & {float(report['worst_window_h_mcv_lower_99_bits_per_raw_bit']):.6f} \\\\"
    )
    out.append(
        f"Conservative working estimate from this profile & {float(report['conservative_working_h_bits_per_raw_bit']):.6f} \\\\"
    )
    out.append("\\bottomrule")
    out.append("\\end{tabularx}")
    out.append("}")
    out.append("")
    out.append(
        "These are marginal MCV estimates, not a complete SP~800-90B non-IID entropy assessment. "
        "Serial dependence or behavior outside the observed windows can reduce the source's actual min-entropy."
    )
    return "\n".join(out) + "\n"


def model_label(block: TestBlock) -> str:
    if block.model:
        return block.model
    return "uncategorized"


def has_entropy_signal(block: TestBlock, bit: int) -> bool:
    r0 = block.groups.get("R0", {}).get(bit)
    r17 = block.groups.get("R17", {}).get(bit)
    if r0 is None or r17 is None:
        return False
    return 0.0 < r0.p1 < 1.0 and 0.0 < r17.p1 < 1.0


def fmt_p1(stat: BitStat | None) -> str:
    return f"{stat.p1:.6f}" if stat else ""


def fmt_bias(stat: BitStat | None) -> str:
    return f"{stat.bias:.6f}" if stat else ""


def fmt_transition(stat: BitStat | None) -> str:
    return f"{stat.transition_rate:.6f}" if stat else ""


def fmt_k_estimate(k: float) -> str:
    if k < 1.0:
        return "\\(<1.000\\)"
    return f"{k:.3f}"


def build_entropy_runs_appendix(dat_path: Path, source_rel: str) -> str:
    blocks = parse_entropy_runs(dat_path)
    grouped: Dict[str, List[TestBlock]] = {}

    for block in blocks:
        grouped.setdefault(model_label(block), []).append(block)

    best_pairs = [p for p in (choose_best_pair(b) for b in blocks) if p is not None]
    best_pair_keys = {(p.test_label, p.bit) for p in best_pairs}

    out: List[str] = []
    out.append("Only bits presenting with some statistical randomness are shown below. Bits showing p values of 0 or 1 are filtered for brevity. Values of \\(k_{\\text{eff}}<1\\) indicate observed decorrelation at least as strong as the independent-sample floor; downstream bounds cap these cases at \\(k_{\\text{eff}}=1\\).")
    out.append("")
    out.append(
        "Rows highlighted in orange are the single least-biased bit per test run (the R17 \\(p_1\\) closest to "
        "\\(0.5\\)) --- these are the exact rows used as the one-bit-per-run sample in "
        "Section~\\ref{ssec:correlation_calibration}'s working-value computation; every other row is shown for "
        "context but is not part of that computation."
    )
    out.append("")
    out.append(f"\\textbf{{Source File:}} \\texttt{{{tex_escape(source_rel)}}}")

    if not grouped:
        out.append("")
        out.append("No parseable entropy test blocks were found.")
        return "\n".join(out) + "\n"

    all_k_values: List[float] = []
    best_pair_k_values: List[float] = []

    for model in sorted(grouped.keys(), key=model_sort_key):
        rows: List[str] = []
        k_values: List[float] = []
        for block in grouped[model]:
            bits = sorted(set(block.groups.get("R0", {}).keys()) | set(block.groups.get("R17", {}).keys()))
            for bit in bits:
                if not has_entropy_signal(block, bit):
                    continue
                r0 = block.groups.get("R0", {}).get(bit)
                r17 = block.groups.get("R17", {}).get(bit)
                assert r0 is not None
                assert r17 is not None
                k = k_inversion_raw(n=17.0, p_in=r0.p1, p_out=r17.p1)
                k_values.append(k)
                test_label = f"test{block.index}"
                is_best = (test_label, bit) in best_pair_keys
                if is_best:
                    best_pair_k_values.append(k_inversion(n=17.0, p_in=r0.p1, p_out=r17.p1))
                row_prefix = "\\rowcolor{orange!20}" if is_best else ""
                rows.append(
                    f"{row_prefix}{test_label} & {bit} & "
                    f"{tex_table_cell(fmt_p1(r0))} & {tex_table_cell(fmt_bias(r0))} & {tex_table_cell(fmt_transition(r0))} & "
                    f"{tex_table_cell(fmt_p1(r17))} & {tex_table_cell(fmt_bias(r17))} & {tex_table_cell(fmt_transition(r17))} & "
                    f"{fmt_k_estimate(k)} \\\\"
                )

        out.append("")
        out.append(f"\\subsection*{{Model {tex_escape(model)}}}")
        if not rows:
            out.append("No non-zero bit rows were present for this model group.")
            continue

        all_k_values.extend(k_values)

        out.append("{\\scriptsize")
        out.append("\\setlength{\\LTleft}{0pt}")
        out.append("\\setlength{\\LTright}{0pt}")
        out.append("\\begin{longtable}{@{}*{9}{r}@{}}")
        out.append("\\toprule")
        out.append("\\textbf{Run} & \\textbf{Bit} & \\textbf{R0 p1} & \\textbf{R0 bias} & \\textbf{R0 trans} & \\textbf{R17 p1} & \\textbf{R17 bias} & \\textbf{R17 trans} & \\textbf{$k_{\\text{eff}}$} \\\\")
        out.append("\\midrule")
        out.append("\\endfirsthead")
        out.append("\\toprule")
        out.append("\\textbf{Run} & \\textbf{Bit} & \\textbf{R0 p1} & \\textbf{R0 bias} & \\textbf{R0 trans} & \\textbf{R17 p1} & \\textbf{R17 bias} & \\textbf{R17 trans} & \\textbf{$k_{\\text{eff}}$} \\\\")
        out.append("\\midrule")
        out.append("\\endhead")
        out.extend(rows)
        out.append("\\midrule")
        out.append(f"\\multicolumn{{8}}{{r}}{{\\textbf{{$k_{{\\text{{eff}}}}$(median)}}}} & \\textbf{{{fmt_k_estimate(statistics.median(k_values))}}} \\\\")
        out.append("\\bottomrule")
        out.append("\\end{longtable}")
        out.append("}")

    if all_k_values:
        capped = [max(k, 1.0) for k in all_k_values]
        combined_median = statistics.median(capped)
        out.append("")
        out.append("\\subsection*{All Models Combined}")
        out.append(
            "The row below is the median \\(k_{\\text{eff}}\\) across every displayed bit row above, all models pooled, "
            "with \\(k_{\\text{eff}}<1\\) entries capped at the floor of \\(1\\) before taking the median (per the capping rule "
            "stated above). It is reported here for completeness and is \\emph{not} the same figure as the "
            "Section~\\ref{ssec:correlation_calibration} working value \\(k_{\\text{eff,median}}\\): that figure is "
            "computed over one representative (highest-signal) bit per test run rather than every signal-bearing "
            "bit shown per run in this appendix, so the two need not match."
        )
        out.append("")
        out.append("{\\scriptsize")
        out.append("\\begin{tabular}{@{}lr@{}}")
        out.append("\\toprule")
        out.append("\\textbf{Combined $k_{\\text{eff}}$(median), all models, all displayed rows} & \\textbf{Value} \\\\")
        out.append("\\midrule")
        out.append(f"$n={len(all_k_values)}$ bit rows & {fmt_k_estimate(combined_median)} \\\\")
        if best_pair_k_values:
            best_pair_median = statistics.median(best_pair_k_values)
            out.append("\\midrule")
            out.append(
                f"\\rowcolor{{orange!20}}$n={len(best_pair_k_values)}$, 1 bit per run, least bias (= "
                f"Section~\\ref{{ssec:correlation_calibration}} working value) & \\textbf{{{fmt_k_estimate(best_pair_median)}}} \\\\"
            )
        out.append("\\bottomrule")
        out.append("\\end{tabular}")
        out.append("}")

    return "\n".join(out) + "\n"


def parse_entropy_runs(dat_path: Path) -> List[TestBlock]:
    if not dat_path.exists():
        return []

    blocks: List[TestBlock] = []
    current: TestBlock | None = None

    with dat_path.open("r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue

            m = TEST_HEADER_RE.match(line)
            if m:
                current = TestBlock(index=int(m.group(1)), groups={})
                blocks.append(current)
                continue

            if current is None:
                continue

            m = MODEL_LINE_RE.match(line)
            if m:
                if not current.has_data:
                    current.model = m.group(1).strip()
                continue

            m = BIT_LINE_RE.match(line)
            if not m:
                continue

            grp = m.group(1)
            bit = int(m.group(2))
            p1 = float(m.group(3))
            bias = float(m.group(4))
            transition_rate = float(m.group(5))
            monobit_z = m.group(6)
            runs_z = m.group(7)
            current.groups.setdefault(grp, {})[bit] = BitStat(
                bit=bit,
                p1=p1,
                bias=bias,
                transition_rate=transition_rate,
                monobit_z=monobit_z,
                runs_z=runs_z,
            )
            current.has_data = True

    return blocks


def choose_best_pair(block: TestBlock) -> PairRow | None:
    g0 = block.groups.get("R0", {})
    g17 = block.groups.get("R17", {})
    common_bits = sorted(set(g0.keys()) & set(g17.keys()))
    if not common_bits:
        return None

    best_bit = min(common_bits, key=lambda b: (abs(g17[b].p1 - 0.5), abs(g0[b].p1 - 0.5), b))
    p_in = g0[best_bit].p1
    p_out = g17[best_bit].p1
    k_raw = k_inversion(n=17.0, p_in=p_in, p_out=p_out)
    return PairRow(test_label=f"test{block.index}", bit=best_bit, p_in=p_in, p_out=p_out, k_raw=k_raw)


def k_inversion_raw(n: float, p_in: float, p_out: float) -> float:
    a = abs(1.0 - 2.0 * p_in)
    b = abs(1.0 - 2.0 * p_out)
    if a <= 0.0 or b <= 0.0:
        return 17.0
    den = math.log(b)
    if abs(den) < 1e-15:
        return 17.0
    return n * math.log(a) / den


def k_inversion(n: float, p_in: float, p_out: float) -> float:
    val = k_inversion_raw(n, p_in, p_out)
    if val < 1.0:
        val = 1.0
    if val > 17.0:
        val = 17.0
    return val


def tukey_quartiles(vals: List[float]) -> Tuple[float, float]:
    s = sorted(vals)
    n = len(s)
    if n == 1:
        return s[0], s[0]
    if n % 2 == 1:
        lower = s[: n // 2]
        upper = s[n // 2 + 1 :]
    else:
        lower = s[: n // 2]
        upper = s[n // 2 :]

    def med(a: List[float]) -> float:
        m = len(a)
        if m == 0:
            return s[0]
        if m % 2 == 1:
            return a[m // 2]
        return (a[m // 2 - 1] + a[m // 2]) / 2.0

    return med(lower), med(upper)


def fmt(x: float, digits: int = 4) -> str:
    return f"{x:.{digits}f}"


def fmt_half_up(x: float, digits: int) -> str:
    quant = Decimal("1." + ("0" * digits))
    return format(Decimal(str(x)).quantize(quant, rounding=ROUND_HALF_UP), f".{digits}f")


def fold_p(p: float) -> float:
    return max(p, 1.0 - p)


def build_correlation_macros(dataset_dir: Path) -> str:
    dat = dataset_dir / "entropy_runs.dat"
    blocks = parse_entropy_runs(dat)
    pairs_all = [p for p in (choose_best_pair(b) for b in blocks) if p is not None]
    display_limit = 9
    pairs = pairs_all[:display_limit]

    out: List[str] = []
    out.append("% auto-generated by scripts/generate_docs_data.py")

    xor_reads = 17
    pool_bytes = 119
    output_bits = 64
    p_worst = 0.7500

    if not pairs_all:
        out.append("\\newcommand{\\CalibRunRows}{test1 & 5 & 0.7500 & 0.5000 & 0.0000 \\\\}")
        out.append("\\newcommand{\\CalibLineSegments}{\\draw[blue!60,opacity=0.8] (1,0.75) -- (2,0.50);}")
        out.append("\\newcommand{\\CalibPointFills}{\\filldraw[blue!80] (1,0.75) circle (0.7pt); \\filldraw[blue!80] (2,0.50) circle (0.7pt);}")
        out.append("\\newcommand{\\CalibKRows}{test1-bit5 & 0.7500 & 0.5000 & 1.000 \\\\}")
        out.append("\\newcommand{\\CalibKMedian}{1.000}")
        out.append("\\newcommand{\\CalibKMean}{1.000}")
        out.append("\\newcommand{\\CalibKSigma}{0.000}")
        out.append("\\newcommand{\\CalibKQOne}{1.000}")
        out.append("\\newcommand{\\CalibKQThree}{1.000}")
        out.append("\\newcommand{\\CalibKIQR}{0.000}")
        out.append("\\newcommand{\\CalibRangeLow}{1.000}")
        out.append("\\newcommand{\\CalibRangeHigh}{1.000}")
        out.append("\\newcommand{\\CalibWorkingK}{1.000}")
        out.append("\\newcommand{\\CalibBiasRZero}{0.2500}")
        out.append("\\newcommand{\\CalibBiasRSeventeen}{0.0000}")
        out.append("\\newcommand{\\CalibYTicks}{\\foreach \\yy/\\lbl in {1/1,2/2,3/3,4/4,5/5,6/6}{\\draw (0.65,\\yy) -- (0.75,\\yy);\\node[left] at (0.65,\\yy) {\\scriptsize \\lbl};}}")
        out.append("\\newcommand{\\CalibKPath}{(1,1.000)}")
        out.append("\\newcommand{\\CalibKPointFills}{\\filldraw[blue!85] (1,1.000) circle (0.8pt);}")
        out.append("\\newcommand{\\CalibXAxisMax}{5.6}")
        out.append("\\newcommand{\\CalibXAxisLabel}{5.65}")
        out.append("\\newcommand{\\CalibXTicks}{\\draw (1,0.55) -- (1,0.65);\\node[below] at (1,0.55) {\\scriptsize 1};}")
        out.append(f"\\newcommand{{\\CalibXorReads}}{{{xor_reads}}}")
        out.append(f"\\newcommand{{\\CalibPoolBytes}}{{{pool_bytes}}}")
        out.append(f"\\newcommand{{\\CalibOutputBits}}{{{output_bits}}}")
        out.append(f"\\newcommand{{\\CalibPWorst}}{{{p_worst:.4f}}}")
        out.append("\\newcommand{\\CalibNeffByte}{17}")
        out.append("\\newcommand{\\CalibNeffPool}{2023}")
        out.append("\\newcommand{\\CalibPOutByte}{0.50000}")
        out.append("\\newcommand{\\CalibPOutPool}{0.50000}")
        out.append("\\newcommand{\\CalibMinEntropyBit}{1.00000}")
        out.append("\\newcommand{\\CalibMinEntropyOutput}{1.00000}")
        out.append("\\newcommand{\\CalibDisplayCount}{1}")
        out.append("\\newcommand{\\CalibTotalCount}{1}")
        out.append("\\newcommand{\\CalibTruncatedNote}{}")
        return "\n".join(out) + "\n"

    run_rows = []
    line_cmds = []
    point_cmds = []
    k_rows = []
    k_vals = []
    bias_r0 = []
    bias_r17 = []

    for p in pairs:
        p_in_fold = fold_p(p.p_in)
        p_out_fold = fold_p(p.p_out)
        run_rows.append(f"{p.test_label} & {p.bit} & {fmt(p_in_fold)} & {fmt(p_out_fold)} & {fmt(abs(p_out_fold-0.5))} \\\\")
        line_cmds.append(f"\\draw[blue!60,opacity=0.8] (1,{fmt(p_in_fold)}) -- (2,{fmt(p_out_fold)});")
        point_cmds.append(f"\\filldraw[blue!80] (1,{fmt(p_in_fold)}) circle (0.7pt); \\filldraw[blue!80] (2,{fmt(p_out_fold)}) circle (0.7pt);")
        k_rows.append(f"{p.test_label}-bit{p.bit} & {fmt(p.p_in)} & {fmt(p.p_out)} & {p.k_raw:.3f} \\\\")

    for p in pairs_all:
        k_vals.append(p.k_raw)
        bias_r0.append(abs(p.p_in - 0.5))
        bias_r17.append(abs(p.p_out - 0.5))

    # Keep summary stats consistent with the displayed 3-decimal k rows.
    ks = sorted(float(fmt_half_up(v, 3)) for v in k_vals)
    k_median = statistics.median(ks)
    k_mean = statistics.mean(ks)
    k_sigma = statistics.pstdev(ks) if len(ks) > 1 else 0.0
    k_q1, k_q3 = tukey_quartiles(ks)
    k_iqr = k_q3 - k_q1
    k_low = min(ks)
    k_high = max(ks)

    y_max = max(6, int(math.ceil(k_high)))
    y_tick_parts = []
    for y in range(1, y_max + 1):
        y_tick_parts.append(
            f"\\draw (0.65,{y}) -- (0.75,{y});\\node[left] at (0.65,{y}) {{\\scriptsize {y}}};"
        )

    x_tick_parts = []
    for i in range(1, len(pairs) + 1):
        x_tick_parts.append(
            f"\\draw ({i},0.55) -- ({i},0.65);\\node[below] at ({i},0.55) {{\\scriptsize {i}}};"
        )

    k_path = " -- ".join(f"({i},{pairs[i-1].k_raw:.3f})" for i in range(1, len(pairs) + 1))
    k_points = "\n".join(
        f"\\filldraw[blue!85] ({i},{pairs[i-1].k_raw:.3f}) circle (0.8pt);" for i in range(1, len(pairs) + 1)
    )

    out.append(f"\\newcommand{{\\CalibRunRows}}{{{' '.join(run_rows)}}}")
    out.append(f"\\newcommand{{\\CalibLineSegments}}{{{' '.join(line_cmds)}}}")
    out.append(f"\\newcommand{{\\CalibPointFills}}{{{' '.join(point_cmds)}}}")
    out.append(f"\\newcommand{{\\CalibKRows}}{{{' '.join(k_rows)}}}")
    out.append(f"\\newcommand{{\\CalibKMedian}}{{{fmt_half_up(k_median, 3)}}}")
    out.append(f"\\newcommand{{\\CalibKMean}}{{{fmt_half_up(k_mean, 3)}}}")
    out.append(f"\\newcommand{{\\CalibKSigma}}{{{fmt_half_up(k_sigma, 3)}}}")
    out.append(f"\\newcommand{{\\CalibKQOne}}{{{fmt_half_up(k_q1, 3)}}}")
    out.append(f"\\newcommand{{\\CalibKQThree}}{{{fmt_half_up(k_q3, 3)}}}")
    out.append(f"\\newcommand{{\\CalibKIQR}}{{{fmt_half_up(k_iqr, 3)}}}")
    out.append(f"\\newcommand{{\\CalibRangeLow}}{{{fmt_half_up(k_low, 3)}}}")
    out.append(f"\\newcommand{{\\CalibRangeHigh}}{{{fmt_half_up(k_high, 3)}}}")
    out.append(f"\\newcommand{{\\CalibWorkingK}}{{{fmt_half_up(k_median, 3)}}}")
    out.append(f"\\newcommand{{\\CalibBiasRZero}}{{{statistics.mean(bias_r0):.4f}}}")
    out.append(f"\\newcommand{{\\CalibBiasRSeventeen}}{{{statistics.mean(bias_r17):.4f}}}")
    out.append(f"\\newcommand{{\\CalibYTicks}}{{{''.join(y_tick_parts)}}}")
    out.append(f"\\newcommand{{\\CalibKPath}}{{{k_path}}}")
    out.append("\\newcommand{\\CalibKPointFills}{" + k_points.replace("\n", " ") + "}")
    out.append(f"\\newcommand{{\\CalibXAxisMax}}{{{len(pairs)+0.6:.1f}}}")
    out.append(f"\\newcommand{{\\CalibXAxisLabel}}{{{len(pairs)+0.65:.2f}}}")
    out.append(f"\\newcommand{{\\CalibXTicks}}{{{''.join(x_tick_parts)}}}")

    k_working = round(k_median, 3)
    n_eff_byte = int(math.floor(xor_reads / k_working)) if k_working > 0 else xor_reads
    if n_eff_byte < 1:
        n_eff_byte = 1
    n_eff_pool = int(math.floor((xor_reads * pool_bytes) / k_working)) if k_working > 0 else xor_reads * pool_bytes
    if n_eff_pool < 1:
        n_eff_pool = 1

    def p_xor(p: float, n: int) -> float:
        return (1.0 - ((1.0 - 2.0 * p) ** n)) / 2.0

    p_out_byte = p_xor(p_worst, n_eff_byte)
    p_out_pool = p_xor(p_worst, n_eff_pool)
    h_inf_bit = -math.log2(max(p_out_byte, 1.0 - p_out_byte))
    h_inf_out = -math.log2(max(p_out_pool, 1.0 - p_out_pool))

    out.append(f"\\newcommand{{\\CalibXorReads}}{{{xor_reads}}}")
    out.append(f"\\newcommand{{\\CalibPoolBytes}}{{{pool_bytes}}}")
    out.append(f"\\newcommand{{\\CalibOutputBits}}{{{output_bits}}}")
    out.append(f"\\newcommand{{\\CalibPWorst}}{{{p_worst:.4f}}}")
    out.append(f"\\newcommand{{\\CalibNeffByte}}{{{n_eff_byte}}}")
    out.append(f"\\newcommand{{\\CalibNeffPool}}{{{n_eff_pool}}}")
    out.append(f"\\newcommand{{\\CalibPOutByte}}{{{p_out_byte:.5f}}}")
    out.append(f"\\newcommand{{\\CalibPOutPool}}{{{p_out_pool:.5f}}}")
    out.append(f"\\newcommand{{\\CalibMinEntropyBit}}{{{h_inf_bit:.5f}}}")
    out.append(f"\\newcommand{{\\CalibMinEntropyOutput}}{{{h_inf_out:.5f}}}")
    out.append(f"\\newcommand{{\\CalibDisplayCount}}{{{len(pairs)}}}")
    out.append(f"\\newcommand{{\\CalibTotalCount}}{{{len(pairs_all)}}}")
    if len(pairs_all) > display_limit:
        out.append("\\newcommand{\\CalibTruncatedNote}{\\vspace{-0.2em}\\begin{center}\\scriptsize(First 9 traces shown in-section; full dataset in Appendix A.)\\end{center}}")
    else:
        out.append("\\newcommand{\\CalibTruncatedNote}{}")

    return "\n".join(out) + "\n"


def _f(x: str) -> float:
    try:
        return float(x.strip())
    except Exception:
        return 0.0


def build_appendix_b_model_summary(datasets_root: Path) -> str:
    appendix_b_dirs = [
        p for p in (datasets_root / "appendix_b", datasets_root / "appendex_b") if p.exists()
    ]
    model_dirs: List[Path] = []
    for appendix_b in appendix_b_dirs:
        model_dirs.extend([p for p in sorted(appendix_b.glob("model*")) if p.is_dir()])

    out: List[str] = []
    out.append("% auto-generated by scripts/generate_docs_data.py")

    if not model_dirs:
        out.append("No model directories were found in \\texttt{datasets/appendix\\_b} (or \\texttt{datasets/appendex\\_b}) at build time.")
        return "\n".join(out) + "\n"

    model_tables: List[str] = []
    for model_dir in model_dirs:
        csv_files = sorted(model_dir.glob("*.csv"))
        if not csv_files:
            continue

        per_unit: Dict[str, Dict[str, object]] = {}

        for csv_path in csv_files:
            with csv_path.open("r", encoding="utf-8", errors="replace", newline="") as f:
                reader = csv.DictReader(f)
                for r in reader:
                    unit = (r.get("primitive", "") or "").strip() or "UNKNOWN"
                    d = per_unit.setdefault(
                        unit,
                        {
                            "n": 0,
                            "pass6": 0,
                            "pass4": 0,
                            "sigma": [],
                            "d6": [],
                            "d4": [],
                            "med_w": [],
                            "med_r": [],
                            "med_e": [],
                            "ov6_w": [],
                            "ov6_r": [],
                            "ov6_e": [],
                            "ov4_w": [],
                            "ov4_r": [],
                            "ov4_e": [],
                        },
                    )
                    d["n"] = int(d["n"]) + 1
                    if (r.get("pass_c6", "").strip().upper() == "PASS"):
                        d["pass6"] = int(d["pass6"]) + 1
                    if (r.get("pass_c4", "").strip().upper() == "PASS"):
                        d["pass4"] = int(d["pass4"]) + 1

                    cast = lambda k: _f(r.get(k, "0"))
                    d["sigma"].append(cast("sigma"))
                    d["d6"].append(cast("max_delta_c6"))
                    d["d4"].append(cast("max_delta_c4"))
                    d["med_w"].append(cast("median_dev_worst"))
                    d["med_r"].append(cast("median_dev_random"))
                    d["med_e"].append(cast("median_dev_edge"))
                    d["ov6_w"].append(cast("over_worst_c6_pct"))
                    d["ov6_r"].append(cast("over_random_c6_pct"))
                    d["ov6_e"].append(cast("over_edge_c6_pct"))
                    d["ov4_w"].append(cast("over_worst_c4_pct"))
                    d["ov4_r"].append(cast("over_random_c4_pct"))
                    d["ov4_e"].append(cast("over_edge_c4_pct"))

        if not per_unit:
            continue

        model_name = model_dir.name.replace("model", "Rev ")
        total_rows = sum(int(v["n"]) for v in per_unit.values())
        unit_rows: List[str] = []

        for unit in sorted(per_unit.keys()):
            d = per_unit[unit]
            n = int(d["n"])
            if n <= 0:
                continue
            mean = lambda key: (statistics.mean(d[key]) if d[key] else 0.0)
            max_over_c6 = max(
                max(d["ov6_w"]) if d["ov6_w"] else 0.0,
                max(d["ov6_r"]) if d["ov6_r"] else 0.0,
                max(d["ov6_e"]) if d["ov6_e"] else 0.0,
            )
            unit_pass = max_over_c6 < 75.0
            row_color = "green!8" if unit_pass else "red!10"
            unit_color = "ForestGreen" if unit_pass else "BrickRed"
            unit_rows.append(
                f"\\rowcolor{{{row_color}}}\\textcolor{{{unit_color}}}{{{tex_escape(unit)}}} & "
                f"{mean('sigma'):.2f} & "
                f"{mean('d6'):.2f}/{mean('d4'):.2f} & "
                f"{mean('med_w'):.1f}/{mean('med_r'):.1f}/{mean('med_e'):.1f} & "
                f"{mean('ov6_w'):.2f}\\%/{mean('ov6_r'):.2f}\\%/{mean('ov6_e'):.2f}\\% & "
                f"{mean('ov4_w'):.2f}\\%/{mean('ov4_r'):.2f}\\%/{mean('ov4_e'):.2f}\\% \\\\"
            )

        model_tables.append("\\begin{table}[htbp]")
        model_tables.append("\\centering")
        model_tables.append(
            f"\\caption{{Timing summary by unit for {tex_escape(model_name)}.}}"
        )
        model_tables.append("\\renewcommand{\\arraystretch}{1.12}")
        model_tables.append("{\\footnotesize")
        model_tables.append("\\begin{tabular}{lccccc}")
        model_tables.append("\\hline")
        model_tables.append("\\textbf{Unit} & \\textbf{Avg $\\sigma$} & \\textbf{Avg $\\Delta$ (c6/c4)} & \\textbf{MedDev (W/R/E)} & \\textbf{Over\\% c6 (W/R/E)} & \\textbf{Over\\% c4 (W/R/E)} \\\\")
        model_tables.append("\\hline")
        model_tables.extend(unit_rows)
        model_tables.append("\\hline")
        model_tables.append("\\end{tabular}")
        model_tables.append("}")
        model_tables.append("\\vspace{-0.6em}")
        model_tables.append(f"{{\\scriptsize\\emph{{Source files parsed: {len(csv_files)}}}}}")
        model_tables.append("\\end{table}")
        model_tables.append("\\vspace{0.2em}")

    if not model_tables:
        out.append("No parseable timing CSV rows were found under \\texttt{datasets/appendix\\_b/model*} (or \\texttt{datasets/appendex\\_b/model*}).")
        return "\n".join(out) + "\n"

    out.extend(model_tables)
    return "\n".join(out) + "\n"


RNG_Z_99 = 2.576
RNG_READS_PER_COLLECTION = 8 * 119
RNG_CONDITIONED_BITS = 192


def rng_mcv_estimate(ones: int, zeros: int) -> Dict[str, float | int]:
    """Recompute the binary marginal MCV estimate from integer counts."""
    samples = ones + zeros
    if samples < 2:
        raise ValueError("RNG statistics require at least two samples")
    p1 = ones / samples
    p_max = max(ones, zeros) / samples
    margin = RNG_Z_99 * math.sqrt(p_max * (1.0 - p_max) / (samples - 1))
    p_upper = min(1.0, p_max + margin)
    return {
        "samples": samples,
        "p1": p1,
        "p_max": p_max,
        "margin": margin,
        "p_upper": p_upper,
        "h_plugin": -math.log2(p_max),
        "h_lower_99": -math.log2(p_upper),
    }


def load_rng_stat_profiles(stats_dir: Path) -> List[Dict[str, object]]:
    """Load checked-in RNG profiles in the analyzer's JSON or CSV format."""
    profiles: List[Dict[str, object]] = []
    for path in sorted(stats_dir.glob("*_rngstats.json")):
        report = json.loads(path.read_text(encoding="utf-8"))
        model = str(report.get("model", report.get("device_model", "uncategorized")))
        runs = report.get("runs", [])
        aggregate = report.get("aggregate", {})
        required_run_fields = {
            "n00", "n01", "n10", "n11", "transition_counts_source",
            "lag1_phi", "h_markov_lower_99_bits_per_raw_bit",
            "first_order_dependency_factor",
        }
        if not isinstance(runs, list) or not runs:
            raise ValueError(f"{path}: no RNG run rows")
        for row in runs:
            missing = required_run_fields.difference(row)
            if missing:
                fields = ", ".join(sorted(missing))
                raise ValueError(
                    f"{path}: stored run is missing {fields}; migrate it with "
                    "analyze_rng_stats.py --in-place"
                )
        if "h_markov_lower_99_bits_per_raw_bit" not in aggregate:
            raise ValueError(
                f"{path}: stored aggregate lacks the Markov estimate; migrate it "
                "with analyze_rng_stats.py --in-place"
            )
        profiles.append({
            "model": model,
            "source_file": path.name,
            "runs": runs,
            "aggregate": aggregate,
        })

    for path in sorted(stats_dir.glob("*_rngstats.csv")):
        with path.open("r", encoding="utf-8", newline="") as source:
            rows = list(csv.DictReader(source))
        if not rows:
            continue
        model = (rows[0].get("model") or "uncategorized").strip()
        runs: List[Dict[str, object]] = []
        for row in rows:
            parsed: Dict[str, object] = {
                "run": int(row["run"]),
                "source": row.get("source", "unknown"),
                "mask": row.get("mask", "unknown"),
            }
            for key in (
                "samples", "ones", "zeros", "transitions",
                "n00", "n01", "n10", "n11",
                "longest", "longest0", "longest1",
            ):
                if row.get(key) not in (None, ""):
                    parsed[key] = int(row[key])
            runs.append(RNG_ANALYZER.analyze_run(parsed))
        profiles.append({"model": model, "source_file": path.name, "runs": runs})
    return profiles


def build_rng_entropy_analysis(stats_dir: Path) -> Tuple[str, str]:
    """Generate the main per-model summary and Appendix A per-window table."""
    profiles = load_rng_stat_profiles(stats_dir)
    detail: List[str] = ["% auto-generated by scripts/generate_docs_data.py"]
    if not profiles:
        missing = "No RNG profiles were found in \\texttt{statistics/rng} at build time.\n"
        return missing, missing

    grouped: Dict[str, Dict[str, object]] = {}
    for profile in profiles:
        model = str(profile["model"])
        group = grouped.setdefault(
            model, {"runs": [], "files": [], "profile_markov": []}
        )
        group["files"].append(str(profile["source_file"]))
        profile_aggregate = profile.get("aggregate")
        if isinstance(profile_aggregate, dict):
            group["profile_markov"].append(
                float(profile_aggregate["h_markov_lower_99_bits_per_raw_bit"])
            )
        for row in profile["runs"]:
            samples = int(row["samples"])
            ones = int(row["ones"])
            zeros = int(row["zeros"])
            if samples != ones + zeros:
                raise ValueError(f"{profile['source_file']}: samples != ones + zeros")
            group["runs"].append(
                {
                    **row,
                    "source_file": str(profile["source_file"]),
                    **rng_mcv_estimate(ones, zeros),
                }
            )

    detail.extend(
        [
            "{\\scriptsize",
            "\\rowcolors{2}{ltgray}{white}",
            "\\begin{xltabular}{\\textwidth}{@{}"
            ">{\\hsize=0.60\\hsize\\raggedright\\arraybackslash}X"
            ">{\\hsize=2.00\\hsize\\raggedright\\arraybackslash}X"
            "*{8}{>{\\hsize=0.925\\hsize\\centering\\arraybackslash}X}@{}}",
            "\\toprule",
            "\\rowcolor{gray!18}",
            "\\textbf{Model} & \\textbf{Profile/test} & \\textbf{$n$} & \\textbf{$\\hat p_1$} & \\textbf{$\\hat p_{\\max}$} & \\textbf{$\\epsilon_{99}$} & \\textbf{$\\rho_1$} & \\textbf{$H_{99}$} & \\textbf{$H_{M,99}$} & \\textbf{$f_{dep}$} \\\\",
            "\\midrule",
            "\\endfirsthead",
            "\\toprule",
            "\\rowcolor{gray!18}",
            "\\textbf{Model} & \\textbf{Profile/test} & \\textbf{$n$} & \\textbf{$\\hat p_1$} & \\textbf{$\\hat p_{\\max}$} & \\textbf{$\\epsilon_{99}$} & \\textbf{$\\rho_1$} & \\textbf{$H_{99}$} & \\textbf{$H_{M,99}$} & \\textbf{$f_{dep}$} \\\\",
            "\\midrule",
            "\\endhead",
        ]
    )

    summaries: List[Dict[str, object]] = []
    for model in sorted(grouped, key=model_sort_key):
        runs = grouped[model]["runs"]
        total_ones = sum(int(row["ones"]) for row in runs)
        total_zeros = sum(int(row["zeros"]) for row in runs)
        aggregate = rng_mcv_estimate(total_ones, total_zeros)
        worst_window_mcv = min(float(row["h_lower_99"]) for row in runs)
        worst_window_markov = min(
            float(row["h_markov_lower_99_bits_per_raw_bit"]) for row in runs
        )
        profile_markov_values = grouped[model]["profile_markov"]
        marginal_h = min(float(aggregate["h_lower_99"]), worst_window_mcv)
        markov_h = min(worst_window_markov, *profile_markov_values)
        max_abs_lag1_phi = max(abs(float(row["lag1_phi"])) for row in runs)
        working_h = min(marginal_h, markov_h)
        dependency_factor = min(1.0, working_h / marginal_h) if marginal_h > 0.0 else 0.0
        raw_collection_h = RNG_READS_PER_COLLECTION * working_h
        summaries.append(
            {
                "model": model,
                "tests": len(runs),
                "aggregate": aggregate,
                "worst_window_mcv": worst_window_mcv,
                "worst_window_markov": worst_window_markov,
                "marginal_h": marginal_h,
                "markov_h": markov_h,
                "dependency_factor": dependency_factor,
                "max_abs_lag1_phi": max_abs_lag1_phi,
                "working_h": working_h,
                "raw_collection_h": raw_collection_h,
                "files": grouped[model]["files"],
            }
        )
        for row in runs:
            profile_id = str(row["source_file"]).split("_rngstats.", 1)[0]
            test_label = f"{profile_id}/{int(row['run']) + 1}"
            detail.append(
                f"{tex_escape(model)} & {tex_escape(test_label)} & {int(row['samples']):,} & "
                f"{float(row['p1']):.6f} & {float(row['p_max']):.6f} & "
                f"{float(row['margin']):.6f} & {float(row['lag1_phi']):.6f} & "
                f"{float(row['h_lower_99']):.6f} & "
                f"{float(row['h_markov_lower_99_bits_per_raw_bit']):.6f} & "
                f"{float(row['first_order_dependency_factor']):.6f} \\\\"
            )

    detail.extend(["\\bottomrule", "\\end{xltabular}", "}", ""])

    detail.extend(
        [
            "\\paragraph{Checked-in source reports}",
            "The table above was generated from the following reports:",
            "\\begin{itemize}[nosep]",
        ]
    )
    source_names = sorted(
        {
            str(source_file)
            for model_group in grouped.values()
            for source_file in model_group["files"]
        }
    )
    for name in source_names:
        url = f"https://github.com/cagscalclabs/lwip-ce/blob/master/statistics/rng/{name}"
        detail.append(f"\\item \\href{{{url}}}{{\\texttt{{{tex_escape(name)}}}}}")
    detail.extend(["\\end{itemize}", ""])

    out: List[str] = ["% auto-generated by scripts/generate_docs_data.py"]
    out.extend(
        [
            "",
            "{\\scriptsize",
            "\\rowcolors{2}{ltgray}{white}",
            "\\begin{xltabular}{\\textwidth}{@{}>{\\raggedright\\arraybackslash}X*{8}{>{\\centering\\arraybackslash}X}@{}}",
            "\\toprule",
            "\\rowcolor{gray!18}",
            f"\\textbf{{Model}} & \\textbf{{Tests}} & \\textbf{{$n$}} & \\textbf{{$H_{{MCV}}$}} & \\textbf{{$H_{{Markov}}$}} & \\textbf{{$f_{{dep}}$}} & \\textbf{{max $|\\rho_1|$}} & \\textbf{{$h_{{model}}$}} & \\textbf{{${RNG_READS_PER_COLLECTION}h_{{model}}$}} \\\\",
            "\\midrule",
        ]
    )
    for summary in summaries:
        aggregate = summary["aggregate"]
        out.append(
            f"{tex_escape(str(summary['model']))} & {int(summary['tests'])} & "
            f"{int(aggregate['samples']):,} & {float(summary['marginal_h']):.6f} & "
            f"{float(summary['markov_h']):.6f} & {float(summary['dependency_factor']):.6f} & "
            f"{float(summary['max_abs_lag1_phi']):.6f} & "
            f"{float(summary['working_h']):.6f} & {float(summary['raw_collection_h']):.3f} \\\\"
        )
    out.extend(["\\bottomrule", "\\end{xltabular}", "}", ""])

    overall_h = min(float(summary["working_h"]) for summary in summaries)
    overall_raw_h = RNG_READS_PER_COLLECTION * overall_h
    overall_credit = min(float(RNG_CONDITIONED_BITS), overall_raw_h)
    out.append(f"\\newcommand{{\\RngOverallH}}{{{overall_h:.6f}}}")
    out.append(f"\\newcommand{{\\RngRawSamplesPerCollection}}{{{RNG_READS_PER_COLLECTION}}}")
    out.append(f"\\newcommand{{\\RngOverallRawCollectionH}}{{{overall_raw_h:.3f}}}")
    out.append(f"\\newcommand{{\\RngOverallCredit}}{{{overall_credit:.0f}}}")
    return "\n".join(out) + "\n", "\n".join(detail) + "\n"


def write_if_changed(path: Path, content: str, force: bool = False) -> bool:
    old = path.read_text(encoding="utf-8") if path.exists() else None
    if not force and old == content:
        return False
    path.write_text(content, encoding="utf-8")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate whitepaper LaTeX fragments from checked-in datasets."
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="regenerate generated files even when the input manifest is unchanged",
    )
    args = parser.parse_args()

    GENERATED_DIR.mkdir(parents=True, exist_ok=True)
    digest = manifest_hash([RNG_STATS_DIR, APPENDIX_B_DIR, APPENDIX_B_ALT_DIR])
    old_digest = MANIFEST_FILE.read_text(encoding="utf-8").strip() if MANIFEST_FILE.exists() else ""

    if (
        not args.force
        and digest == old_digest
        and RNG_ENTROPY_TEX.exists()
        and RNG_ENTROPY_APPENDIX_TEX.exists()
        and APPENDIX_B_TEX.exists()
        and RNG_REQUEST_SNIPPET.exists()
        and RNG_DISTRIBUTION_SVG.exists()
    ):
        print("docs-data: cache hit (inputs unchanged)")
        return 0

    rng_entropy, rng_entropy_appendix = build_rng_entropy_analysis(RNG_STATS_DIR)
    appendix_b = build_appendix_b_model_summary(DATASETS_ROOT)

    changed = False
    changed |= write_if_changed(RNG_ENTROPY_TEX, rng_entropy, args.force)
    changed |= write_if_changed(RNG_ENTROPY_APPENDIX_TEX, rng_entropy_appendix, args.force)
    changed |= write_if_changed(APPENDIX_B_TEX, appendix_b, args.force)
    changed |= write_if_changed(
        RNG_REQUEST_SNIPPET,
        extract_c_declaration(RNG_API_HEADER, "tls_request_random_bytes"),
        args.force,
    )
    old_chart = (
        RNG_DISTRIBUTION_SVG.read_text(encoding="utf-8")
        if RNG_DISTRIBUTION_SVG.exists()
        else None
    )
    rng_report = RNG_REPORTER.build_report(
        RNG_REPORTER.load_profiles(RNG_STATS_DIR)
    )
    RNG_REPORTER.write_svg(RNG_DISTRIBUTION_SVG, rng_report, paper_chart=True)
    changed |= old_chart != RNG_DISTRIBUTION_SVG.read_text(encoding="utf-8")

    MANIFEST_FILE.write_text(digest + "\n", encoding="utf-8")

    if args.force:
        print("docs-data: force-regenerated generated files")
    elif changed:
        print("docs-data: regenerated generated files")
    else:
        print("docs-data: manifest updated (content unchanged)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

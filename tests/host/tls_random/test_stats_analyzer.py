"""Validate the raw-tap profiler's MCV entropy calculations."""

import importlib.util
import math
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
ANALYZER = ROOT / "tests/profiling/tls_rng_stats/tools/analyze_rng_stats.py"
SPEC = importlib.util.spec_from_file_location("analyze_rng_stats", ANALYZER)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


text = """\
rng_stats,version=1,runs=2,samples_per_run=1000
run=0,source=D65800,mask=04,samples=1000,ones=500,zeros=500,transitions=500,longest=4,longest0=4,longest1=3,p1_q16=32768,bias_q16=0,transition_q16=32800
run=1,source=D65800,mask=04,samples=1000,ones=550,zeros=450,transitions=480,longest=5,longest0=4,longest1=5,p1_q16=36045,bias_q16=3277,transition_q16=31488
"""

runs = MODULE.parse_runs(text)
report = MODULE.analyze(runs)

assert len(report["runs"]) == 2
assert report["aggregate"]["samples"] == 2000
assert math.isclose(report["aggregate"]["p1"], 0.525)
assert report["aggregate"]["h_mcv_plugin_bits_per_raw_bit"] < 1.0
assert (
    report["aggregate"]["h_mcv_lower_99_bits_per_raw_bit"]
    < report["aggregate"]["h_mcv_plugin_bits_per_raw_bit"]
)
assert report["conservative_working_h_bits_per_raw_bit"] == min(
    report["worst_window_h_mcv_lower_99_bits_per_raw_bit"],
    report["aggregate"]["h_mcv_lower_99_bits_per_raw_bit"],
)

print("RNG stats analyzer passed: parsing and MCV confidence estimate")

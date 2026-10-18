"""Validate raw-tap marginal and first-order entropy calculations."""

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
assert all(
    row["transition_counts_source"] == "reconstructed_conservatively"
    for row in report["runs"]
)
assert (
    report["transition_counts_provenance"]
    == "includes_conservative_legacy_reconstruction"
)
# Persisting the selected matrix must not cause a later analyzer pass to
# mislabel reconstructed legacy counts as directly recorded v2 counts.
reanalyzed = MODULE.analyze(report["runs"])
assert all(
    row["transition_counts_source"] == "reconstructed_conservatively"
    for row in reanalyzed["runs"]
)
assert math.isclose(report["aggregate"]["transition_rate"], 980 / 1998)
assert abs(report["aggregate"]["lag1_phi"]) < 0.06
assert report["conservative_working_h_bits_per_raw_bit"] <= min(
    report["worst_window_h_mcv_lower_99_bits_per_raw_bit"],
    report["aggregate"]["h_mcv_lower_99_bits_per_raw_bit"],
)

alternating_text = """\
rng_stats,version=2,runs=1,samples_per_run=1000
run=0,source=D65800,mask=04,samples=1000,ones=500,zeros=500,transitions=999,n00=0,n01=500,n10=499,n11=0,longest=1,longest0=1,longest1=1,p1_q16=32768,bias_q16=0,transition_q16=65536
"""
alternating = MODULE.analyze(MODULE.parse_runs(alternating_text))
alternating_run = alternating["runs"][0]
assert alternating_run["transition_counts_source"] == "recorded"
assert alternating["transition_counts_provenance"] == "recorded"
assert alternating_run["lag1_phi"] == -1.0
assert alternating_run["h_markov_lower_99_bits_per_raw_bit"] < 0.01
assert alternating["first_order_dependency_factor"] < 0.01

iid_counts = {"n00": 250, "n01": 250, "n10": 250, "n11": 249}
iid = MODULE.transition_estimate(iid_counts, ones=500, zeros=500)
assert abs(iid["lag1_phi"]) < 0.002
assert iid["h_markov_plugin_bits_per_raw_bit"] > 0.99

print("RNG stats analyzer passed: marginal and first-order estimates")

import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / ".github/scripts/run_fuzz_tests.py"
SPEC = importlib.util.spec_from_file_location("run_fuzz_tests", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def test_runner_covers_every_make_target() -> None:
    makefile = (ROOT / "tests/fuzz/makefile").read_text()
    declared = makefile.split("TARGETS =", 1)[1].splitlines()[0].split()
    assert tuple(declared) == MODULE.TARGETS


def test_libfuzzer_stats_are_normalized() -> None:
    stats = MODULE.parse_stats("""
stat::number_of_executed_units: 1234
stat::average_exec_per_sec: 98
stat::peak_rss_mb: 76
""")
    result = MODULE.FuzzResult("json", 0, 5010, stats)
    assert MODULE.stats_text(result) == (
        "5010 ms; 1234 executions; 98 exec/s; 76 MiB peak RSS"
    )


def test_nested_result_matches_parallel_runner_schema() -> None:
    result = MODULE.nested_unit(MODULE.FuzzResult("xml", 0, 1000, {}))
    assert result == {
        "unit": "xml",
        "description": "libFuzzer target xml",
        "status": "pass",
        "tests": [{
            "test": "Fuzz campaign",
            "description": "1000 ms",
            "status": "pass",
        }],
    }


def test_build_failure_is_explicit() -> None:
    result = MODULE.nested_unit(
        MODULE.FuzzResult("tls", 2, 42, {}, build_error=True)
    )
    assert result["status"] == "fail"
    assert result["build_error"] is True
    assert result["tests"][0]["test"] == "Harness build"


if __name__ == "__main__":
    test_runner_covers_every_make_target()
    test_libfuzzer_stats_are_normalized()
    test_nested_result_matches_parallel_runner_schema()
    test_build_failure_is_explicit()
    print("parallel fuzz runner self-test: PASS")

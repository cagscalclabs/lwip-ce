import importlib.util
import sys
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[3] / ".github/scripts/run_nettests.py"
SPEC = importlib.util.spec_from_file_location("run_nettests", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def test_namespace_names_fit_linux_interface_limit() -> None:
    namespaces = [MODULE.namespace_for(index) for index in range(len(MODULE.SUITES))]
    assert len({item.name for item in namespaces}) == len(namespaces)
    assert all(len(item.root_interface) <= 15 for item in namespaces)
    assert all(len(item.peer_interface) <= 15 for item in namespaces)


def test_nested_unit_matches_unit_runner_schema() -> None:
    result = MODULE.nested_unit("sockets", 0, [
        {"test": "SOCKETS - lwip_start", "grade": "Pass"},
        {"test": "SOCKETS - expected rejection", "grade": "Skipped"},
    ])

    assert result == {
        "unit": "sockets",
        "description": "lwIP-CE networked suite NETTEST",
        "status": "pass",
        "tests": [
            {"test": "lwip_start", "description": "lwip_start", "status": "pass", "stats": ""},
            {"test": "expected rejection", "description": "expected rejection", "status": "skip", "stats": ""},
        ],
    }


def test_nonzero_suite_exit_is_failure_even_without_rows() -> None:
    result = MODULE.nested_unit("raw", 124, [])
    assert result["status"] == "fail"
    assert result["tests"][0]["status"] == "fail"

    build = MODULE.nested_unit("raw", 2, [
        {"test": "RAW - Suite build", "grade": "Fail"}
    ], build_error=True)
    assert build["build_error"] is True
    assert build["tests"][0]["test"] == "Suite build"


def test_heap_metrics_are_added_to_legacy_rows() -> None:
    rows = [{"test": "PERF - transfer", "grade": "Pass"}]
    MODULE.add_heap_stats(rows, {
        "first_heap_peak": {"value": 1200, "unit": "B"},
        "second_heap_peak": {"value": 1800, "unit": "B"},
        "heap_idle": {"value": 400, "unit": "B"},
    })
    assert rows[0]["stats"] == "heap peak 1800 B; heap idle 400 B"


if __name__ == "__main__":
    test_namespace_names_fit_linux_interface_limit()
    test_nested_unit_matches_unit_runner_schema()
    test_nonzero_suite_exit_is_failure_even_without_rows()
    test_heap_metrics_are_added_to_legacy_rows()
    print("parallel nettest runner self-test: PASS")

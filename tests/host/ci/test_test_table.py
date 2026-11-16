import importlib.util
import json
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / ".github/scripts/test_table.py"
SPEC = importlib.util.spec_from_file_location("test_table", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def test_render_sections_lead_with_status_and_failures() -> None:
    nested = [{
        "module": "tls",
        "description": "TLS subsystem tests",
        "status": "fail",
        "units": [{
            "unit": "hash",
            "description": "hashes",
            "status": "fail",
            "tests": [
                {"test": "SHA-256", "description": "known answer",
                 "status": "pass", "stats": "10 ms"},
                {"test": "SHA-384", "description": "known answer",
                 "status": "fail", "stats": "20 ms"},
            ],
        }, {
            "unit": "certificates", "description": "certificates",
            "status": "skip",
            "tests": [{"test": "fixture", "description": "fixture unavailable",
                       "status": "skip"}],
        }],
    }]
    rows = [
        {"group": "NETTEST", "module": "NETTEST", "test": "TLS - handshake",
         "grade": "Pass", "stats": "100 ms"},
        {"group": "NETTEST", "module": "NETTEST", "test": "TLS - tls bulk session",
         "grade": "Pass"},
        {"group": "FUZZ", "module": "FUZZ", "test": "x509",
         "grade": "Pass", "stats": "1000 executions"},
    ]
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "results-unit.json").write_text(json.dumps(nested))
        (root / "rows.json").write_text(json.dumps(rows))
        output = root / "summary.md"
        MODULE.render(root, output, ["UNIT|Suite execution|failure"])
        text = output.read_text()

    # One titled status line per job, in CI order.
    assert text.startswith("### ❌ Unit tests — 1/3 passed\n")
    assert "2 units · 1 failed, 1 skipped" in text
    assert text.index("Unit tests") < text.index("Network tests") < text.index("Fuzzing")
    # Failures come first, readable without expanding anything.
    assert "> [!CAUTION]\n> **1 failed**" in text
    assert "| hash | known answer (SHA-384) | 20 ms |" in text
    # The fallback is suppressed once the job produced real results.
    assert "Suite execution" not in text
    # Overview: one row per unit with its tally.
    assert "| hash | ❌ | 1/2 |" in text
    assert "| certificates | ⏭️ | 0/1 |" in text
    # A failing unit's details open by default; tests keep their measurements.
    assert "<details open>\n<summary>❌ <b>hash</b> — 1/2 passed</summary>" in text
    assert "| known answer (SHA-256) | ✅ | 10 ms |" in text
    # Single-result units carry their measurement in the overview, no tally.
    assert "### ✅ Network tests — 1/1 passed" in text
    assert "| TLS | ✅ | 100 ms |" in text
    assert "| x509 | ✅ | 1000 executions |" in text
    # A passing connection gate is hidden.
    assert "tls bulk session" not in text


def test_fallback_is_a_one_test_unit() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        output = root / "summary.md"
        MODULE.render(root / "missing", output, ["SAST|Semgrep|failure"])
        text = output.read_text()
    assert text.startswith("### ❌ Static analysis — 0/1 passed\n")
    assert "| Semgrep | — |  |" in text
    assert "| Semgrep | ❌ |" in text


def test_render_accepts_one_result_file() -> None:
    nested = [{
        "module": "fuzz", "status": "pass", "units": [{
            "unit": "x509", "status": "pass",
            "tests": [{"test": "Fuzz campaign", "status": "pass"}],
        }],
    }]
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        result = root / "results-fuzz.json"
        result.write_text(json.dumps(nested))
        output = root / "summary.md"
        MODULE.render(result, output, ["FUZZ|All targets|failure"])
        text = output.read_text()
    assert text.startswith("### ✅ Fuzzing — 1/1 passed\n")
    assert "| x509 | ✅ |" in text
    assert "All targets" not in text
    assert "<details" not in text


if __name__ == "__main__":
    test_render_sections_lead_with_status_and_failures()
    test_fallback_is_a_one_test_unit()
    test_render_accepts_one_result_file()
    print("test summary renderer: PASS")

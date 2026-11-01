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


def test_render_builds_module_unit_test_hierarchy() -> None:
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

    assert "| Module | # Units | # Pass | # Fail | # Skip |" in text
    assert "| 🟩 TLS | 2 | 0 | 1 | 1 |" in text
    assert "| 🟩 UNIT |" not in text
    assert "| 🟨 NETTEST | 1 | 1 | 0 | 0 |" in text
    assert "<summary>TLS Units</summary>" in text
    assert "- **hash** — SHA-384: known answer (20 ms)" in text
    assert "| hash | 2 | 1 | 1 | 0 |" in text
    assert "<summary>hash Tests — ❌ Fail</summary>" in text
    assert "| SHA-256 | ✅ Pass | known answer | 10 ms |" in text
    assert "<summary>TLS Tests — ✅ Pass</summary>" in text
    assert "<summary>x509 Tests — ✅ Pass</summary>" in text


def test_fallback_is_a_one_test_unit() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        output = root / "summary.md"
        MODULE.render(root / "missing", output, ["SAST|Semgrep|failure"])
        text = output.read_text()
    assert "| 🟥 SAST | 1 | 0 | 1 | 0 |" in text
    assert "| Semgrep | 1 | 0 | 1 | 0 |" in text
    assert "| Result | ❌ Fail |  |  |" in text


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
    assert "| ⚫ FUZZ | 1 | 1 | 0 | 0 |" in text
    assert "<summary>x509 Tests — ✅ Pass</summary>" in text


if __name__ == "__main__":
    test_render_builds_module_unit_test_hierarchy()
    test_fallback_is_a_one_test_unit()
    test_render_accepts_one_result_file()
    print("hierarchical test summary renderer: PASS")

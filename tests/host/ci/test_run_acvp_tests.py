import importlib.util
import json
import re
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / ".github/scripts/run_acvp_tests.py"
sys.path.insert(0, str(SCRIPT.parent))
SPEC = importlib.util.spec_from_file_location("run_acvp_tests", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def test_every_unit_has_one_build_directory_and_unique_program() -> None:
    assert len(MODULE.UNITS) == 16
    assert len({unit.program for unit in MODULE.UNITS}) == len(MODULE.UNITS)
    primitives = set()
    for unit in MODULE.UNITS:
        makefile = ROOT / "tests/acvp" / unit.directory / "makefile"
        text = makefile.read_text()
        assert f"NAME = {unit.program}" in text
        assert f"ACVP_ALGORITHM = {unit.algorithm}" in text
        match = re.search(r"^ACVP_PRIMITIVE = (\d+)$", text, re.MULTILINE)
        assert match is not None
        primitives.add(int(match.group(1)))
    assert primitives == set(range(1, 17))


def test_generated_corpus_is_covered_exactly_once() -> None:
    corpus = ROOT / "tests/validation/acvp/corpus/prompt.json"
    if not corpus.is_file():
        return
    document = json.loads(corpus.read_text())
    selected = [MODULE.select_document(document, unit)[-1] for unit in MODULE.UNITS]
    assert len({item["vsId"] for item in selected}) == len(MODULE.UNITS)
    assert {item["vsId"] for item in selected} == {
        item["vsId"] for item in MODULE.vectors(document)
    }


def test_documents_are_split_by_algorithm_and_mode() -> None:
    document = [
        {"acvVersion": "1.0"},
        {"vsId": 1, "algorithm": "KDA", "mode": "HKDF", "testGroups": []},
        {"vsId": 2, "algorithm": "SHA2-256", "testGroups": []},
    ]
    hkdf = next(unit for unit in MODULE.UNITS if unit.directory == "test_hkdf")
    selected = MODULE.select_document(document, hkdf)
    assert selected == [document[0], document[1]]
    assert MODULE.select_expected(document, selected) == selected


def test_nested_result_matches_other_parallel_runners() -> None:
    unit = MODULE.UNITS[0]
    result = MODULE.nested_unit(unit, {
        "tests": [{"tcId": 7, "mode": "AFT", "passed": True,
                   "detail": "matched independent reference"}]
    }, 0)
    assert result["status"] == "pass"
    assert result["tests"] == [{
        "test": "AFT #7",
        "description": "matched independent reference",
        "status": "pass",
    }]


def test_single_unit_autotest_transfers_only_its_program() -> None:
    validation = ROOT / "tests/validation/acvp"
    sys.path.insert(0, str(validation))
    spec = importlib.util.spec_from_file_location("acvp_run", validation / "run.py")
    run_module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(run_module)
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        binary = work / "AVS256.8xp"
        binary.touch()
        autotest = work / "autotest.json"
        run_module.write_autotest(autotest, "usb|plug", 1234, "AVS256", binary)
        document = json.loads(autotest.read_text())
    assert document["transfer_files"] == ["AVS256.8xp"]
    assert document["target"]["name"] == "AVS256"
    assert all("INSTALL" not in step for step in document["sequence"])


if __name__ == "__main__":
    test_every_unit_has_one_build_directory_and_unique_program()
    test_generated_corpus_is_covered_exactly_once()
    test_documents_are_split_by_algorithm_and_mode()
    test_nested_result_matches_other_parallel_runners()
    test_single_unit_autotest_transfers_only_its_program()
    print("parallel ACVP runner self-test: PASS")

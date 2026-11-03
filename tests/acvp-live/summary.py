#!/usr/bin/env python3
"""Build hierarchical job-summary input for a live ACVP session."""

from __future__ import annotations

import argparse
import json
from collections import OrderedDict
from pathlib import Path


def read_json(path: Path) -> object | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def vector_sets(document: object | None) -> list[dict]:
    if not isinstance(document, list):
        return []
    return [
        item for item in document
        if isinstance(item, dict)
        and isinstance(item.get("vsId"), int)
        and isinstance(item.get("algorithm"), str)
    ]


def response_ids(document: object | None) -> set[int]:
    if not isinstance(document, list):
        return set()
    return {
        item["vsId"] for item in document
        if isinstance(item, dict) and isinstance(item.get("vsId"), int)
    }


def outcome_status(outcome: str) -> str:
    if outcome == "success":
        return "pass"
    if outcome in {"failure", "cancelled", "timed_out"}:
        return "fail"
    return "skipped"


def build_results(vectors: object | None, responses: object | None,
                  grading: object | None, run_outcome: str,
                  submit_outcome: str, grade_outcome: str) -> list[dict]:
    prompts = vector_sets(vectors)
    completed = response_ids(responses)
    grading_passed = (
        grading.get("passed") if isinstance(grading, dict)
        and isinstance(grading.get("passed"), bool) else None
    )

    modules: OrderedDict[str, list[dict]] = OrderedDict()
    for vector in prompts:
        algorithm = vector["algorithm"]
        mode = vector.get("mode")
        module = f"{algorithm} {mode}" if mode else algorithm
        vsid = vector["vsId"]
        calculator_status = "pass" if vsid in completed else (
            "fail" if run_outcome in {"success", "failure", "cancelled", "timed_out"}
            else "skipped"
        )
        if grading_passed is True:
            nist_status = "pass"
        elif grading_passed is False:
            nist_status = "fail"
        else:
            nist_status = outcome_status(grade_outcome)
        tests = [
            {
                "test": "Calculator response",
                "description": f"Response for NIST vector set {vsid}",
                "status": calculator_status,
            },
            {
                "test": "NIST response upload",
                "description": "Upload of the session response document",
                "status": outcome_status(submit_outcome),
            },
            {
                "test": "NIST grading",
                "description": "NIST ACVP server grading verdict",
                "status": nist_status,
            },
        ]
        modules.setdefault(module, []).append({
            "unit": f"vsId {vsid}",
            "status": "fail" if any(test["status"] == "fail" for test in tests)
            else "pass" if all(test["status"] == "pass" for test in tests)
            else "skipped",
            "tests": tests,
        })

    if not modules:
        tests = [{
            "test": "Vector acquisition",
            "description": "No NIST vector sets were available for the run",
            "status": "fail" if run_outcome == "failure" else "skipped",
        }]
        modules["ACVP LIVE"] = [{
            "unit": "Workflow",
            "status": tests[0]["status"],
            "tests": tests,
        }]

    return [
        {
            "module": module,
            "status": "fail" if any(unit["status"] == "fail" for unit in units)
            else "pass" if all(unit["status"] == "pass" for unit in units)
            else "skipped",
            "units": units,
        }
        for module, units in modules.items()
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vectors", type=Path, required=True)
    parser.add_argument("--responses", type=Path, required=True)
    parser.add_argument("--grading", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run-outcome", default="skipped")
    parser.add_argument("--submit-outcome", default="skipped")
    parser.add_argument("--grade-outcome", default="skipped")
    args = parser.parse_args()

    results = build_results(
        read_json(args.vectors), read_json(args.responses),
        read_json(args.grading), args.run_outcome,
        args.submit_outcome, args.grade_outcome,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()

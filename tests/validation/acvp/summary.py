#!/usr/bin/env python3
"""Render ACVP fixture results for the GitHub Actions job summary."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent


def table_text(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def vector_sets(document: Any) -> dict[int, dict[str, Any]]:
    if not isinstance(document, list):
        raise ValueError("ACVP document is not a list")
    result: dict[int, dict[str, Any]] = {}
    for item in document:
        if isinstance(item, dict) and "vsId" in item:
            result[int(item["vsId"])] = item
    return result


def test_cases(vector_set: dict[str, Any]) -> dict[int, dict[str, Any]]:
    result: dict[int, dict[str, Any]] = {}
    for group in vector_set.get("testGroups", []):
        for test in group.get("tests", []):
            result[int(test["tcId"])] = test
    return result


def describe_mode(vector_set: dict[str, Any], group: dict[str, Any]) -> str:
    parts = [vector_set.get("mode"), group.get("testType"), group.get("direction")]
    return "/".join(str(part) for part in parts if part)


def render(
    prompt: Any,
    expected: Any,
    response: Any | None,
    run_outcome: str,
) -> tuple[str, dict[str, Any], bool]:
    prompts = vector_sets(prompt)
    expected_sets = vector_sets(expected)
    response_sets = vector_sets(response) if response is not None else {}
    rows: list[dict[str, Any]] = []

    for vs_id, vector_set in prompts.items():
        expected_tests = test_cases(expected_sets.get(vs_id, {}))
        response_tests = test_cases(response_sets.get(vs_id, {}))
        groups = vector_set.get("testGroups", [])
        for group in groups:
            for prompt_test in group.get("tests", []):
                tc_id = int(prompt_test["tcId"])
                wanted = expected_tests.get(tc_id)
                actual = response_tests.get(tc_id)
                passed = wanted is not None and actual == wanted
                if actual is None:
                    detail = "response missing"
                elif wanted is None:
                    detail = "expected result missing"
                elif passed:
                    detail = "matched expected response"
                else:
                    detail = "response mismatch"
                rows.append({
                    "vsId": vs_id,
                    "tcId": tc_id,
                    "algorithm": vector_set.get("algorithm", "unknown"),
                    "revision": vector_set.get("revision", ""),
                    "mode": describe_mode(vector_set, group),
                    "passed": passed,
                    "detail": detail,
                })

    passed_count = sum(row["passed"] for row in rows)
    failed_count = len(rows) - passed_count
    run_passed = run_outcome == "success"
    overall = run_passed and failed_count == 0 and bool(rows)
    report = {
        "passed": overall,
        "runOutcome": run_outcome,
        "total": len(rows),
        "passedTests": passed_count,
        "failedTests": failed_count,
        "tests": rows,
    }

    lines = [
        "## ACVP primitive validation",
        "",
        f"**{'✅ PASS' if overall else '❌ FAIL'}** — "
        f"{passed_count}/{len(rows)} test cases matched; CEmu execution: `{table_text(run_outcome)}`.",
        "",
        "| Vector set | Algorithm | Revision | Mode | Test case | Result |",
        "| ---: | --- | --- | --- | ---: | --- |",
    ]
    for row in rows:
        result = "✅ Pass" if row["passed"] else f"❌ {row['detail']}"
        lines.append(
            f"| {row['vsId']} | {table_text(row['algorithm'])} | "
            f"{table_text(row['revision'])} | {table_text(row['mode'])} | "
            f"{row['tcId']} | {result} |"
        )
    if not rows:
        lines.append("| — | — | — | — | — | ❌ No readable test results |")
    lines.extend([
        "",
        "The fixture responses were produced by the shipping `lwip.lib` primitives inside CEmu and compared with the checked-in expected ACVP response.",
        "",
    ])
    return "\n".join(lines), report, overall


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prompt", type=Path, default=HERE / "fixtures" / "prompt.json")
    parser.add_argument("--expected", type=Path, default=HERE / "fixtures" / "expected.json")
    parser.add_argument("--response", type=Path, default=HERE / "response.json")
    parser.add_argument("--markdown", type=Path, default=HERE / "summary.md")
    parser.add_argument("--results", type=Path, default=HERE / "results.json")
    parser.add_argument("--github-summary", type=Path)
    parser.add_argument("--run-outcome", default="success")
    args = parser.parse_args()

    try:
        prompt = json.loads(args.prompt.read_text())
        expected = json.loads(args.expected.read_text())
        response = json.loads(args.response.read_text()) if args.response.is_file() else None
        markdown, report, passed = render(prompt, expected, response, args.run_outcome)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        markdown = f"## ACVP primitive validation\n\n❌ **FAIL** — unable to render results: `{table_text(exc)}`.\n"
        report = {"passed": False, "runOutcome": args.run_outcome, "error": str(exc)}
        passed = False

    args.markdown.write_text(markdown)
    args.results.write_text(json.dumps(report, indent=2) + "\n")
    github_summary = args.github_summary or (
        Path(os.environ["GITHUB_STEP_SUMMARY"]) if os.environ.get("GITHUB_STEP_SUMMARY") else None
    )
    if github_summary:
        with github_summary.open("a") as stream:
            stream.write(markdown)
    print(markdown)
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())

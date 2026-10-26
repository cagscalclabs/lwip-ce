#!/usr/bin/env python3
"""Render ACVP fixture results for the GitHub Actions job summary."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from validate import validate_document

HERE = Path(__file__).resolve().parent


def table_text(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def render(
    prompt: Any,
    expected: Any,
    response: Any | None,
    oracle: dict,
    run_outcome: str,
) -> tuple[str, dict[str, Any], bool]:
    report = validate_document(prompt, expected, response, oracle)
    rows = report["tests"]
    passed_count, failed_count = report["passedTests"], report["failedTests"]
    run_passed = run_outcome == "success"
    overall = run_passed and failed_count == 0 and bool(rows)
    report.update({"passed": overall, "runOutcome": run_outcome})

    aggregate: dict[tuple[str, str], list[int]] = {}
    for row in rows:
        key = (row["algorithm"], row["mode"])
        counts = aggregate.setdefault(key, [0, 0])
        counts[0] += 1; counts[1] += bool(row["passed"])

    lines = [
        "## ACVP primitive validation",
        "",
        f"**{'✅ PASS' if overall else '❌ FAIL'}** — "
        f"{passed_count}/{len(rows)} test cases matched; CEmu execution: `{table_text(run_outcome)}`.",
        "",
        "| Primitive | Modes exercised | Vectors | Passed | Result |",
        "| --- | --- | ---: | ---: | --- |",
    ]
    for (algorithm, mode), (total, passed) in aggregate.items():
        lines.append(f"| {table_text(algorithm)} | {table_text(mode)} | {total} | {passed} | "
                     f"{'✅ Pass' if total == passed else '❌ Fail'} |")
    if not rows:
        lines.append("| — | — | 0 | 0 | ❌ No readable test results |")
    failures = [row for row in rows if not row["passed"]]
    if failures:
        lines.extend(["", "### Failures", ""])
        lines.extend(f"- `{row['algorithm']} tcId {row['tcId']}`: {table_text(row['detail'])}"
                     for row in failures[:50])
    lines.extend([
        "",
        "Deterministic responses are compared with independent host implementations; generated-key ECDSA, X25519, and P-256 results are verified semantically.",
        "",
    ])
    return "\n".join(lines), report, overall


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prompt", type=Path, default=HERE / "corpus" / "prompt.json")
    parser.add_argument("--expected", type=Path, default=HERE / "corpus" / "expected.json")
    parser.add_argument("--oracle", type=Path, default=HERE / "corpus" / "oracle.json")
    parser.add_argument("--response", type=Path, default=HERE / "response.json")
    parser.add_argument("--markdown", type=Path, default=HERE / "summary.md")
    parser.add_argument("--results", type=Path, default=HERE / "results.json")
    parser.add_argument("--github-summary", type=Path)
    parser.add_argument("--run-outcome", default="success")
    args = parser.parse_args()

    try:
        prompt = json.loads(args.prompt.read_text())
        expected = json.loads(args.expected.read_text())
        oracle = json.loads(args.oracle.read_text())
        response = json.loads(args.response.read_text()) if args.response.is_file() else None
        markdown, report, passed = render(prompt, expected, response, oracle, args.run_outcome)
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

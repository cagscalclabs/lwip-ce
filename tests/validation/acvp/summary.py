#!/usr/bin/env python3
"""Render and persist ACVP fixture results."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from validate import validate_document

HERE = Path(__file__).resolve().parent


def table_text(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def write_evidence_bundle(directory: Path, prompt: Any, expected: Any,
                          response: Any | None, report: dict, oracle: dict) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    expected_bundle = {
        "exactResults": expected,
        "semanticExpectations": {
            "DetECDSA": {
                "rule": "Each P-256/SHA2-256 signature must verify under the returned group public key; repeated messages must produce identical RFC 6979 signatures."
            },
            "XECDH": {
                "rule": "The returned Curve25519 public key and shared secret must match an independent exchange using the test server private key.",
                "serverPrivateByTcId": oracle.get("x25519", {}),
            },
            "KAS-ECC": {
                "rule": "The returned P-256 public key and shared secret must match an independent CDH exchange using the test server private scalar.",
                "serverPrivateByTcId": oracle.get("p256", {}),
            },
        },
    }
    bundle = {
        "format": "lwip-ce-acvp-vectors-v1",
        "knownAnswerVectors": prompt,
        "expectedResults": expected_bundle,
        "calculatorResults": response,
        "validationResults": report,
    }
    (directory / "acvp-validation.vectors").write_text(json.dumps(bundle, indent=2) + "\n")


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
        lines.extend(f"- `{row['algorithm']} ({row['mode']})`: {table_text(row['detail'])}"
                     for row in failures[:50])
    lines.extend([
        "",
        "Deterministic responses are compared with independent host implementations; generated-key ECDSA, X25519, and P-256 results are verified semantically.",
        "",
        "The complete known-answer vectors, expected results, calculator responses, and per-vector validation results are attached as `acvp-validation.vectors` in the workflow artifact.",
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
    parser.add_argument("--artifact-dir", type=Path, default=HERE / "artifacts")
    parser.add_argument("--github-summary", type=Path)
    parser.add_argument("--run-outcome", default="success")
    args = parser.parse_args()

    try:
        prompt = json.loads(args.prompt.read_text())
        expected = json.loads(args.expected.read_text())
        oracle = json.loads(args.oracle.read_text())
        response = json.loads(args.response.read_text()) if args.response.is_file() else None
        markdown, report, passed = render(prompt, expected, response, oracle, args.run_outcome)
        write_evidence_bundle(args.artifact_dir, prompt, expected, response, report, oracle)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        markdown = f"## ACVP primitive validation\n\n❌ **FAIL** — unable to render results: `{table_text(exc)}`.\n"
        report = {"passed": False, "runOutcome": args.run_outcome, "error": str(exc)}
        passed = False

    args.markdown.write_text(markdown)
    args.results.write_text(json.dumps(report, indent=2) + "\n")
    if args.github_summary:
        with args.github_summary.open("a") as stream:
            stream.write(markdown)
    print(f"ACVP summary: {report.get('passedTests', 0)}/{report.get('total', 0)} vectors passed; "
          f"Markdown written to {args.markdown}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())

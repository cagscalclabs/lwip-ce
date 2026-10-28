#!/usr/bin/env python3
"""Normalize CI test outputs and render one Module | Test | Grade table."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def write_rows(path: Path, rows: list[dict[str, str]]) -> None:
    path.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")


def grade(value: object) -> str:
    value = str(value or "").lower()
    if value in {"success", "passed", "pass", "ok", "true"}:
        return "Pass"
    if value in {"failure", "failed", "fail", "false", "timed_out", "timeout"}:
        return "Fail"
    return "Skipped"


def module_name(name: str) -> str:
    for prefix in ("tls_", "parsers_", "lwip_"):
        if name.startswith(prefix):
            name = name[len(prefix):]
            break
    return name.replace("_", " ").upper()


def unit_rows(results_path: Path, repo: Path) -> list[dict[str, str]]:
    document = json.loads(results_path.read_text(encoding="utf-8"))
    rows: list[dict[str, str]] = []
    manifests = {p.parent.name: p for p in (repo / "tests/unit").glob("*/autotest.json")}
    for result in document.get("results", {}).get("tests", []):
        name = str(result.get("name", "unit"))
        status = str(result.get("status", "failed"))
        failed = {part for part in str(result.get("failed_hash_ids", "")).split(",") if part}
        manifest_path = manifests.get(name)
        if not manifest_path:
            rows.append({"group": "UNIT", "module": module_name(name),
                         "test": name, "grade": grade(status)})
            continue
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        hash_ids = [entry.split("|", 1)[1] for entry in manifest.get("sequence", [])
                    if entry.startswith("hashWait|")]
        for hash_id in hash_ids:
            description = manifest.get("hashes", {}).get(hash_id, {}).get(
                "description", f"Hash {hash_id}"
            )
            if status == "passed":
                row_grade = "Pass"
            elif status.startswith("skipped") or status.startswith("timeout"):
                row_grade = "Skipped"
            else:
                row_grade = "Fail" if not failed or hash_id in failed else "Pass"
            rows.append({"group": "UNIT", "module": module_name(name),
                         "test": str(description), "grade": row_grade})
    return rows


def acvp_rows(path: Path) -> list[dict[str, str]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    rows = []
    for index, result in enumerate(document.get("tests", []), 1):
        algorithm = str(result.get("algorithm", "ACVP"))
        mode = str(result.get("mode", "vector"))
        test_id = result.get("tcId", result.get("testId", index))
        detail = str(result.get("detail", "")).strip()
        label = f"{mode} #{test_id}"
        if detail and not result.get("passed", False):
            label += f" — {detail}"
        rows.append({"group": "ACVP", "module": algorithm, "test": label,
                     "grade": "Pass" if result.get("passed") else "Fail"})
    return rows


def dast_rows(path: Path) -> list[dict[str, str]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    return [
        {
            "group": "DAST",
            "module": "DAST",
            "test": str(item.get("name", item.get("id", "probe"))),
            "grade": grade(item.get("grade")),
        }
        for item in document.get("results", [])
    ]


def render(input_dir: Path, output: Path, fallbacks: list[str]) -> None:
    rows: list[dict[str, str]] = []
    for path in sorted(input_dir.rglob("*.json")) if input_dir.exists() else []:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(value, list):
            rows.extend(item for item in value if isinstance(item, dict)
                        and {"module", "test", "grade"} <= item.keys())

    present = {(str(row["module"]), str(row["test"])) for row in rows}
    present_groups = {str(row.get("group", row["module"])) for row in rows}
    grouped_fallbacks = {"UNIT", "ACVP", "NETTEST", "DAST", "HOST", "FUZZ"}
    for fallback in fallbacks:
        module, test, result = fallback.split("|", 2)
        group_present = module in grouped_fallbacks and module in present_groups
        if not group_present and (module, test) not in present:
            rows.append({"module": module, "test": test, "grade": grade(result)})

    normalized = [
        {"module": str(row["module"]), "test": str(row["test"]),
         "grade": grade(row["grade"])}
        for row in rows
    ]
    ordered = sorted(normalized,
                     key=lambda row: (row["module"].casefold(), row["test"].casefold()))

    def md(value: str) -> str:
        return value.replace("|", "\\|").replace("\n", " ")

    lines = ["## Test results", "", "| Module | Test | Grade |", "|---|---|---|"]
    lines.extend(f"| {md(row['module'])} | {md(row['test'])} | {row['grade']} |"
                 for row in ordered)
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    unit = sub.add_parser("unit")
    unit.add_argument("--results", type=Path, required=True)
    unit.add_argument("--repo", type=Path, default=Path("."))
    unit.add_argument("--output", type=Path, required=True)

    acvp = sub.add_parser("acvp")
    acvp.add_argument("--results", type=Path, required=True)
    acvp.add_argument("--output", type=Path, required=True)

    dast = sub.add_parser("dast")
    dast.add_argument("--results", type=Path, required=True)
    dast.add_argument("--output", type=Path, required=True)

    row = sub.add_parser("row")
    row.add_argument("--module", required=True)
    row.add_argument("--test", required=True)
    row.add_argument("--grade", required=True)
    row.add_argument("--output", type=Path, required=True)

    table = sub.add_parser("render")
    table.add_argument("--input", type=Path, required=True)
    table.add_argument("--output", type=Path, required=True)
    table.add_argument("--fallback", action="append", default=[])

    args = parser.parse_args()
    if args.command == "unit":
        write_rows(args.output, unit_rows(args.results, args.repo))
    elif args.command == "acvp":
        write_rows(args.output, acvp_rows(args.results))
    elif args.command == "dast":
        write_rows(args.output, dast_rows(args.results))
    elif args.command == "row":
        write_rows(args.output, [{"group": args.module, "module": args.module,
                                  "test": args.test,
                                  "grade": grade(args.grade)}])
    else:
        render(args.input, args.output, args.fallback)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Normalize CI test outputs and render hierarchical module summaries.

Every suite reports whatever it can measure — milliseconds, heap bytes, or a
preformatted string — and it all lands in one Stats cell. Net suites emit
connection-gate rows as well as the assertion rows; passing gates are hidden
so the row that carries the measurements represents the test.
"""

from __future__ import annotations

import argparse
import html
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


# Stats are free-form: whichever measurements a suite produces are collected
# into one cell, in a stable order (time, heap, then anything explicit).
_TIME_KEYS = ("time_ms", "duration", "emulated_time")
_HEAP_KEYS = ("heap_used", "heap", "heap_bytes")


def _quantity(value: object, unit: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if text.endswith(unit):
        return text
    return f"{text} {unit}"


def stats_of(row: dict) -> str:
    """Collect every qualifying measurement for a row into one cell.

    Accepts either explicit ``stats`` (string or list) or the individual
    measurement fields suites already emit: a duration in milliseconds
    (``time_ms``/``duration``/``emulated_time``) and a heap figure in bytes
    (``heap_used``/``heap``/``heap_bytes``). Unknown keys are ignored so a
    suite can grow new measurements without breaking the table.
    """
    parts: list[str] = []
    explicit = row.get("stats")
    if isinstance(explicit, list):
        parts.extend(str(item).strip() for item in explicit if str(item).strip())
    elif explicit:
        parts.append(str(explicit).strip())

    for key in _TIME_KEYS:
        text = _quantity(row.get(key), "ms")
        if text:
            parts.append(text)
            break
    for key in _HEAP_KEYS:
        text = _quantity(row.get(key), "B")
        if text:
            parts.append(f"heap {text}")
            break

    seen: set[str] = set()
    unique = [item for item in parts if not (item in seen or seen.add(item))]
    return "; ".join(unique)


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
        # No timing here: `duration` is the whole module's wall time, and
        # repeating it on every vector makes each vector look that slow.
        stats = stats_of({k: v for k, v in result.items()
                          if k not in _TIME_KEYS})
        failed = {part for part in str(result.get("failed_hash_ids", "")).split(",") if part}
        manifest_path = manifests.get(name)
        if not manifest_path:
            rows.append({"group": "UNIT", "module": module_name(name),
                         "test": name, "grade": grade(status),
                         "stats": stats})
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
                         "test": str(description), "grade": row_grade,
                         "stats": stats})
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
                     "grade": "Pass" if result.get("passed") else "Fail",
                     "stats": ""})
    return rows


def dast_rows(path: Path) -> list[dict[str, str]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    return [
        {
            "group": "DAST",
            "module": "DAST",
            "test": str(item.get("name", item.get("id", "probe"))),
            "grade": grade(item.get("grade")),
            "stats": stats_of(item),
        }
        for item in document.get("results", [])
    ]



# Rows the net suites emit to gate a connection, not to assert the test result:
# every name here appears as `if (!check("...")) return;` in tests/net/*/src,
# i.e. a failed guard aborts the test and the real assertion is emitted later.
# They are hidden from the table while they pass so the row that carries the
# measurements is the one that represents the test; a failing guard is still
# shown, and a guard that is the last row of its suite is kept (nothing
# followed it, so it is that suite's result).
NET_GUARD_ROWS = {
    "acd_add", "altcp_tls_create_config_psk_client",
    "altcp_tls_create_config_psk_server", "arp entry for gateway",
    "bulk connect", "create_ex rx_ring_max 1024", "events create",
    "half-close connect", "hold connect", "igmp join",
    "ipv6 link-local preferred", "keyupdate session", "loopback listen",
    "loopback perf listen", "pbuf_alloc pool chain", "raw tcp download connect",
    "raw_new ICMP", "server listen", "sntp time set", "tcp download connect",
    "tcp upload connect", "tls bulk session", "tls upload session",
    "udp blast bind", "udp connect", "udp_new + bind",
    "ws throughput session",
    # Generated by perf's rtt helper ("%s rtt session"), so not greppable above.
    "tcp rtt session", "udp rtt session", "ws rtt session",
}


def drop_net_guards(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    """Hide passing connection-gate rows that another row of the same suite
    follows, so one row per test carries its stats."""
    kept: list[dict[str, str]] = []
    last_in_suite = {}
    for row in rows:
        if str(row.get("group", "")) == "NETTEST":
            suite = str(row["test"]).split(" - ", 1)[0]
            last_in_suite[suite] = row
    for row in rows:
        if (str(row.get("group", "")) == "NETTEST"
                and grade(row.get("grade")) == "Pass"
                and str(row["test"]).split(" - ", 1)[-1] in NET_GUARD_ROWS
                and last_in_suite.get(str(row["test"]).split(" - ", 1)[0]) is not row):
            continue
        kept.append(row)
    return kept

def render(input_dir: Path, output: Path, fallbacks: list[str]) -> None:
    rows: list[dict[str, str]] = []
    nested: list[tuple[str, dict]] = []
    present_categories: set[str] = set()

    def result_category(path: Path, module: str) -> str:
        name = path.name
        if name == "results-unit.json":
            return "UNIT"
        if name == "results-net.json":
            return "NETTEST"
        if name == "results-units.json":
            return "ACVP"
        if name == "results-fuzz.json":
            return "FUZZ"
        return module.upper()

    for path in sorted(input_dir.rglob("*.json")) if input_dir.exists() else []:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(value, list):
            for item in value:
                if not isinstance(item, dict):
                    continue
                if {"module", "status", "units"} <= item.keys() and isinstance(item["units"], list):
                    category = result_category(path, str(item["module"]))
                    nested.append((category, item))
                    present_categories.add(category)
                elif {"module", "test", "grade"} <= item.keys():
                    rows.append(item)

    present = {(str(row["module"]), str(row["test"])) for row in rows}
    present_groups = {str(row.get("group", row["module"])) for row in rows} | present_categories
    grouped_fallbacks = {"UNIT", "ACVP", "NETTEST", "DAST", "HOST", "FUZZ"}
    for fallback in fallbacks:
        module, test, result = fallback.split("|", 2)
        group_present = module in grouped_fallbacks and module in present_groups
        if not group_present and (module, test) not in present:
            rows.append({"group": module, "module": module, "test": test,
                         "grade": grade(result)})

    merged: dict[tuple[str, str, str], dict[str, str]] = {}
    for row in drop_net_guards(rows):
        group = str(row.get("group", row["module"]))
        key = (group, str(row["module"]), str(row["test"]))
        stats = stats_of(row)
        if key not in merged:
            merged[key] = {"group": group,
                           "module": key[1], "test": key[2],
                           "grade": grade(row["grade"]), "stats": stats}
        else:
            severity = {"Skipped": 0, "Pass": 1, "Fail": 2}
            new_grade = grade(row["grade"])
            if severity[new_grade] > severity[merged[key]["grade"]]:
                merged[key]["grade"] = new_grade
            parts = [p for p in (merged[key]["stats"], stats) if p]
            seen: set[str] = set()
            merged[key]["stats"] = "; ".join(
                item for item in "; ".join(parts).split("; ")
                if item and not (item in seen or seen.add(item))
            )
    normalized = list(merged.values())
    group_rank = {name: i for i, name in enumerate(
        ["PREREQUISITE", "UNIT", "HOST", "NETTEST", "DAST", "ACVP", "RFC", "SAST", "FUZZ"])}
    ordered = sorted(normalized,
                     key=lambda row: (group_rank.get(str(row.get("group", "")).upper(), 99),
                                      str(row.get("group", "")).casefold(),
                                      row["module"].casefold(),
                                      row["test"].casefold()))

    def md(value: str) -> str:
        return value.replace("|", "\\|").replace("\n", " ")

    # GitHub step summaries sanitise inline styles, so a row cannot be shaded;
    # an icon per grade plus an alert above the table is the readable
    # equivalent (alerts render as coloured callouts).
    ICONS = {"Pass": "\u2705", "Fail": "\u274c", "Skipped": "\u23ed\ufe0f"}

    def grade_cell(value: str) -> str:
        return f"{ICONS.get(value, '')} {value}".strip()

    # Nested runner JSON is authoritative and retains the real
    # module -> unit -> test hierarchy. Flat rows remain supported for jobs
    # such as HOST/RFC/SAST that do not yet emit the shared nested schema.
    hierarchy: dict[str, dict[str, list[dict[str, str]]]] = {}
    module_categories: dict[str, str] = {}
    for category, result in nested:
        module = str(result["module"]).upper()
        module_categories[module] = category
        module_units = hierarchy.setdefault(module, {})
        for index, unit_result in enumerate(result["units"], 1):
            if not isinstance(unit_result, dict):
                continue
            unit = str(unit_result.get("unit", f"unit {index}"))
            tests = unit_result.get("tests", [])
            if not isinstance(tests, list) or not tests:
                tests = [{
                    "test": "Result",
                    "description": str(unit_result.get("description", "")),
                    "status": unit_result.get("status", "fail"),
                }]
            destination = module_units.setdefault(unit, [])
            for test_index, test_result in enumerate(tests, 1):
                if not isinstance(test_result, dict):
                    continue
                destination.append({
                    "test": str(test_result.get("test", f"test {test_index}")),
                    "description": str(test_result.get("description", "")),
                    "grade": grade(test_result.get("status")),
                    "stats": stats_of(test_result),
                })

    # Reconstruct the same shape for legacy flat rows.
    for row in ordered:
        module = str(row.get("group", "")).strip() or str(row["module"])
        module_categories.setdefault(module, module.upper())
        source_unit = str(row["module"])
        test = str(row["test"])
        if module.upper() == "NETTEST" and " - " in test:
            unit, test = test.split(" - ", 1)
        elif source_unit.casefold() != module.casefold():
            unit = source_unit
        else:
            # Single-row modules (fuzz target, SAST tool, prerequisite, etc.)
            # use the row itself as a one-test unit.
            unit, test = test, "Result"
        hierarchy.setdefault(module, {}).setdefault(unit, []).append({
            "test": test, "description": "",
            "grade": row["grade"], "stats": row["stats"],
        })

    category_rank = {name: i for i, name in enumerate(
        ["PREREQUISITE", "UNIT", "HOST", "NETTEST", "DAST", "ACVP", "RFC", "SAST", "FUZZ"])}
    hierarchy = dict(sorted(
        hierarchy.items(),
        key=lambda item: (category_rank.get(module_categories[item[0]], 99),
                          item[0].casefold()),
    ))

    def aggregate(tests: list[dict[str, str]]) -> str:
        grades = {test["grade"] for test in tests}
        if "Fail" in grades:
            return "Fail"
        if "Pass" in grades:
            return "Pass"
        return "Skipped"

    module_counts: dict[str, dict[str, int]] = {}
    unit_grades: dict[str, dict[str, str]] = {}
    for module, units in hierarchy.items():
        unit_grades[module] = {unit: aggregate(tests) for unit, tests in units.items()}
        module_counts[module] = {
            name: sum(value == name for value in unit_grades[module].values())
            for name in ("Pass", "Fail", "Skipped")
        }

    failures = [
        (module, unit, test)
        for module, units in hierarchy.items()
        for unit, tests in units.items()
        for test in tests if test["grade"] == "Fail"
    ]
    total_units = sum(len(units) for units in hierarchy.values())
    lines = ["## Test results", "",
             f"**{len(hierarchy)} modules, {total_units} units, "
             f"{sum(len(tests) for units in hierarchy.values() for tests in units.values())} tests** — "
             f"{len(failures)} failing.", ""]
    if failures:
        lines += ["> [!WARNING]",
                  f"> {len(failures)} test failure"
                  f"{'s' if len(failures) != 1 else ''}; expand the affected module below.", ""]

    GROUP_STYLE = {
        "PREREQUISITE": "\u26aa", "UNIT": "\U0001f7e9", "HOST": "\U0001f7e6",
        "NETTEST": "\U0001f7e8", "DAST": "\U0001f7e7", "ACVP": "\U0001f7ea",
        "RFC": "\U0001f7e5", "SAST": "\U0001f7e5", "FUZZ": "\u26ab",
    }
    lines += ["| Module | # Units | # Pass | # Fail | # Skip |",
              "|---|---:|---:|---:|---:|"]
    for module, units in hierarchy.items():
        counts = module_counts[module]
        icon = GROUP_STYLE.get(module_categories[module], "")
        lines.append(
            f"| {md(f'{icon} {module}'.strip())} | {len(units)} | "
            f"{counts['Pass']} | {counts['Fail']} | {counts['Skipped']} |"
        )

    for module, units in hierarchy.items():
        module_failures = [(unit, test) for mod, unit, test in failures if mod == module]
        lines += ["", "<details>",
                  f"<summary>{html.escape(module)} Units</summary>", ""]
        if module_failures:
            lines += ["#### Failures", ""]
            lines.extend(
                f"- **{md(unit)}** — {md(test['test'])}"
                + (f": {md(test['description'])}" if test["description"] and
                   test["description"] != test["test"] else "")
                + (f" ({md(test['stats'])})" if test["stats"] else "")
                for unit, test in module_failures
            )
            lines.append("")

        lines += ["| Unit | # Tests | # Pass | # Fail | # Skip |",
                  "|---|---:|---:|---:|---:|"]
        for unit, tests in units.items():
            counts = {name: sum(test["grade"] == name for test in tests)
                      for name in ("Pass", "Fail", "Skipped")}
            lines.append(
                f"| {md(unit)} | {len(tests)} | {counts['Pass']} | "
                f"{counts['Fail']} | {counts['Skipped']} |"
            )

        for unit, tests in units.items():
            lines += ["", "<details>",
                      f"<summary>{html.escape(unit)} Tests — "
                      f"{grade_cell(unit_grades[module][unit])}</summary>", "",
                      "| Test | Grade | Description | Stats |", "|---|---|---|---|"]
            lines.extend(
                f"| {md(test['test'])} | {grade_cell(test['grade'])} | "
                f"{md(test['description'])} | {md(test['stats'])} |" for test in tests
            )
            lines += ["", "</details>"]
        lines += ["", "</details>"]
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    unit = sub.add_parser("unit")
    unit.add_argument("--results", type=Path, required=True)
    unit.add_argument("--repo", type=Path, default=Path("."))
    unit.add_argument("--output", type=Path, required=True)
    unit.add_argument("--stat", action="append", default=[],
                      help="suite-level measurement applied to every row")

    acvp = sub.add_parser("acvp")
    acvp.add_argument("--results", type=Path, required=True)
    acvp.add_argument("--output", type=Path, required=True)
    acvp.add_argument("--stat", action="append", default=[],
                      help="suite-level measurement applied to every row")

    dast = sub.add_parser("dast")
    dast.add_argument("--results", type=Path, required=True)
    dast.add_argument("--output", type=Path, required=True)
    dast.add_argument("--stat", action="append", default=[])

    row = sub.add_parser("row")
    row.add_argument("--module", required=True)
    row.add_argument("--test", required=True)
    row.add_argument("--grade", required=True)
    row.add_argument("--stat", action="append", default=[],
                     help="measurement for the Stats column, e.g. '1234 ms'")
    row.add_argument("--output", type=Path, required=True)

    table = sub.add_parser("render")
    table.add_argument("--input", type=Path, required=True)
    table.add_argument("--output", type=Path, required=True)
    table.add_argument("--fallback", action="append", default=[])

    args = parser.parse_args()

    def with_stats(rows: list[dict[str, str]]) -> list[dict[str, str]]:
        extra = "; ".join(item for item in getattr(args, "stat", []) if item.strip())
        if extra:
            for row in rows:
                row["stats"] = "; ".join(p for p in (row.get("stats", ""), extra) if p)
        return rows

    if args.command == "unit":
        write_rows(args.output, with_stats(unit_rows(args.results, args.repo)))
    elif args.command == "acvp":
        write_rows(args.output, with_stats(acvp_rows(args.results)))
    elif args.command == "dast":
        write_rows(args.output, with_stats(dast_rows(args.results)))
    elif args.command == "row":
        write_rows(args.output, [{"group": args.module, "module": args.module,
                                  "test": args.test,
                                  "grade": grade(args.grade),
                                  "stats": "; ".join(args.stat)}])
    else:
        render(args.input, args.output, args.fallback)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Normalize CI test outputs and render one table of grades and stats.

Every suite reports whatever it can measure — milliseconds, heap bytes, or a
preformatted string — and it all lands in one Stats cell. Net suites emit
connection-gate rows as well as the assertion rows; passing gates are hidden
so the row that carries the measurements represents the test.
"""

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
            rows.append({"group": module, "module": module, "test": test,
                         "grade": grade(result)})

    merged: dict[tuple[str, str], dict[str, str]] = {}
    for row in drop_net_guards(rows):
        key = (str(row["module"]), str(row["test"]))
        stats = stats_of(row)
        if key not in merged:
            merged[key] = {"group": str(row.get("group", "")),
                           "module": key[0], "test": key[1],
                           "grade": grade(row["grade"]), "stats": stats}
        else:
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

    failures = [row for row in ordered if row["grade"] == "Fail"]

    counts = {name: sum(1 for row in ordered if row["grade"] == name)
              for name in ("Pass", "Fail", "Skipped")}
    lines = ["## Test results", "",
             f"**{counts['Pass']} passed, {counts['Fail']} failed, "
             f"{counts['Skipped']} skipped** across {len(ordered)} rows.", ""]
    if failures:
        lines += ["> [!WARNING]",
                  f"> {len(failures)} failing: "
                  + ", ".join(f"{row['module']} / {row['test']}" for row in failures[:10])
                  + (f" (+{len(failures) - 10} more)" if len(failures) > 10 else ""),
                  ""]
    # Presentation: a short summary table at the top (one row per module,
    # linked to its section) and, underneath, one collapsible table per group.
    # GitHub sanitises inline styles so rows cannot be tinted, and a table row
    # cannot contain <details>; a summary table plus anchored sections is the
    # closest reachable form, and browsers open a closed <details> when you
    # navigate to an anchor inside it.
    GROUP_STYLE = {
        "PREREQUISITE": "\u26aa", "UNIT": "\U0001f7e9", "HOST": "\U0001f7e6",
        "NETTEST": "\U0001f7e8", "DAST": "\U0001f7e7", "ACVP": "\U0001f7ea",
        "RFC": "\U0001f7e5", "SAST": "\U0001f7e5", "FUZZ": "\u26ab",
    }
    GROUP_LABEL = {
        "PREREQUISITE": "prerequisites", "UNIT": "unit tests", "HOST": "host tests",
        "NETTEST": "network tests", "DAST": "DAST", "ACVP": "ACVP",
        "RFC": "RFC review", "SAST": "SAST", "FUZZ": "fuzz",
    }
    GROUP_ORDER = ["PREREQUISITE", "UNIT", "HOST", "NETTEST", "DAST", "ACVP",
                   "RFC", "SAST", "FUZZ"]

    def group_of(row: dict) -> str:
        return (str(row.get("group", "")).strip()
                or str(row.get("module", "")).strip() or "OTHER")

    def anchor(group: str) -> str:
        return "grp-" + group.lower().replace(" ", "-").replace("/", "-")

    # Rows grouped for the sections, modules summarised in the summary table.
    sections: dict[str, list[dict]] = {}
    for row in ordered:
        sections.setdefault(group_of(row), []).append(row)
    section_order = sorted(
        sections,
        key=lambda g: (GROUP_ORDER.index(g) if g in GROUP_ORDER else len(GROUP_ORDER),
                       g.casefold()))

    modules: dict[str, dict] = {}
    for row in ordered:
        key = str(row["module"])
        entry = modules.setdefault(key, {"group": group_of(row), "tests": 0,
                                         "Pass": 0, "Fail": 0, "Skipped": 0})
        entry["tests"] += 1
        entry[grade(row["grade"])] += 1
    module_order = sorted(
        modules,
        key=lambda name: (GROUP_ORDER.index(modules[name]["group"])
                          if modules[name]["group"] in GROUP_ORDER else len(GROUP_ORDER),
                          modules[name]["group"].casefold(), name.casefold()))

    lines += ["| Module | Tests | Pass | Fail | Skip |", "|---|---|---|---|---|"]
    for name in module_order:
        entry = modules[name]
        icon = GROUP_STYLE.get(entry["group"].upper(), "")
        cell = f"[{icon} {name}](#{anchor(entry['group'])})".strip()
        lines.append(f"| {md(cell)} | {entry['tests']} | {entry['Pass']} | "
                     f"{entry['Fail']} | {entry['Skipped']} |")

    for group in section_order:
        rows = sections[group]
        counts_g = {name: sum(1 for row in rows if grade(row["grade"]) == name)
                    for name in ("Pass", "Fail", "Skipped")}
        icon = GROUP_STYLE.get(group.upper(), "")
        label = GROUP_LABEL.get(group.upper(), group)
        headline = (f"{icon} {label} — {counts_g['Pass']} pass, "
                    f"{counts_g['Fail']} fail, {counts_g['Skipped']} skip").strip()
        # A section with a failure is never hidden behind a click.
        open_attr = " open" if counts_g["Fail"] else ""
        lines += ["", f"<details{open_attr}>", f"<summary>{headline}</summary>", "",
                  f'<a id="{anchor(group)}" name="{anchor(group)}"></a>', "",
                  f"### {icon} {label}".strip(), "",
                  "| Module | Test | Grade | Stats |", "|---|---|---|---|"]
        lines.extend(
            f"| {md(row['module'])} | {md(row['test'])} | "
            f"{grade_cell(row['grade'])} | {md(row['stats'])} |"
            for row in rows)
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

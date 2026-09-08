#!/usr/bin/env python3
"""Render tests/dast.json to a Markdown summary and gate on failures.

Used by .github/workflows/dast.yml (writes to $GITHUB_STEP_SUMMARY) and
runnable locally:

    python3 build-tools/dast/dast_report.py            # print summary, exit nonzero on fail
    python3 build-tools/dast/dast_report.py --summary $GITHUB_STEP_SUMMARY

Exit code: 0 if no test graded "fail", 1 otherwise (or if the report is
missing/unreadable).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
REPORT = REPO_ROOT / "tests" / "dast.json"

GRADE_ICON = {"ok": "✅", "fail": "❌", "skip": "⏭️"}


def render(doc: dict) -> str:
    s = doc.get("summary", {})
    out: list[str] = []
    out.append("## lwIP-CE DAST Report")
    out.append("")
    out.append(f"- **Target:** `{doc.get('target_ip', '?')}`")
    out.append(f"- **Generated:** {doc.get('generated', '?')}")
    out.append(
        f"- **Result:** {s.get('ok', 0)} ok / "
        f"{s.get('fail', 0)} fail / {s.get('skip', 0)} skip "
        f"({s.get('total', 0)} total)"
    )
    out.append("")
    out.append("| | Test | Intent | Expect | Response | Grade |")
    out.append("|---|---|---|---|---|---|")
    for r in doc.get("results", []):
        icon = GRADE_ICON.get(r.get("grade", ""), "❓")
        note = f" <br>📝 {r['notes']}" if r.get("notes") else ""
        ovr = " *(override)*" if r.get("grade_override") else ""
        out.append(
            f"| {icon} | **{md(r.get('name', r.get('id', '?')))}**"
            f" <br>`{md(r.get('id', ''))}`{note} "
            f"| {md(r.get('intent', ''))} "
            f"| `{md(r.get('expect', ''))}` "
            f"| `{md(r.get('response', ''))}` "
            f"| {md(r.get('grade', ''))}{ovr} |"
        )
    out.append("")
    fails = [r for r in doc.get("results", []) if r.get("grade") == "fail"]
    if fails:
        out.append("### ❌ Failures")
        out.append("")
        for r in fails:
            out.append(
                f"- **{md(r.get('name', r.get('id')))}** "
                f"(`{md(r.get('id'))}`): reported `{md(r.get('response'))}`, "
                f"expected one of the test's ok responses."
            )
        out.append("")
    return "\n".join(out)


def md(s) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ")


def main() -> int:
    ap = argparse.ArgumentParser(description="Render + gate lwIP-CE DAST report")
    ap.add_argument("--report", default=str(REPORT),
                    help="path to dast.json (default tests/dast.json)")
    ap.add_argument("--summary",
                    help="append the rendered Markdown to this file too "
                         "(e.g. $GITHUB_STEP_SUMMARY)")
    args = ap.parse_args()

    path = Path(args.report)
    if not path.is_file():
        msg = (f"## lwIP-CE DAST Report\n\n"
               f"❌ **{path} not found.** Run `build-tools/dast/lwip-dast.sh "
               f"--ip <calc>` against a live calc to produce it.\n")
        emit(msg, args.summary)
        print(f"ERROR: {path} not found", file=sys.stderr)
        return 1

    try:
        doc = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        msg = f"## lwIP-CE DAST Report\n\n❌ **Could not parse {path}:** {exc}\n"
        emit(msg, args.summary)
        return 1

    rendered = render(doc)
    emit(rendered, args.summary)

    fails = sum(1 for r in doc.get("results", []) if r.get("grade") == "fail")
    if fails:
        print(f"DAST: {fails} test(s) failed", file=sys.stderr)
        return 1
    print("DAST: all tests ok")
    return 0


def emit(text: str, summary_path: str | None) -> None:
    print(text)
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write(text + "\n")


if __name__ == "__main__":
    sys.exit(main())

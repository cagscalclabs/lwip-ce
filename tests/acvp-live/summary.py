#!/usr/bin/env python3
"""Render the public summary for a live NIST ACVP session."""

from __future__ import annotations

import argparse
import json
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


def algorithm_label(vector: dict) -> str:
    label = vector["algorithm"]
    mode = vector.get("mode")
    if isinstance(mode, str) and mode:
        label += f" {mode}"
    return label


def grade_label(grading: object | None) -> str:
    if isinstance(grading, dict):
        if grading.get("passed") is True:
            return "✅ Pass"
        if grading.get("passed") is False:
            return "❌ Fail"
    return "⚪ Not graded"


def build_summary(vectors: object | None, grading: object | None,
                  server: str) -> str:
    prompts = vector_sets(vectors)
    verdict = grade_label(grading)
    session_id = (
        grading.get("test_session_id")
        if isinstance(grading, dict) else None
    )

    metadata = [f"**NIST ACVP server:** `{server}`"]
    if isinstance(session_id, int):
        metadata.append(f"**Test session:** `{session_id}`")

    lines = [
        "## NIST ACVP Live Results",
        "",
        " · ".join(metadata),
        "",
        "| NIST vsID | Algorithm(s) covered | Result |",
        "|---:|---|:---:|",
    ]
    if prompts:
        lines.extend(
            f"| {vector['vsId']} | {algorithm_label(vector)} | {verdict} |"
            for vector in prompts
        )
    else:
        lines.append(f"| — | No vector sets available | {verdict} |")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vectors", type=Path, required=True)
    parser.add_argument("--grading", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--server", default="demo.acvts.nist.gov")
    args = parser.parse_args()

    summary = build_summary(
        read_json(args.vectors), read_json(args.grading), args.server,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(summary, encoding="utf-8")


if __name__ == "__main__":
    main()

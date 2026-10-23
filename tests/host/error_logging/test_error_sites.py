#!/usr/bin/env python3
"""Reject silent fatal aborts in project-owned transport integration code.

Low-level lwIP uses abort as both an error operation and an ordinary ownership
cleanup primitive.  Project transport adapters must therefore either use their
logging abort macro or explicitly mark a raw abort as cleanup/caller-requested.
This keeps newly-added protocol failure sites from degenerating into a lone
downstream socket error with no originating traceback entry.
"""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[3]
FILES = (
    ROOT / "src/apps/altcp_tls/altcp_tls_ce.c",
    ROOT / "src/apps/altcp_ws/altcp_ws.c",
    ROOT / "src/lwIP.c",
)
RAW_ABORT = re.compile(r"\b(?:altcp|tcp)_abort\s*\(")
ERROR_MACRO_DEFINE = re.compile(r"^\s*#define\s+\w*ERROR_ABORT")
FATAL_RETURN = re.compile(r"\breturn\s+ERR_ABRT\s*;")


def audit_file(path: Path) -> list[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    failures: list[str] = []
    in_error_macro = False

    for index, line in enumerate(lines):
        stripped = line.lstrip()
        if stripped.startswith(("/*", "*", "//")):
            continue
        if ERROR_MACRO_DEFINE.search(line):
            in_error_macro = line.rstrip().endswith("\\")
            continue
        if in_error_macro:
            if not line.rstrip().endswith("\\"):
                in_error_macro = False
            continue
        if not RAW_ABORT.search(line):
            if FATAL_RETURN.search(line):
                context = "\n".join(lines[max(0, index - 8):index + 1])
                reported = any(token in context for token in (
                    "ERROR_ABORT(", "ERROR_ABORT_CODE(", "ERROR_AUDIT:",
                    "ERROR_CODE(", "ERROR();", "helper already aborted",
                ))
                if not reported:
                    failures.append(
                        f"{path.relative_to(ROOT)}:{index + 1}: ERR_ABRT "
                        "return lacks a local error emission or propagation annotation"
                    )
            continue

        context = "\n".join(lines[max(0, index - 2):index + 1])
        reported = any(token in context for token in (
            "ERROR_AUDIT:", "ERROR_CODE(", "ERROR();",
        ))
        if not reported:
            failures.append(
                f"{path.relative_to(ROOT)}:{index + 1}: raw abort lacks "
                "a logging abort macro or ERROR_AUDIT cleanup annotation"
            )
    return failures


failures = [failure for path in FILES for failure in audit_file(path)]
if failures:
    raise AssertionError("\n".join(failures))

print("error-site audit passed")

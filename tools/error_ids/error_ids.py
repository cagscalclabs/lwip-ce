#!/usr/bin/env python3
"""Maintain the eXXXX error-ID registry in src/include/lwip/logging.h.

Every ERROR/WARN-class call site carries a stable ID as its first argument:

    ERROR(LWIP_E0001);
    ERROR_CODE(LWIP_E0002, status);
    LWIP_TRACE_RETURN(LWIP_E0003, tcp_write(...));

and each ID is one enumerator in logging.h with a trailing description:

    LWIP_E0002 = 0x0002, // ServerHello too short. Trigger: `len < 4`

The log writer prints the ID as eXXXX (lowercase hex) on TBK and EVT: ERR:
lines, and the cagscalclabs bug reporter fetches logging.h at the reported
revision to explain each ID. IDs are therefore part of the on-disk log format:

  * append-only: an ID is never renumbered, reused, or deleted;
  * 1:1: each ID names exactly one call site;
  * a call site that is removed keeps its enumerator, marked "RETIRED".

Commands
  assign   Give every call site that lacks an ID the next free ID, append its
           enumerator with a drafted "[auto]" description, and rewrite the
           site in place. Replace "[auto]" drafts with a hand-written
           description when convenient.
  check    Verify the invariants above (used by CI). With --base REF, also
           verify that no ID present at REF was removed or renumbered.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "src/include/lwip/logging.h"
SCAN_DIRS = (ROOT / "src",)
SKIP_FILES = {REGISTRY}

BEGIN_MARK = "/* error-ids:begin"
END_MARK = "/* error-ids:end */"

# Macros whose first argument is an error ID. Wrapper macros defined in .c
# files (and forwarding the ID to ERROR/ERROR_CODE) are listed too.
SITE_MACROS = {
    "ERROR": "ERR",
    "ERROR_CODE": "ERR",
    "ERROR_INFO": "ERR",
    "LWIP_TRACE_RETURN": "ERR",
    "WARN": "WARN",
    "WARN_CODE": "WARN",
    "ALTCP_WS_ERROR_ABORT": "ERR",
    "ALTCP_WS_ERROR_ABORT_CODE": "ERR",
    "ALTCP_TLS_CE_ERROR_ABORT": "ERR",
    "ALTCP_TLS_CE_ERROR_ABORT_CODE": "ERR",
}

ID_RE = re.compile(r"^LWIP_E([0-9A-F]{4})$")
ENTRY_RE = re.compile(
    r"^\s*LWIP_E([0-9A-F]{4})\s*=\s*0x([0-9A-Fa-f]{4})\s*,\s*//\s*(.*?)\s*$"
)
SITE_RE = re.compile(r"\b(" + "|".join(sorted(SITE_MACROS, key=len, reverse=True)) + r")\s*\(")
MAX_ID = 0xFFFF


# ---------------------------------------------------------------------------
# Minimal C lexer: classifies each character as code / comment / literal /
# preprocessor so that sites are only found in real code.
# ---------------------------------------------------------------------------

CODE, COMMENT, LITERAL, PREPROC = 0, 1, 2, 3


@dataclass
class Comment:
    start: int
    end: int
    text: str


def classify(src: str) -> tuple[list[int], list[Comment]]:
    kind = [CODE] * len(src)
    comments: list[Comment] = []
    i, n = 0, len(src)
    line_start = True
    while i < n:
        c = src[i]
        if line_start and c in " \t":
            i += 1
            continue
        if line_start and c == "#":
            # Preprocessor directive, including backslash continuations.
            j = i
            while j < n:
                if src[j] == "\n" and src[j - 1] != "\\":
                    break
                j += 1
            for k in range(i, j):
                kind[k] = PREPROC
            i = j
            continue
        line_start = c == "\n"
        if src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                kind[k] = COMMENT
            comments.append(Comment(i, j, src[i + 2:j]))
            i = j
            continue
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                kind[k] = COMMENT
            comments.append(Comment(i, j, src[i + 2:j - 2]))
            i = j
            continue
        if c in "\"'":
            j = i + 1
            while j < n and src[j] != c:
                j += 2 if src[j] == "\\" else 1
            j = min(j + 1, n)
            for k in range(i, j):
                kind[k] = LITERAL
            i = j
            continue
        i += 1
    return kind, comments


@dataclass
class Site:
    path: Path
    macro: str
    name_pos: int      # index of the macro name
    open_pos: int      # index of "("
    close_pos: int     # index of matching ")"
    args: list[str]    # top-level arguments, stripped

    @property
    def eid(self) -> int | None:
        if self.args:
            m = ID_RE.match(self.args[0])
            if m:
                return int(m.group(1), 16)
        return None

    def line(self, src: str) -> int:
        return src.count("\n", 0, self.name_pos) + 1


def find_sites(path: Path, src: str, kind: list[int]) -> list[Site]:
    sites = []
    for m in SITE_RE.finditer(src):
        start = m.start(1)
        if kind[start] != CODE:
            continue
        open_pos = m.end() - 1
        depth, j, arg_start, args = 0, open_pos, open_pos + 1, []
        while j < len(src):
            if kind[j] == CODE:
                ch = src[j]
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        break
                elif ch == "," and depth == 1:
                    args.append(src[arg_start:j])
                    arg_start = j + 1
            j += 1
        last = src[arg_start:j]
        if args or last.strip():
            args.append(last)
        sites.append(Site(path, m.group(1), start, open_pos, j,
                          [" ".join(a.split()) for a in args]))
    return sites


def source_files() -> list[Path]:
    files = []
    for d in SCAN_DIRS:
        for p in sorted(d.rglob("*")):
            if p.suffix in (".c", ".h") and p.is_file() and p not in SKIP_FILES:
                files.append(p)
    return files


# ---------------------------------------------------------------------------
# Description drafting
# ---------------------------------------------------------------------------

KEYWORDS = {"if", "while", "for", "switch", "return", "sizeof", "__attribute__",
            "defined", "do", "else"}


def code_only(src: str, kind: list[int]) -> str:
    """Source with comments/literals/preprocessor blanked (offsets preserved)."""
    return "".join(ch if k == CODE or ch == "\n" else " " for ch, k in zip(src, kind))


def matching_open(code: str, close: int) -> int:
    depth = 0
    for j in range(close, -1, -1):
        if code[j] == ")":
            depth += 1
        elif code[j] == "(":
            depth -= 1
            if depth == 0:
                return j
    return -1


def enclosing_function(code: str, pos: int) -> str:
    depth, body_open = 0, -1
    for j in range(pos - 1, -1, -1):
        if code[j] == "}":
            depth += 1
        elif code[j] == "{":
            if depth == 0:
                body_open = j
            else:
                depth -= 1
    # body_open is now the outermost "{" enclosing pos (the function body).
    if body_open < 0:
        return ""
    hdr_start = max(code.rfind(";", 0, body_open), code.rfind("}", 0, body_open)) + 1
    header = code[hdr_start:body_open]
    name, paren = "", 0
    for m in re.finditer(r"(\w+)\s*\(|[()]", header):
        tok = m.group(0)
        if tok == "(":
            paren += 1
        elif tok == ")":
            paren -= 1
        else:
            if paren == 0 and m.group(1) not in KEYWORDS:
                name = m.group(1)
            paren += 1
    return name


def clean_comment(text: str) -> str:
    lines = [re.sub(r"^\s*\*+\s?", "", ln).strip() for ln in text.splitlines()]
    s = " ".join(ln for ln in lines if ln)
    s = re.sub(r"\s+", " ", s).strip(" */")
    s = s.replace("Trigger:", "trigger:").rstrip("\\")
    return s


def first_sentence(s: str, limit: int = 160) -> str:
    m = re.match(r"(.+?[.!?])(\s|$)", s)
    s = m.group(1) if m else s
    if len(s) > limit:
        s = s[:limit - 1].rsplit(" ", 1)[0].rstrip(" ,;:-") + "…"
    return s.rstrip(".")


def innermost_open(code: str, pos: int) -> int:
    """Index of the innermost unmatched "{" before pos, or -1."""
    depth = 0
    for j in range(pos - 1, -1, -1):
        if code[j] == "}":
            depth += 1
        elif code[j] == "{":
            if depth == 0:
                return j
            depth -= 1
    return -1


def comment_directly_above(src: str, comments: list[Comment], pos: int) -> str:
    above = [c for c in comments if c.end <= pos and not src[c.end:pos].strip()]
    return clean_comment(above[-1].text) if above else ""


def case_label(code: str, block_open: int, pos: int) -> str:
    """Nearest "case X:" / "default:" in block_open..pos at the block's own level."""
    label, depth = "", 0
    seg = code[block_open + 1:pos]
    for m in re.finditer(r"[{}]|\b(case\s+[^:;]+?|default)\s*:(?!:)", seg):
        if m.group(0) == "{":
            depth += 1
        elif m.group(0) == "}":
            depth -= 1
        elif depth == 0:
            label = squash(m.group(1), 80)
    return label


def squash(s: str, limit: int = 160) -> str:
    s = " ".join(s.split()).replace("`", "'")
    if len(s) > limit:
        s = s[:limit - 1].rstrip() + "…"
    return s


def draft_description(site: Site, src: str, code: str, comments: list[Comment]) -> str:
    pos = site.name_pos
    func = enclosing_function(code, pos)
    block_open = innermost_open(code, pos)

    # Statement start: last ; { } at the site's own level.
    stmt_start = max(code.rfind(";", 0, pos), code.rfind("{", 0, pos), code.rfind("}", 0, pos)) + 1

    trigger, cond_kw_pos = "", -1

    def cond_before(end: int) -> tuple[str, int]:
        t = code[:end].rstrip()
        if t.endswith(")"):
            o = matching_open(code, len(t) - 1)
            kw = re.search(r"\b(if|while|for|switch)\s*$", code[:o])
            if o > 0 and kw:
                inner = code[o + 1:len(t) - 1]
                label = {"if": "", "while": "while ", "for": "for ", "switch": "switch "}[kw.group(1)]
                return label + squash(inner), kw.start()
        if re.search(r"\belse\s*$", t):
            return "else branch", re.search(r"\belse\s*$", t).start()
        return "", -1

    # Brace-less "if (x) ERROR();"
    trigger, cond_kw_pos = cond_before(pos) if code[stmt_start:pos].strip() else ("", -1)
    if not trigger and block_open >= 0:
        trigger = case_label(code, block_open, pos)
        if not trigger:
            trigger, cond_kw_pos = cond_before(block_open)

    # An if inside a switch case: name the case too ("x != 16 (case FOO)").
    outer_kw_pos = -1
    if cond_kw_pos >= 0:
        parent_open = innermost_open(code, cond_kw_pos)
        if parent_open >= 0:
            case = case_label(code, parent_open, cond_kw_pos)
            if case and trigger and not trigger.startswith("case"):
                trigger += f" ({case})"
            _, outer_kw_pos = cond_before(parent_open)

    # LWIP_TRACE_RETURN(id, call(...)) forwards the callee's error; with a
    # constant (LWIP_TRACE_RETURN(id, ERR_MEM)) it is an ordinary failure.
    traced_call = None
    if site.macro == "LWIP_TRACE_RETURN" and len(site.args) >= 2:
        traced_call = re.match(r"\s*\(?\s*(\w+)\s*\(", site.args[1])
        if traced_call:
            trigger = squash(site.args[1]) + " returned an error"

    # Comment, nearest first: immediately before the site (no statement in
    # between), directly above the controlling if/case statement, then
    # directly above the enclosing switch/if one level out.
    note = ""
    lo = block_open if block_open >= 0 else stmt_start
    inner = [c for c in comments if lo <= c.start and c.end <= pos
             and ";" not in code[c.end:pos] and "}" not in code[c.end:pos]]
    if inner:
        note = clean_comment(inner[-1].text)
    if not note and cond_kw_pos >= 0:
        note = comment_directly_above(src, comments, cond_kw_pos)
    if not note and outer_kw_pos >= 0:
        note = comment_directly_above(src, comments, outer_kw_pos)

    # What happens next: return X / goto L.
    after = code[site.close_pos + 1:site.close_pos + 400]
    nxt = re.match(r"\s*;\s*(return\b[^;]*|goto\s+\w+)", after)
    outcome = ""
    if nxt:
        stmt = " ".join(nxt.group(1).split())
        if stmt.startswith("return"):
            val = stmt[len("return"):].strip()
            outcome = f"returns {val}" if val else "returns"
        else:
            outcome = "aborts (" + stmt + ")"

    where = f"{func}()" if func else site.path.name
    if traced_call:
        what = f"propagates a failure from {traced_call.group(1)}()"
    elif site.macro == "LWIP_TRACE_RETURN" and len(site.args) >= 2 and not note:
        what = f"fails and returns {squash(site.args[1], 60)}"
    elif note:
        what = first_sentence(note)
    else:
        verb = "warns" if SITE_MACROS[site.macro] == "WARN" else "fails"
        what = verb + (f" and {outcome}" if outcome else "")

    desc = f"[auto] {where}: {what}" + ("" if what.endswith("…") else ".")
    if trigger:
        desc += f" Trigger: `{trigger}`"
    return desc


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

@dataclass
class Registry:
    text: str
    begin: int        # index just after the begin-marker line
    end: int          # index of the end marker line start
    entries: dict[int, str]


def load_registry(text: str | None = None) -> Registry:
    text = REGISTRY.read_text(encoding="utf-8") if text is None else text
    b = text.find(BEGIN_MARK)
    e = text.find(END_MARK)
    if b < 0 or e < 0 or e < b:
        sys.exit(f"{REGISTRY.relative_to(ROOT)}: error-id markers not found")
    begin = text.index("\n", b) + 1
    end = text.rfind("\n", 0, e) + 1
    entries: dict[int, str] = {}
    for ln in text[begin:end].splitlines():
        if not ln.strip():
            continue
        m = ENTRY_RE.match(ln)
        if not m:
            sys.exit(f"{REGISTRY.relative_to(ROOT)}: malformed registry line: {ln.strip()}")
        num = int(m.group(1), 16)
        if int(m.group(2), 16) != num:
            sys.exit(f"{REGISTRY.relative_to(ROOT)}: LWIP_E{m.group(1)} has value 0x{m.group(2)}")
        if num in entries:
            sys.exit(f"{REGISTRY.relative_to(ROOT)}: LWIP_E{num:04X} defined twice")
        entries[num] = m.group(3)
    return Registry(text, begin, end, entries)


def entry_line(num: int, desc: str) -> str:
    return f"    LWIP_E{num:04X} = 0x{num:04X}, // {desc}\n"


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def scan() -> list[tuple[Path, str, list[int], list[Comment], list[Site]]]:
    out = []
    for p in source_files():
        src = p.read_text(encoding="utf-8")
        if not SITE_RE.search(src):
            continue
        kind, comments = classify(src)
        sites = find_sites(p, src, kind)
        if sites:
            out.append((p, src, kind, comments, sites))
    return out


def cmd_assign(_args: argparse.Namespace) -> int:
    reg = load_registry()
    next_id = max(reg.entries, default=0) + 1
    new_entries: list[str] = []
    total = 0
    for path, src, kind, comments, sites in scan():
        todo = [s for s in sites if s.eid is None]
        if not todo:
            continue
        code = code_only(src, kind)
        pieces, last = [], 0
        for s in todo:
            if next_id > MAX_ID:
                sys.exit("error-ID space exhausted")
            desc = draft_description(s, src, code, comments)
            new_entries.append(entry_line(next_id, desc))
            pieces.append(src[last:s.open_pos + 1])
            pieces.append(f"LWIP_E{next_id:04X}" + (", " if s.args else ""))
            last = s.open_pos + 1
            next_id += 1
        pieces.append(src[last:])
        path.write_text("".join(pieces), encoding="utf-8")
        total += len(todo)
        print(f"{path.relative_to(ROOT)}: assigned {len(todo)}")
    if new_entries:
        reg = load_registry()  # registry file may also have been rewritten above
        text = reg.text[:reg.end] + "".join(new_entries) + reg.text[reg.end:]
        REGISTRY.write_text(text, encoding="utf-8")
    print(f"assigned {total} new error ID(s)")
    return 0


def cmd_redraft(_args: argparse.Namespace) -> int:
    """Regenerate [auto] descriptions from the current call sites."""
    reg = load_registry()
    fresh: dict[int, str] = {}
    for _path, src, kind, comments, sites in scan():
        code = code_only(src, kind)
        for s in sites:
            if s.eid is not None and reg.entries.get(s.eid, "").startswith("[auto]"):
                fresh[s.eid] = draft_description(s, src, code, comments)
    lines = reg.text[reg.begin:reg.end].splitlines(keepends=True)
    changed = 0
    for i, ln in enumerate(lines):
        m = ENTRY_RE.match(ln)
        if m and int(m.group(1), 16) in fresh:
            num = int(m.group(1), 16)
            new = entry_line(num, fresh[num])
            if new != ln:
                lines[i] = new
                changed += 1
    REGISTRY.write_text(reg.text[:reg.begin] + "".join(lines) + reg.text[reg.end:], encoding="utf-8")
    print(f"redrafted {changed} [auto] description(s)")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    reg = load_registry()
    problems: list[str] = []
    used: dict[int, str] = {}
    for path, src, _kind, _comments, sites in scan():
        for s in sites:
            where = f"{path.relative_to(ROOT)}:{s.line(src)}"
            if s.eid is None:
                problems.append(f"{where}: {s.macro}() has no error ID "
                                "(run tools/error_ids/error_ids.py assign)")
                continue
            if s.eid in used:
                problems.append(f"{where}: LWIP_E{s.eid:04X} already used at {used[s.eid]}")
            else:
                used[s.eid] = where
            if s.eid not in reg.entries:
                problems.append(f"{where}: LWIP_E{s.eid:04X} is not defined in logging.h")

    for num, desc in sorted(reg.entries.items()):
        if num == 0:
            continue
        if not desc:
            problems.append(f"LWIP_E{num:04X}: missing description")
        if num not in used and "RETIRED" not in desc:
            problems.append(f"LWIP_E{num:04X}: defined but unused; mark its description RETIRED")

    if args.base:
        try:
            old = subprocess.run(
                ["git", "-C", str(ROOT), "show", f"{args.base}:{REGISTRY.relative_to(ROOT)}"],
                check=True, capture_output=True, text=True).stdout
        except subprocess.CalledProcessError:
            old = None
            print(f"warning: could not read logging.h at {args.base}; append-only check skipped "
                  "(shallow checkout?)")
        if old and BEGIN_MARK in old:
            for num in load_registry(old).entries:
                if num not in reg.entries:
                    problems.append(f"LWIP_E{num:04X} existed at {args.base} but was removed "
                                    "(IDs are append-only; mark it RETIRED instead)")

    auto = sum(1 for d in reg.entries.values() if d.startswith("[auto]"))
    for p in problems:
        print(p)
    print(f"{len(used)} call sites, {len(reg.entries) - 1} IDs defined, "
          f"{auto} with drafted [auto] descriptions, {len(problems)} problem(s)")
    return 1 if problems else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("assign", help="assign IDs to call sites that lack one")
    sub.add_parser("redraft", help="regenerate [auto] descriptions from current call sites")
    c = sub.add_parser("check", help="verify registry invariants")
    c.add_argument("--base", help="git ref to compare against for append-only check")
    args = ap.parse_args()
    return {"assign": cmd_assign, "redraft": cmd_redraft, "check": cmd_check}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())

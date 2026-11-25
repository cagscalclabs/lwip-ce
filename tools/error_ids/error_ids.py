#!/usr/bin/env python3
"""Maintain the eXXXX error-ID registry in src/include/lwip/logging.h.

Every ERROR/WARN-class call site carries a stable ID as its first argument:

    ERROR(LWIP_E0001);
    ERROR_CODE(LWIP_E0002, status);
    LWIP_TRACE_RETURN(LWIP_E0003, tcp_write(...));

and each ID is one enumerator in logging.h with a trailing description:

    LWIP_E0002 = 0x0002, // ServerHello too short. Trigger: `len < 4` @peer:60 @tls:60

The trailing @category:NN tags are evidence weights: how strongly this error,
on its own, points at that category of bug (NN = confidence %, 1-100). The
bug reporter combines them per category across a log. @propagate marks a site
that only forwards a callee's failure. Categories are listed between the
error-categories:begin/end markers in logging.h.

The log writer prints the ID as eXXXX (lowercase hex) on TBK and EVT: ERR:
lines, and the cagscalclabs bug reporter fetches logging.h at the reported
revision to explain each ID. IDs are therefore part of the on-disk log format:

  * append-only: an ID is never renumbered, reused, or deleted;
  * 1:1: each ID names exactly one call site;
  * a call site that is removed keeps its enumerator, marked "RETIRED".

Commands
  assign   Give every call site that lacks an ID the next free ID, append its
           enumerator with a drafted "[auto]" description and evidence tags,
           and rewrite the site in place. Replace "[auto]" drafts with a
           hand-written description when convenient.
  redraft  Regenerate the description and tags of every "[auto]" entry.
  tag      Draft evidence tags for entries that have none (--all: redraft the
           tags of every entry, keeping descriptions).
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
TAGS_RE = re.compile(r"((?:\s+@[A-Za-z_]\w*(?::\S*)?)+)\s*$")
TAG_RE = re.compile(r"@([A-Za-z_]\w*)(?::(\S*))?")
CAT_BEGIN = "error-categories:begin"
CAT_END = "error-categories:end"
FLAGS = {"propagate"}
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
# Evidence-tag drafting
#
# Heuristic first pass, meant to be reviewed: the file says which subsystem an
# error belongs to, and the trigger refines it (an allocation that came back
# NULL is a memory problem wherever it happens; a NULL parameter is caller
# misuse; a bounds check while parsing received bytes is a misbehaving peer).
# ---------------------------------------------------------------------------

# (path substring, category, confidence); first match wins.
FILE_CATEGORY = [
    ("tls/core/x509.c", "cert", 70),
    ("tls/core/truststore.c", "cert", 70),
    ("tls/core/ocsp.c", "cert", 65),
    ("altcp_tls/altcp_tls_ocsp.c", "cert", 65),
    ("tls/core/primitives/", "crypto", 60),
    ("tls/core/hash.c", "crypto", 60),
    ("tls/core/hmac.c", "crypto", 60),
    ("tls/core/hkdf.c", "crypto", 60),
    ("tls/core/rsa.c", "crypto", 60),
    ("tls/core/random.c", "crypto", 70),
    ("tls/core/key.c", "crypto", 55),
    ("tls/core/passwords.c", "crypto", 55),
    ("tls/core/", "tls", 60),
    ("apps/altcp_tls/", "tls", 55),
    ("apps/altcp_ws/", "ws", 60),
    ("core/dns.c", "dns", 70),
    ("core/udp.c", "transport", 50),
    ("core/ipv4/", "wire", 50),
    ("netif/", "wire", 50),
    ("drivers/usb_ethernet.c", "usb", 70),
    ("drivers/mem.c", "memory", 70),
    ("core/app_config.c", "config", 60),
    ("core/log_file.c", "storage", 60),
    ("core/dispatch.c", "logic", 45),
    ("lwIP.c", "transport", 50),
]

ALLOC_CALL = re.compile(r"(alloc|malloc|calloc|realloc|_new\b|^new_|_create|create_|_dup\b|strdup|charge|_grow\b|pbuf_alloc)", re.I)
ALLOC_TEXT = re.compile(r"\bERR_MEM\b|out of memory|\bOOM\b|could not allocate|alloc(ation)? fail|\bno memory\b|\bexhaust", re.I)
PEER_FUNC = re.compile(r"(recv|parse|decode|consume|feed|_input|process|_rx|handle_rx|verify|reasm|digit_pair|time_to_unix|import)", re.I)
PEER_TRIGGER = re.compile(r"(offset|_end\b|\blen\b|_len\b|data\[|\.tag\b|asn1|tls_asn1|!=|>|<|\bcase\b|default|\btag\b)")
STATE_TRIGGER = re.compile(r"->state\b|\bstate\s*!=|unexpected|\bflags\b.*&")
UNUSED_KINDS = {"else branch"}


def function_params(code: str, pos: int) -> set[str]:
    """Parameter names of the function enclosing pos (best effort)."""
    depth, body_open = 0, -1
    for j in range(pos - 1, -1, -1):
        if code[j] == "}":
            depth += 1
        elif code[j] == "{":
            if depth == 0:
                body_open = j
            else:
                depth -= 1
    if body_open < 0:
        return set()
    hdr = code[:body_open].rstrip()
    if not hdr.endswith(")"):
        return set()
    o = matching_open(code, len(hdr) - 1)
    names = set()
    for part in code[o + 1:len(hdr) - 1].split(","):
        m = re.search(r"(\w+)\s*(\[[^\]]*\])?\s*$", part.strip())
        if m and m.group(1) != "void":
            names.add(m.group(1))
    return names


def trigger_terms(trigger: str) -> list[str]:
    t = re.sub(r"\s*\((case [^)]*|default)\)\s*$", "", trigger.strip())
    return [x.strip() for x in re.split(r"\|\|", t) if x.strip()]


def is_param_check(terms: list[str], params: set[str]) -> bool:
    """Every OR-term is a NULL/zero/range test of a parameter: caller misuse."""
    if not terms or not params:
        return False
    for term in terms:
        for t in re.split(r"&&", term.strip("() ")):
            t = t.strip("() ")
            m = (re.fullmatch(r"!\s*(\w+)(?:->\w+)*", t)
                 or re.fullmatch(r"(\w+)(?:->\w+)*\s*[!=]=\s*(?:NULL|0)", t)
                 or re.fullmatch(r"(\w+)\s*(?:<|>|<=|>=)\s*\w+", t))
            if not m or m.group(1) not in params:
                return False
    return True


CALL_TERM = re.compile(r"!?\s*(\w+)\s*\(.*\)\s*(?:(?:!=|==)\s*[\w.>-]+)?")
CALLEE_CATEGORY = [
    (re.compile(r"asn1|parse|decode|pem|der_|digit"), "peer", 55),
    (re.compile(r"hkdf|hmac|hash|aes|rsa|drbg|random|rng|mgf|ecdh|x25519|p256|aead|cipher|pbkdf"), "crypto", 40),
    (re.compile(r"x509|cert|truststore|ocsp"), "cert", 45),
]


def failed_calls(terms: list[str]) -> list[str] | None:
    """Callee names when every OR-term is a failed function call, else None."""
    names = []
    for t in terms:
        m = CALL_TERM.fullmatch(t.strip())
        if not m or m.group(1) in KEYWORDS or m.group(1) == "sizeof":
            return None
        names.append(m.group(1))
    return names or None


def alloc_checked_var(terms: list[str], code: str, pos: int) -> bool:
    """A single NULL test of a variable that was last assigned from an allocator."""
    if len(terms) != 1:
        return False
    t = terms[0].strip("() ")
    m = re.fullmatch(r"!\s*([\w>.\-]+)", t) or re.fullmatch(r"([\w>.\-]+)\s*==\s*NULL", t)
    if not m:
        return False
    var = re.escape(m.group(1))
    window = code[max(0, pos - 3000):pos]
    assigns = list(re.finditer(var + r"\s*=\s*(?:\([^()]*\)\s*)?(\w+)\s*\(", window))
    return bool(assigns) and bool(ALLOC_CALL.search(assigns[-1].group(1)))


def draft_tags(site: Site, src: str, code: str, desc: str) -> str:
    rel = site.path.relative_to(ROOT).as_posix()
    cat, conf = next(((c, n) for sub, c, n in FILE_CATEGORY if sub in rel), ("logic", 30))
    func = enclosing_function(code, site.name_pos)
    fl = func.lower()
    tm = re.search(r"Trigger: `(.*)`\s*$", desc)
    trigger = tm.group(1) if tm else ""
    terms = trigger_terms(trigger)
    tags: dict[str, int] = {}

    def add(c: str, n: int) -> None:
        tags[c] = max(tags.get(c, 0), n)

    # Subsystem refinements by function name.
    if cat == "tls" and re.search(r"cert|x509", fl):
        cat, conf = "cert", 65
    if "dns" in fl and cat != "dns":
        add("dns", 60)

    # Propagation: the callee's own ID carries the evidence.
    if "propagates a failure from" in desc:
        callee = re.search(r"from (\w+)\(\)", desc)
        if callee and ALLOC_CALL.search(callee.group(1)):
            add("memory", 70)
        add(cat, 20)
        return render_tags(tags, site, propagate=True)

    alloc = ALLOC_TEXT.search(desc) or alloc_checked_var(terms, code, site.name_pos)
    param = is_param_check(terms, function_params(code, site.name_pos))
    callees = None if (alloc or param) else failed_calls(terms)

    if callees:
        # A callee reported failure. Whatever it hit is the real evidence
        # (and has its own ID if it logs), so weigh this site lower.
        add(cat, 35)
        for name in callees:
            nl = name.lower()
            if ALLOC_CALL.search(nl):
                add("memory", 70)
            for rx, c, n in CALLEE_CATEGORY:
                if rx.search(nl):
                    add(c, n)
                    break
        if "peer" in tags and cat in ("tls", "cert"):
            add(cat, 50)
    elif re.search(r"\breturns ERR_ARG\b", desc) and not trigger:
        add("api", 60)
        add(cat, 25)
    elif alloc:
        add("memory", 85)
        add(cat, 20)
    elif param:
        add("api", 75)
        add(cat, 20)
    else:
        add(cat, conf)
        if re.search(r"hostname|san_matches", fl):
            add("cert", 85)
        if "validity" in fl or "time_to_unix" in fl:
            add("cert", 80)
        if re.search(r"\bERR_RTE\b|no route|gateway", desc):
            add("wire", 60)
            add("config", 40)
        if re.search(r"\bERR_IF\b|shutting_down|xmit_fatal|usb_", desc):
            add("usb", 70)
        if re.search(r"time(d)? ?out", desc, re.I):
            add("transport", 50)
        peer_area = cat in ("tls", "cert", "ws", "dns", "wire", "transport")
        bare = trigger.replace("->", ".")
        if peer_area and PEER_FUNC.search(fl) and trigger not in UNUSED_KINDS \
                and PEER_TRIGGER.search(bare) and not STATE_TRIGGER.search(trigger):
            add("peer", 60 if cat in ("tls", "cert", "ws") else 45)
        if STATE_TRIGGER.search(trigger):
            add("logic", 45)
    return render_tags(tags, site)


def render_tags(tags: dict[str, int], site: Site, propagate: bool = False) -> str:
    scale = 0.6 if SITE_MACROS.get(site.macro) == "WARN" else 1.0
    out = []
    for c, n in sorted(tags.items(), key=lambda kv: (-kv[1], kv[0])):
        n = int(round(n * scale / 5.0) * 5)
        out.append(f"@{c}:{min(95, max(5, n))}")
    if propagate:
        out.append("@propagate")
    return " ".join(out)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

@dataclass
class Registry:
    text: str
    begin: int        # index just after the begin-marker line
    end: int          # index of the end marker line start
    entries: dict[int, str]               # description, tags stripped
    tags: dict[int, str]                  # raw tag text ("@tls:60 @peer:55")


def split_tags(text: str) -> tuple[str, str]:
    padded = " " + text
    m = TAGS_RE.search(padded)
    if not m:
        return text, ""
    return padded[:m.start()].strip(), m.group(1).strip()


def parse_tags(tags: str) -> list[tuple[str, str | None]]:
    return [(m.group(1), m.group(2)) for m in TAG_RE.finditer(tags)]


def load_categories(text: str) -> dict[str, str]:
    """Category vocabulary from the error-categories block in logging.h."""
    b, e = text.find(CAT_BEGIN), text.find(CAT_END)
    if b < 0 or e < b:
        sys.exit(f"{REGISTRY.relative_to(ROOT)}: error-categories markers not found")
    cats = {}
    for ln in text[text.index("\n", b) + 1:text.rfind("\n", 0, e)].splitlines():
        m = re.match(r"^\s*\*?\s*([a-z]+)\s{2,}(.+?)\s*$", ln)
        if m:
            cats[m.group(1)] = m.group(2)
    return cats


def load_registry(text: str | None = None) -> Registry:
    text = REGISTRY.read_text(encoding="utf-8") if text is None else text
    b = text.find(BEGIN_MARK)
    e = text.find(END_MARK)
    if b < 0 or e < 0 or e < b:
        sys.exit(f"{REGISTRY.relative_to(ROOT)}: error-id markers not found")
    begin = text.index("\n", b) + 1
    end = text.rfind("\n", 0, e) + 1
    entries: dict[int, str] = {}
    tags: dict[int, str] = {}
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
        entries[num], tags[num] = split_tags(m.group(3))
    return Registry(text, begin, end, entries, tags)


def entry_line(num: int, desc: str, tags: str = "") -> str:
    return f"    LWIP_E{num:04X} = 0x{num:04X}, // {desc}" + (f" {tags}" if tags else "") + "\n"


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
            new_entries.append(entry_line(next_id, desc, draft_tags(s, src, code, desc)))
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
    fresh: dict[int, tuple[str, str]] = {}
    for _path, src, kind, comments, sites in scan():
        code = code_only(src, kind)
        for s in sites:
            if s.eid is not None and reg.entries.get(s.eid, "").startswith("[auto]"):
                desc = draft_description(s, src, code, comments)
                fresh[s.eid] = (desc, draft_tags(s, src, code, desc))
    changed = rewrite_entries(reg, fresh)
    print(f"redrafted {changed} [auto] entr{'y' if changed == 1 else 'ies'}")
    return 0


def rewrite_entries(reg: Registry, fresh: dict[int, tuple[str, str]]) -> int:
    lines = reg.text[reg.begin:reg.end].splitlines(keepends=True)
    changed = 0
    for i, ln in enumerate(lines):
        m = ENTRY_RE.match(ln)
        if m and int(m.group(1), 16) in fresh:
            num = int(m.group(1), 16)
            new = entry_line(num, *fresh[num])
            if new != ln:
                lines[i] = new
                changed += 1
    REGISTRY.write_text(reg.text[:reg.begin] + "".join(lines) + reg.text[reg.end:], encoding="utf-8")
    return changed


def cmd_tag(args: argparse.Namespace) -> int:
    """Draft evidence tags from each entry's current description and site."""
    reg = load_registry()
    fresh: dict[int, tuple[str, str]] = {}
    for _path, src, kind, _comments, sites in scan():
        code = code_only(src, kind)
        for s in sites:
            if s.eid is None or s.eid not in reg.entries:
                continue
            if reg.tags.get(s.eid) and not args.all:
                continue
            desc = reg.entries[s.eid]
            fresh[s.eid] = (desc, draft_tags(s, src, code, desc))
    changed = rewrite_entries(reg, fresh)
    print(f"tagged {changed} entr{'y' if changed == 1 else 'ies'}")
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

    cats = load_categories(reg.text)
    for num, desc in sorted(reg.entries.items()):
        if num == 0:
            continue
        name = f"LWIP_E{num:04X}"
        if not desc:
            problems.append(f"{name}: missing description")
        if num not in used and "RETIRED" not in desc:
            problems.append(f"{name}: defined but unused; mark its description RETIRED")
        weighted = 0
        for tag, val in parse_tags(reg.tags.get(num, "")):
            if tag in FLAGS:
                if val is not None:
                    problems.append(f"{name}: @{tag} takes no value")
            elif tag not in cats:
                problems.append(f"{name}: unknown evidence category @{tag} "
                                f"(known: {', '.join(sorted(cats))})")
            elif val is None or not val.isdigit() or not 1 <= int(val) <= 100:
                problems.append(f"{name}: @{tag} needs a confidence 1-100 (e.g. @{tag}:60)")
            else:
                weighted += 1
        if weighted == 0 and "RETIRED" not in desc:
            problems.append(f"{name}: no evidence tags (run tools/error_ids/error_ids.py tag)")

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
    sub.add_parser("redraft", help="regenerate [auto] descriptions and tags from current call sites")
    t = sub.add_parser("tag", help="draft evidence tags for entries that have none")
    t.add_argument("--all", action="store_true", help="redraft tags on every entry (descriptions are kept)")
    c = sub.add_parser("check", help="verify registry invariants")
    c.add_argument("--base", help="git ref to compare against for append-only check")
    args = ap.parse_args()
    return {"assign": cmd_assign, "redraft": cmd_redraft, "tag": cmd_tag,
            "check": cmd_check}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())

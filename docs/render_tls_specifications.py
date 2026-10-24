#!/usr/bin/env python3
"""Render the TLS compliance XML ledger as standalone static HTML."""

from __future__ import annotations

import argparse
import html
from collections import Counter, defaultdict
from pathlib import Path
import xml.etree.ElementTree as ET


CSS = r"""
:root {
  color-scheme: light;
  --bg:#fff; --fg:#1f2328; --muted:#59636e; --line:#d1d9e0;
  --panel:#f6f8fa; --link:#0969da; --ok-bg:#dafbe1; --ok-fg:#116329;
  --dev-bg:#ffebe9; --dev-fg:#82071e; --ev-bg:#fff8c5; --ev-fg:#7d4e00;
  --part-bg:#ddf4ff; --part-fg:#0550ae; --na-bg:#eaeef2; --na-fg:#424a53;
  --rev-bg:#f0f6ff; --rev-fg:#0550ae; --rev-border:#b0c8f0;
}
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--fg);
       font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }
main { max-width:1100px; margin:0 auto; padding:24px 16px 64px; }
h1 { font-size:1.6rem; margin:0 0 4px; }
h2 { font-size:1.15rem; margin:32px 0 8px; padding-top:8px;
     border-top:1px solid var(--line); }
p.lead { color:var(--muted); margin:0 0 16px; }
.summary { display:flex; flex-wrap:wrap; gap:8px; margin:16px 0; }
.badge { display:inline-block; padding:1px 8px; border-radius:999px;
         font-size:12px; font-weight:600; white-space:nowrap; }
.COMPLIANT { background:var(--ok-bg); color:var(--ok-fg); }
.DEVIANT { background:var(--dev-bg); color:var(--dev-fg); }
.NEEDS-EVIDENCE { background:var(--ev-bg); color:var(--ev-fg); }
.PARTIAL { background:var(--part-bg); color:var(--part-fg); }
.NOT-APPLICABLE { background:var(--na-bg); color:var(--na-fg); }
.stat { padding:8px 14px; border-radius:8px; background:var(--panel);
        border:1px solid var(--line); }
.stat b { font-size:1.3rem; display:block; line-height:1.2; }
.stat span { color:var(--muted); font-size:12px; }
.filters { display:flex; align-items:end; flex-wrap:wrap; gap:8px 16px;
           margin:18px 0; padding:12px 14px; border:1px solid var(--line);
           border-radius:8px; background:var(--panel); }
.filter-field { display:grid; gap:4px; }
.filter-field label { color:var(--muted); font-size:12px; font-weight:600; }
.filter-field select { min-width:190px; padding:7px 30px 7px 9px;
                       border:1px solid var(--line); border-radius:6px;
                       background:var(--bg); color:var(--fg); font:inherit; }
.filter-status { color:var(--muted); padding-bottom:7px; }
.policy { margin:12px 0 18px; padding:10px 14px;
          border-left:4px solid var(--dev-fg); border-radius:4px;
          background:var(--panel); }
td.justification { color:var(--muted); }
.missing-justification { color:var(--dev-fg); font-style:italic; }
nav.toc { display:flex; flex-wrap:wrap; gap:6px 14px; font-size:13px; }
nav.toc a,.back a { color:var(--link); text-decoration:none; }
nav.toc a:hover { text-decoration:underline; }
table { width:100%; border-collapse:collapse; table-layout:fixed; }
th,td { text-align:left; vertical-align:top; padding:8px 10px;
        border-bottom:1px solid var(--line); overflow-wrap:anywhere; }
th { color:var(--muted); font-size:12px; text-transform:uppercase;
     letter-spacing:.04em; }
td.sec { width:13%; overflow-wrap:anywhere; word-break:break-word; }
td.grade { width:120px; }
td.loc { font:12.5px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace; width:20%;
         word-break:break-all; overflow-wrap:anywhere; }
td.note { width:22%; overflow-wrap:anywhere; word-break:break-word; }
td.justification { width:18%; overflow-wrap:anywhere; word-break:break-word; }
td.reviews { width:17%; overflow-wrap:anywhere; word-break:break-word; }
.review-entry { margin-bottom:6px; padding:5px 8px; border-radius:4px;
                background:var(--rev-bg); border:1px solid var(--rev-border); }
.review-entry:last-child { margin-bottom:0; }
.review-person { font-weight:600; color:var(--rev-fg); font-size:12px; }
.review-scope { color:var(--muted); font-size:11px; font-style:italic; }
.review-note { font-size:12px; margin-top:2px; }
.no-reviews { color:var(--muted); font-style:italic; font-size:12px; }
[hidden] { display:none !important; }
@media (max-width:720px) {
  table,thead,tbody,tr,td { display:block; }
  thead { display:none; }
  tr { border-bottom:1px solid var(--line); padding:8px 0; }
  td { border:0; padding:2px 0; width:auto !important; }
}
"""


SCRIPT = r"""
(function () {
  var filter = document.getElementById("grade-filter");
  var status = document.getElementById("filter-status");
  var groups = document.querySelectorAll(".audit-group");
  var tocLinks = document.querySelectorAll("[data-audit-link]");
  var total = document.querySelectorAll("tr[data-grade]").length;
  function applyGradeFilter() {
    var selected = filter.value;
    var visibleTotal = 0;
    for (var i = 0; i < groups.length; i++) {
      var rows = groups[i].querySelectorAll("tr[data-grade]");
      var visibleInGroup = 0;
      for (var j = 0; j < rows.length; j++) {
        var show = selected === "ALL" || rows[j].dataset.grade === selected;
        rows[j].hidden = !show;
        if (show) { visibleInGroup++; visibleTotal++; }
      }
      groups[i].hidden = visibleInGroup === 0;
      if (tocLinks[i]) { tocLinks[i].hidden = visibleInGroup === 0; }
    }
    status.textContent = selected === "ALL"
      ? "Showing all " + total + " entries"
      : "Showing " + visibleTotal + " of " + total + " entries";
  }
  filter.addEventListener("change", applyGradeFilter);
  applyGradeFilter();
}());
"""


def text(node: ET.Element, name: str) -> str:
    child = node.find(name)
    return "" if child is None or child.text is None else child.text.strip()


def esc(value: str) -> str:
    return html.escape(value, quote=True)


def _parse_requirements(source: Path) -> tuple[list[dict], dict[str, list[dict]]]:
    root = ET.parse(source).getroot()
    if root.tag != "tls-specifications":
        raise ValueError(f"unexpected document root: {root.tag}")
    requirements = []
    groups: dict[str, list[dict]] = defaultdict(list)
    for node in root.findall("requirement"):
        item = {name: text(node, name) for name in
                ("ref", "section", "location", "grade", "note", "justification")}
        if not all(item[name] for name in ("ref", "section", "location", "grade")):
            raise ValueError("requirement is missing ref, section, location, or grade")
        reviewers = []
        reviews_node = node.find("reviews")
        if reviews_node is not None:
            for rb in reviews_node.findall("reviewed-by"):
                reviewer = {
                    "person": text(rb, "person"),
                    "scope":  text(rb, "scope"),
                    "note":   text(rb, "note"),
                }
                if reviewer["person"]:
                    reviewers.append(reviewer)
        item["reviewers"] = reviewers
        requirements.append(item)
        groups[item["ref"]].append(item)
    return requirements, groups


def _build_body(requirements: list[dict], groups: dict[str, list[dict]]) -> list[str]:
    counts = Counter(item["grade"] for item in requirements)
    out = ['<p class="lead">Clause-by-clause ledger mapping the standards this TLS '
           "implementation targets (RFC, NIST SP, FIPS) to the code that satisfies "
           f"or deviates from them. {len(requirements)} entries.</p>",
           '<div class="summary">']
    for grade in sorted(counts):
        out.append(f'<div class="stat"><b>{counts[grade]}</b>'
                   f'<span class="badge {esc(grade)}">{esc(grade)}</span></div>')
    out.extend(['</div><div class="filters"><div class="filter-field">',
                '<label for="grade-filter">Filter by grade</label>',
                '<select id="grade-filter"><option value="ALL">All grades</option>'])
    for grade in sorted(counts):
        out.append(f'<option value="{esc(grade)}">{esc(grade)}</option>')
    out.extend(['</select></div>',
                f'<div id="filter-status" class="filter-status" aria-live="polite">'
                f'Showing all {len(requirements)} entries</div></div>',
                '<p class="policy"><strong>Deviation policy:</strong> Every '
                '<span class="badge DEVIANT">DEVIANT</span> result is expected to be '
                'fixed. If a deviation is intentionally retained because of platform '
                'constraints, its audit entry must include a specific '
                '<code>&lt;justification&gt;...&lt;/justification&gt;</code> explaining why. '
                "The grade is the current status; a compliant entry's note may retain "
                'the original audit finding for traceability.</p>',
                '<nav class="toc">'])

    ordered_refs = sorted(groups)
    anchors = {ref: f"standard-{index}" for index, ref in enumerate(ordered_refs, 1)}
    for ref in ordered_refs:
        out.append(f'<a href="#{anchors[ref]}" data-audit-link="true">'
                   f'{esc(ref)} ({len(groups[ref])})</a>')
    out.append('</nav>')

    for ref in ordered_refs:
        out.extend([f'<section class="audit-group"><h2 id="{anchors[ref]}">{esc(ref)}</h2>',
                    '<table><thead><tr><th>Section</th><th>Location</th><th>Grade</th>'
                    '<th>Note</th><th>Justification</th><th>Reviews</th></tr></thead><tbody>'])
        for item in groups[ref]:
            justification = esc(item["justification"])
            if not justification and item["grade"] == "DEVIANT":
                justification = '<span class="missing-justification">Not yet documented.</span>'
            if item["reviewers"]:
                reviews_html = ""
                for r in item["reviewers"]:
                    reviews_html += '<div class="review-entry">'
                    reviews_html += f'<div class="review-person">{esc(r["person"])}</div>'
                    if r["scope"]:
                        reviews_html += f'<div class="review-scope">{esc(r["scope"])}</div>'
                    if r["note"]:
                        reviews_html += f'<div class="review-note">{esc(r["note"])}</div>'
                    reviews_html += '</div>'
            else:
                reviews_html = '<span class="no-reviews">—</span>'
            out.append(f'<tr data-grade="{esc(item["grade"])}">'
                       f'<td class="sec">{esc(item["section"])}</td>'
                       f'<td class="loc">{esc(item["location"])}</td>'
                       f'<td class="grade"><span class="badge {esc(item["grade"])}">'
                       f'{esc(item["grade"])}</span></td>'
                       f'<td class="note">{esc(item["note"])}</td>'
                       f'<td class="justification">{justification}</td>'
                       f'<td class="reviews">{reviews_html}</td></tr>')
        out.append('</tbody></table></section>')
    out.append(f"<script>{SCRIPT}</script>")
    return out


def render(source: Path, destination: Path) -> None:
    """Render a standalone HTML page (used by the CLI)."""
    requirements, groups = _parse_requirements(source)
    body = _build_body(requirements, groups)
    out = ["<!doctype html>", '<html lang="en"><head>',
           '<meta charset="utf-8">',
           '<meta name="viewport" content="width=device-width,initial-scale=1">',
           '<title>lwIP-CE TLS Specification Compliance</title>',
           f"<style>{CSS}</style>", "</head><body><main>",
           "<h1>lwIP-CE TLS Specification Compliance</h1>"]
    out.extend(body)
    out.append("</main></body></html>")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("\n".join(out), encoding="utf-8")


def render_fragment(source: Path, destination: Path) -> None:
    """Render a bare HTML fragment for embedding via Sphinx ``.. raw:: html``."""
    requirements, groups = _parse_requirements(source)
    body = _build_body(requirements, groups)
    out = [f"<style>{CSS}</style>"]
    out.extend(body)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("\n".join(out), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--fragment", action="store_true",
                        help="emit a bare HTML fragment instead of a full page")
    args = parser.parse_args()
    if args.fragment:
        render_fragment(args.source, args.destination)
    else:
        render(args.source, args.destination)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Render the latest branch CI results as a self-contained SVG dashboard."""

from __future__ import annotations

import argparse
import html
import os
from datetime import UTC, datetime
from pathlib import Path


GATES = (
    ("Change Classification", "CI_CLASSIFY"),
    ("Build", "CI_BUILD"),
    ("Test Workflow", "CI_TESTS"),
    ("Unit Tests", "CI_UNIT"),
    ("RFC Compliance", "CI_RFC"),
    ("ACVP", "CI_ACVP"),
    ("SAST / Semgrep", "CI_SAST"),
    ("CodeQL", "CI_CODEQL"),
    ("Network Tests", "CI_NETWORK"),
    ("DAST", "CI_DAST"),
    ("Host Tests", "CI_HOST"),
    ("Fuzzing", "CI_FUZZ"),
    ("ROM Setup", "CI_ROM"),
    ("ROM Cleanup", "CI_ROM_CLEANUP"),
    ("Promotion Policy", "CI_POLICY"),
)

STYLES = {
    "success": ("#2de2a6", "PASS", "check"),
    "auto": ("#2de2a6", "AUTO", "check"),
    "review": ("#ffd166", "REVIEW", "alert"),
    "failure": ("#ff5d73", "FAIL", "cross"),
    "reject": ("#ff5d73", "REJECT", "cross"),
    "cancelled": ("#ff9f43", "CANCELLED", "alert"),
    "timed_out": ("#ff9f43", "TIMEOUT", "alert"),
    "skipped": ("#7f8ca8", "SKIPPED", "dash"),
    "not run": ("#7f8ca8", "NOT RUN", "dash"),
    "": ("#7f8ca8", "NOT RUN", "dash"),
}


def esc(value: str) -> str:
    return html.escape(value, quote=True)


def icon(kind: str, x: int, y: int, color: str) -> str:
    circle = (
        f'<circle cx="{x}" cy="{y}" r="17" fill="{color}" fill-opacity=".13" '
        f'stroke="{color}" stroke-width="2"/>'
    )
    if kind == "check":
        mark = f'<path d="M{x-8} {y}l6 6 11-13" fill="none" stroke="{color}" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>'
    elif kind == "cross":
        mark = f'<path d="M{x-7} {y-7}l14 14m0-14l-14 14" fill="none" stroke="{color}" stroke-width="3" stroke-linecap="round"/>'
    elif kind == "alert":
        mark = f'<path d="M{x} {y-9}v11m0 6v.2" fill="none" stroke="{color}" stroke-width="3" stroke-linecap="round"/>'
    else:
        mark = f'<path d="M{x-7} {y}h14" fill="none" stroke="{color}" stroke-width="3" stroke-linecap="round"/>'
    return circle + mark


def render(branch: str, sha: str, run_url: str) -> str:
    width = 1080
    card_width, card_height = 326, 96
    gap_x, gap_y = 21, 18
    start_x, start_y = 30, 174
    rows = (len(GATES) + 2) // 3
    height = start_y + rows * card_height + (rows - 1) * gap_y + 76
    branch_color = "#6ee7ff" if branch == "master" else "#c084fc"
    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")

    cards: list[str] = []
    for index, (label, variable) in enumerate(GATES):
        raw_status = os.environ.get(variable, "").strip().lower()
        color, display, kind = STYLES.get(raw_status, ("#7f8ca8", raw_status.upper() or "UNKNOWN", "dash"))
        col, row = index % 3, index // 3
        x = start_x + col * (card_width + gap_x)
        y = start_y + row * (card_height + gap_y)
        cards.append(
            f"""
    <g class="card">
      <rect x="{x}" y="{y}" width="{card_width}" height="{card_height}" rx="15" fill="#111a2e" stroke="#263653"/>
      <rect x="{x}" y="{y}" width="5" height="{card_height}" rx="2.5" fill="{color}"/>
      <text x="{x+25}" y="{y+38}" class="gate">{esc(label)}</text>
      <text x="{x+25}" y="{y+67}" class="status" fill="{color}">{esc(display)}</text>
      {icon(kind, x+card_width-36, y+48, color)}
    </g>"""
        )

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-labelledby="title desc">
  <title id="title">lwIP-CE {esc(branch)} CI status</title>
  <desc id="desc">Latest build and test results for commit {esc(sha)}</desc>
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#07101f"/>
      <stop offset=".55" stop-color="#0b1224"/>
      <stop offset="1" stop-color="#11152b"/>
    </linearGradient>
    <radialGradient id="glow" cx="88%" cy="0" r="75%">
      <stop offset="0" stop-color="{branch_color}" stop-opacity=".16"/>
      <stop offset="1" stop-color="{branch_color}" stop-opacity="0"/>
    </radialGradient>
    <pattern id="grid" width="28" height="28" patternUnits="userSpaceOnUse">
      <path d="M28 0H0v28" fill="none" stroke="#8ba3ca" stroke-opacity=".035"/>
    </pattern>
    <filter id="shadow" x="-15%" y="-20%" width="130%" height="150%">
      <feDropShadow dx="0" dy="7" stdDeviation="8" flood-color="#000814" flood-opacity=".38"/>
    </filter>
    <style>
      text {{ font-family: Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif; }}
      .eyebrow {{ font-size: 13px; font-weight: 750; letter-spacing: 2.6px; }}
      .heading {{ fill: #f4f7ff; font-size: 34px; font-weight: 760; letter-spacing: -.5px; }}
      .meta {{ fill: #91a0bb; font-size: 14px; font-weight: 500; }}
      .gate {{ fill: #eef3ff; font-size: 17px; font-weight: 680; }}
      .status {{ font-size: 12px; font-weight: 800; letter-spacing: 1.6px; }}
      .card {{ filter: url(#shadow); }}
    </style>
  </defs>
  <rect width="{width}" height="{height}" rx="22" fill="url(#bg)"/>
  <rect width="{width}" height="{height}" rx="22" fill="url(#glow)"/>
  <rect width="{width}" height="{height}" rx="22" fill="url(#grid)"/>
  <rect x="1" y="1" width="{width-2}" height="{height-2}" rx="21" fill="none" stroke="#2a3855"/>

  <text x="31" y="43" class="eyebrow" fill="{branch_color}">LWIP-CE // CONTINUOUS INTEGRATION</text>
  <text x="30" y="89" class="heading">{esc(branch.upper())} STATUS MATRIX</text>
  <rect x="30" y="111" width="{max(104, 68 + len(branch) * 9)}" height="31" rx="15.5" fill="{branch_color}" fill-opacity=".11" stroke="{branch_color}" stroke-opacity=".55"/>
  <circle cx="48" cy="126.5" r="4" fill="{branch_color}"/>
  <text x="60" y="132" class="eyebrow" fill="{branch_color}" style="font-size:11px;letter-spacing:1.4px">{esc(branch.upper())}</text>
  <text x="{width-30}" y="116" class="meta" text-anchor="end">commit {esc(sha[:12])}</text>
  <text x="{width-30}" y="139" class="meta" text-anchor="end">updated {esc(generated)}</text>
  {''.join(cards)}
  <line x1="30" y1="{height-48}" x2="{width-30}" y2="{height-48}" stroke="#263653"/>
  <text x="30" y="{height-22}" class="meta">Generated from the latest {esc(branch)} gate</text>
  <a href="{esc(run_url)}"><text x="{width-30}" y="{height-22}" class="meta" text-anchor="end" fill="{branch_color}">VIEW WORKFLOW RUN →</text></a>
</svg>
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--branch", required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--run-url", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(render(args.branch, args.sha, args.run_url), encoding="utf-8")


if __name__ == "__main__":
    main()

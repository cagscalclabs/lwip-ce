#!/usr/bin/env python3
"""NIST ACVP offline fetch/submit wrapper.

Uses a locally-built acvp_app (from github.com/cisco/libacvp) to authenticate
with the NIST ACVP demo server and either:

  --fetch   Download vector sets to vectors/<vsId>.json (one file per vector set).
            Requires network access and TOTP secret.

  --submit  Upload response files from responses/<vsId>.json back to NIST.
            Requires the same session file produced by --fetch.

Environment variables (mirrors acvp_app conventions):
  ACV_SERVER      NIST ACVP server hostname (default: demo.acvts.nist.gov)
  ACV_PORT        Server port (default: 443)
  ACV_CERT_FILE   Path to client TLS certificate
  ACV_KEY_FILE    Path to client private key
  ACV_TOTP_SEED   Base32-encoded TOTP seed (org secret ACVP_TOTP)
  ACV_CA_FILE     CA chain for server verification (optional; system default used otherwise)
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
LIBACVP_REPO = "https://github.com/cisco/libacvp"
LIBACVP_DIR = HERE / "libacvp"
ACVP_APP = LIBACVP_DIR / "app" / "acvp_app"
VECTORS_DIR = HERE / "vectors"
RESPONSES_DIR = HERE / "responses"
SESSION_FILE = HERE / "session.json"
CAPABILITIES_FILE = HERE / "capabilities.json"


def build_libacvp() -> None:
    """Clone and build acvp_app if not already present."""
    if ACVP_APP.exists():
        return
    print("Building libacvp...", flush=True)
    LIBACVP_DIR.mkdir(parents=True, exist_ok=True)
    if not (LIBACVP_DIR / ".git").exists():
        subprocess.run(
            ["git", "clone", "--depth=1", LIBACVP_REPO, str(LIBACVP_DIR)],
            check=True,
        )
    subprocess.run(["autoreconf", "-i"], cwd=LIBACVP_DIR, check=True)
    subprocess.run(
        [
            "./configure",
            "--with-libcurl-dir=/usr",
            "--with-ssl-dir=/usr/local/ssl",
            "--disable-fom",
        ],
        cwd=LIBACVP_DIR, check=True,
    )
    subprocess.run(["make", "-j4"], cwd=LIBACVP_DIR, check=True)
    if not ACVP_APP.exists():
        raise RuntimeError(f"acvp_app not found after build at {ACVP_APP}")
    print("acvp_app built.", flush=True)


def acvp_env() -> dict[str, str]:
    """Build environment for acvp_app, propagating ACV_* variables."""
    env = os.environ.copy()
    defaults = {
        "ACV_SERVER": "demo.acvts.nist.gov",
        "ACV_PORT": "443",
    }
    for k, v in defaults.items():
        env.setdefault(k, v)
    required = ["ACV_CERT_FILE", "ACV_KEY_FILE", "ACV_TOTP_SEED"]
    missing = [k for k in required if not env.get(k)]
    if missing:
        raise RuntimeError(f"Required env vars not set: {', '.join(missing)}")
    return env


def write_vector_files(combined_req: Path) -> list[Path]:
    """Split a combined acvp_app vector request file into per-vsId files.

    Also writes vectors/combined.json in ACVP prompt-list format
    ([{acvVersion}, {vsId...}, ...]) for use with the CEmu runner.
    """
    VECTORS_DIR.mkdir(exist_ok=True)
    data = json.loads(combined_req.read_text())
    # acvp_app saves as an array of vector set objects
    if isinstance(data, list):
        sets = data
    elif isinstance(data, dict) and "vectorSets" in data:
        sets = data["vectorSets"]
    else:
        sets = [data]
    paths = []
    for vs in sets:
        vsid = vs.get("vsId", "unknown")
        out = VECTORS_DIR / f"{vsid}.json"
        out.write_text(json.dumps(vs, indent=2) + "\n")
        paths.append(out)
        print(f"  vector set {vsid} → {out.name}", flush=True)
    # Write combined prompt in ACVP list format for the CEmu runner
    combined = [{"acvVersion": "1.0"}, *sets]
    (VECTORS_DIR / "combined.json").write_text(json.dumps(combined, indent=2) + "\n")
    return paths


def collect_responses() -> Path:
    """Collect responses for upload.

    If responses/combined.json exists (written by the CEmu runner), use it
    directly after splitting it into per-vsId files.  Otherwise merge all
    per-vsId files in responses/.
    """
    RESPONSES_DIR.mkdir(exist_ok=True)
    cemu_combined = RESPONSES_DIR / "combined.json"
    if cemu_combined.exists():
        # CEmu runner writes a list; split into per-vsId files as well
        data = json.loads(cemu_combined.read_text())
        items = data if isinstance(data, list) else [data]
        for item in items:
            vsid = item.get("vsId", "unknown")
            (RESPONSES_DIR / f"{vsid}.json").write_text(
                json.dumps(item, indent=2) + "\n")
        combined = HERE / "combined_responses.json"
        combined.write_text(json.dumps(items, indent=2) + "\n")
        return combined
    responses = []
    for f in sorted(RESPONSES_DIR.glob("*.json")):
        if f.name == "combined.json":
            continue
        responses.append(json.loads(f.read_text()))
    combined = HERE / "combined_responses.json"
    combined.write_text(json.dumps(responses, indent=2) + "\n")
    return combined


def cmd_fetch(args: argparse.Namespace) -> int:
    build_libacvp()
    env = acvp_env()
    VECTORS_DIR.mkdir(exist_ok=True)
    combined_req = HERE / "vectors_combined.json"

    # Phase 1: register capabilities and download vector sets
    print("Fetching vectors from NIST ACVP...", flush=True)
    result = subprocess.run(
        [
            str(ACVP_APP),
            "--manual_registration", str(CAPABILITIES_FILE),
            "--disable_fips",
            "--vector_req", str(combined_req),
        ],
        env=env,
        cwd=str(LIBACVP_DIR),
    )
    if result.returncode != 0:
        print("acvp_app fetch failed", file=sys.stderr)
        return 1

    # Split into per-vsId files for run.py
    paths = write_vector_files(combined_req)
    print(f"Downloaded {len(paths)} vector set(s) to {VECTORS_DIR}/", flush=True)

    # Save the session file path for submit step
    sessions = list(LIBACVP_DIR.glob("testSession_*.json"))
    if sessions:
        newest = max(sessions, key=lambda p: p.stat().st_mtime)
        import shutil
        shutil.copy2(newest, SESSION_FILE)
        print(f"Session saved to {SESSION_FILE}", flush=True)
    else:
        print("Warning: no testSession_*.json found; submit step will need --session", flush=True)

    return 0


def cmd_get_results(args: argparse.Namespace) -> int:
    build_libacvp()
    env = acvp_env()

    session = args.session or SESSION_FILE
    if not Path(session).exists():
        print(f"Session file not found: {session}", file=sys.stderr)
        print("Run --fetch first, or pass --session <path>", file=sys.stderr)
        return 1

    results_file = HERE / "results.json"
    print("Fetching grading results from NIST ACVP...", flush=True)
    result = subprocess.run(
        [
            str(ACVP_APP),
            "--get_results",
            "--disable_fips",
            "--session", str(session),
            "--save_to", str(results_file),
        ],
        env=env,
        cwd=str(LIBACVP_DIR),
    )
    if result.returncode != 0:
        print("acvp_app get_results failed", file=sys.stderr)
        return 1

    if not results_file.exists():
        print("No results file produced; server may still be grading — retry later",
              file=sys.stderr)
        return 1

    data = json.loads(results_file.read_text())
    _print_results(data)
    return 0


def _print_results(data: object) -> None:
    """Pretty-print grading results to stdout."""
    sets = data if isinstance(data, list) else data.get("vectorSets", [data])
    passed = 0
    failed = 0
    for vs in sets:
        vsid = vs.get("vsId", "?")
        status = vs.get("status", vs.get("disposition", "unknown"))
        alg = vs.get("algorithm", "")
        mode = vs.get("mode", "")
        label = f"{alg}/{mode}" if mode else alg
        ok = str(status).lower() in ("passed", "approved")
        mark = "PASS" if ok else "FAIL"
        print(f"  [{mark}] vsId {vsid:>6}  {label}  ({status})")
        if ok:
            passed += 1
        else:
            failed += 1
    total = passed + failed
    print(f"\n{passed}/{total} vector set(s) passed.")
    if failed:
        print(f"{failed} FAILED — check results.json for details.")


def cmd_submit(args: argparse.Namespace) -> int:
    build_libacvp()
    env = acvp_env()

    session = args.session or SESSION_FILE
    if not Path(session).exists():
        print(f"Session file not found: {session}", file=sys.stderr)
        print("Run --fetch first, or pass --session <path>", file=sys.stderr)
        return 1

    combined_rsp = collect_responses()
    n = len(json.loads(combined_rsp.read_text()))
    print(f"Uploading {n} response(s) to NIST ACVP...", flush=True)

    result = subprocess.run(
        [
            str(ACVP_APP),
            "--manual_registration", str(CAPABILITIES_FILE),
            "--disable_fips",
            "--vector_upload", str(combined_rsp),
        ],
        env=env,
        cwd=str(LIBACVP_DIR),
    )
    if result.returncode != 0:
        print("acvp_app submit failed", file=sys.stderr)
        return 1

    print("Upload complete.", flush=True)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NIST ACVP offline fetch/submit wrapper"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("fetch", help="Download vector sets from NIST")

    p_submit = sub.add_parser("submit", help="Upload calc responses to NIST")
    p_submit.add_argument(
        "--session", default=None,
        help="Path to testSession JSON (default: session.json next to this script)",
    )

    p_results = sub.add_parser("get_results", help="Fetch and print grading results from NIST")
    p_results.add_argument(
        "--session", default=None,
        help="Path to testSession JSON (default: session.json next to this script)",
    )

    sub.add_parser("build", help="Build acvp_app only (no network calls)")

    args = parser.parse_args()

    if args.command == "build":
        ACVP_APP.unlink(missing_ok=True)
        build_libacvp()
        return 0
    if args.command == "fetch":
        return cmd_fetch(args)
    if args.command == "submit":
        return cmd_submit(args)
    if args.command == "get_results":
        return cmd_get_results(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())

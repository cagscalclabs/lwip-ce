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
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
LIBACVP_REPO = "https://github.com/cisco/libacvp"
LIBACVP_REF = os.environ.get("LIBACVP_REF", "v2.3.1")
LIBACVP_DIR = HERE / "libacvp"
ACVP_APP = LIBACVP_DIR / "app" / "acvp_app"
VECTORS_DIR = HERE / "vectors"
RESPONSES_DIR = HERE / "responses"
SESSION_FILE = HERE / "session.json"
UPLOAD_CONTEXT_FILE = HERE / "upload_context.json"
CAPABILITIES_FILE = HERE / "capabilities.json"
RESULTS_FILE = HERE / "results.json"
RESULTS_LOG = HERE / "results.log"


def build_libacvp() -> None:
    """Clone and build acvp_app if not already present."""
    LIBACVP_DIR.mkdir(parents=True, exist_ok=True)
    if not (LIBACVP_DIR / ".git").exists():
        print("Cloning libacvp...", flush=True)
        subprocess.run(
            ["git", "clone", "--depth=1", "--branch", LIBACVP_REF,
             LIBACVP_REPO, str(LIBACVP_DIR)],
            check=True,
        )
    expected = subprocess.run(
        ["git", "rev-parse", f"{LIBACVP_REF}^{{commit}}"], cwd=LIBACVP_DIR,
        text=True, capture_output=True,
    )
    actual = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=LIBACVP_DIR,
        text=True, capture_output=True, check=True,
    ).stdout.strip()
    if expected.returncode == 0 and actual != expected.stdout.strip():
        raise RuntimeError(
            f"existing libacvp checkout is {actual}, expected {LIBACVP_REF}; "
            f"remove {LIBACVP_DIR} and retry"
        )
    if ACVP_APP.exists():
        return
    print("Building libacvp...", flush=True)
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
    env["ACV_SESSION_SAVE_PATH"] = str(HERE)
    env["ACV_SESSION_SAVE_PREFIX"] = "acvpLiveSession"
    return env


def _openssl(args: list[str]) -> bytes:
    result = subprocess.run(
        ["openssl", *args], capture_output=True, check=False,
    )
    if result.returncode:
        detail = result.stderr.decode(errors="replace").strip()
        raise RuntimeError(f"openssl {' '.join(args[:2])} failed: {detail}")
    return result.stdout


def validate_credentials(env: dict[str, str]) -> None:
    """Fail before registration if the configured client key is unusable."""
    certificate = Path(env["ACV_CERT_FILE"])
    private_key = Path(env["ACV_KEY_FILE"])
    if not certificate.is_file() or not private_key.is_file():
        raise RuntimeError("ACVP client certificate or private key is missing")
    # The job may run for almost eight hours; reject a certificate that could
    # expire while the test session is active.
    _openssl(["x509", "-in", str(certificate), "-noout", "-checkend", "28800"])
    cert_public = _openssl(["x509", "-in", str(certificate), "-pubkey", "-noout"])
    key_public = _openssl(["pkey", "-in", str(private_key), "-pubout"])
    if cert_public != key_public:
        raise RuntimeError("ACVP client private key does not match client.cer")


def _secure_write(path: Path, value: object) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.unlink(missing_ok=True)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
        temporary.replace(path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _load_upload_context() -> dict:
    if not UPLOAD_CONTEXT_FILE.is_file():
        raise RuntimeError("ACVP upload context is missing; run fetch first")
    value = json.loads(UPLOAD_CONTEXT_FILE.read_text())
    required = ("url", "jwt", "vectorSetUrls")
    if not isinstance(value, dict) or any(name not in value for name in required):
        raise RuntimeError("ACVP upload context is malformed")
    return value


def _order_and_validate_responses(context: dict,
                                  responses: list[dict]) -> list[dict]:
    """Require one response for every vector set in the registered session."""
    urls = context.get("vectorSetUrls")
    if not isinstance(urls, list) or not urls or not all(isinstance(url, str)
                                                         for url in urls):
        raise RuntimeError("ACVP upload context has invalid vector-set URLs")
    expected = [url.rstrip("/").rsplit("/", 1)[-1] for url in urls]
    if any(not vsid.isdigit() for vsid in expected) or len(set(expected)) != len(expected):
        raise RuntimeError("ACVP upload context has invalid vector-set IDs")

    by_vsid: dict[str, dict] = {}
    for response in responses:
        if not isinstance(response, dict) or "vsId" not in response:
            raise RuntimeError("calculator response contains a malformed vector set")
        vsid = str(response["vsId"])
        if vsid in by_vsid:
            raise RuntimeError(f"calculator returned duplicate response for vsId {vsid}")
        by_vsid[vsid] = response

    expected_set = set(expected)
    missing = [vsid for vsid in expected if vsid not in by_vsid]
    unexpected = [vsid for vsid in by_vsid if vsid not in expected_set]
    if missing or unexpected:
        details = []
        if missing:
            details.append(f"missing vsId(s): {', '.join(missing)}")
        if unexpected:
            details.append(f"unexpected vsId(s): {', '.join(unexpected)}")
        raise RuntimeError("calculator responses do not match the ACVP session (" +
                           "; ".join(details) + ")")
    return [by_vsid[vsid] for vsid in expected]


def write_vector_files(combined_req: Path) -> list[Path]:
    """Split a combined acvp_app vector request file into per-vsId files.

    Also writes vectors/combined.json in ACVP prompt-list format
    ([{acvVersion}, {vsId...}, ...]) for use with the CEmu runner.
    """
    if VECTORS_DIR.exists():
        shutil.rmtree(VECTORS_DIR)
    VECTORS_DIR.mkdir()
    data = json.loads(combined_req.read_text())
    # libacvp request-only files are [session metadata, vector set, ...].
    # The metadata is required again for --vector_upload but must never be
    # presented to the calculator as an algorithm vector set.
    if not isinstance(data, list) or len(data) < 2 or not isinstance(data[0], dict):
        raise RuntimeError("libacvp vector request has an unexpected structure")
    context = data[0]
    required = ("url", "jwt", "vectorSetUrls")
    if any(name not in context for name in required):
        raise RuntimeError("libacvp vector request is missing session metadata")
    sets = data[1:]
    if not all(isinstance(vs, dict) and "vsId" in vs and "algorithm" in vs
               for vs in sets):
        raise RuntimeError("libacvp vector request contains a malformed vector set")
    _secure_write(UPLOAD_CONTEXT_FILE, context)
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
    context = _load_upload_context()
    RESPONSES_DIR.mkdir(exist_ok=True)
    cemu_combined = RESPONSES_DIR / "combined.json"
    if cemu_combined.exists():
        # CEmu writes [ACVP version header, response, ...].  libacvp upload
        # requires [session metadata, response, ...].
        data = json.loads(cemu_combined.read_text())
        if (not isinstance(data, list) or not data or
                not isinstance(data[0], dict) or "acvVersion" not in data[0]):
            raise RuntimeError("calculator response has an unexpected structure")
        items = data[1:]
        if not items or not all(isinstance(item, dict) and "vsId" in item
                                for item in items):
            raise RuntimeError("calculator response contains no vector-set responses")
        items = _order_and_validate_responses(context, items)
        for item in items:
            vsid = item.get("vsId", "unknown")
            (RESPONSES_DIR / f"{vsid}.json").write_text(
                json.dumps(item, indent=2) + "\n")
        combined = HERE / "combined_responses.json"
        _secure_write(combined, [context, *items])
        return combined
    responses = []
    for f in sorted(RESPONSES_DIR.glob("*.json")):
        if f.name == "combined.json":
            continue
        responses.append(json.loads(f.read_text()))
    combined = HERE / "combined_responses.json"
    if not responses:
        raise RuntimeError("no calculator responses are available for upload")
    responses = _order_and_validate_responses(context, responses)
    _secure_write(combined, [context, *responses])
    return combined


def cmd_fetch(args: argparse.Namespace) -> int:
    build_libacvp()
    env = acvp_env()
    validate_credentials(env)
    combined_req = HERE / "vectors_combined.json"
    combined_req.unlink(missing_ok=True)
    SESSION_FILE.unlink(missing_ok=True)
    UPLOAD_CONTEXT_FILE.unlink(missing_ok=True)
    for old_session in HERE.glob("acvpLiveSession*.json"):
        old_session.unlink()

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
    combined_req.unlink(missing_ok=True)
    print(f"Downloaded {len(paths)} vector set(s) to {VECTORS_DIR}/", flush=True)

    # Save the session file path for submit step
    sessions = list(HERE.glob("acvpLiveSession*.json"))
    if sessions:
        if len(sessions) != 1:
            raise RuntimeError(f"expected one ACVP session file, found {len(sessions)}")
        newest = sessions[0]
        newest.replace(SESSION_FILE)
        SESSION_FILE.chmod(0o600)
        print(f"Session saved to {SESSION_FILE}", flush=True)
    else:
        print("libacvp did not create a session file", file=sys.stderr)
        return 1

    return 0


def cmd_get_results(args: argparse.Namespace) -> int:
    build_libacvp()
    env = acvp_env()
    validate_credentials(env)

    session = args.session or SESSION_FILE
    if not Path(session).exists():
        print(f"Session file not found: {session}", file=sys.stderr)
        print("Run --fetch first, or pass --session <path>", file=sys.stderr)
        return 1

    print("Fetching grading results from NIST ACVP...", flush=True)
    result = subprocess.run(
        [
            str(ACVP_APP),
            "--get_results", str(session),
            "--disable_fips",
        ],
        env=env,
        cwd=str(LIBACVP_DIR),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    output = result.stdout or ""
    RESULTS_LOG.write_text(output)
    print(output, end="" if output.endswith("\n") else "\n")
    passed = result.returncode == 0 and "Passed all vectors in test session!" in output
    session_data = json.loads(Path(session).read_text())
    session_url = session_data.get("url") if isinstance(session_data, dict) else None
    session_id = None
    if isinstance(session_url, str):
        candidate = session_url.rstrip("/").rsplit("/", 1)[-1]
        if candidate.isdigit():
            session_id = int(candidate)
    RESULTS_FILE.write_text(json.dumps({
        "passed": passed,
        "test_session_id": session_id,
        "acvp_app_status": result.returncode,
        "log": RESULTS_LOG.name,
    }, indent=2) + "\n")
    if not passed:
        print("NIST ACVP grading did not report a passing test session", file=sys.stderr)
        return 1
    return 0


def cmd_submit(args: argparse.Namespace) -> int:
    build_libacvp()
    env = acvp_env()
    validate_credentials(env)

    session = args.session or SESSION_FILE
    if not Path(session).exists():
        print(f"Session file not found: {session}", file=sys.stderr)
        print("Run --fetch first, or pass --session <path>", file=sys.stderr)
        return 1

    combined_rsp = collect_responses()
    n = len(json.loads(combined_rsp.read_text())) - 1
    print(f"Uploading {n} response(s) to NIST ACVP...", flush=True)

    result = subprocess.run(
        [
            str(ACVP_APP),
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
    try:
        sys.exit(main())
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError,
            subprocess.SubprocessError) as exc:
        print(f"ACVP offline error: {exc}", file=sys.stderr)
        sys.exit(1)

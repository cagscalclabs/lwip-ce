#!/usr/bin/env python3
"""Run the locally reproducible lwIP-CE test workflow end to end."""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
USB_STEP = "usb|eth,cemu0,dhcp=192.168.84.2/24,gw=192.168.84.1,dns=192.168.84.1"


class LocalTestError(RuntimeError):
    pass


def enabled(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def show(command: list[str]) -> str:
    return " ".join(subprocess.list2cmdline([item]) for item in command)


def run(
    name: str,
    command: list[str],
    *,
    env: dict[str, str],
    check: bool = False,
    informational: bool = False,
) -> int:
    print(f"\n===== {name} =====", flush=True)
    print(f"+ {show(command)}", flush=True)
    result = subprocess.run(command, cwd=ROOT, env=env, check=False)
    label = "PASS" if result.returncode == 0 else (
        "INFO-FAIL" if informational else "FAIL"
    )
    print(f"===== {name}: {label} =====", flush=True)
    if check and result.returncode:
        raise LocalTestError(f"{name} failed with status {result.returncode}")
    return result.returncode


def require_file(path: Path, label: str) -> Path:
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise LocalTestError(f"{label} does not exist: {resolved}")
    return resolved


def host_tests(env: dict[str, str]) -> int:
    tests = sorted((ROOT / "tests/host").glob("*/run.py"))
    tests.extend(sorted((ROOT / "tests/host").glob("*/test_*.py")))
    failures = 0
    for test in tests:
        failures += run(
            f"host/{test.parent.name}/{test.stem}",
            [sys.executable, str(test)],
            env=env,
        ) != 0
    return failures


def root_command(command: list[str], env: dict[str, str]) -> list[str]:
    environment = [
        f"PATH={env['PATH']}",
        f"CEDEV={env.get('CEDEV', '')}",
        f"AUTOTESTER_IMAGE={env['AUTOTESTER_IMAGE']}",
    ]
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return ["env", *environment, *command]
    if shutil.which("sudo") is None:
        raise LocalTestError("network tests require root and sudo is unavailable")
    return ["sudo", "env", *environment, *command]


def raw_rom_root_command(command: list[str], env: dict[str, str]) -> list[str]:
    environment = [
        "-u", "AUTOTESTER_IMAGE",
        f"PATH={env['PATH']}",
        f"CEDEV={env.get('CEDEV', '')}",
        f"AUTOTESTER_ROM={env['AUTOTESTER_ROM']}",
    ]
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return ["env", *environment, *command]
    if shutil.which("sudo") is None:
        raise LocalTestError("network tests require root and sudo is unavailable")
    return ["sudo", "env", *environment, *command]


def network_tests(
    env: dict[str, str], results: Path, autotester: Path, signer: Path
) -> int:
    if platform.system() != "Linux":
        raise LocalTestError("network, ACVP, and DAST emulator tests require Linux namespaces")
    for program in ("ip", "iptables", "sysctl"):
        if shutil.which(program) is None:
            raise LocalTestError(f"network tests require {program}")
    convbin = shutil.which("convbin", path=env["PATH"])
    if not convbin:
        raise LocalTestError("network tests require convbin in PATH")

    failures = 0
    validation = ROOT / "tests/validation/acvp"
    acvp_command = [
        sys.executable, str(ROOT / ".github/scripts/run_acvp_tests.py"),
        str(ROOT / "tests/acvp"),
        "--validation-dir", str(validation),
        "--autotester", str(autotester),
        "--usb", USB_STEP,
        "--prompt", str(validation / "corpus/prompt.json"),
        "--expected", str(validation / "corpus/expected.json"),
        "--oracle", str(validation / "corpus/oracle.json"),
        "--response", str(results / "acvp-response.json"),
        "--output", str(results / "results-acvp.json"),
        "--artifacts-dir", str(results / "acvp-units"),
        "--timeout-ms", "60000000",
    ]
    failures += run(
        "ACVP calculator validation", root_command(acvp_command, env), env=env
    ) != 0

    net_command = [
        sys.executable, str(ROOT / ".github/scripts/run_nettests.py"),
        str(ROOT / "tests/net"),
        "--autotester", str(autotester),
        "--usb", USB_STEP,
        "--truststore-signer", str(signer),
        "--convbin", convbin,
        "--output", str(results / "results-net.json"),
        "--rows", str(results / "test-rows-net.json"),
        "--metrics", str(results / "metrics-net.json"),
        "--endpoint-probes", str(results / "endpoint-probes.json"),
        "--artifacts-dir", str(results / "net-artifacts"),
    ]
    failures += run(
        "network calculator suites", root_command(net_command, env), env=env
    ) != 0

    dast_dir = ROOT / "tests/profiling/lwip_dast"
    failures += run(
        "generate DAST calculator manifest",
        [sys.executable, str(ROOT / "build-tools/dast/lwip-dast.py"), "--gen-header"],
        env=env,
    ) != 0
    failures += run(
        "verify DAST manifest",
        [
            "git", "diff", "--exit-code", "--",
            "tests/profiling/lwip_dast/src/dast_tests.h",
        ],
        env=env,
    ) != 0
    failures += run(
        "build DAST calculator program",
        ["make", "-C", str(dast_dir), f"RELEASE_ROOT={ROOT / 'build'}"],
        env=env,
    ) != 0
    dast_command = [
        sys.executable, str(dast_dir / "ci.py"),
        "--autotester", str(autotester), "--usb", USB_STEP,
    ]
    failures += run(
        "live DAST probes", raw_rom_root_command(dast_command, env), env=env
    ) != 0
    failures += run(
        "render DAST report",
        [sys.executable, str(ROOT / "build-tools/dast/dast_report.py")], env=env,
    ) != 0
    return failures


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--rom", type=Path,
        default=Path(os.environ["AUTOTESTER_ROM"]) if os.environ.get("AUTOTESTER_ROM") else None,
        help="local CE ROM (default: AUTOTESTER_ROM)",
    )
    parser.add_argument(
        "--work-dir", type=Path, default=ROOT / "build/local-tests",
        help="prepared image, tools, logs, and JSON results",
    )
    parser.add_argument(
        "--fuzz-seconds", type=int,
        default=int(os.environ.get("FUZZ_SECONDS", "300")),
    )
    parser.add_argument(
        "--network", action="store_true", default=enabled(os.environ.get("LOCAL_NETWORK_TESTS")),
        help="also run Linux/root network, calculator ACVP, and DAST-capable suites",
    )
    parser.add_argument(
        "--truststore-signer", type=Path,
        default=(Path(os.environ["TRUSTSTORE_SIGNER_FILE"])
                 if os.environ.get("TRUSTSTORE_SIGNER_FILE") else None),
        help="private key used to sign the temporary local TLS truststore",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.rom is None:
        raise LocalTestError(
            "set AUTOTESTER_ROM=/path/to/ce.rom or pass --rom; the ROM is never bundled"
        )
    if args.fuzz_seconds < 1:
        raise LocalTestError("FUZZ_SECONDS must be positive")
    rom = require_file(args.rom, "ROM")
    signer = None
    if args.network:
        if args.truststore_signer is None:
            raise LocalTestError(
                "LOCAL_NETWORK_TESTS=1 also requires TRUSTSTORE_SIGNER_FILE"
            )
        signer = require_file(args.truststore_signer, "truststore signer")

    results = args.work_dir.resolve()
    tools = results / "bin"
    image = results / "ce-patched.ce"
    autotester = tools / "cemu-autotester"
    results.mkdir(parents=True, exist_ok=True)
    tools.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["PATH"] = os.pathsep.join([str(tools), env.get("PATH", "")])
    env["AUTOTESTER_ROM"] = str(rom)
    env["AUTOTESTER_IMAGE"] = str(image)
    env.setdefault("CEDEV", str(Path(shutil.which("cedev-config") or "").parent.parent))

    prepare = [
        sys.executable, str(ROOT / ".github/scripts/prepare_cemu_image.py"),
        "--rom", str(rom),
        "--release", str(ROOT / "build"),
        "--output", str(image),
        "--autotester-output", str(autotester),
        "--headless-output", str(tools / "cemu-headless"),
        "--work-dir", str(results / "CEmu"),
    ]
    run("prepare CEmu image", prepare, env=env, check=True)

    failures = 0
    failures += run(
        "calculator unit tests",
        [
            sys.executable, str(ROOT / ".github/scripts/run_unit_tests.py"),
            str(ROOT / "tests/unit"), "--output", str(results / "results-unit.json"),
        ],
        env=env,
    ) != 0

    failures += host_tests(env)

    validation = ROOT / "tests/validation/acvp"
    failures += run(
        "generate ACVP differential corpus",
        [sys.executable, str(validation / "generate_vectors.py")], env=env,
    ) != 0
    failures += run(
        "ACVP host self-test",
        [sys.executable, str(validation / "selftest.py")], env=env,
    ) != 0

    failures += run(
        "fuzz targets",
        [
            sys.executable, str(ROOT / ".github/scripts/run_fuzz_tests.py"),
            str(ROOT / "tests/fuzz"),
            "--seconds", str(args.fuzz_seconds),
            "--output", str(results / "results-fuzz.json"),
            "--rows", str(results / "test-rows-fuzz.json"),
            "--artifacts-dir", str(results / "fuzz-logs"),
        ],
        env=env,
    ) != 0

    benchmark_dir = ROOT / "tests/profiling/primitives_bench"
    benchmark_rc = run(
        "build informational benchmark",
        ["make", "-C", str(benchmark_dir)], env=env, informational=True,
    )
    if benchmark_rc == 0:
        run(
            "run informational benchmark",
            [str(autotester), str(benchmark_dir / "autotest.json")],
            env=env,
            informational=True,
        )

    if args.network:
        assert signer is not None
        failures += network_tests(env, results, autotester, signer)
    else:
        print(
            "\nSKIP network/ACVP-emulator/DAST stages: set LOCAL_NETWORK_TESTS=1 "
            "and TRUSTSTORE_SIGNER_FILE on Linux to enable them."
        )

    print("SKIP CodeQL, GitHub artifact checks, and PR RFC review: CI-only services.")
    print(f"\nLocal workflow complete: {failures} gating stage(s) failed.")
    return min(failures, 125)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LocalTestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)

#!/usr/bin/env python3
"""Build patched CEmu tools and install a local lwIP release into a ROM image.

This is the shared implementation used by CI and local developers.  It does
not download or decrypt a calculator ROM.  Supply a ROM you are authorized to
use and a release directory produced by ``make dylib``.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
VERSIONS_FILE = ROOT / ".github" / "ci-versions.env"
AUTOTESTER_PATCH = ROOT / "build-tools" / "patches" / "cemu-autotester.patch"
CEMU_REPOSITORY = "https://github.com/alessiodam/CEmu-lwIP-CE.git"
CLIBS_URL = (
    "https://github.com/CE-Programming/libraries/releases/latest/download/"
    "clibs.8xg"
)


class PreparationError(RuntimeError):
    """A reproducible image-preparation step failed."""


def pinned_version(name: str) -> str:
    for raw_line in VERSIONS_FILE.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key == name and value:
            return value
    raise PreparationError(f"{name} is missing from {VERSIONS_FILE}")


def display_command(command: list[str]) -> str:
    return " ".join(subprocess.list2cmdline([part]) for part in command)


def run(
    command: list[str],
    *,
    cwd: Path | None = None,
    input_text: str | None = None,
    capture: bool = False,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    print(f"+ {display_command(command)}", flush=True)
    result = subprocess.run(
        command,
        cwd=cwd,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
        check=False,
    )
    if check and result.returncode != 0:
        if result.stdout:
            print(result.stdout, end="" if result.stdout.endswith("\n") else "\n")
        raise PreparationError(
            f"command exited with status {result.returncode}: "
            f"{display_command(command)}"
        )
    return result


def require_program(name: str) -> None:
    if shutil.which(name) is None:
        raise PreparationError(f"required program is not installed: {name}")


def ensure_path_has_no_whitespace(path: Path, label: str) -> None:
    if any(char.isspace() for char in str(path)):
        raise PreparationError(
            f"{label} contains whitespace, which CEmu's command parser cannot quote: {path}"
        )


def prepare_cemu_checkout(cemu_dir: Path, ref: str) -> None:
    git_dir = cemu_dir / ".git"
    if not git_dir.exists():
        if cemu_dir.exists() and any(cemu_dir.iterdir()):
            raise PreparationError(f"CEmu work directory is not empty: {cemu_dir}")
        cemu_dir.mkdir(parents=True, exist_ok=True)
        run(["git", "init", "-q", str(cemu_dir)])
        run([
            "git", "-C", str(cemu_dir), "fetch", "-q", "--depth", "1",
            CEMU_REPOSITORY, ref,
        ])
        run(["git", "-C", str(cemu_dir), "checkout", "-q", "--detach", "FETCH_HEAD"])
    else:
        head = run(
            ["git", "-C", str(cemu_dir), "rev-parse", "HEAD"], capture=True
        ).stdout.strip()
        expected = run(
            ["git", "-C", str(cemu_dir), "rev-parse", f"{ref}^{{commit}}"],
            capture=True,
            check=False,
        )
        if expected.returncode != 0:
            run([
                "git", "-C", str(cemu_dir), "fetch", "-q", "--depth", "1",
                CEMU_REPOSITORY, ref,
            ])
            expected_sha = run(
                ["git", "-C", str(cemu_dir), "rev-parse", "FETCH_HEAD"], capture=True
            ).stdout.strip()
        else:
            expected_sha = expected.stdout.strip()
        if head != expected_sha:
            raise PreparationError(
                f"existing CEmu checkout is at {head}, expected {expected_sha}; "
                "use an empty --work-dir"
            )

    run([
        "git", "-C", str(cemu_dir), "submodule", "update", "-q", "--init",
        "--depth", "1",
    ])


def apply_autotester_patch(cemu_dir: Path) -> None:
    check = run(
        ["git", "-C", str(cemu_dir), "apply", "--check", str(AUTOTESTER_PATCH)],
        capture=True,
        check=False,
    )
    if check.returncode == 0:
        run(["git", "-C", str(cemu_dir), "apply", str(AUTOTESTER_PATCH)])
        return

    reverse = run(
        [
            "git", "-C", str(cemu_dir), "apply", "--reverse", "--check",
            str(AUTOTESTER_PATCH),
        ],
        capture=True,
        check=False,
    )
    if reverse.returncode != 0:
        raise PreparationError(
            "cemu-autotester.patch neither applies cleanly nor is already applied"
        )
    print("CEmu autotester patch is already applied.")


def patch_build_ninja(build_dir: Path, core_dir: Path) -> None:
    """Fix GNU ld link-order bug in CEmu's generated build.ninja.

    CMakeLists.txt puts -lcemucore in CMAKE_EXE_LINKER_FLAGS, which the
    Ninja link rule expands before the object files.  GNU ld's left-to-right
    pass then leaves both directions of the archive↔frontend mutual dependency
    unresolved (emu_run etc. and gui_console_printf etc.).

    Fix: remove -lcemucore from LINK_FLAGS, correct the relative -L path to
    an absolute one, and inject LINK_LIBRARIES = /abs/path/libcemucore.a into
    each executable's build block — LINK_LIBRARIES expands after $in (the .o
    files), so the archive is seen last and both directions resolve.
    """
    import re as _re
    cemucore_a = str(core_dir / "libcemucore.a")
    ninja = build_dir / "build.ninja"
    text = ninja.read_text(encoding="utf-8")
    text = _re.sub(r"-L\S*core/?", f"-L{core_dir}", text)
    text = text.replace("-lcemucore", "")
    for target in ("cemu-headless", "autotester"):
        text = _re.sub(
            rf"(build {_re.escape(target)}:.*?)(  TARGET_SUPPORT_DIR = [^\n]+)",
            rf"\1\2\n  LINK_LIBRARIES = {cemucore_a}",
            text, flags=_re.S,
        )
    ninja.write_text(text, encoding="utf-8")
    print(f"build.ninja patched: {cemucore_a} moved to LINK_LIBRARIES (after objects)")


def build_cemu_tools(cemu_dir: Path, jobs: int) -> tuple[Path, Path]:
    run(["make", "-C", str(cemu_dir / "core"), f"-j{jobs}"])
    apply_autotester_patch(cemu_dir)

    build_dir = cemu_dir / "build"
    run([
        "cmake", "-S", str(cemu_dir / "tests" / "autotester"),
        "-B", str(build_dir), "-DCMAKE_BUILD_TYPE=Release", "-GNinja",
    ])
    patch_build_ninja(build_dir, cemu_dir / "core")
    run(["cmake", "--build", str(build_dir), f"-j{jobs}"])

    headless = build_dir / "cemu-headless"
    autotester = build_dir / "autotester"
    if not headless.is_file() or not autotester.is_file():
        raise PreparationError("CEmu build did not produce both required executables")
    if b"AUTOTESTER_IMAGE" not in autotester.read_bytes():
        raise PreparationError("built autotester does not contain image-loading support")
    return headless, autotester


def download_clibs(destination: Path) -> None:
    print(f"Downloading {CLIBS_URL} -> {destination}")
    request = urllib.request.Request(CLIBS_URL, headers={"User-Agent": "lwip-ce-ci"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            with destination.open("wb") as output:
                shutil.copyfileobj(response, output)
    except OSError as exc:
        raise PreparationError(f"could not download clibs.8xg: {exc}") from exc


def release_files(release_dir: Path) -> list[Path]:
    files = [release_dir / "lwip.8xv"]
    files.extend(
        path for path in sorted((release_dir / "appinst").glob("LWIP.*.8xv"))
        if not path.name.startswith("._")
    )
    files.append(release_dir / "appinst" / "lwIPINST.8xp")
    missing = [path for path in files if not path.is_file()]
    if missing:
        raise PreparationError(
            "release is incomplete; missing: " + ", ".join(str(path) for path in missing)
        )
    if len(files) == 2:
        raise PreparationError(f"no LWIP.*.8xv application variables found in {release_dir}")
    return files


# FNV-1a hash of the full 320x240 frame for the installer's completion
# screen ("Successfully installed. App: lwIP"). The installer is built from
# this repo and the CEmu ROM/toolchain is pinned, so this is stable. If the
# installer UI text changes, update this constant; the wait fails closed
# rather than saving a half-installed image.
INSTALLED_SCREEN_HASH = "F104ABEC"
INSTALL_POLL_STEP_MS = 1000
INSTALL_TIMEOUT_MS = 300000


def installer_commands(clibs: Path, release_dir: Path) -> list[str]:
    """Commands that stage every release file and start the installer."""
    commands = [f"send-file auto {clibs}"]
    commands.extend(f"send-file auto {path}" for path in release_files(release_dir))
    commands.extend(["run 5000", "launch INSTALL asm"])
    return commands


def installer_finish_commands(output: Path) -> list[str]:
    """Dismiss the completion prompt, settle, and save the prepared image."""
    return ["key left", "key enter", "run 5000", f"save-state {output}", "quit"]


def _headless_send(process: subprocess.Popen[str], command: str) -> str:
    process.stdin.write(command + "\n")
    process.stdin.flush()
    while True:
        line = process.stdout.readline()
        if not line:
            raise PreparationError(f"cemu-headless exited while running: {command}")
        line = line.rstrip("\n")
        if line.startswith("ERR "):
            raise PreparationError(f"cemu-headless rejected {command!r}: {line}")
        if line.startswith("OK "):
            return line
        # Startup diagnostics and USB transfer progress are not responses.


def install_release(
    headless: Path, rom: Path, release_dir: Path, clibs: Path, output: Path
) -> None:
    for path, label in (
        (rom, "ROM path"),
        (release_dir, "release path"),
        (clibs, "clibs path"),
        (output, "output path"),
    ):
        ensure_path_has_no_whitespace(path, label)

    output.parent.mkdir(parents=True, exist_ok=True)
    process = subprocess.Popen(
        [str(headless), "--rom", str(rom)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    try:
        for command in installer_commands(clibs, release_dir):
            _headless_send(process, command)

        waited = 0
        screen_hash = "?"
        while waited < INSTALL_TIMEOUT_MS:
            _headless_send(process, f"run {INSTALL_POLL_STEP_MS}")
            waited += INSTALL_POLL_STEP_MS
            response = _headless_send(process, "screen-hash")
            screen_hash = response.rsplit(" ", 1)[-1]
            if screen_hash == INSTALLED_SCREEN_HASH:
                break
        else:
            raise PreparationError(
                "installer did not reach its completion screen within "
                f"{INSTALL_TIMEOUT_MS} ms (last hash {screen_hash})"
            )

        for command in installer_finish_commands(output):
            _headless_send(process, command)
        process.wait(timeout=60)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()

    if not output.is_file():
        raise PreparationError(f"CEmu did not create the prepared image: {output}")


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rom", required=True, type=Path, help="decrypted CE ROM")
    parser.add_argument(
        "--release", required=True, type=Path,
        help="lwIP release directory (normally ./build after make dylib)",
    )
    parser.add_argument("--output", required=True, type=Path, help="prepared .ce image")
    parser.add_argument(
        "--autotester-output", type=Path,
        help="destination for the patched autotester (default: beside --output)",
    )
    parser.add_argument(
        "--headless-output", type=Path,
        help="optional destination for cemu-headless",
    )
    parser.add_argument("--clibs", type=Path, help="existing clibs.8xg; otherwise download it")
    parser.add_argument(
        "--work-dir", type=Path,
        help="persistent CEmu checkout/build directory (default: temporary)",
    )
    parser.add_argument(
        "--jobs", type=positive_int, default=max(1, os.cpu_count() or 1),
        help="parallel build jobs (default: CPU count)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    rom = args.rom.resolve()
    release_dir = args.release.resolve()
    output = args.output.resolve()
    autotester_output = (
        args.autotester_output.resolve()
        if args.autotester_output
        else output.with_name("cemu-autotester-image")
    )
    headless_output = args.headless_output.resolve() if args.headless_output else None

    if not rom.is_file():
        raise PreparationError(f"ROM does not exist: {rom}")
    if not release_dir.is_dir():
        raise PreparationError(f"release directory does not exist: {release_dir}")
    release_files(release_dir)
    for program in ("git", "make", "cmake", "ninja"):
        require_program(program)

    temporary: tempfile.TemporaryDirectory[str] | None = None
    if args.work_dir:
        cemu_dir = args.work_dir.resolve()
    else:
        temporary = tempfile.TemporaryDirectory(prefix="lwip-ce-cemu-")
        cemu_dir = Path(temporary.name) / "CEmu"

    try:
        prepare_cemu_checkout(cemu_dir, pinned_version("CEMU_REF"))
        headless, autotester = build_cemu_tools(cemu_dir, args.jobs)

        if args.clibs:
            clibs = args.clibs.resolve()
            if not clibs.is_file():
                raise PreparationError(f"clibs.8xg does not exist: {clibs}")
        else:
            clibs = cemu_dir.parent / "clibs.8xg"
            download_clibs(clibs)

        install_release(headless, rom, release_dir, clibs, output)

        autotester_output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(autotester, autotester_output)
        autotester_output.chmod(autotester_output.stat().st_mode | 0o111)
        if headless_output:
            headless_output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(headless, headless_output)
            headless_output.chmod(headless_output.stat().st_mode | 0o111)
    finally:
        if temporary is not None:
            temporary.cleanup()

    print(f"Prepared CEmu image: {output}")
    print(f"Patched autotester: {autotester_output}")
    print(f"Run units with AUTOTESTER_IMAGE={output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PreparationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)

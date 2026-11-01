import importlib.util
import tempfile
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[3] / ".github/scripts/prepare_cemu_image.py"
SPEC = importlib.util.spec_from_file_location("prepare_cemu_image", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def make_release(root: Path) -> tuple[Path, Path, Path, Path]:
    release = root / "release"
    appinst = release / "appinst"
    appinst.mkdir(parents=True)
    lwip = release / "lwip.8xv"
    appvar = appinst / "LWIP.TEST.8xv"
    installer = appinst / "lwIPINST.8xp"
    for path in (lwip, appvar, installer):
        path.write_bytes(b"test")
    return release, lwip, appvar, installer


def test_installer_commands_match_ci_sequence() -> None:
    with tempfile.TemporaryDirectory() as raw_dir:
        root = Path(raw_dir)
        release, lwip, appvar, installer = make_release(root)
        clibs = root / "clibs.8xg"
        output = root / "prepared.ce"

        assert MODULE.installer_commands(clibs, release) == [
            f"send-file auto {clibs}",
            f"send-file auto {lwip}",
            f"send-file auto {appvar}",
            f"send-file auto {installer}",
            "run 5000",
            "launch INSTALL asm",
        ]
        assert MODULE.installer_finish_commands(output) == [
            "key left",
            "key enter",
            "run 5000",
            f"save-state {output}",
            "quit",
        ]


def test_installer_wait_is_deterministic() -> None:
    assert MODULE.INSTALLED_SCREEN_HASH
    assert MODULE.INSTALL_POLL_STEP_MS > 0
    assert MODULE.INSTALL_TIMEOUT_MS >= MODULE.INSTALL_POLL_STEP_MS


def test_release_files_rejects_missing_appvars() -> None:
    with tempfile.TemporaryDirectory() as raw_dir:
        root = Path(raw_dir)
        release, _, appvar, _ = make_release(root)
        appvar.unlink()
        try:
            MODULE.release_files(release)
        except MODULE.PreparationError as exc:
            assert "no LWIP.*.8xv" in str(exc)
        else:
            raise AssertionError("incomplete release was accepted")


if __name__ == "__main__":
    test_installer_commands_match_ci_sequence()
    test_installer_wait_is_deterministic()
    test_release_files_rejects_missing_appvars()
    print("CEmu image preparation self-test: PASS")

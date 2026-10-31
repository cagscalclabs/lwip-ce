#!/usr/bin/env python3
"""Patch CEmu's generated build.ninja to fix GNU ld link order.

CEmu's CMakeLists.txt puts -lcemucore in CMAKE_EXE_LINKER_FLAGS, which
Ninja's link rule expands as:

    c++ FLAGS LINK_FLAGS <objects> LINK_PATH LINK_LIBRARIES

So -lcemucore fires before the .o files — GNU ld's left-to-right pass
leaves symbols from libcemucore.a unresolved when the archive is listed
before the objects that reference it (and vice-versa for gui_console_*
which the archive calls into the frontend objects).

Fix: strip -lcemucore from LINK_FLAGS and inject LINK_LIBRARIES = -lcemucore
into the cemu-headless build block. LINK_LIBRARIES is expanded after $in
(the .o files), so the archive is seen last — both directions resolved.
"""

import re
import sys
from pathlib import Path

if len(sys.argv) != 3:
    raise SystemExit(f"usage: {Path(sys.argv[0]).name} BUILD_NINJA CEMU_CORE_DIR")

ninja_path = Path(sys.argv[1])
# Absolute path to the core/ directory where libcemucore.a lives.
# sys.argv[2] is $RUNNER_TEMP/CEmu/core (passed from the CI step).
core_dir = Path(sys.argv[2]).resolve()
cemucore_a = core_dir / "libcemucore.a"

if not ninja_path.is_file():
    raise SystemExit(f"build.ninja not found: {ninja_path}")
if not cemucore_a.is_file():
    raise SystemExit(f"CEmu core archive not found: {cemucore_a}")

text = ninja_path.read_text()

# Replace the relative -L../../core/ (wrong from the build dir) with the
# absolute path, and strip -lcemucore from LINK_FLAGS entirely so it no
# longer appears before the object files.
library_flags = text.count("-lcemucore")
if library_flags == 0:
    raise SystemExit("build.ninja contains no -lcemucore flags to relocate")
text = re.sub(r"-L\S*core/?", "", text)
text = text.replace("-lcemucore", "")

# Inject the archive immediately below each executable's ``build`` edge.
# Per-edge variables may appear in any order in Ninja.  Do not anchor this to
# TARGET_SUPPORT_DIR: CMake emits that field on macOS but omits it on Linux,
# which previously made the patch silently do nothing in GitHub Actions.
for target in ("cemu-headless", "autotester"):
    text, replacements = re.subn(
        rf"^(build {re.escape(target)}:[^\n]+)$",
        rf"\1\n  LINK_LIBRARIES = {cemucore_a}",
        text,
        count=1,
        flags=re.M,
    )
    if replacements != 1:
        raise SystemExit(
            f"expected one Ninja build edge for {target}, found {replacements}"
        )

if "-lcemucore" in text:
    raise SystemExit("failed to remove every early -lcemucore flag")

ninja_path.write_text(text)
print(
    f"build.ninja patched: relocated {library_flags} -lcemucore flag(s); "
    f"injected {cemucore_a} after each target's objects"
)

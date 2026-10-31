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

import os
import re
import sys

ninja_path = sys.argv[1]
# Absolute path to the core/ directory where libcemucore.a lives.
# sys.argv[2] is $RUNNER_TEMP/CEmu/core (passed from the CI step).
core_dir = sys.argv[2]
cemucore_a = os.path.join(core_dir, "libcemucore.a")

text = open(ninja_path).read()

# Replace the relative -L../../core/ (wrong from the build dir) with the
# absolute path, and strip -lcemucore from LINK_FLAGS entirely so it no
# longer appears before the object files.
text = re.sub(r"-L\S*core/?", f"-L{core_dir}", text)
text = text.replace("-lcemucore", "")

# Inject the archive by absolute path into LINK_LIBRARIES for both targets
# (cemu-headless and autotester).  LINK_LIBRARIES expands after $in (the .o
# files) in the Ninja link rule, so GNU ld sees the archive last — resolving
# both directions: .o → archive (emu_run etc.) and archive → .o
# (gui_console_printf etc.).
for target in ("cemu-headless", "autotester"):
    text = re.sub(
        rf"(build {re.escape(target)}:.*?)(  TARGET_SUPPORT_DIR = [^\n]+)",
        rf"\1\2\n  LINK_LIBRARIES = {cemucore_a}",
        text,
        flags=re.S,
    )

open(ninja_path, "w").write(text)
print(f"build.ninja patched: {cemucore_a} injected into LINK_LIBRARIES (after objects)")

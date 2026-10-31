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

path = sys.argv[1]
text = open(path).read()

text = text.replace("-lcemucore", "")

text = re.sub(
    r"(build cemu-headless:.*?)(  TARGET_SUPPORT_DIR = [^\n]+)",
    r"\1\2\n  LINK_LIBRARIES = -lcemucore",
    text,
    flags=re.S,
)

open(path, "w").write(text)
print("build.ninja patched: -lcemucore moved to LINK_LIBRARIES (after objects)")

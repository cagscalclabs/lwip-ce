# ----------------------------
# Makefile Options
# ----------------------------

NAME = lwIP
ICON = icon.png
DESCRIPTION = "lwIP-CE Network Stack"
COMPRESSED = NO
ARCHIVED = NO

CFLAGS = -Wall -Wextra -Oz -I src/include
CXXFLAGS = -Wall -Wextra -Oz -I src/include
ASFLAGS = -I src/tls/core -I src/tls/core/share

# Use a project-local copy of the application linker script (the
# toolchain's meta/linker_script_app.ld plus the fixed early lwIP dylib
# export descriptor and the folded-in X25519 relocation sections —
# formerly a separate supplementary -T linker script, now only used by
# the standalone tests as tests/common/x25519_reloc.ld).
# Set before the toolchain include so its `LINKER_SCRIPT ?=` default
# does not win.
LINKER_SCRIPT = $(CURDIR)/build-tools/meta/linker_script_lwip.ld

# Memory layout contract:
#
#   lwIP app (this build):
#     BSSHEAP_LOW  = 0xD052C6   (toolchain default for flash apps)
#     BSSHEAP_HIGH = BSSHEAP_LOW + 8 KiB = 0xD072C6
#     The 8 KiB window holds the app's own .bss and .data at runtime
#     (~6.6 KiB used, the remainder is headroom for API growth).
#
#   Consumer apps using lwIP:
#     BSSHEAP_LOW  >= 0xD072C6  (= this build's BSSHEAP_HIGH)
#     so the consumer's BSS starts above lwIP-app's reserved window.
#
# Override BSSHEAP_HIGH before the toolchain include so its `?=` default
# does not win.
BSSHEAP_HIGH = 0xD072C6

LTO = NO
CEDEV_TOOLCHAIN ?= $(if $(CEDEV),$(CEDEV),$(shell cedev-config --prefix))
# The lwIP resident app provides the LWIP libload symbols; if a previous
# release installed lwip.lib, do not auto-import that stub into the app
# that defines the real functions.
LIBLOAD_LIBS = $(filter-out %/lwip.lib,$(wildcard $(CEDEV_TOOLCHAIN)/lib/libload/*.lib))

APPLICATION = YES
APPLICATION_DESCRIPTION = "lwIP-CE Network Stack"

# ----------------------------

include $(shell cedev-config --makefile)

# The vendored x25519 submodule ships a standalone test harness at
# src/tls/contrib/x25519/src/main.c whose `int main()` collides with
# the project's own src/main.c. The toolchain's rwildcard pulls every
# *.c under src/, so filter that one out and rebuild LINK_CSOURCES /
# OBJECTS as simply-expanded values so downstream rules can't re-expand
# the original recursive recipe. Keeps the submodule pristine.
CSOURCES := $(filter-out src/tls/contrib/x25519/src/main.c,$(CSOURCES))
LINK_CSOURCES := $(call UPDIR_ADD,$(CSOURCES:%.$(C_EXTENSION)=$(OBJDIR)/%.$(C_EXTENSION).o))
OBJECTS := $(LINK_CSOURCES) $(LINK_CPPSOURCES) $(LINK_ASMSOURCES) $(LINK_PREASMSOURCES)

# Run a full build of this project in dylib mode
# Set `REBUILD_EXPORTS=1` to rebuild the exports table rather than
# append new entries (this will break backwards compatibility).
.PHONY: dylib
dylib:
	make clean
	$(CURDIR)/build-tools/build-release-dylib.sh

# Package output of `make dylib` (and readmes) into `lwip.zip`
.PHONY: release
release:
	@if [ ! -d build ]; then echo "Run 'make dylib' first to produce build/"; exit 1; fi
	cp README.md build/README.md
	cp CHANGELOG.md build/CHANGELOG.md
	cp SECURITY.md build/SECURITY.md
	rm -f lwip.zip
	zip -r lwip.zip build/ \
	    -x "*/obj/*" \
	    -x "*/bin/*" \
	    -x "*/.DS_Store" \
	    -x "*/__MACOSX/*" \
	    -x "*/._*"

# Combine `make dylib` and `make release` into a single command.
# Setting `REBUILD_EXPORTS=1` is valid here too.
.PHONY: dylib-release
dylib-release:
	make dylib
	make release

.PHONY: sizes
sizes:linker_script_app
	@if [ ! -f bin/$(NAME).map ]; then echo "Run 'make' first to produce bin/$(NAME).map"; exit 1; fi
	@printf '\nlwIP-CE memory footprint (from bin/$(NAME).map):\n\n'
	@MAPFILE=bin/$(NAME).map python3 build-tools/scripts/helpers/print_sizes.py
	@printf '\n  Consumer link contract:\n'
	@printf '    --defsym BSSHEAP_LOW=<base>\n'
	@printf '    --defsym BSSHEAP_HIGH=<base + reserve + heap_shared_with_lwip>\n\n'

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
LINKER_SCRIPT = $(CURDIR)/linker_script_lwip.ld

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

# Regenerate src/functable.s from the actual set of public symbols
# emitted by every library .c file, then mirror the public header tree
# to $(LWIP_RELEASE_DIR)/lwip/ (conn.h + cryptography.h + internal/*.h).
# Run after adding/removing any public API. See tools/functable.py for
# the export scanner and tools/header_dump.py for the header generator.
#
# header_dump.py uses libclang, which on this dev machine only loads
# cleanly from the Homebrew python3.11 binary against the Xcode CLT's
# libclang.dylib — pip-install of the bindings is unavailable. Override
# with `make functable HEADER_PYTHON=/path/to/python3` if you have a
# working clang.cindex elsewhere.
#
# Optional local AI doc cleanup:
#   make functable LWIP_AI_DOCSTRINGS=1
# Defaults to qwen2.5-coder:7b via Ollama and caches by generated header
# content. If Ollama is missing, the header generator exits with install
# instructions. CI/release builds should leave this disabled unless
# explicitly preparing refreshed release documentation.
HEADER_PYTHON ?= /opt/homebrew/bin/python3.11
LWIP_RELEASE_DIR ?= $(CURDIR)/build

.PHONY: functable
functable:
	LWIP_RELEASE_DIR="$(LWIP_RELEASE_DIR)" python3 $(CURDIR)/tools/functable.py
	LWIP_RELEASE_DIR="$(LWIP_RELEASE_DIR)" $(HEADER_PYTHON) $(CURDIR)/tools/header_dump.py

# Full dylib release build. The script owns dependency checkout, generated
# package staging under submodules/toolchain/src/lwip, libload make/install,
# and copying the completed package to build/.
.PHONY: dylib
dylib:
	$(CURDIR)/build-release-dylib.sh

# Print section sizes and the contract a libload consumer needs to honor
# when reserving RAM for lwIP's .data + .bss. Run after a build.
#
# The total reserve = ___data_len + ___bss_len. Consumers link with:
#   --defsym BSSHEAP_LOW=<base>
#   --defsym BSSHEAP_HIGH=<base + reserve + heap_shared_with_lwip>
.PHONY: sizes
sizes:
	@if [ ! -f bin/$(NAME).map ]; then echo "Run 'make' first to produce bin/$(NAME).map"; exit 1; fi
	@printf '\nlwIP-CE memory footprint (from bin/$(NAME).map):\n\n'
	@MAPFILE=bin/$(NAME).map python3 tools/print_sizes.py
	@printf '\n  Consumer link contract:\n'
	@printf '    --defsym BSSHEAP_LOW=<base>\n'
	@printf '    --defsym BSSHEAP_HIGH=<base + reserve + heap_shared_with_lwip>\n\n'

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
# toolchain's meta/linker_script_app.ld plus the __lwip_fn_table_off
# export-table offset and the folded-in X25519 relocation sections —
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
# to release/lwip/ (conn.h + cryptography.h + internal/*.h). Run after
# adding/removing any public API. See tools/functable.py for the export
# scanner and tools/header_dump.py for the header generator.
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

.PHONY: functable
functable:
	python3 $(CURDIR)/tools/functable.py
	$(HEADER_PYTHON) $(CURDIR)/tools/header_dump.py

# Full dylib build: produce the lwIP flash app, the libload stub
# (release/lwip.asm) with the export-table offset baked in, and a
# transferable installer (the .8ek can't be sent to a calc directly —
# unsigned flash apps can't be sideloaded — so it is split into AppVars
# that the app_tools installer reconstitutes and flashes on-device).
#
# AppVar split parameters. APPVAR_PREFIX + the decimal index must fit in
# 8 chars (TI var-name limit); APPVAR_SPLIT_SIZE is the per-AppVar payload
# and MUST match between the convbin split and the installer build, or the
# installer's size check rejects the AppVars.
DYLIB_APPVAR_PREFIX = LWIP
DYLIB_APPVAR_SPLIT_SIZE = 65200
APP_TOOLS_INSTALLER = $(CURDIR)/tools/app_tools/installer
#
# Ordering matters. functable.py generates BOTH src/functable.s (the
# in-app export table) and release/lwip.asm (the libload stub whose
# bootstrap needs __lwip_fn_table_off = offset of _fn_exports_table). The
# offset is only known after the app is linked and its map exists, but the
# app build consumes src/functable.s — so we run functable twice:
#
#   1. --append: (re)generate the table append-only (slot-stable ABI) and
#      a provisional stub (offset 0x000000).
#   2. make build: build the app, producing bin/$(NAME).8ek + .map.
#   3. --append --map: re-emit ONLY the stub with the real offset parsed
#      from the map. src/functable.s is byte-identical to pass 1, so the
#      app does not need a rebuild.
#   4. split the .8ek into AppVars and build the installer program; move
#      the installer + AppVars into release/.
#   5. build the libload library (.8xv) from release/lwip.asm.
#
# Step 5 currently assumes the toolchain-source layout (release/makefile
# includes ../common.mk and uses fasmg); it is attempted but not allowed
# to fail the whole target, since the release-layout wiring is handled
# separately.
.PHONY: dylib
dylib:
	python3 $(CURDIR)/tools/functable.py --append
	$(MAKE) build
	python3 $(CURDIR)/tools/functable.py --append --map bin/$(NAME).map
	@echo "==> splitting $(NAME).8ek into installer AppVars ($(DYLIB_APPVAR_PREFIX)*, $(DYLIB_APPVAR_SPLIT_SIZE)B each)"
	$(Q)$(CONVBIN) --iformat 8ek --input bin/$(NAME).8ek \
		--oformat 8xv-split --maxvarsize $(DYLIB_APPVAR_SPLIT_SIZE) \
		--name $(DYLIB_APPVAR_PREFIX) --output release/$(DYLIB_APPVAR_PREFIX).8xv
	@echo "==> building app_tools installer (APPVAR_PREFIX=$(DYLIB_APPVAR_PREFIX), APPVAR_SPLIT_SIZE=$(DYLIB_APPVAR_SPLIT_SIZE))"
	$(Q)$(MAKE) -C $(APP_TOOLS_INSTALLER) \
		APPVAR_PREFIX="$(DYLIB_APPVAR_PREFIX)" \
		APPVAR_SPLIT_SIZE=$(DYLIB_APPVAR_SPLIT_SIZE)
	$(Q)cp $(APP_TOOLS_INSTALLER)/bin/INSTALL.8xp release/$(NAME)INST.8xp
	@echo "==> dylib installer ready in release/: $(NAME)INST.8xp + $(DYLIB_APPVAR_PREFIX)*.8xv"
	@echo "==> building libload stub (release/lwip.asm -> lwip.8xv)"
	@$(MAKE) -C release all || echo "==> NOTE: release lib build skipped/failed (expected outside toolchain-source layout); release/lwip.asm is generated with the offset baked in."

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

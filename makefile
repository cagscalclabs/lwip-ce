# ----------------------------
# Makefile Options
# ----------------------------

NAME = DEMO
ICON = icon.png
DESCRIPTION = "CE Toolchain Demo"
COMPRESSED = NO
ARCHIVED = NO

CFLAGS = -Wall -Wextra -Oz -I src/include
CXXFLAGS = -Wall -Wextra -Oz -I src/include
ASFLAGS = -I src/tls/core -I src/tls/core/share
EXTRA_LDFLAGS += -T src/tls/core/x25519_reloc.ld

LTO = NO

APPLICATION = YES

# ----------------------------

include $(shell cedev-config --makefile)

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

CE_LIBIFY ?= ce-libify
CEDEV_TOOLCHAIN ?= $(if $(CEDEV),$(CEDEV),$(shell cedev-config --prefix))
APP_TOOLS_CACHE := obj/libify/app_tools
APP_TOOLS_INPUTS := ce-libify.toml $(wildcard build-tools/patches/app_tools-*.patch)
APP_TOOLS_INPUT_STAMP := $(APP_TOOLS_CACHE)/.lwip-ce-inputs
X25519_DIR := src/tls/contrib/x25519
X25519_PATCH := build-tools/patches/x25519-scratch-overlay.patch

.PHONY: all build prepare-installer prepare-x25519
all: dylib

# The upstream X25519 submodule declares its working buffer as loadable
# .x25519.data.  lwIP overlays that buffer with the other TLS scratch regions,
# so convert it to an uninitialized, primitive-owned input section before the
# build.  Keep this as a checked-in patch: edits made directly in a submodule
# worktree are not carried by the parent repository and therefore disappear in
# clean CI checkouts.
prepare-x25519:
	@if git -C "$(X25519_DIR)" apply --reverse --check "$(CURDIR)/$(X25519_PATCH)" >/dev/null 2>&1; then \
		:; \
	elif git -C "$(X25519_DIR)" apply --check "$(CURDIR)/$(X25519_PATCH)"; then \
		echo "[x25519] applying TLS scratch-overlay section patch"; \
		git -C "$(X25519_DIR)" apply "$(CURDIR)/$(X25519_PATCH)"; \
	else \
		echo "[x25519] scratch-overlay patch does not apply cleanly" >&2; \
		exit 1; \
	fi

# ce-libify 1.1.2 reuses its app_tools checkout without checking whether the
# selected ref or installer patches changed. Invalidate only that generated
# checkout when one of its inputs is newer, then let ce-libify recreate it.
prepare-installer:
	@if [ -d "$(APP_TOOLS_CACHE)" ]; then \
		refresh=; \
		if [ ! -f "$(APP_TOOLS_INPUT_STAMP)" ]; then \
			refresh=1; \
		else \
			for input in $(APP_TOOLS_INPUTS); do \
				if [ "$$input" -nt "$(APP_TOOLS_INPUT_STAMP)" ]; then \
					refresh=1; \
					break; \
				fi; \
			done; \
		fi; \
		if [ -n "$$refresh" ]; then \
			echo "[installer] invalidating stale app_tools cache"; \
			rm -rf "$(APP_TOOLS_CACHE)"; \
		fi; \
	fi

build: prepare-x25519 prepare-installer
	$(CE_LIBIFY) build
	@if [ -d "$(APP_TOOLS_CACHE)" ]; then \
		touch "$(APP_TOOLS_INPUT_STAMP)"; \
	fi

.PHONY: dylib
dylib: build
	mkdir -p build/appinst
	rm -f build/appinst/LWIP.*.8xv
	cp bin/LWIP.8xv build/lwip.8xv
	cp bin/LWIP.lib build/lwip.lib
	cp bin/LWIP.*.8xv build/appinst/
	cp bin/INSTALL.8xp build/appinst/lwIPINST.8xp
	mkdir -p "$(CEDEV_TOOLCHAIN)/lib/libload" "$(CEDEV_TOOLCHAIN)/include/lwip"
	cp build/lwip.lib "$(CEDEV_TOOLCHAIN)/lib/libload/lwip.lib"
	cp -R build/lwip/. "$(CEDEV_TOOLCHAIN)/include/lwip"
	cp build/lwip.h build/cryptography.h build/parsers.h build/wireless.h "$(CEDEV_TOOLCHAIN)/include/"
	mkdir -p tests/common
	rm -f tests/common/LWIP.*.8xv
	cp build/appinst/* build/lwip.8xv build/lwip.lib tests/common/
	python3 tests/common/scripts/sync_appvars.py

.PHONY: clean
clean:
	$(CE_LIBIFY) clean

# Package output of `make dylib` (and readmes) into `lwip.zip`
RELEASE_TOOLS := tools/lwip-cert-converter
.PHONY: release
release:
	@if [ ! -d build ]; then echo "Run 'make dylib' first to produce build/"; exit 1; fi
	rm -f lwip.zip
	@release_stage=$$(mktemp -d); \
	trap 'rm -rf "$$release_stage"' EXIT; \
	mkdir -p "$$release_stage/lwip"; \
	cp -R build/. "$$release_stage/lwip/"; \
	if [ -e "$$release_stage/lwip/examples" ] || [ -L "$$release_stage/lwip/examples" ]; then \
		rm -rf "$$release_stage/lwip/examples"; \
	fi; \
	cp -R examples "$$release_stage/lwip/examples"; \
	cp README.md CHANGELOG.md SECURITY.md "$$release_stage/lwip/"; \
	mkdir -p "$$release_stage/lwip/tools"; \
	cp $(RELEASE_TOOLS) "$$release_stage/lwip/tools/"; \
	cd "$$release_stage"; \
	zip -r "$(CURDIR)/lwip.zip" lwip/ \
	    -x "*/obj/*" \
	    -x "*/bin/*" \
	    -x "*/.DS_Store" \
	    -x "*/__MACOSX/*" \
	    -x "*/._*"

# Combine `make dylib` and `make release` into a single command.
.PHONY: dylib-release
dylib-release:
	make dylib
	make release

.PHONY: sizes
sizes:
	@if [ ! -f bin/lwIP.map ]; then echo "Run 'make' first to produce bin/lwIP.map"; exit 1; fi
	@printf '\nlwIP-CE memory footprint (from bin/lwIP.map):\n\n'
	@MAPFILE=bin/lwIP.map python3 build-tools/scripts/helpers/print_sizes.py
	@printf '\n  Consumer link contract:\n'
	@printf '    --defsym BSSHEAP_LOW=<base>\n'
	@printf '    --defsym BSSHEAP_HIGH=<base + reserve + heap_shared_with_lwip>\n\n'

# Regenerate derived datasets and build the whitepaper using the same PDF
# options as CI. Force a clean rebuild to prevent stale cross-reference state.
.PHONY: whitepaper
whitepaper:
	cd $(CURDIR)/docs/whitepaper && python3 scripts/generate_docs_data.py
	cd $(CURDIR)/docs/whitepaper && latexmk -gg -pdf -shell-escape -interaction=nonstopmode -file-line-error whitepaper.tex

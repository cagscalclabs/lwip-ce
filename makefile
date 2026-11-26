CE_LIBIFY ?= ce-libify
CEDEV_TOOLCHAIN ?= $(if $(CEDEV),$(CEDEV),$(shell cedev-config --prefix))
X25519_DIR := src/tls/contrib/x25519
X25519_PATCH := tools/build/patches/x25519-scratch-overlay.patch

.PHONY: all build prepare-x25519 run-tests
all: dylib

# Reproduce the locally runnable CI workflow. A calculator ROM must be
# supplied by the developer; it is never downloaded or stored by this repo.
#
#   AUTOTESTER_ROM=/path/to/ce.rom make run-tests
#
# Set LOCAL_NETWORK_TESTS=1 and TRUSTSTORE_SIGNER_FILE=/secure/key.pem on
# Linux to include the root/network-namespace calculator suites.
LOCAL_TEST_ROOT ?= $(if $(TMPDIR),$(TMPDIR)lwip-ce-local-tests,/tmp/lwip-ce-local-tests)
FUZZ_SECONDS ?= 300
run-tests:
	@if [ -z "$(AUTOTESTER_ROM)" ]; then \
		echo "AUTOTESTER_ROM=/path/to/ce.rom is required" >&2; \
		exit 2; \
	fi
	$(MAKE) dylib
	python3 .github/scripts/run_local_tests.py \
		--rom "$(AUTOTESTER_ROM)" \
		--work-dir "$(LOCAL_TEST_ROOT)" \
		--fuzz-seconds "$(FUZZ_SECONDS)"

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

build: prepare-x25519
	$(CE_LIBIFY) build

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
RELEASE_TOOLS := tools/helpers/lwip-cert-converter tools/bridge/lwip-acm-bridge.py tools/bridge/lwip-acm-bridge.md

# Root certificate store bundled into lwip.zip. Downloaded fresh for every
# release from the truststore-latest tag, unless TRUSTSTORE names a local
# lwIPCERT.8xv (offline builds, or pinning a specific store). The release
# fails if the store's format doesn't match TLS_TRUSTSTORE_VERSION, since
# the library would reject it.
TRUSTSTORE ?=
TRUSTSTORE_URL := https://github.com/cagscalclabs/lwip-ce/releases/download/truststore-latest/lwIPCERT.8xv
TRUSTSTORE_STAGE := bin/release-truststore

.PHONY: fetch-truststore
fetch-truststore:
	@set -e; \
	rm -rf "$(TRUSTSTORE_STAGE)"; \
	mkdir -p "$(TRUSTSTORE_STAGE)"; \
	if [ -n "$(TRUSTSTORE)" ]; then \
		cp "$(TRUSTSTORE)" "$(TRUSTSTORE_STAGE)/lwIPCERT.8xv"; \
		source="$(TRUSTSTORE)"; \
	else \
		echo "Downloading $(TRUSTSTORE_URL)"; \
		curl -fsSL --retry 3 -o "$(TRUSTSTORE_STAGE)/lwIPCERT.8xv" "$(TRUSTSTORE_URL)"; \
		source="$(TRUSTSTORE_URL)"; \
	fi; \
	python3 tools/build/scripts/check_truststore.py \
		"$(TRUSTSTORE_STAGE)/lwIPCERT.8xv" src/tls/includes/truststore.h \
		--source "$$source" --out "$(TRUSTSTORE_STAGE)/TRUSTSTORE.txt"

.PHONY: release
release: fetch-truststore
	@if [ ! -d build ]; then echo "Run 'make dylib' first to produce build/"; exit 1; fi
	rm -f lwip.zip
	@set -e; \
	release_stage=$$(mktemp -d); \
	trap 'rm -rf "$$release_stage"' EXIT; \
	mkdir -p "$$release_stage/lwip"; \
	cp -R build/. "$$release_stage/lwip/"; \
	if [ -e "$$release_stage/lwip/examples" ] || [ -L "$$release_stage/lwip/examples" ]; then \
		rm -rf "$$release_stage/lwip/examples"; \
	fi; \
	cp -R examples "$$release_stage/lwip/examples"; \
	cp README.md CHANGELOG.md SECURITY.md "$$release_stage/lwip/"; \
	cp "$(TRUSTSTORE_STAGE)/lwIPCERT.8xv" "$(TRUSTSTORE_STAGE)/TRUSTSTORE.txt" "$$release_stage/lwip/"; \
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
	@MAPFILE=bin/lwIP.map python3 tools/build/scripts/helpers/print_sizes.py
	@printf '\n  Consumer link contract:\n'
	@printf '    --defsym BSSHEAP_LOW=<base>\n'
	@printf '    --defsym BSSHEAP_HIGH=<base + reserve + heap_shared_with_lwip>\n\n'

# Regenerate derived datasets and build the whitepaper using the same PDF
# options as CI. Force a clean rebuild to prevent stale cross-reference state.
.PHONY: whitepaper
whitepaper:
	cd $(CURDIR)/docs/whitepaper && python3 scripts/generate_docs_data.py
	cd $(CURDIR)/docs/whitepaper && latexmk -gg -pdf -shell-escape -interaction=nonstopmode -file-line-error whitepaper.tex

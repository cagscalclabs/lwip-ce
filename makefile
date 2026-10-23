CE_LIBIFY ?= ce-libify
CEDEV_TOOLCHAIN ?= $(if $(CEDEV),$(CEDEV),$(shell cedev-config --prefix))

.PHONY: all build
all: dylib
build:
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
	cp build/appinst/* build/lwip.8xv build/lwip.lib tests/common/

.PHONY: clean
clean:
	$(CE_LIBIFY) clean

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

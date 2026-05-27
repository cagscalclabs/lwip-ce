HOMEBREW_PREFIX ?= $(shell brew --prefix 2>/dev/null || echo /opt/homebrew)
export DYLD_LIBRARY_PATH := $(HOMEBREW_PREFIX)/opt/expat/lib:$(DYLD_LIBRARY_PATH)

SPHINXBUILD ?= $(shell command -v sphinx-build 2>/dev/null || echo $(HOMEBREW_PREFIX)/bin/sphinx-build)
DOXYGEN ?= $(shell command -v doxygen 2>/dev/null || echo $(HOMEBREW_PREFIX)/opt/doxygen/bin/doxygen)
SOURCEDIR = .
BUILDDIR = _build
WHITEPAPER_STATIC = _static/whitepaper.pdf
WHITEPAPER_RELEASE_URL ?= https://github.com/cagscalclabs/lwip-ce/releases/download/whitepaper-latest/whitepaper.pdf

.PHONY: html doxygen whitepaper-pdf clean

html: doxygen whitepaper-pdf
	$(SPHINXBUILD) -b html "$(SOURCEDIR)" "$(BUILDDIR)/html"

doxygen:
	$(DOXYGEN) Doxyfile

whitepaper-pdf:
	@mkdir -p "_static"
	@curl -fL --retry 3 --connect-timeout 10 "$(WHITEPAPER_RELEASE_URL)" -o "$(WHITEPAPER_STATIC)"
	@echo "downloaded $(WHITEPAPER_RELEASE_URL) -> $(WHITEPAPER_STATIC)"

clean:
	rm -rf "$(BUILDDIR)" "_doxygen" "$(WHITEPAPER_STATIC)"

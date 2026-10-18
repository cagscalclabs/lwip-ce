HOMEBREW_PREFIX ?= $(shell brew --prefix 2>/dev/null || echo /opt/homebrew)
export DYLD_LIBRARY_PATH := $(HOMEBREW_PREFIX)/opt/expat/lib:$(DYLD_LIBRARY_PATH)

SPHINXBUILD ?= $(shell command -v sphinx-build 2>/dev/null || echo $(HOMEBREW_PREFIX)/bin/sphinx-build)
DOXYGEN ?= $(shell command -v doxygen 2>/dev/null || echo $(HOMEBREW_PREFIX)/opt/doxygen/bin/doxygen)
SOURCEDIR = .
BUILDDIR = _build
LWIP_RELEASE_DIR ?= ../build
LWIP_EXPORTS ?= exports.txt
HEADER_PYTHON ?= python3

.PHONY: html doxygen release-headers clean

html: doxygen
	$(SPHINXBUILD) -b html "$(SOURCEDIR)" "$(BUILDDIR)/html"

doxygen: release-headers
	$(DOXYGEN) Doxyfile

release-headers:
	cd .. && LWIP_RELEASE_DIR="$(abspath $(LWIP_RELEASE_DIR))" LWIP_EXPORTS="$(LWIP_EXPORTS)" $(HEADER_PYTHON) build-tools/scripts/generate_lwip_headers.py

clean:
	rm -rf "$(BUILDDIR)" "_doxygen" "$(LWIP_RELEASE_DIR)"

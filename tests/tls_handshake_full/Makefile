# ----------------------------
# Makefile Options
# ----------------------------

NAME = TLSTEST
ICON = icon.png
ARCHIVED = NO
DESCRIPTION = "TLS 1.3 Full Handshake Test"
COMPRESSED = NO

CFLAGS = -Wall -Wextra -Oz -I../../src/include -I../../src/tls/includes
CXXFLAGS = -Wall -Wextra -Oz -I../../src/include -I../../src/tls/includes

# Test main
SOURCES = src/main.c

# Pull in TLS core files (test currently incomplete, needs implementation)
# Once test functions are implemented, uncomment and add needed sources:
# EXTRA_C_SOURCES = ../../src/tls/core/handshake.c ../../src/tls/core/hkdf.c etc.

# ----------------------------

# Add header directories
HEADER_DIRS := ../../src/include ../../src/tls/includes src/include $(HEADER_DIRS)

include $(shell cedev-config --makefile)

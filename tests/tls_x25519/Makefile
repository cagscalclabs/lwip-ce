# ----------------------------
# Makefile Options
# ----------------------------

NAME = X25519
ARCHIVED = NO
DESCRIPTION = "X25519 RFC 7748 Test"
COMPRESSED = NO

CFLAGS = -Wall -Wextra -Oz -I../../src -I../../src/include -I../../src/tls/includes
CXXFLAGS = -Wall -Wextra -Oz -I../../src -I../../src/include -I../../src/tls/includes

SOURCES = src/main.c

EXTRA_ASM_SOURCES = \
	../../src/tls/core/x25519.asm

HEADER_DIRS := ../../src/include ../../src/tls/includes src/include $(HEADER_DIRS)

include $(shell cedev-config --makefile)

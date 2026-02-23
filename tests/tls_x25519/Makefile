# ----------------------------
# Makefile Options
# ----------------------------

NAME = X25519
ARCHIVED = NO
DESCRIPTION = "X25519 RFC 7748 Test"
COMPRESSED = NO

CFLAGS = -Wall -Wextra -Oz -I../../src -I../../src/include -I../../src/tls/contrib/x25519/src
CXXFLAGS = -Wall -Wextra -Oz -I../../src -I../../src/include -I../../src/tls/contrib/x25519/src

SOURCES = src/main.c

EXTRA_ASM_SOURCES = \
	../../src/tls/contrib/x25519/src/x25519.asm

HEADER_DIRS := ../../src/include ../../src/tls/contrib/x25519/src src/include $(HEADER_DIRS)

include $(shell cedev-config --makefile)

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

# Pull in TLS core files needed for handshake test
EXTRA_C_SOURCES = \
	../../src/tls/core/handshake.c \
	../../src/tls/core/hkdf.c \
	../../src/tls/core/hmac.c \
	../../src/tls/core/hash.c \
	../../src/tls/core/aes.c \
	../../src/core/mem.c \
	../../src/core/stats.c

# Assembly files
EXTRA_ASM_SOURCES = \
	../../src/tls/core/sha256.asm \
	../../src/tls/core/bytes.asm \
	../../src/tls/core/share/bigint.asm \
	../../src/tls/core/share/helpers.asm \
	../../src/tls/core/random.asm

# ----------------------------

# Add header directories
HEADER_DIRS := ../../src/include ../../src/tls/includes src/include $(HEADER_DIRS)

include $(shell cedev-config --makefile)

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

# Test main and TLS implementations
SOURCES = src/main.c src/handshake.c src/hkdf.c src/hmac.c src/hash.c src/aes.c

# Assembly files
ASM = src/sha256.asm src/random.asm src/bytes.asm src/share/bigint.asm src/share/flash.asm src/share/helpers.asm src/share/nostack.asm

# ----------------------------

# Add header directories
HEADER_DIRS := ../../src/include ../../src/tls/includes src/include $(HEADER_DIRS)

include $(shell cedev-config --makefile)

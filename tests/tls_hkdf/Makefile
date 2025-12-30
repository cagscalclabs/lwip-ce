# ----------------------------
# Makefile Options
# ----------------------------

NAME = HKDF
ICON = icon.png
ARCHIVED = NO
DESCRIPTION = "HKDF test"
COMPRESSED = NO

CFLAGS = -Wall -Wextra -Oz -I../../src/include -I../../src/tls/includes
CXXFLAGS = -Wall -Wextra -Oz -I../../src/include -I../../src/tls/includes

# Test main and TLS implementations
SOURCES = src/main.c src/hkdf.c src/hmac.c src/hash.c

# Assembly files
ASM = src/sha256.asm src/share/bigint.asm

# ----------------------------

# Add header directories
HEADER_DIRS := ../../src/include ../../src/tls/includes src/include $(HEADER_DIRS)

include $(shell cedev-config --makefile)

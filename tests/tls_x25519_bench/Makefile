# ----------------------------
# Makefile Options
# ----------------------------

NAME = X25519B
ICON = icon.png
ARCHIVED = NO
DESCRIPTION = "x25519 bench"
COMPRESSED = NO

CFLAGS = -Wall -Wextra -Oz -I../../src/include -I../../src/tls/includes
CXXFLAGS = -Wall -Wextra -Oz -I../../src/include -I../../src/tls/includes

# Test main and x25519 implementation
SOURCES = src/main.c src/x25519.c

# Assembly files (local wrappers)
ASM = src/x25519_field.asm src/x25519_karat.asm src/x25519_mul_wrapper.asm

# ----------------------------

# Add header directories
HEADER_DIRS := ../../src/include ../../src/tls/includes src/include $(HEADER_DIRS)

include $(shell cedev-config --makefile)

# ----------------------------
# Makefile Options
# ----------------------------

NAME = X25519
ICON = icon.png
ARCHIVED = NO
DESCRIPTION = "x25519 ECDH test"
COMPRESSED = NO

CFLAGS = -Wall -Wextra -Oz -I../../src/include -I../../src/tls/includes
CXXFLAGS = -Wall -Wextra -Oz -I../../src/include -I../../src/tls/includes

# Test main
SOURCES = src/main.c

# Pull in required TLS core files
EXTRA_C_SOURCES = ../../src/tls/core/x25519.c

# Assembly files (local wrappers)
ASM = src/x25519_field.asm src/x25519_karat.asm src/x25519_mul_wrapper.asm

# ----------------------------

# Add header directories
HEADER_DIRS := ../../src/include ../../src/tls/includes src/include $(HEADER_DIRS)

include $(shell cedev-config --makefile)

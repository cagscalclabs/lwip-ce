# ----------------------------
# Makefile Options
# ----------------------------

NAME = P256ECDH
ICON = icon.png
ARCHIVED = NO
DESCRIPTION = "P-256 ECDH test"
COMPRESSED = NO

CFLAGS = -Wall -Wextra -Oz -I../../src/include -I../../src/tls/includes
CXXFLAGS = -Wall -Wextra -Oz -I../../src/include -I../../src/tls/includes

# Test main and ECC implementation
SOURCES = src/main.c src/ecc.c

# Assembly files (local wrappers)
ASM = src/p256_field.asm src/montgomery.asm

# ----------------------------

# Add header directories
HEADER_DIRS := ../../src/include ../../src/tls/includes src/include $(HEADER_DIRS)

include $(shell cedev-config --makefile)

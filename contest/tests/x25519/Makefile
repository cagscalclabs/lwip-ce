# ----------------------------
# Makefile Options
# ----------------------------

NAME = X25519T
ICON = icon.png
ARCHIVED = NO
DESCRIPTION = "X25519 Test Suite"
COMPRESSED = NO

CFLAGS = -Wall -Wextra -Oz
CXXFLAGS = -Wall -Wextra -Oz

# Test main
SOURCES = src/main.c

# Pull in X25519 implementation (contestant provides these)
# EXTRA_C_SOURCES = ../../src/x25519.c
# EXTRA_ASM_SOURCES = ../../src/curve25519_field.asm

# ----------------------------

include $(shell cedev-config --makefile)

# ----------------------------
# Makefile Options
# ----------------------------

NAME = P256FLD
ICON = icon.png
ARCHIVED = NO
DESCRIPTION = "P-256 field arithmetic test"
COMPRESSED = NO

CFLAGS = -Wall -Wextra -Oz
CXXFLAGS = -Wall -Wextra -Oz

# Only compile the test main file
SOURCES = src/main.c

# Assembly files (local wrappers that include actual implementations)
ASM = src/p256_field.asm src/montgomery.asm

# ----------------------------

# Add header directories without symlinks
HEADER_DIRS := ../../src/include ../../src/tls/includes src/include $(HEADER_DIRS)

include $(shell cedev-config --makefile)

# ----------------------------
# Makefile Options
# ----------------------------

NAME = DEMO
ICON = icon.png
ARCHIVED = NO
DESCRIPTION = "tls_montgomery test"
COMPRESSED = NO

CFLAGS = -Wall -Wextra -Oz -I../../src/tls/includes
CXXFLAGS = -Wall -Wextra -Oz -I../../src/tls/includes
ASM = ../../src/tls/core/share/montgomery.asm

# ----------------------------

HEADER_DIRS := src/include $(HEADER_DIRS)

include $(shell cedev-config --makefile)

# ----------------------------
# Makefile Options
# ----------------------------

NAME = DEMO
ICON = icon.png
ARCHIVED = NO
DESCRIPTION = "tls_asn1 test"
COMPRESSED = NO

CFLAGS = -Wall -Wextra -Oz -I../../src/include -I../../src/tls/includes
CXXFLAGS = -Wall -Wextra -Oz -I../../src/include -I../../src/tls/includes

CFLAGS += -ffunction-sections -fdata-sections
CXXFLAGS += -ffunction-sections -fdata-sections
EXTRA_LDFLAGS += -Wl,--gc-sections

# Test main
SOURCES = src/main.c

# Pull in required TLS core files
EXTRA_C_SOURCES = ../../src/tls/core/asn1.c ../../src/tls/core/base64.c

# Assembly files (rmemcpy needed by asn1.c)
EXTRA_ASM_SOURCES = ../../src/tls/core/share/helpers.asm

# ----------------------------

# Add header directories
HEADER_DIRS := ../../src/include ../../src/tls/includes src/include $(HEADER_DIRS)

include $(shell cedev-config --makefile)

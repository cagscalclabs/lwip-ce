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

# Test main
SOURCES = src/main.c

# Pull in required TLS core files
SOURCES += ../../src/tls/core/hkdf.c
SOURCES += ../../src/tls/core/hmac.c
SOURCES += ../../src/tls/core/hash.c

# Assembly files from TLS core
ASM = ../../src/tls/core/sha256.asm
ASM += $(wildcard ../../src/arch/share/*.asm)

# ----------------------------

# Add header directories
HEADER_DIRS := ../../src/include ../../src/tls/includes src/include $(HEADER_DIRS)

include $(shell cedev-config --makefile)

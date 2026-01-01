# ----------------------------
# Makefile Options
# ----------------------------

NAME = KEYDERIV
ICON = icon.png
ARCHIVED = NO
DESCRIPTION = "TLS 1.3 Key Derivation Test"
COMPRESSED = NO

CFLAGS = -Wall -Wextra -Oz -I../../src/include -I../../src/tls/includes
CXXFLAGS = -Wall -Wextra -Oz -I../../src/include -I../../src/tls/includes

# Test main
SOURCES = src/main.c

# Pull in required TLS core files
SOURCES += ../../src/tls/core/handshake.c
SOURCES += ../../src/tls/core/hkdf.c
SOURCES += ../../src/tls/core/hmac.c
SOURCES += ../../src/tls/core/hash.c

# Assembly files from TLS core and arch
ASM = ../../src/tls/core/sha256.asm
ASM += ../../src/tls/core/random.asm
ASM += $(wildcard ../../src/arch/share/*.asm)

# ----------------------------

# Add header directories
HEADER_DIRS := ../../src/include ../../src/tls/includes src/include $(HEADER_DIRS)

include $(shell cedev-config --makefile)

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
EXTRA_C_SOURCES = ../../src/tls/core/handshake.c ../../src/tls/core/hkdf.c ../../src/tls/core/hmac.c ../../src/tls/core/hash.c

# Assembly files from TLS core
EXTRA_ASM_SOURCES = ../../src/tls/core/sha256.asm ../../src/tls/core/random.asm ../../src/tls/core/bytes.asm ../../src/tls/core/share/bigint.asm

# ----------------------------

# Add header directories
HEADER_DIRS := ../../src/include ../../src/tls/includes src/include $(HEADER_DIRS)

include $(shell cedev-config --makefile)

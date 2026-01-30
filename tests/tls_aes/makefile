# ----------------------------
# Makefile Options
# ----------------------------

NAME = DEMO
ICON = icon.png
ARCHIVED = NO
DESCRIPTION = "tls_aes test"
COMPRESSED = NO

CFLAGS = -Wall -Wextra -Oz -I../../src/include -I../../src/tls/includes
CXXFLAGS = -Wall -Wextra -Oz -I../../src/include -I../../src/tls/includes

CFLAGS += -ffunction-sections -fdata-sections
CXXFLAGS += -ffunction-sections -fdata-sections
EXTRA_LDFLAGS += -Wl,--gc-sections

# Test main
SOURCES = src/main.c

# Pull in required TLS core files
EXTRA_C_SOURCES = ../../src/tls/core/aes.c ../../src/tls/core/bytes.c

# Assembly files (bytelen_to_bitlen in bytes.asm, gf128_mul in bigint.asm for GCM)
EXTRA_ASM_SOURCES = ../../src/tls/core/bytes.asm ../../src/tls/core/share/bigint.asm \
	../../src/tls/core/share/crypto_guard.asm \
	../../src/tls/core/share/nostack.asm

# ----------------------------

# Add header directories
HEADER_DIRS := ../../src/include ../../src/tls/includes src/include $(HEADER_DIRS)

include $(shell cedev-config --makefile)

# ----------------------------
# Makefile Options
# ----------------------------

NAME = PSSTEST
ICON = icon.png
ARCHIVED = NO
DESCRIPTION = "RSA-PSS Test"
COMPRESSED = NO

CFLAGS = -Wall -Wextra -Oz -I../../src -I../../src/include -I../../src/tls/includes
CXXFLAGS = -Wall -Wextra -Oz -I../../src -I../../src/include -I../../src/tls/includes

CFLAGS += -ffunction-sections -fdata-sections
CXXFLAGS += -ffunction-sections -fdata-sections
EXTRA_LDFLAGS += -Wl,--gc-sections

# Test main
SOURCES = src/main.c

# Pull in required TLS core files
EXTRA_C_SOURCES = ../../src/tls/core/rsa.c ../../src/tls/core/hash.c ../../src/tls/core/hmac.c ../../src/tls/core/tls.c ../../src/tls/core/bytes.c ../../src/core/mem.c ../../src/drivers/mem.c ../../src/core/stats.c

# Assembly files from TLS core
EXTRA_ASM_SOURCES = ../../src/tls/core/sha256.asm ../../src/tls/core/bytes.asm ../../src/tls/core/share/bigint.asm ../../src/tls/core/random.asm \
	../../src/tls/core/share/crypto_guard.asm \
	../../src/tls/core/share/nostack.asm

# ----------------------------

# Add header directories
HEADER_DIRS := ../../src/include ../../src/tls/includes src/include $(HEADER_DIRS)

include $(shell cedev-config --makefile)

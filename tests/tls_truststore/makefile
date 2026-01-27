# ----------------------------
# Makefile Options
# ----------------------------

NAME = TRUSTST
ICON = icon.png
ARCHIVED = NO
DESCRIPTION = "TLS Truststore Test"
COMPRESSED = NO

CFLAGS = -Wall -Wextra -Oz -I../../src -I../../src/include -I../../src/tls/includes
CXXFLAGS = -Wall -Wextra -Oz -I../../src -I../../src/include -I../../src/tls/includes

# Test main
SOURCES = src/main.c

# Pull in required TLS core files
EXTRA_C_SOURCES = ../../src/tls/core/truststore.c ../../src/tls/core/rsa.c ../../src/tls/core/hash.c ../../src/tls/core/tls.c ../../src/core/mem.c ../../src/drivers/mem.c ../../src/core/stats.c ../../src/core/logging.c ../../src/core/app_config.c

# Assembly files from TLS core
EXTRA_ASM_SOURCES = ../../src/tls/core/sha256.asm ../../src/tls/core/bytes.asm ../../src/tls/core/share/bigint.asm ../../src/tls/core/random.asm

# ----------------------------

# Add header directories
HEADER_DIRS := ../../src ../../src/include ../../src/tls/includes src/include $(HEADER_DIRS)

include $(shell cedev-config --makefile)

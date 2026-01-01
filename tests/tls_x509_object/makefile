# ----------------------------
# Makefile Options
# ----------------------------

NAME = DEMO
ICON = icon.png
ARCHIVED = NO
DESCRIPTION = "tls_x509_object test"
COMPRESSED = NO

CFLAGS = -Wall -Wextra -Oz -I../../src/include -I../../src/tls/includes
CXXFLAGS = -Wall -Wextra -Oz -I../../src/include -I../../src/tls/includes

# Test main
SOURCES = src/main.c

# Pull in required TLS core files
EXTRA_C_SOURCES = ../../src/tls/core/keyobject.c ../../src/tls/core/asn1.c ../../src/tls/core/base64.c ../../src/core/mem.c ../../src/tls/core/aes.c ../../src/tls/core/passwords.c ../../src/tls/core/hash.c ../../src/tls/core/hmac.c ../../src/core/stats.c

# Assembly files (AES+PBKDF2 dependencies)
EXTRA_ASM_SOURCES = ../../src/tls/core/share/helpers.asm ../../src/tls/core/bytes.asm ../../src/tls/core/share/bigint.asm ../../src/tls/core/sha256.asm

# ----------------------------

# Add header directories
HEADER_DIRS := ../../src/include ../../src/tls/includes src/include $(HEADER_DIRS)

include $(shell cedev-config --makefile)

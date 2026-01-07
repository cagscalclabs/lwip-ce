# ----------------------------
# Makefile Options
# ----------------------------

NAME = DEMO
ICON = icon.png
ARCHIVED = NO
DESCRIPTION = "tls_private_key_object test"
COMPRESSED = NO

CFLAGS = -Wall -Wextra -Oz -I../../src -I../../src/include -I../../src/tls/includes
CXXFLAGS = -Wall -Wextra -Oz -I../../src -I../../src/include -I../../src/tls/includes

# ----------------------------

EXTRA_C_SOURCES = \
	../../src/tls/core/keyobject.c \
	../../src/tls/core/asn1.c \
	../../src/tls/core/base64.c \
	../../src/tls/core/passwords.c \
	../../src/tls/core/hmac.c \
	../../src/tls/core/hash.c \
	../../src/tls/core/aes.c \
	../../src/core/mem.c \
	../../src/drivers/mem.c \
	../../src/core/stats.c

EXTRA_ASM_SOURCES = \
	../../src/tls/core/sha256.asm \
	../../src/tls/core/bytes.asm \
	../../src/tls/core/share/bigint.asm \
	../../src/tls/core/share/helpers.asm \
	../../src/tls/core/random.asm

HEADER_DIRS := ../../src ../../src/include ../../src/tls/includes src/include $(HEADER_DIRS)

include $(shell cedev-config --makefile)

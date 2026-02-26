# ----------------------------
# Makefile Options
# ----------------------------

NAME = TIMINGS
ICON = icon.png
ARCHIVED = NO
DESCRIPTION = "tls timing test"
COMPRESSED = NO

CFLAGS = -Wall -Wextra -Oz -I../../src/include -I../../src/tls/includes -I../../src/tls/contrib/x25519/src
CXXFLAGS = -Wall -Wextra -Oz -I../../src/include -I../../src/tls/includes -I../../src/tls/contrib/x25519/src
# Uncomment to enable verbose timing diagnostics in tests/tls_timing/src/main.c
# CFLAGS += -DTLS_TIMING_VERBOSE
# CXXFLAGS += -DTLS_TIMING_VERBOSE

SOURCES = src/main.c

EXTRA_C_SOURCES = \
	../../src/tls/core/aes.c \
	../../src/tls/core/bytes.c \
	../../src/tls/core/hash.c \
	../../src/tls/core/hkdf.c \
	../../src/tls/core/hmac.c \
	../../src/tls/core/passwords.c

EXTRA_ASM_SOURCES = \
	../../src/tls/core/bytes.asm \
	../../src/tls/core/random.asm \
	../../src/tls/core/sha256.asm \
	../../src/tls/core/share/bigint.asm \
	../../src/tls/core/share/crypto_guard.asm \
	../../src/tls/contrib/x25519/src/x25519.asm

HEADER_DIRS := ../../src/include ../../src/tls/includes ../../src/tls/contrib/x25519/src src/include $(HEADER_DIRS)

include $(shell cedev-config --makefile)

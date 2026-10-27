# ----------------------------
# Makefile Options
# ----------------------------
# Static variant: assembles p256.s with -DP256_TEST so the test-only
# p256_test_retry_k shim is available, and does not link the resident
# lwip.lib (its tls_p256_* symbols would collide with the statically
# assembled ones).

NAME = P256RT
ARCHIVED = NO
BSSHEAP_LOW = 0xD072C6
DESCRIPTION = "RFC 6979 P-256 nonce-retry test"
COMPRESSED = YES

CFLAGS = -Wall -Wextra -Oz
CXXFLAGS = -Wall -Wextra -Oz

SOURCES = src/main.c

LIBLOAD_LIBS :=

ASFLAGS = --defsym P256_TEST=1 -I ../../../src/tls/core/share
EXTRA_ASM_SOURCES = ../../../src/tls/core/primitives/p256.s \
                    ../../../src/tls/core/primitives/sha256.s \
                    ../../../src/tls/core/primitives/bytes.s \
                    ../../../src/tls/core/primitives/rsa.s \
                    ../../../src/tls/core/share/helpers.s \
                    ../../../src/tls/core/share/crypto_guard.s \
                    ../../../src/tls/core/share/memory.s
EXTRA_LDFLAGS += -T ../../common/saferam_defaults.ld -T crypto_scratch.ld --no-warn-execstack

# ----------------------------

include $(shell cedev-config --makefile)

# ----------------------------
# Makefile Options
# ----------------------------

include ../common/makefile

NAME = TIMINGS
ICON = icon.png
ARCHIVED = NO
DESCRIPTION = "tls timing test"
COMPRESSED = NO

CFLAGS = -Wall -Wextra -Oz -I../../src/include -I../../src/tls/includes -I../../src/tls/contrib/x25519/src
CXXFLAGS = -Wall -Wextra -Oz -I../../src/include -I../../src/tls/includes -I../../src/tls/contrib/x25519/src
# Uncomment to enable verbose timing diagnostics in tests/tls_timing/src/main.c
 CFLAGS += -DTLS_TIMING_VERBOSE
 CXXFLAGS += -DTLS_TIMING_VERBOSE

SOURCES = src/main.c

EXTRA_C_SOURCES = \
	$(TLS_CORE)/aes.c \
	$(TLS_CORE)/bytes.c \
	$(TLS_CORE)/hash.c \
	$(TLS_CORE)/hkdf.c \
	$(TLS_CORE)/hmac.c \
	$(TLS_CORE)/passwords.c

X25519_DIR := $(PROJECT_ROOT)/src/tls/contrib/x25519/src

EXTRA_ASM_SOURCES = \
	$(TLS_CORE)/bytes.asm \
	$(TLS_CORE)/random.asm \
	$(TLS_CORE)/sha256.asm \
	$(TLS_CORE)/share/bigint.asm \
	$(TLS_CORE)/share/crypto_guard.asm \
	$(X25519_DIR)/x25519.asm

HEADER_DIRS := $(PROJECT_ROOT)/src/include $(TLS_INC) $(X25519_DIR) $(HEADER_DIRS)

include $(shell cedev-config --makefile)

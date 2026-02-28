# ----------------------------
# Makefile Options
# ----------------------------

include ../../common/makefile

NAME = TIMINGS
ICON = icon.png
ARCHIVED = NO
DESCRIPTION = "tls timing test"
COMPRESSED = NO



CFLAGS = -Wall -Wextra -Oz -I$(LWIP_INC) -I$(TLS_INC) -I$(X25519_DIR)
CXXFLAGS = -Wall -Wextra -Oz -I$(LWIP_INC) -I$(TLS_INC) -I$(X25519_DIR)
# Verbose diagnostics are opt-in for local runs only.
# Enable with: make TLS_TIMING_VERBOSE=1
TLS_TIMING_VERBOSE ?= 0
ifeq ($(GITHUB_ACTIONS),true)
TLS_TIMING_VERBOSE := 0
endif
ifeq ($(TLS_TIMING_VERBOSE),1)
CFLAGS += -DTLS_TIMING_VERBOSE
CXXFLAGS += -DTLS_TIMING_VERBOSE
endif

SOURCES = src/main.c

EXTRA_C_SOURCES = \
	$(TLS_CORE)/aes.c \
	$(TLS_CORE)/bytes.c \
	$(TLS_CORE)/hash.c \
	$(TLS_CORE)/hkdf.c \
	$(TLS_CORE)/hmac.c \
	$(TLS_CORE)/passwords.c

EXTRA_ASM_SOURCES = \
	$(TLS_CORE)/bytes.asm \
	$(TLS_CORE)/random.asm \
	$(TLS_CORE)/sha256.asm \
	$(TLS_CORE)/share/bigint.asm \
	$(TLS_CORE)/share/crypto_guard.asm \
	$(X25519_DIR)/x25519.asm

HEADER_DIRS := $(PROJECT_ROOT)/src/include $(TLS_INC) $(X25519_DIR) $(HEADER_DIRS)

include $(shell cedev-config --makefile)

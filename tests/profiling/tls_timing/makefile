# ----------------------------
# Makefile Options
# ----------------------------

include ../../common/makefile

# Add -I path so the assembler can find virtuals.inc et al.
ASFLAGS += $(TLS_ASM_INCLUDES)

# x25519 hot loop is relocated to ti.cursorImage at runtime; the
# linker script defines _x25519_reloc_load_start / _x25519_reloc_len.
EXTRA_LDFLAGS += -T $(TLS_CORE_REL)/x25519_reloc.ld

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
CFLAGS += -DTLS_TIMING_AUTORUN
CXXFLAGS += -DTLS_TIMING_AUTORUN
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
	$(TLS_CORE_REL)/bytes.s \
	$(TLS_CORE_REL)/random.s \
	$(TLS_CORE_REL)/sha256.s \
	$(TLS_CORE_REL)/share/bigint.s \
	$(TLS_CORE_REL)/share/crypto_guard.s \
	$(X25519_DIR_REL)/x25519.s

HEADER_DIRS := $(PROJECT_ROOT)/src/include $(TLS_INC) $(X25519_DIR) $(HEADER_DIRS)

include $(shell cedev-config --makefile)

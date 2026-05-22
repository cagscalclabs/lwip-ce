# ----------------------------
# Makefile Options
# ----------------------------

include ../../common/makefile

# Add -I path so the assembler can find virtuals.inc et al.
ASFLAGS += $(TLS_ASM_INCLUDES)

NAME = ACVPTEST
ICON = icon.png
ARCHIVED = NO
DESCRIPTION = "NIST ACVP-format primitive validation"
COMPRESSED = NO

CFLAGS = -Wall -Wextra -Oz -I$(LWIP_INC) -I$(TLS_INC) -I$(X25519_DIR)
CXXFLAGS = -Wall -Wextra -Oz -I$(LWIP_INC) -I$(TLS_INC) -I$(X25519_DIR)

SOURCES = src/main.c

EXTRA_C_SOURCES = \
	$(TLS_CORE)/aes.c \
	$(TLS_CORE)/bytes.c \
	$(TLS_CORE)/hash.c \
	$(TLS_CORE)/hkdf.c \
	$(TLS_CORE)/hmac.c \
	$(TLS_CORE)/passwords.c \
	$(TLS_CORE)/rsa.c \
	$(TLS_CORE)/asn1.c \
	$(PROJECT_ROOT)/src/drivers/mem.c

# NOTE: keep this in sync with whatever the timing test uses; the toolchain
# v15 migration moved most ASM files from .asm to .s. If the timing test's
# makefile changes here, this one needs the same change.
EXTRA_ASM_SOURCES = \
	$(TLS_CORE_REL)/bytes.s \
	$(TLS_CORE_REL)/random.s \
	$(TLS_CORE_REL)/sha256.s \
	$(TLS_CORE_REL)/share/bigint.s \
	$(TLS_CORE_REL)/share/crypto_guard.s \
	$(X25519_DIR_REL)/x25519.s

# x25519 hot loop is relocated to ti.cursorImage at runtime; the linker
# script defines _x25519_reloc_load_start / _x25519_reloc_len.
EXTRA_LDFLAGS += -T $(TLS_CORE_REL)/x25519_reloc.ld

HEADER_DIRS := $(PROJECT_ROOT)/src/include $(TLS_INC) $(X25519_DIR) $(HEADER_DIRS)

include $(shell cedev-config --makefile)

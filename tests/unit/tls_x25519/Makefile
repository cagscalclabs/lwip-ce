# ----------------------------
# Makefile Options
# ----------------------------

include ../../common/makefile

# Add -I path so the assembler can find virtuals.inc et al.
ASFLAGS += $(TLS_ASM_INCLUDES)

# x25519 hot loop is relocated to ti.cursorImage at runtime; the
# linker script defines _x25519_reloc_load_start / _x25519_reloc_len.
EXTRA_LDFLAGS += -T $(TLS_CORE_REL)/x25519_reloc.ld

NAME = X25519
ARCHIVED = NO
DESCRIPTION = "X25519 RFC 7748 Test"
COMPRESSED = NO

X25519_DIR := $(PROJECT_ROOT)/src/tls/contrib/x25519/src

CFLAGS = -Wall -Wextra -Oz -I$(PROJECT_ROOT)/src -I$(LWIP_INC) -I$(X25519_DIR)
CXXFLAGS = -Wall -Wextra -Oz -I$(PROJECT_ROOT)/src -I$(LWIP_INC) -I$(X25519_DIR)

SOURCES = src/main.c

EXTRA_ASM_SOURCES = \
	$(X25519_DIR_REL)/x25519.s

HEADER_DIRS := $(LWIP_INC) $(X25519_DIR) src/include $(HEADER_DIRS)

include $(shell cedev-config --makefile)

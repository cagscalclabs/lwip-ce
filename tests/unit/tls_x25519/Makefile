# ----------------------------
# Makefile Options
# ----------------------------

include ../../common/makefile

NAME = X25519
ARCHIVED = NO
DESCRIPTION = "X25519 RFC 7748 Test"
COMPRESSED = NO

X25519_DIR := $(PROJECT_ROOT)/src/tls/contrib/x25519/src

CFLAGS = -Wall -Wextra -Oz -I$(PROJECT_ROOT)/src -I$(LWIP_INC) -I$(X25519_DIR)
CXXFLAGS = -Wall -Wextra -Oz -I$(PROJECT_ROOT)/src -I$(LWIP_INC) -I$(X25519_DIR)

SOURCES = src/main.c

EXTRA_ASM_SOURCES = \
	$(X25519_DIR)/x25519.asm

HEADER_DIRS := $(LWIP_INC) $(X25519_DIR) src/include $(HEADER_DIRS)

include $(shell cedev-config --makefile)

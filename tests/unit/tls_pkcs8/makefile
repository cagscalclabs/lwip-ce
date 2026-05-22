# ----------------------------
# Makefile Options
# ----------------------------

include ../../common/makefile

# Add -I path so the assembler can find virtuals.inc et al.
ASFLAGS += $(TLS_ASM_INCLUDES)

NAME = PKCS8T
ICON = icon.png
ARCHIVED = NO
DESCRIPTION = "tls_pkcs8 parser test"
COMPRESSED = NO

CFLAGS = -Wall -Wextra -Oz -I$(PROJECT_ROOT)/src -I$(LWIP_INC) -I$(TLS_INC)
CXXFLAGS = -Wall -Wextra -Oz -I$(PROJECT_ROOT)/src -I$(LWIP_INC) -I$(TLS_INC)

# ----------------------------

EXTRA_C_SOURCES = \
	$(TLS_CORE)/keyobject.c \
	$(TLS_CORE)/tls.c \
	$(TLS_CORE)/pkcs8.c \
	$(TLS_CORE)/asn1.c \
	$(TLS_CORE)/base64.c \
	$(TLS_CORE)/passwords.c \
	$(TLS_CORE)/hmac.c \
	$(TLS_CORE)/hash.c \
	$(TLS_CORE)/aes.c \
	$(TLS_CORE)/bytes.c \
	$(PROJECT_ROOT)/src/core/mem.c \
	$(PROJECT_ROOT)/src/drivers/mem.c \
	$(PROJECT_ROOT)/src/core/stats.c

EXTRA_ASM_SOURCES = $(TLS_ASM_TLS_FULL)

HEADER_DIRS := $(PROJECT_ROOT)/src $(LWIP_INC) $(TLS_INC) src/include $(HEADER_DIRS)

include $(shell cedev-config --makefile)

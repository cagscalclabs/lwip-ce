# ----------------------------
# Makefile Options
# ----------------------------

include ../common/makefile

NAME = X509T
ICON = icon.png
ARCHIVED = NO
DESCRIPTION = "tls_x509 parser test"
COMPRESSED = NO

CFLAGS = -Wall -Wextra -Oz -I$(PROJECT_ROOT)/src -I$(LWIP_INC) -I$(TLS_INC)
CXXFLAGS = -Wall -Wextra -Oz -I$(PROJECT_ROOT)/src -I$(LWIP_INC) -I$(TLS_INC)

# ----------------------------

EXTRA_C_SOURCES = \
	$(TLS_CORE)/tls.c \
	$(TLS_CORE)/x509.c \
	$(TLS_CORE)/asn1.c \
	$(TLS_CORE)/base64.c \
	$(TLS_CORE)/bytes.c \
	$(PROJECT_ROOT)/src/core/mem.c \
	$(PROJECT_ROOT)/src/drivers/mem.c \
	$(PROJECT_ROOT)/src/core/stats.c

HEADER_DIRS := $(PROJECT_ROOT)/src $(LWIP_INC) $(TLS_INC) src/include $(HEADER_DIRS)

include $(shell cedev-config --makefile)

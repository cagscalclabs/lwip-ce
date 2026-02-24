# ----------------------------
# Makefile Options
# ----------------------------

NAME = X509T
ICON = icon.png
ARCHIVED = NO
DESCRIPTION = "tls_x509 parser test"
COMPRESSED = NO

CFLAGS = -Wall -Wextra -Oz -I../../src -I../../src/include -I../../src/tls/includes
CXXFLAGS = -Wall -Wextra -Oz -I../../src -I../../src/include -I../../src/tls/includes

# ----------------------------

EXTRA_C_SOURCES = \
	../../src/tls/core/tls.c \
	../../src/tls/core/x509.c \
	../../src/tls/core/asn1.c \
	../../src/tls/core/base64.c \
	../../src/tls/core/bytes.c \
	../../src/core/mem.c \
	../../src/drivers/mem.c \
	../../src/core/stats.c

HEADER_DIRS := ../../src ../../src/include ../../src/tls/includes src/include $(HEADER_DIRS)

include $(shell cedev-config --makefile)

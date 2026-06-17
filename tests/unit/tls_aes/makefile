# ----------------------------
# Makefile Options
# ----------------------------
# Dyload variant: links against the resident lwip.lib (installed into
# $(CEDEV)/lib/libload/ by build.yml's nightly dylib build) instead of
# statically compiling TLS core sources from src/.

NAME = XAES
ICON = icon.png
ARCHIVED = NO
BSSHEAP_LOW = 0xD072C6
DESCRIPTION = "tls_aes test"
COMPRESSED = NO

CFLAGS = -Wall -Wextra -Oz
CXXFLAGS = -Wall -Wextra -Oz

SOURCES = src/main.c

# ----------------------------

include $(shell cedev-config --makefile)

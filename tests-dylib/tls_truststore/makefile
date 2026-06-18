# ----------------------------
# Makefile Options
# ----------------------------
# Dyload variant: links against the resident lwip.lib (installed into
# $(CEDEV)/lib/libload/ by build.yml's nightly dylib build) instead of
# statically compiling TLS core sources from src/. The allocator is
# bootstrapped by the real public lwip_init() entry point, not a
# hand-rolled mem_init()/mem_buffer_create() call.

NAME = XTRUST
ICON = icon.png
ARCHIVED = NO
BSSHEAP_LOW = 0xD072C6
DESCRIPTION = "TLS Truststore Test"
COMPRESSED = NO

CFLAGS = -Wall -Wextra -Oz
CXXFLAGS = -Wall -Wextra -Oz

SOURCES = src/main.c

# ----------------------------

include $(shell cedev-config --makefile)

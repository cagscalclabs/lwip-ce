# ----------------------------
# Makefile Options
# ----------------------------
# Dyload variant: links against the resident lwip.lib. Allocator is
# bootstrapped via the real public lwip_init(), not a hand-rolled
# mem_init_static() arena.

NAME = X509T
ICON = icon.png
ARCHIVED = NO
BSSHEAP_LOW = 0xD072C6
DESCRIPTION = "tls_x509 parser test"
COMPRESSED = NO

CFLAGS = -Wall -Wextra -Oz
CXXFLAGS = -Wall -Wextra -Oz

SOURCES = src/main.c

# ----------------------------

include $(shell cedev-config --makefile)

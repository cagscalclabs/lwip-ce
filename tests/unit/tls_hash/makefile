# ----------------------------
# Makefile Options
# ----------------------------
# Dyload variant: links against the resident lwip.lib.

NAME = XHASH
ICON = icon.png
ARCHIVED = YES
BSSHEAP_LOW = 0xD072C6
DESCRIPTION = "tls_hash test"
COMPRESSED = NO

CFLAGS = -Wall -Wextra -Oz
CXXFLAGS = -Wall -Wextra -Oz
LTO = NO

SOURCES = src/main.c

# ----------------------------

include $(shell cedev-config --makefile)

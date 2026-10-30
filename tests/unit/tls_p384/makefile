# ----------------------------
# Makefile Options
# ----------------------------
# Dyload variant: links against the resident lwip.lib.

NAME = P384
ARCHIVED = YES
BSSHEAP_LOW = 0xD072C6
DESCRIPTION = "P-384 ECDH/ECDSA Test"
COMPRESSED = YES

CFLAGS = -Wall -Wextra -Oz
CXXFLAGS = -Wall -Wextra -Oz
LTO = NO

SOURCES = src/main.c

# ----------------------------

include $(shell cedev-config --makefile)

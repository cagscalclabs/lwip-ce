# ----------------------------
# Makefile Options
# ----------------------------

NAME = LWHTTPD
DESCRIPTION = "lwIP HTTP Server Example"
COMPRESSED = NO
ARCHIVED = YES
BSSHEAP_LOW = 0xD072C6

CFLAGS = -Wall -Wextra -Oz
CXXFLAGS = -Wall -Wextra -Oz
EXTRA_LDFLAGS += --no-warn-execstack
EXTRA_PRE_LDFLAGS += --no-warn-execstack

# ----------------------------

include $(shell cedev-config --makefile)

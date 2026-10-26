# ----------------------------
# Makefile Options
# ----------------------------
NAME = NETTEST
ARCHIVED = YES
BSSHEAP_LOW = 0xD072C6
DESCRIPTION = "lwIP-CE networked integration test"
COMPRESSED = YES

CFLAGS = -Wall -Wextra -Oz
CXXFLAGS = -Wall -Wextra -Oz
EXTRA_LDFLAGS += --no-warn-execstack
EXTRA_PRE_LDFLAGS += --no-warn-execstack

# ----------------------------

include $(shell cedev-config --makefile)

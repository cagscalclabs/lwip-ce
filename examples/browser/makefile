# ----------------------------
# Makefile Options
# ----------------------------

NAME = LWBRWS
DESCRIPTION = "lwIP Raw Browser Example"
COMPRESSED = NO
ARCHIVED = YES
BSSHEAP_LOW = 0xD072C6

BROWSER_URL ?= http://example.com/

CFLAGS = -Wall -Wextra -Oz \
    -DBROWSER_URL=\"$(BROWSER_URL)\"
CXXFLAGS = $(CFLAGS)

# ----------------------------

include $(shell cedev-config --makefile)

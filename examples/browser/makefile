# ----------------------------
# Makefile Options
# ----------------------------

NAME = CEBROWSE
DESCRIPTION = "lwIP Raw Browser Example"
COMPRESSED = NO
ARCHIVED = YES
BSSHEAP_LOW = 0xD072C6

BROWSER_URL ?= http://example.com/

CFLAGS = -Wall -Wextra -Oz \
    -DBROWSER_URL=\"$(BROWSER_URL)\"
CXXFLAGS = $(CFLAGS)
EXTRA_LDFLAGS += --no-warn-execstack
EXTRA_PRE_LDFLAGS += --no-warn-execstack

# ----------------------------

include $(shell cedev-config --makefile)

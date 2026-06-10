# ----------------------------
# Makefile Options
# ----------------------------

PROJECT_ROOT := ../../..
LWIP_RELEASE_DIR ?= $(PROJECT_ROOT)/build

NAME = DYLBFUNC
DESCRIPTION = "lwIP dylib smoke"
ARCHIVED = NO
COMPRESSED = NO
LTO = NO

# lwIP reserves 0xD052C6..0xD072C6 for the resident app's runtime BSS/data.
BSSHEAP_LOW = 0xD072C6

CFLAGS = -Wall -Wextra -Oz \
	-I$(LWIP_RELEASE_DIR)
CXXFLAGS = $(CFLAGS)

EXTRA_LIBLOAD_LIBS = $(LWIP_RELEASE_DIR)/lwip.lib

# ----------------------------

include $(shell cedev-config --makefile)

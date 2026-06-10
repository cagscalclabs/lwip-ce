# ----------------------------
# Makefile Options
# ----------------------------

PROJECT_ROOT := ../../..
LWIP_RELEASE_DIR ?= $(PROJECT_ROOT)/build

NAME = DYLRSA
DESCRIPTION = "lwIP dylib RSA probe"
ARCHIVED = NO
COMPRESSED = NO
LTO = NO

# lwIP reserves 0xD052C6..0xD072C6 for the resident app's runtime BSS/data.
BSSHEAP_LOW = 0xD072C6

# Keep the caller program easy to debug in CEmu. The resident lwIP app still
# needs bin/lwIP.map for addresses inside the dylib body.
CFLAGS = -Wall -Wextra -O0 -g \
	-I$(LWIP_RELEASE_DIR)
CXXFLAGS = $(CFLAGS)

CEDEV_TOOLCHAIN ?= $(if $(CEDEV),$(CEDEV),$(shell cedev-config --prefix))
LIBLOAD_LIBS = $(filter-out %/lwip.lib,$(wildcard $(CEDEV_TOOLCHAIN)/lib/libload/*.lib)) \
	$(LWIP_RELEASE_DIR)/lwip.lib

# ----------------------------

include $(shell cedev-config --makefile)

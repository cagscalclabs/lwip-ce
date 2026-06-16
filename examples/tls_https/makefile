# ----------------------------
# Makefile Options
# ----------------------------

PROJECT_ROOT := ../..
RELEASE_ROOT ?= $(if $(wildcard ../../lwip),../..,$(PROJECT_ROOT)/build)
CEDEV_TOOLCHAIN ?= $(shell cedev-config --prefix)
LIBLOAD_LIBS := $(filter-out %/lwip.lib,$(wildcard $(CEDEV_TOOLCHAIN)/lib/libload/*.lib)) $(RELEASE_ROOT)/lwip.lib

NAME = LWHTTPS
DESCRIPTION = "lwIP TLS HTTPS Example"
COMPRESSED = NO
ARCHIVED = YES
BSSHEAP_LOW = 0xD072C6

CFLAGS = -Wall -Wextra -Oz -I$(RELEASE_ROOT) -I..
CXXFLAGS = -Wall -Wextra -Oz -I$(RELEASE_ROOT) -I..

# ----------------------------

include $(shell cedev-config --makefile)

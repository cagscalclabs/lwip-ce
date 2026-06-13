# ----------------------------
# Makefile Options
# ----------------------------

PROJECT_ROOT := ../..
RELEASE_ROOT ?= $(if $(wildcard ../../lwip),../..,$(PROJECT_ROOT)/build)

NAME = LWNTP
DESCRIPTION = "lwIP NTP Time Example"
COMPRESSED = NO
ARCHIVED = NO
BSSHEAP_LOW = 0xD072C6

CFLAGS = -Wall -Wextra -Oz -I$(RELEASE_ROOT) -I..
CXXFLAGS = -Wall -Wextra -Oz -I$(RELEASE_ROOT) -I..

# ----------------------------

include $(shell cedev-config --makefile)

ARCHIVED = YES
COMPRESSED = YES
BSSHEAP_LOW = 0xD072C6

CFLAGS = -Wall -Wextra -Oz -I../common
CXXFLAGS = -Wall -Wextra -Oz -I../common
EXTRA_C_SOURCES = ../common/net.c
EXTRA_LDFLAGS += --no-warn-execstack
EXTRA_PRE_LDFLAGS += --no-warn-execstack

include $(shell cedev-config --makefile)

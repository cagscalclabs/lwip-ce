NAME = ACVPRUN
DESCRIPTION = "ACVP network validation service"
ARCHIVED = YES
COMPRESSED = YES
BSSHEAP_LOW = 0xD072C6

CFLAGS = -Wall -Wextra -Oz -I../../net/common
CXXFLAGS = -Wall -Wextra -Oz -I../../net/common
EXTRA_C_SOURCES = ../../net/common/net.c
EXTRA_LDFLAGS += --no-warn-execstack
EXTRA_PRE_LDFLAGS += --no-warn-execstack

include $(shell cedev-config --makefile)

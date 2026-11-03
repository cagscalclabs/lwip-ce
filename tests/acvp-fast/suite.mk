DESCRIPTION = "ACVP $(ACVP_ALGORITHM)"
ARCHIVED = YES
COMPRESSED = YES
BSSHEAP_LOW = 0xD072C6

CFLAGS = -Wall -Wextra -Oz -I../../net/common -DACVP_PRIMITIVE=$(ACVP_PRIMITIVE)
CXXFLAGS = -Wall -Wextra -Oz -I../../net/common
EXTRA_C_SOURCES = ../../validation/acvp/src/main.c ../../net/common/net.c
EXTRA_LDFLAGS += --no-warn-execstack
EXTRA_PRE_LDFLAGS += --no-warn-execstack

include $(shell cedev-config --makefile)

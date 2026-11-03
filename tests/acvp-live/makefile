NAME = ACVPRUN
DESCRIPTION = "NIST ACVP live release harness"
ARCHIVED = YES
COMPRESSED = YES
BSSHEAP_LOW = 0xD072C6

CFLAGS = -Wall -Wextra -Oz -I../net/common
CXXFLAGS = -Wall -Wextra -Oz -I../net/common
EXTRA_C_SOURCES = ../validation/acvp/src/main.c ../net/common/net.c
EXTRA_LDFLAGS += --no-warn-execstack
EXTRA_PRE_LDFLAGS += --no-warn-execstack

include $(shell cedev-config --makefile)

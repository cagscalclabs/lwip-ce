# ----------------------------
# Makefile Options
# ----------------------------

include ../../common/makefile

NAME = MEMBUF
ARCHIVED = NO
DESCRIPTION = "membuffer test"
COMPRESSED = NO

CFLAGS = -Wall -Wextra -Oz -I$(PROJECT_ROOT)/src -I$(LWIP_INC) -I../../../src/drivers
CXXFLAGS = -Wall -Wextra -Oz -I$(PROJECT_ROOT)/src -I$(LWIP_INC) -I../../../src/drivers

SOURCES = src/main.c src/stubs.c

EXTRA_C_SOURCES = ../../../src/drivers/mem.c

HEADER_DIRS := $(PROJECT_ROOT)/src $(LWIP_INC) ../../../src/drivers src/include $(HEADER_DIRS)

include $(shell cedev-config --makefile)

# ----------------------------
# Makefile Options
# ----------------------------

PROJECT_ROOT := ../../..
INSTALLER_SRC := $(PROJECT_ROOT)/tools/app_tools/installer/src

NAME = DYLBFUNC
DESCRIPTION = "lwIP dylib smoke"
ARCHIVED = NO
COMPRESSED = NO
LTO = NO

# lwIP reserves 0xD052C6..0xD072C6 for the resident app's runtime BSS/data.
BSSHEAP_LOW = 0xD072C6

CFLAGS = -Wall -Wextra -Oz \
	-DAPPVAR_PREFIX=\"LWIP\" \
	-DAPPVAR_SPLIT_SIZE=65200 \
	-I$(INSTALLER_SRC)
CXXFLAGS = $(CFLAGS)

EXTRA_ASM_SOURCES = \
	../../../tools/app_tools/installer/src/app.s \
	../../../tools/app_tools/installer/src/flash.s \
	../../../tools/app_tools/installer/src/ports.s

# ----------------------------

include $(shell cedev-config --makefile)

# ----------------------------
# Makefile Options
# ----------------------------

NAME = lwIP
ICON = icon.png
DESCRIPTION = lwIP Networking Stack

APP_NAME = lwIP
APP_VERSION = 0

CFLAGS = -Wall -Wextra -Oz -I src/include
CXXFLAGS = -Wall -Wextra -Oz -I src/include
OUTPUT_MAP = YES
HAS_LIBC = YES

BSSHEAP_LOW ?= D052C6
# BSSHEAP_LOW ?= D11FD8
# BSSHEAP_HIGH ?= D13FD8
# ----------------------------

# This is just to shut up the linker, lwIP is an app, it takes user malloc
ALLOCATOR = CUSTOM
EXTRA_ASM_SOURCES = src/custom_allocator.src

include app_tools/makefile


# defining a build rule for the generation of a function table
# to ensure all modules are built into lwip
HEADER_DIRS := src/include/lwip/
EXCLUDE_LIST := src/include/lwip/debug.h
FUNCTABLE_FILE := src/functable.h
HELPER_FILES := $(FUNCTABLE_FILE) tmp/headers.tmp

functiontable: $(HELPER_FILES)

$(HELPER_FILES):
	./make_functable.sh
	

.PHONY: functiontable

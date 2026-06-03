# ----------------------------
# Makefile Options
# ----------------------------

include ../../common/makefile

NAME = ETHRX
ICON = icon.png
ARCHIVED = NO
DESCRIPTION = "Ethernet RX test"
COMPRESSED = NO

CFLAGS = -Wall -Wextra -Oz -DLWIP_ETHERNET_TEST_HOOKS -I$(LWIP_INC) -I../../../src -I../../../src/drivers
CXXFLAGS = -Wall -Wextra -Oz -DLWIP_ETHERNET_TEST_HOOKS -I$(LWIP_INC) -I../../../src -I../../../src/drivers

SOURCES = src/main.c src/stubs.c

EXTRA_C_SOURCES = ../../../src/drivers/usb_ethernet.c ../../../src/drivers/mem.c ../../../src/lwip-imports.c

HEADER_DIRS := $(LWIP_INC) ../../../src ../../../src/drivers src/include $(HEADER_DIRS)

include $(shell cedev-config --makefile)

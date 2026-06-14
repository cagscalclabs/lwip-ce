# cedbg - headless CEmu debugger frontend
#
# Builds libcemucore.a (with debug support) from the CEmu source tree, then
# links the cedbg frontend against it.

CEMU_DIR ?= $(HOME)/CEmu
CORE_DIR  = $(CEMU_DIR)/core
CORE_LIB  = $(CORE_DIR)/libcemucore.a

CC      = gcc

# libusb (for CEmu's physical USB passthrough backend, core/usb/physical.c).
LIBUSB_CFLAGS = $(shell pkg-config --cflags libusb-1.0)
LIBUSB_LIBS   = $(shell pkg-config --libs libusb-1.0)

CFLAGS  = -Wall -Wextra -O2 -std=gnu11 -I$(CORE_DIR) $(LIBUSB_CFLAGS)
# DLIBUSB_SUPPORT enables usb_physical_device (else it's a ENOSYS stub).
CORE_CFLAGS = -Wall -Wextra -fPIC -O2 -std=gnu11 -DDEBUG_SUPPORT -DLIBUSB_SUPPORT $(LIBUSB_CFLAGS)

all: cedbg

# Build the core static lib with debug + libusb support enabled.
$(CORE_LIB):
	$(MAKE) -C $(CORE_DIR) CFLAGS="$(CORE_CFLAGS)" lib

SRCS = cedbg.c netbridge.c

cedbg: $(SRCS) netbridge.h $(CORE_LIB)
	$(CC) $(CFLAGS) -DDEBUG_SUPPORT $(SRCS) $(CORE_LIB) $(LIBUSB_LIBS) -o cedbg

clean:
	rm -f cedbg

clean-core:
	$(MAKE) -C $(CORE_DIR) clean

.PHONY: all clean clean-core

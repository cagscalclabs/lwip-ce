NAME        = DISC
DESCRIPTION = "lwIP Discord Relay"
COMPRESSED  = NO
ARCHIVED    = YES
BSSHEAP_LOW = 0xD052C6

# Default relay host shown in the setup screen (user can change it at runtime)
RELAY_DEFAULT_HOST ?=
RELAY_DEFAULT_PORT ?= 8443

CFLAGS = -Wall -Wextra -Oz \
    -DRELAY_DEFAULT_HOST=\"$(RELAY_DEFAULT_HOST)\" \
    -DRELAY_DEFAULT_PORT=\"$(RELAY_DEFAULT_PORT)\"
CXXFLAGS = $(CFLAGS)

include $(shell cedev-config --makefile)

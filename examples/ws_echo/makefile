NAME        = WSECHO
DESCRIPTION = "lwIP WebSocket Echo Example"
COMPRESSED  = NO
ARCHIVED    = YES
BSSHEAP_LOW = 0xD072C6

WS_HOST ?= websocket-echo.com
CFLAGS   = -Wall -Wextra -Oz -DWS_HOST=\"$(WS_HOST)\"
CXXFLAGS = $(CFLAGS)

include $(shell cedev-config --makefile)

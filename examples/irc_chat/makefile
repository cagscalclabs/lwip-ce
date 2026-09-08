# ----------------------------
# Makefile Options
# ----------------------------

NAME = IRCE
DESCRIPTION = "lwIP IRC Chat Example"
COMPRESSED = NO
ARCHIVED = YES
BSSHEAP_LOW = 0xD072C6

IRC_HOST ?= irc.efnet.org
IRC_PORT ?= 6667
IRC_TLS_PORT ?= 6697
IRC_CHANNEL ?= \#cemetech
IRC_NICK ?= LWIPCE
IRC_DEBUG ?= 0

CFLAGS = -Wall -Wextra -Oz \
    -DIRC_HOST=\"$(IRC_HOST)\" \
    -DIRC_PORT=$(IRC_PORT) \
    -DIRC_TLS_PORT=$(IRC_TLS_PORT) \
    -DIRC_CHANNEL=\"$(IRC_CHANNEL)\" \
    -DIRC_NICK=\"$(IRC_NICK)\" \
    -DIRC_DEBUG=$(IRC_DEBUG)
CXXFLAGS = $(CFLAGS)

# ----------------------------

include $(shell cedev-config --makefile)

# ----------------------------
# Makefile Options
# ----------------------------

NAME = LWIRC
DESCRIPTION = "lwIP IRC Chat Example"
COMPRESSED = NO
ARCHIVED = YES
BSSHEAP_LOW = 0xD072C6

IRC_HOST ?= irc.efnet.org
IRC_PORT ?= 6667
IRC_CHANNEL ?= \#cemetech
IRC_NICK ?= LWIPCE

CFLAGS = -Wall -Wextra -Oz \
    -DIRC_HOST=\"$(IRC_HOST)\" \
    -DIRC_PORT=$(IRC_PORT) \
    -DIRC_CHANNEL=\"$(IRC_CHANNEL)\" \
    -DIRC_NICK=\"$(IRC_NICK)\"
CXXFLAGS = $(CFLAGS)

# ----------------------------

include $(shell cedev-config --makefile)

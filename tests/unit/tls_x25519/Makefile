# ----------------------------
# Makefile Options
# ----------------------------
# Dyload variant: links against the resident lwip.lib (the public
# tls_x25519_secret/tls_x25519_publickey wrappers, not the raw asm).

NAME = X25519
ARCHIVED = NO
BSSHEAP_LOW = 0xD072C6
DESCRIPTION = "X25519 RFC 7748 Test"
COMPRESSED = NO

CFLAGS = -Wall -Wextra -Oz
CXXFLAGS = -Wall -Wextra -Oz

SOURCES = src/main.c

# ----------------------------

include $(shell cedev-config --makefile)

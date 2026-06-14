# ----------------------------
# Makefile Options
# ----------------------------

PROJECT_ROOT := ../..
RELEASE_ROOT ?= $(if $(wildcard ../../lwip),../..,$(PROJECT_ROOT)/build)

NAME = LWTLCHAT
DESCRIPTION = "lwIP TLS Chat Example"
COMPRESSED = NO
ARCHIVED = YES
BSSHEAP_LOW = 0xD072C6

SERVER_IP ?= 192.168.2.14

CFLAGS = -Wall -Wextra -Oz -I$(RELEASE_ROOT) -I.. -DCHAT_HOST=\"$(SERVER_IP)\"
CXXFLAGS = -Wall -Wextra -Oz -I$(RELEASE_ROOT) -I.. -DCHAT_HOST=\"$(SERVER_IP)\"

# ----------------------------

include $(shell cedev-config --makefile)

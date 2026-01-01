# ----------------------------
# Makefile Options
# ----------------------------

NAME = TLSTEST
ICON = icon.png
ARCHIVED = NO
DESCRIPTION = "TLS 1.3 Full Handshake Test"
COMPRESSED = NO

CFLAGS = -Wall -Wextra -Oz -I../../src/include -I../../src/tls/includes -I../../src/crypto -I../../src/arch/share
CXXFLAGS = -Wall -Wextra -Oz -I../../src/include -I../../src/tls/includes -I../../src/crypto -I../../src/arch/share

# Test main
SOURCES = src/main.c

# Pull in only TLS core files (handshake, HKDF, etc.)
SOURCES += $(wildcard ../../src/tls/core/*.c)

# Pull in only crypto files (no networking, no drivers)
SOURCES += $(wildcard ../../src/crypto/*.c)

# Pull in assembly files from crypto and arch (no driver ASM)
ASM = $(wildcard ../../src/crypto/*.asm)
ASM += $(wildcard ../../src/arch/share/*.asm)

# ----------------------------

# Add header directories
HEADER_DIRS := ../../src/include ../../src/tls/includes src/include $(HEADER_DIRS)

include $(shell cedev-config --makefile)

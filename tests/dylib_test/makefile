# ----------------------------
# Makefile Options
# ----------------------------

NAME = DYLIBT
ICON = icon.png
ARCHIVED = NO
DESCRIPTION = "dylib test"
COMPRESSED = NO

CFLAGS = -Wall -Wextra -Oz -I../../src/include -I../../src/tls/includes -I../../libload
CXXFLAGS = -Wall -Wextra -Oz -I../../src/include -I../../src/tls/includes -I../../libload

# Test main
SOURCES = src/main.c

# Link against lwIP libload stub
EXTRA_LIBLOAD_LIBS = ../../libload/lwip.lib

# ----------------------------

# Add header directories
HEADER_DIRS := ../../src/include ../../src/tls/includes ../../libload src/include $(HEADER_DIRS)

include $(shell cedev-config --makefile)

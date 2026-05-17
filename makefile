# ----------------------------
# Makefile Options
# ----------------------------

NAME = DEMO
ICON = icon.png
DESCRIPTION = "CE Toolchain Demo"
COMPRESSED = NO
ARCHIVED = NO

CFLAGS = -Wall -Wextra -Oz -I src/include
CXXFLAGS = -Wall -Wextra -Oz -I src/include
ASFLAGS = -I src/tls/core -I src/tls/core/share

APPLICATION = YES

# ----------------------------

include $(shell cedev-config --makefile)

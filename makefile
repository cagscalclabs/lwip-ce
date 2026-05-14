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
APPLICATION = YES

# ----------------------------

include $(shell cedev-config --makefile)

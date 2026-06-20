# ----------------------------
# Makefile Options
# ----------------------------
# Dyload variant: links against the resident lwip.lib (installed into
# $(CEDEV)/lib/libload/ by build.yml's nightly dylib build) instead of
# statically compiling TLS core sources from src/.

NAME = XTIMING
ICON = icon.png
ARCHIVED = NO
BSSHEAP_LOW = 0xD072C6
DESCRIPTION = "tls_timing test"
COMPRESSED = NO

# TLS_TIMING_AUTORUN: skip the per-primitive "Press any key" waits and the
# final "Done." prompt. Required for unattended CI runs (CEmu autotester has
# no way to send a keypress) -- without it, the test hangs forever on
# os_GetKey() after the first primitive (BYTES) and CI sees only that one
# result. Omit this define for interactive/manual runs on real hardware.
CFLAGS = -Wall -Wextra -Oz -DTLS_TIMING_AUTORUN
CXXFLAGS = -Wall -Wextra -Oz -DTLS_TIMING_AUTORUN

SOURCES = src/main.c

# ----------------------------

include $(shell cedev-config --makefile)

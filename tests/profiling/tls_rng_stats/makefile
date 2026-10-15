# ----------------------------
# Makefile Options
# ----------------------------
# Links against the resident lwip.lib so the profiler exercises the exact
# public tls_rng_compute_stats() API shipped to applications.

NAME = RNGSTAT
ARCHIVED = NO
BSSHEAP_LOW = 0xD072C6
DESCRIPTION = "TLS raw tap profiler"
COMPRESSED = NO

CFLAGS = -Wall -Wextra -Oz
CXXFLAGS = -Wall -Wextra -Oz

SOURCES = src/main.c

# ----------------------------

include $(shell cedev-config --makefile)

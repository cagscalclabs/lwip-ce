# ----------------------------
# P-256 assembly profiling target
# ----------------------------
# Standalone: statically assembles src/tls/core/p256.s into the program and
# does NOT link lwip.lib (the libload copy of lwip.lib is filtered out of
# LIBLOAD_LIBS, so nothing can silently resolve against the resident dylib).
#
# P256_TEST exposes the C-ABI test shims (p256_test_mont_mul etc.) used to
# time individual primitives.  tls_p256_sign lives in its own section and is
# discarded by --gc-sections because this program never calls it, so no
# SHA-256 implementation is needed here.
#
# Build:   make            (on-calc: prints results, waits for a key)
#          make debug      (also mirrors results to the emulator console)

NAME = P256PROF
ARCHIVED = NO
DESCRIPTION = "P-256 asm profiling"
COMPRESSED = NO

CFLAGS = -Wall -Wextra -Oz
ASFLAGS = --defsym P256_TEST=1

EXTRA_ASM_SOURCES = ../../src/tls/core/p256.s

LIBLOAD_LIBS = $(filter-out %lwip.lib,$(wildcard $(shell cedev-config --prefix)/lib/libload/*.lib))

# ----------------------------

include $(shell cedev-config --makefile)

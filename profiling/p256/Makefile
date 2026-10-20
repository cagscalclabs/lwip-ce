# ----------------------------
# P-256 assembly profiling target
# ----------------------------
# Standalone: statically assembles src/tls/core/p256.s into the program and
# does NOT link lwip.lib (the libload copy of lwip.lib is filtered out of
# LIBLOAD_LIBS, so nothing can silently resolve against the resident dylib).
#
# P256_TEST exposes the C-ABI test shims (p256_test_mont_mul etc.) used to
# time individual primitives.  tls_p256_sign (RFC 6979) needs SHA-256, so
# src/tls/core/sha256.s is assembled in too; src/sha_support.s pins its
# scratch overlay base (_sprng_entropy_pool) to 0xE30800 as the lwIP linker
# script does, and supplies u64_addi.
#
# Build:   make            (on-calc: prints results, waits for a key)
#          make debug      (also mirrors results to the emulator console)

NAME = P256PROF
ARCHIVED = NO
DESCRIPTION = "P-256 asm profiling"
COMPRESSED = NO

CFLAGS = -Wall -Wextra -Oz
ASFLAGS = --defsym P256_TEST=1 -I ../../src/tls/core/share

EXTRA_ASM_SOURCES = ../../src/tls/core/p256.s ../../src/tls/core/sha256.s \
                    ../../src/tls/core/share/crypto_guard.s

LIBLOAD_LIBS = $(filter-out %lwip.lib,$(wildcard $(shell cedev-config --prefix)/lib/libload/*.lib))

# ----------------------------

include $(shell cedev-config --makefile)

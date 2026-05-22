COMMON_MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
PROJECT_ROOT := $(realpath $(COMMON_MAKEFILE_DIR)/../..)
TLS_CORE := $(PROJECT_ROOT)/src/tls/core
TLS_INC := $(PROJECT_ROOT)/src/tls/includes
LWIP_INC := $(PROJECT_ROOT)/src/include
X25519_DIR := $(PROJECT_ROOT)/src/tls/contrib/x25519/src

# CEdev toolchain v15 NOTE:
#   The cedev makefile's ASM build rules ($(OBJDIR)/%.s.o pattern) mangle
#   absolute source paths into nonsense like 'obj//abs/path/file.s.o' which
#   then fails to assemble. C sources are unaffected. Workaround: use the
#   _REL variants below for EXTRA_ASM_SOURCES, while keeping EXTRA_C_SOURCES
#   on the absolute variants above. Both forms point to the same files.
#
# Relative paths are computed from each test's own directory (3 levels up:
# tests/<category>/<name>/ -> project root).
TLS_CORE_REL := ../../../src/tls/core
X25519_DIR_REL := ../../../src/tls/contrib/x25519/src

# Assembler include path: needed for .s files that .include "virtuals.inc"
# (sha256.s, random.s, share/crypto_guard.s). Absolute path is fine here
# because -I flags don't go through the OBJDIR pattern mangling.
TLS_ASM_INCLUDES := -I $(TLS_CORE)/share

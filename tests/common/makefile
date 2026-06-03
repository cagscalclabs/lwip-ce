COMMON_MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
PROJECT_ROOT := $(realpath $(COMMON_MAKEFILE_DIR)/../..)
TLS_CORE := $(PROJECT_ROOT)/src/tls/core
TLS_INC := $(PROJECT_ROOT)/src/tls/includes
LWIP_INC := $(PROJECT_ROOT)/src/include
X25519_DIR := $(PROJECT_ROOT)/src/tls/contrib/x25519/src

# Provide a default address for _sprng_entropy_pool (the RNG safe-RAM
# scratch base). The real app defines this via the safe-RAM OVERLAY in
# linker_script_lwip.ld; standalone test programs that assemble random.s /
# sha256.s (which include virtuals.inc's `extern _sprng_entropy_pool`)
# would otherwise fail to link. PROVIDE yields to any real definition.
EXTRA_LDFLAGS += -T $(COMMON_MAKEFILE_DIR)saferam_defaults.ld

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

TLS_ASM_SHA256 := $(TLS_CORE_REL)/sha256.s
TLS_ASM_BYTES := $(TLS_CORE_REL)/bytes.s
TLS_ASM_BIGINT := $(TLS_CORE_REL)/share/bigint.s
TLS_ASM_HELPERS := $(TLS_CORE_REL)/share/helpers.s
TLS_ASM_RANDOM := $(TLS_CORE_REL)/random.s
TLS_ASM_CRYPTO_GUARD := $(TLS_CORE_REL)/share/crypto_guard.s

TLS_ASM_AES := $(TLS_ASM_BYTES) $(TLS_ASM_BIGINT) $(TLS_ASM_CRYPTO_GUARD)
TLS_ASM_HASH := $(TLS_ASM_SHA256) $(TLS_ASM_BYTES) $(TLS_ASM_BIGINT) $(TLS_ASM_RANDOM) $(TLS_ASM_CRYPTO_GUARD)
TLS_ASM_TLS_FULL := $(TLS_ASM_SHA256) $(TLS_ASM_BYTES) $(TLS_ASM_BIGINT) $(TLS_ASM_HELPERS) $(TLS_ASM_RANDOM) $(TLS_ASM_CRYPTO_GUARD)

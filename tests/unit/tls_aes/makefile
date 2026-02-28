# ----------------------------
# Makefile Options
# ----------------------------

include ../../common/makefile

NAME = DEMO
ICON = icon.png
ARCHIVED = NO
DESCRIPTION = "tls_aes test"
COMPRESSED = NO

CFLAGS = -Wall -Wextra -Oz -I$(LWIP_INC) -I$(TLS_INC)
CXXFLAGS = -Wall -Wextra -Oz -I$(LWIP_INC) -I$(TLS_INC)


# Test main
SOURCES = src/main.c

# Pull in required TLS core files
EXTRA_C_SOURCES = $(TLS_CORE)/aes.c $(TLS_CORE)/bytes.c

# Assembly files (bytelen_to_bitlen in bytes.asm, gf128_mul in bigint.asm for GCM)
EXTRA_ASM_SOURCES = $(TLS_CORE)/bytes.asm $(TLS_CORE)/share/bigint.asm \
	$(TLS_CORE)/share/crypto_guard.asm \

# ----------------------------

# Add header directories
HEADER_DIRS := $(LWIP_INC) $(TLS_INC) src/include $(HEADER_DIRS)

include $(shell cedev-config --makefile)

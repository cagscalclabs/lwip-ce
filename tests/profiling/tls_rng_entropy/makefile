# ----------------------------
# Makefile Options
# ----------------------------

include ../../common/makefile

NAME = RNGENT
ARCHIVED = NO
DESCRIPTION = "tls rng entropy capture"
COMPRESSED = NO

CFLAGS = -Wall -Wextra -Oz -I$(LWIP_INC) -I$(TLS_INC)
CXXFLAGS = -Wall -Wextra -Oz -I$(LWIP_INC) -I$(TLS_INC)

SOURCES = src/main.c

EXTRA_ASM_SOURCES = \
	$(TLS_CORE)/bytes.asm \
	$(TLS_CORE)/random.asm \
	$(TLS_CORE)/sha256.asm \
	$(TLS_CORE)/share/bigint.asm \
	$(TLS_CORE)/share/crypto_guard.asm

HEADER_DIRS := $(LWIP_INC) $(TLS_INC) src/include $(HEADER_DIRS)

include $(shell cedev-config --makefile)

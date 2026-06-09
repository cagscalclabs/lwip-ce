# ----------------------------
# Makefile Options
# ----------------------------

include ../../common/makefile

# Add -I path so the assembler can find virtuals.inc et al.
ASFLAGS += $(TLS_ASM_INCLUDES)

NAME = RNGENT
ARCHIVED = NO
DESCRIPTION = "tls rng entropy capture"
COMPRESSED = NO

CFLAGS = -Wall -Wextra -Oz -I$(LWIP_INC) -I$(TLS_INC)
CXXFLAGS = -Wall -Wextra -Oz -I$(LWIP_INC) -I$(TLS_INC)

SOURCES = src/main.c

EXTRA_ASM_SOURCES = \
	$(TLS_CORE_REL)/bytes.s \
	$(TLS_CORE_REL)/random.s \
	$(TLS_CORE_REL)/sha256.s \
	$(TLS_CORE_REL)/share/bigint.s \
	$(TLS_CORE_REL)/share/crypto_guard.s

HEADER_DIRS := $(LWIP_INC) $(TLS_INC) src/include $(HEADER_DIRS)

include $(shell cedev-config --makefile)

# ----------------------------
# Makefile Options
# ----------------------------

include ../../common/makefile

NAME = TLSRNG
ICON = icon.png
ARCHIVED = NO
DESCRIPTION = "tls_rng test"
COMPRESSED = NO

CFLAGS = -Wall -Wextra -Oz -I$(PROJECT_ROOT)/src -I$(LWIP_INC) -I$(TLS_INC)
CXXFLAGS = -Wall -Wextra -Oz -I$(PROJECT_ROOT)/src -I$(LWIP_INC) -I$(TLS_INC)

SOURCES = src/main.c

EXTRA_C_SOURCES = \
	$(TLS_CORE)/tls.c \
	$(TLS_CORE)/hash.c \
	$(TLS_CORE)/rsa.c \
	$(TLS_CORE)/bytes.c \
	$(PROJECT_ROOT)/src/core/mem.c \
	$(PROJECT_ROOT)/src/core/stats.c \
	$(PROJECT_ROOT)/src/drivers/mem.c \
	$(PROJECT_ROOT)/src/core/logging.c \
	$(PROJECT_ROOT)/src/core/app_config.c

EXTRA_ASM_SOURCES = \
	$(TLS_CORE)/random.asm \
	$(TLS_CORE)/sha256.asm \
	$(TLS_CORE)/bytes.asm \
	$(TLS_CORE)/share/bigint.asm \
	$(TLS_CORE)/share/helpers.asm \
	$(TLS_CORE)/share/crypto_guard.asm

HEADER_DIRS := $(PROJECT_ROOT)/src $(LWIP_INC) $(TLS_INC) src/include $(HEADER_DIRS)

include $(shell cedev-config --makefile)

# ----------------------------
# Makefile Options
# ----------------------------

include ../common/makefile

NAME = TRUSTST
ICON = icon.png
ARCHIVED = NO
DESCRIPTION = "TLS Truststore Test"
COMPRESSED = NO

CFLAGS = -Wall -Wextra -Oz -I$(PROJECT_ROOT)/src -I$(LWIP_INC) -I$(TLS_INC)
CXXFLAGS = -Wall -Wextra -Oz -I$(PROJECT_ROOT)/src -I$(LWIP_INC) -I$(TLS_INC)


# Test main
SOURCES = src/main.c

# Pull in required TLS core files
EXTRA_C_SOURCES = $(TLS_CORE)/truststore.c $(TLS_CORE)/rsa.c $(TLS_CORE)/hash.c $(TLS_CORE)/tls.c $(TLS_CORE)/bytes.c $(TLS_CORE)/asn1.c $(TLS_CORE)/base64.c $(TLS_CORE)/keyobject.c $(TLS_CORE)/pkcs8.c $(TLS_CORE)/x509.c $(TLS_CORE)/passwords.c $(TLS_CORE)/aes.c $(PROJECT_ROOT)/src/core/mem.c $(PROJECT_ROOT)/src/drivers/mem.c $(PROJECT_ROOT)/src/core/stats.c $(PROJECT_ROOT)/src/core/logging.c $(PROJECT_ROOT)/src/core/app_config.c

# Assembly files from TLS core
EXTRA_ASM_SOURCES = $(TLS_CORE)/sha256.asm $(TLS_CORE)/bytes.asm $(TLS_CORE)/share/bigint.asm $(TLS_CORE)/random.asm \
	$(TLS_CORE)/share/helpers.asm \
	$(TLS_CORE)/share/crypto_guard.asm \

# ----------------------------

# Add header directories
HEADER_DIRS := $(PROJECT_ROOT)/src $(LWIP_INC) $(TLS_INC) src/include $(HEADER_DIRS)

include $(shell cedev-config --makefile)

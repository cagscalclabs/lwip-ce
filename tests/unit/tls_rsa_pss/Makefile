# ----------------------------
# Makefile Options
# ----------------------------

include ../../common/makefile

# Add -I path so the assembler can find virtuals.inc et al.
ASFLAGS += $(TLS_ASM_INCLUDES)

NAME = PSSTEST
ICON = icon.png
ARCHIVED = NO
DESCRIPTION = "RSA-PSS Test"
COMPRESSED = NO

CFLAGS = -Wall -Wextra -Oz -I$(PROJECT_ROOT)/src -I$(LWIP_INC) -I$(TLS_INC)
CXXFLAGS = -Wall -Wextra -Oz -I$(PROJECT_ROOT)/src -I$(LWIP_INC) -I$(TLS_INC)


# Test main
SOURCES = src/main.c

# Pull in required TLS core files
EXTRA_C_SOURCES = $(TLS_CORE)/rsa.c $(TLS_CORE)/hash.c $(TLS_CORE)/hmac.c $(TLS_CORE)/bytes.c $(PROJECT_ROOT)/src/core/mem.c $(PROJECT_ROOT)/src/drivers/mem.c $(PROJECT_ROOT)/src/core/stats.c

# Assembly files from TLS core
EXTRA_ASM_SOURCES = $(TLS_ASM_HASH)

# ----------------------------

# Add header directories
HEADER_DIRS := $(LWIP_INC) $(TLS_INC) src/include $(HEADER_DIRS)

include $(shell cedev-config --makefile)

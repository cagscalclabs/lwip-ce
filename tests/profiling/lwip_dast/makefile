# ----------------------------
# lwIP-CE DAST calc-side harness
# ----------------------------

PROJECT_ROOT := ../../..
RELEASE_ROOT ?= $(if $(wildcard $(PROJECT_ROOT)/lwip),$(PROJECT_ROOT),$(PROJECT_ROOT)/build)
EXAMPLES_ROOT := $(PROJECT_ROOT)/examples
CEDEV_TOOLCHAIN ?= $(shell cedev-config --prefix)
LIBLOAD_LIBS := $(filter-out %/lwip.lib,$(wildcard $(CEDEV_TOOLCHAIN)/lib/libload/*.lib)) $(RELEASE_ROOT)/lwip.lib

NAME = LWDAST
DESCRIPTION = "lwIP DAST harness"
COMPRESSED = NO
ARCHIVED = NO
BSSHEAP_LOW = 0xD072C6

# -I$(RELEASE_ROOT)   <lwip.h> + lwip/core/*, links libload lwip.lib
# -I$(EXAMPLES_ROOT)  common/lwip_example.h (shared boot/UI helpers)
# -Isrc               dast_tests.h (generated from dast_tests.json)
CFLAGS = -Wall -Wextra -Oz -I$(RELEASE_ROOT) -I$(EXAMPLES_ROOT) -Isrc
CXXFLAGS = -Wall -Wextra -Oz -I$(RELEASE_ROOT) -I$(EXAMPLES_ROOT) -Isrc

# ----------------------------

include $(shell cedev-config --makefile)

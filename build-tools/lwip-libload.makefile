# Copyright (C) 2015-2026 CE Programming
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

COMMON_MK := $(CURDIR)/../common.mk

ifneq ($(wildcard $(COMMON_MK)),)
include $(COMMON_MK)
INSTALL_PREREQS := all
else
V ?= 0
ifeq ($(V),0)
Q = @
else
Q =
endif

DESTDIR ?= $(if $(CEDEV),$(CEDEV),$(HOME)/CEdev)
PREFIX ?=
INSTALL_DIR := $(patsubst %/,%,$(DESTDIR))/$(PREFIX)
INSTALL_LIB := $(INSTALL_DIR)/lib/libload
INSTALL_H := $(INSTALL_DIR)/include

FASMG ?= fasmg
MKDIR ?= mkdir -p "$1"
REMOVE ?= rm -f $1
RMDIR ?= rm -rf "$1"
COPY ?= cp "$1" "$2"
COPYDIR ?= cp -R "$1" "$2"
INSTALL_PREREQS := lwip.lib lwip.8xv
endif

LIB_SRC := lwip.asm
LIB_LIB := lwip.lib
LIB_8XV := lwip.8xv
LIB_H_DIR := lwip
LIB_CORE_H := lwip.h
LIB_CRYPTO_H := cryptography.h

all: $(LIB_8XV)

ifneq ($(wildcard $(COMMON_MK)),)
$(LIB_8XV): $(LIB_SRC)
	$(Q)$(FASMG) $< $@
else
$(LIB_LIB) $(LIB_8XV):
	$(Q)test -f $@ || { echo "missing $@; rerun build-release-dylib.sh"; exit 1; }
endif

clean:
	$(Q)$(call REMOVE,$(LIB_LIB) $(LIB_8XV))

install: $(INSTALL_PREREQS)
	$(Q)$(call MKDIR,$(INSTALL_LIB))
	$(Q)$(call MKDIR,$(INSTALL_H))
	$(Q)$(call COPY,$(LIB_LIB),$(INSTALL_LIB))
	$(Q)$(call RMDIR,$(INSTALL_H)/$(LIB_H_DIR))
	$(Q)$(call COPYDIR,$(LIB_H_DIR),$(INSTALL_H))
	$(Q)$(call COPY,$(LIB_CORE_H),$(INSTALL_H))
	$(Q)$(call COPY,$(LIB_CRYPTO_H),$(INSTALL_H))

.PHONY: all clean install

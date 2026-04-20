# ----------------------------
# Makefile Options
# ----------------------------

NAME = lwIP
ICON = icon.png
DESCRIPTION = lwIP Networking Stack

APP_NAME = lwIP
APP_VERSION = 0

CFLAGS = -Wall -Wextra -Oz -I src/include -DAPP_RELOC=1
CXXFLAGS = -Wall -Wextra -Oz -I src/include -DAPP_RELOC=1
LDFLAGS = -DAPP_RELOC=1

OUTPUT_MAP = NO
HAS_LIBC = YES

# BSSHEAP_LOW ?= D052C6
# BSSHEAP_LOW ?= D11FD8
# BSSHEAP_HIGH ?= D13FD8
# ----------------------------

# Include standard allocator from toolchain
EXTRA_ASM_SOURCES = $(CEDEV)/lib/libc/allocator_standard.c.src

include app_tools/makefile

# defining a build rule for the generation of a function table
# to ensure all modules are built into lwip
HEADER_DIRS := src/include/lwip/
EXCLUDE_LIST := src/include/lwip/debug.h
FUNCTABLE_FILE := src/functable.h
HELPER_FILES := $(FUNCTABLE_FILE) tmp/headers.tmp

.PHONY: security-review
security-review:
	@set -eu; \
	OUT="SEC_RESULTS.md"; \
	TMP="$$(mktemp -d)"; \
	FAIL=0; \
	SEC_DIRS="src/tls src/drivers"; \
	SEC_C_FILES="$$(find $$SEC_DIRS -type f -name '*.c')"; \
	ANALYZE_INC="-Isrc/include -Isrc/tls/includes"; \
	if [ -n "$${CEDEV:-}" ] && [ -d "$$CEDEV/include" ]; then \
	  ANALYZE_INC="$$ANALYZE_INC -I$$CEDEV/include"; \
	fi; \
	ANALYZE_DEFS="-D__INT24_TYPE__=int -D__UINT24_TYPE__=unsigned -Duint24_t=unsigned"; \
	RUN_TIMEOUT=""; \
	if command -v timeout >/dev/null 2>&1; then \
	  RUN_TIMEOUT="timeout"; \
	elif command -v gtimeout >/dev/null 2>&1; then \
	  RUN_TIMEOUT="gtimeout"; \
	fi; \
	{ \
	  echo "# Security Review Results"; \
	  echo ""; \
	  echo "Generated: $$(date -u '+%Y-%m-%d %H:%M:%SZ')"; \
	  echo "Repository: \`$$(basename "$$(pwd)")\`"; \
	  echo "Scope: \`$$SEC_DIRS\`"; \
	  echo ""; \
	} > "$$OUT"; \
	CPP_LOG="$$TMP/cppcheck.log"; \
	if command -v cppcheck >/dev/null 2>&1; then \
	  if [ -n "$$RUN_TIMEOUT" ]; then \
	    if $$RUN_TIMEOUT 600 cppcheck --enable=warning,style,performance,portability,information --inconclusive --max-configs=1 --error-exitcode=2 --std=c99 --quiet -Isrc/include -Isrc/tls/includes $$ANALYZE_DEFS $$SEC_C_FILES > "$$CPP_LOG" 2>&1; then CPP_STATUS="PASS"; else CPP_STATUS="FAIL"; FAIL=1; fi; \
	  else \
	    if cppcheck --enable=warning,style,performance,portability,information --inconclusive --max-configs=1 --error-exitcode=2 --std=c99 --quiet -Isrc/include -Isrc/tls/includes $$ANALYZE_DEFS $$SEC_C_FILES > "$$CPP_LOG" 2>&1; then CPP_STATUS="PASS"; else CPP_STATUS="FAIL"; FAIL=1; fi; \
	  fi; \
	else \
	  echo "cppcheck not found in PATH" > "$$CPP_LOG"; CPP_STATUS="MISSING"; FAIL=1; \
	fi; \
	{ \
	  echo "## cppcheck"; \
	  echo ""; \
	  echo "Status: **$$CPP_STATUS**"; \
	  echo ""; \
	  echo '```text'; \
	  cat "$$CPP_LOG"; \
	  echo '```'; \
	  echo ""; \
	} >> "$$OUT"; \
	SB_LOG="$$TMP/scanbuild.log"; \
	SB_CMD=""; \
	for c in scan-build scan-build-18 scan-build-17 scan-build-16 scan-build-15 scan-build-14; do \
	  if command -v $$c >/dev/null 2>&1; then SB_CMD=$$c; break; fi; \
	done; \
	if [ -n "$$SB_CMD" ]; then \
	  if [ -n "$$RUN_TIMEOUT" ]; then \
	    if $$RUN_TIMEOUT 900 "$$SB_CMD" --status-bugs -o "$$TMP/scan-build-out" sh -c "for f in \$$(find $$SEC_DIRS -type f -name '*.c'); do clang --analyze -std=c99 $$ANALYZE_INC $$ANALYZE_DEFS -DAPP_RELOC=1 \$$f || exit 1; done" > "$$SB_LOG" 2>&1; then SB_STATUS="PASS"; else SB_STATUS="FAIL"; FAIL=1; fi; \
	  else \
	    if "$$SB_CMD" --status-bugs -o "$$TMP/scan-build-out" sh -c "for f in \$$(find $$SEC_DIRS -type f -name '*.c'); do clang --analyze -std=c99 $$ANALYZE_INC $$ANALYZE_DEFS -DAPP_RELOC=1 \$$f || exit 1; done" > "$$SB_LOG" 2>&1; then SB_STATUS="PASS"; else SB_STATUS="FAIL"; FAIL=1; fi; \
	  fi; \
	else \
	  echo "scan-build not found in PATH" > "$$SB_LOG"; SB_STATUS="MISSING"; FAIL=1; \
	fi; \
	{ \
	  echo "## clang scan-build"; \
	  echo ""; \
	  echo "Status: **$$SB_STATUS**"; \
	  echo ""; \
	  echo '```text'; \
	  cat "$$SB_LOG"; \
	  echo '```'; \
	  echo ""; \
	  echo "## Summary"; \
	  echo ""; \
	} >> "$$OUT"; \
	if [ "$$FAIL" -eq 0 ]; then \
	  echo "Overall status: **PASS**" >> "$$OUT"; \
	else \
	  echo "Overall status: **FAIL**" >> "$$OUT"; \
	fi; \
	rm -rf "$$TMP"; \
	if [ "$$FAIL" -ne 0 ]; then \
	  echo "Security review completed with failures. See $$OUT."; \
	  exit 1; \
	fi; \
	echo "Security review completed successfully. See $$OUT."

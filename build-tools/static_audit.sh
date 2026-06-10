#!/bin/bash
# build-tools/static_audit.sh — list non-static functions in a .c that are
# never referenced from any other TU.
#
# Usage: build-tools/static_audit.sh src/tls/core/aes.c
#
# Each candidate is a function defined in the file with no `static`
# qualifier that no other .c/.h grep can find. Mark them `static` in
# the source to shrink the public-API surface.
set -uo pipefail
# Don't `set -e` — grep with zero matches returns 1, which is normal here.
target="${1:?usage: $0 <path-to-.c>}"
base=$(basename "$target" .c)

# Functions defined in target (non-static; matches `<type> name(...)` at column 0)
ctags_bin=${CTAGS:-/opt/homebrew/bin/ctags}
defs=$("$ctags_bin" --language-force=c --c-kinds=f -f- "$target" 2>/dev/null \
       | awk '$0 !~ /file:/ {print $1}' | sort -u)

for fn in $defs; do
  # Skip if the definition itself is static
  if grep -nE "^[[:space:]]*static[[:space:]].*\b$fn[[:space:]]*\(" "$target" >/dev/null 2>&1; then
    continue
  fi
  # Count CALL-site refs outside this file. Only .c files count as
  # callers; .h matches are just prototypes (often the file's own header).
  # Inside the .c we strip the definition site to avoid counting it.
  refs=$(grep -RnE "\b$fn\b" --include="*.c" src tests 2>/dev/null \
         | grep -v "^${target}:" | wc -l | tr -d ' ')
  if [ "$refs" -eq 0 ]; then
    # Where is the prototype declared? If it's in a header, the header
    # line should be removed when the function becomes static.
    proto_loc=$(grep -RnE "^\s*[a-zA-Z_][a-zA-Z0-9_ \*]*\b$fn\b\s*\(" \
                --include="*.h" src 2>/dev/null | head -1)
    if [ -n "$proto_loc" ]; then
      echo "STATIC?  $fn   (also remove prototype: $proto_loc)"
    else
      echo "STATIC?  $fn"
    fi
  fi
done

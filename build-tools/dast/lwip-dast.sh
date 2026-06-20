#!/usr/bin/env bash
# lwIP-CE DAST harness launcher.
#
#   ./build-tools/dast/lwip-dast.sh --ip 192.168.1.42 [--iface en0] [--settle 1.0] [--tls-bind 0.0.0.0]
#
# Sends malformed/overflow/flood probes (scapy) and host-side TLS fixtures
# at a calc running the paired calc-side harness in tests/profiling/lwip_dast,
# grades each test, and writes tests/dast.json. See build-tools/dast/lwip-dast.py
# for details.
#
# Raw packet crafting needs root / CAP_NET_RAW; the script re-execs under
# sudo if not already privileged (override with DAST_NO_SUDO=1).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
RUNNER="$SCRIPT_DIR/lwip-dast.py"
# Prefer pyenv's python3 by absolute path -- not Homebrew's python3.11,
# whose bottled pyexpat.so has been observed linked against the macOS
# system libexpat instead of Homebrew's own, breaking pip/ensurepip
# entirely. An absolute path also survives the sudo re-exec below, which
# resets $PATH and would otherwise silently fall back to /usr/bin/python3.
PYENV_PYTHON="$(pyenv root 2>/dev/null)/versions/$(pyenv version-name 2>/dev/null)/bin/python3"
if [[ -n "${DAST_PYTHON:-}" ]]; then
    PYTHON="$DAST_PYTHON"
elif [[ -x "$PYENV_PYTHON" ]]; then
    PYTHON="$PYENV_PYTHON"
else
    PYTHON="python3"
fi

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

command -v "$PYTHON" >/dev/null 2>&1 || die "$PYTHON not found (set DAST_PYTHON)"
[[ -f "$RUNNER" ]] || die "missing $RUNNER"

for arg in "$@"; do
    [[ "$arg" == "--gen-header" ]] && exec "$PYTHON" "$RUNNER" "$@"
done

# Keep the calc-side C test list in sync with the manifest before a run.
"$PYTHON" "$RUNNER" --gen-header

# scapy + raw sockets need privilege unless we're only doing a dry run.
needs_priv=1
for arg in "$@"; do
    [[ "$arg" == "--self-test" || "$arg" == "--gen-header" ]] && needs_priv=0
done

if [[ "$needs_priv" == "1" && "${DAST_NO_SUDO:-0}" != "1" && "$(id -u)" != "0" ]]; then
    echo "==> re-running under sudo for raw socket access (DAST_NO_SUDO=1 to skip)"
    exec sudo DAST_PYTHON="$PYTHON" "$PYTHON" "$RUNNER" "$@"
fi

exec "$PYTHON" "$RUNNER" "$@"

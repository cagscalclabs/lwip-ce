#!/usr/bin/env bash
# lwIP-CE DAST harness launcher.
#
#   ./build-tools/dast/lwip-dast.sh --ip 192.168.1.42 [--iface en0] [--settle 1.0]
#
# Sends malformed/overflow/flood probes (scapy) at a calc running the
# paired calc-side harness in tests/profiling/lwip_dast, prompts the
# operator for what the calc did, grades each test, and writes
# tests/dast.json. See build-tools/dast/lwip-dast.py for details.
#
# Raw packet crafting needs root / CAP_NET_RAW; the script re-execs under
# sudo if not already privileged (override with DAST_NO_SUDO=1).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
RUNNER="$SCRIPT_DIR/lwip-dast.py"
PYTHON="${DAST_PYTHON:-python3}"

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

command -v "$PYTHON" >/dev/null 2>&1 || die "$PYTHON not found (set DAST_PYTHON)"
[[ -f "$RUNNER" ]] || die "missing $RUNNER"

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

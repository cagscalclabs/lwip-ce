#!/usr/bin/env bash
set -euo pipefail

TOOLS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$TOOLS/.." && pwd)"
CALCLINK="$TOOLS/bin/calclink"
STAMP="$TOOLS/.lwip-installed"
LWIP_BUILD="$REPO/build"
BRIDGE_PORT=""
PUSH_CALC=1

usage() {
    echo "usage: push.sh [--bridge PORT] [--bridge-only] [--lwip BUILD_DIR]" >&2
    echo "  pushes lwIP and the Wi-Fi examples to the calculator over USB;" >&2
    echo "  --bridge PORT also builds and flashes wifi_bridge/ to the ESP32 on PORT" >&2
    exit 2
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --bridge) [[ $# -ge 2 ]] || usage; BRIDGE_PORT="$2"; shift 2 ;;
        --bridge-only) PUSH_CALC=0; shift ;;
        --lwip) [[ $# -ge 2 ]] || usage; LWIP_BUILD="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) usage ;;
    esac
done

if [[ -n "$BRIDGE_PORT" ]]; then
    if ! command -v idf.py >/dev/null 2>&1; then
        for env in "$HOME/.espressif/tools/activate_idf_v6.1.sh" "${IDF_PATH:-}/export.sh"; do
            if [[ -f "$env" ]]; then
                set +u
                source "$env" >/dev/null 2>&1
                set -u
                break
            fi
        done
    fi
    idf.py -C "$REPO/wifi_bridge" -p "$BRIDGE_PORT" build flash
    echo "push: bridge flashed on $BRIDGE_PORT"
fi

[[ $PUSH_CALC -eq 1 ]] || exit 0

make -s -C "$TOOLS" bin/calclink

link() {
    "$CALCLINK" "$@" 2> >(grep -v -e 'INFO' -e 'WARNING' -e '^$' >&2)
}

programs=()
for example in wifi_ping wifi_api; do
    make -s -C "$REPO/examples/$example" >/dev/null
    programs+=("$REPO"/examples/"$example"/bin/*.8xp)
done

link gc || link gc

shopt -s nullglob
parts=("$LWIP_BUILD"/appinst/LWIP.*.8xv)
installer="$LWIP_BUILD/appinst/lwIPINST.8xp"
stub="$LWIP_BUILD/lwip.8xv"
shopt -u nullglob
[[ ${#parts[@]} -gt 0 && -f "$installer" && -f "$stub" ]] || {
    echo "push: no lwIP release in $LWIP_BUILD, run 'make dylib' first" >&2
    exit 1
}

hash="$(cat "${parts[@]}" "$installer" "$stub" | sha256sum | cut -d' ' -f1)"
installed=0
link has-app lwIP && installed=1

if [[ $installed -eq 1 && -f "$STAMP" && "$(cat "$STAMP")" == "$hash" ]]; then
    echo "push: lwIP up to date"
else
    if [[ $installed -eq 1 ]]; then
        link del-app lwIP
        link gc || link gc
    fi
    link send "${parts[@]}" "$installer" "$stub"
    link run "$installer"
    for ((tries = 0; tries < 60; tries++)); do
        sleep 3
        link has-app lwIP 2>/dev/null && break
    done
    if [[ $tries -ge 60 ]]; then
        echo "push: lwIP install failed, check the calculator screen" >&2
        exit 1
    fi
    for ((tries = 0; tries < 30; tries++)); do
        sleep 2
        link key 0x05 2>/dev/null && break
    done
    link key 0x09
    echo "$hash" > "$STAMP"
    echo "push: lwIP installed"
fi

link send "${programs[@]}"
echo "push: sent ${programs[*]##*/}"

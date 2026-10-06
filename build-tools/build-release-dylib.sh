#!/usr/bin/env bash
set -euo pipefail

BUILD_TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$BUILD_TOOLS_DIR/.." && pwd)"

DEPS_DIR="${LWIP_DEPS_DIR:-$ROOT_DIR/submodules}"
APP_TOOLS_DIR="${APP_TOOLS_DIR:-$DEPS_DIR/app_tools}"
TOOLCHAIN_DIR="${TOOLCHAIN_DIR:-$DEPS_DIR/toolchain}"
TOOLCHAIN_SRC="${TOOLCHAIN_SRC:-$TOOLCHAIN_DIR/src}"
STAGE_DIR="${LWIP_TOOLCHAIN_STAGE:-$TOOLCHAIN_SRC/lwip}"
RELEASE_DIR="${LWIP_RELEASE_DIR:-$ROOT_DIR/build}"

APP_TOOLS_REPO="${APP_TOOLS_REPO:-https://github.com/CE-Programming/app_tools.git}"
APP_TOOLS_REF="${APP_TOOLS_REF:-master}"
TOOLCHAIN_REPO="${TOOLCHAIN_REPO:-https://github.com/CE-Programming/toolchain.git}"
TOOLCHAIN_REF="${TOOLCHAIN_REF:-master}"
APP_TOOLS_PATCH="$BUILD_TOOLS_DIR/patches/app_tools-installer-lwip.patch"

DYLIB_APPVAR_PREFIX="${DYLIB_APPVAR_PREFIX:-LWIP}"
DYLIB_APPVAR_SPLIT_SIZE="${DYLIB_APPVAR_SPLIT_SIZE:-65200}"
DYLIB_INSTALL_PREFIX="${DYLIB_INSTALL_PREFIX:-}"
ROOT_MAKE_TARGET="${LWIP_ROOT_MAKE_TARGET:-build}"

# The export table is append-only by default (existing slot positions are
# stable ABI). A full purge-and-regenerate is a deliberate, hand-triggered
# decision: REBUILD_EXPORTS=1 ./build-tools/build-release-dylib.sh (or
# REBUILD_EXPORTS=1 make dylib). This is the only way to drop stale slots.
REBUILD_EXPORTS="${REBUILD_EXPORTS:-0}"

log() {
    printf '==> %s\n' "$*"
}

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

# Announce a step, run a noisy command (compiler/linker/git output) quietly,
# then mark it Done or Fail on the same line. On success, only the one
# "==> message... Done" line is printed; on failure, the command's full
# stdout+stderr is dumped before dying, so nothing needed for debugging is
# lost. Set QUIET_BUILD=0 to always show the raw output as it runs instead
# (step lines still print, but without the trailing Done/Fail, since the
# command's own output follows immediately on the same stream).
step() {
    local message="$1"
    shift
    if [[ "${QUIET_BUILD:-1}" == "0" ]]; then
        log "$message" >&2
        "$@"
        return
    fi
    printf '==> %s... ' "$message" >&2
    local log_file
    log_file="$(mktemp)"
    if ! "$@" >"$log_file" 2>&1; then
        printf 'Fail\n' >&2
        cat "$log_file" >&2
        rm -f "$log_file"
        die "command failed: $*"
    fi
    rm -f "$log_file"
    printf 'Done\n' >&2
}

git_checkout() {
    local repo="$1"
    local ref="$2"
    local dir="$3"

    if [[ ! -d "$dir" ]] || ! git -C "$dir" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        rm -rf "$dir"
        run_quiet git clone --recursive "$repo" "$dir"
    fi

    run_quiet bash -c '
        git -C "$1" fetch --tags origin "$2" || git -C "$1" fetch --tags origin
    ' _ "$dir" "$ref"
    run_quiet git -C "$dir" checkout "$ref"
    run_quiet git -C "$dir" submodule update --init --recursive
}

# Run a command, discarding its output entirely unless it fails (in which
# case the output is dumped before dying). Used for sub-steps nested inside
# a `step` that will itself print Done/Fail — nesting `step` directly would
# print a redundant intermediate status line.
run_quiet() {
    if [[ "${QUIET_BUILD:-1}" == "0" ]]; then
        "$@"
        return
    fi
    local log_file
    log_file="$(mktemp)"
    if ! "$@" >"$log_file" 2>&1; then
        cat "$log_file" >&2
        rm -f "$log_file"
        die "command failed: $*"
    fi
    rm -f "$log_file"
}

checkout_dependencies() {
    mkdir -p "$DEPS_DIR"

    if [[ "${LWIP_SKIP_DEP_CHECKOUT:-0}" == "1" ]]; then
        [[ -d "$APP_TOOLS_DIR" ]] || die "missing app_tools checkout at $APP_TOOLS_DIR"
        [[ -d "$TOOLCHAIN_DIR" ]] || die "missing toolchain checkout at $TOOLCHAIN_DIR"
        return
    fi

    if [[ "$APP_TOOLS_DIR" == "$ROOT_DIR/submodules/app_tools" && -f "$ROOT_DIR/.gitmodules" ]]; then
        step "checking out app_tools" \
            git -C "$ROOT_DIR" submodule update --init --recursive submodules/app_tools
    else
        step "checking out app_tools" \
            git_checkout "$APP_TOOLS_REPO" "$APP_TOOLS_REF" "$APP_TOOLS_DIR"
    fi

    step "checking out CE toolchain source" \
        git_checkout "$TOOLCHAIN_REPO" "$TOOLCHAIN_REF" "$TOOLCHAIN_DIR"
}

apply_app_tools_patch() {
    [[ -f "$APP_TOOLS_PATCH" ]] || return 0

    if git -C "$APP_TOOLS_DIR" apply --check "$APP_TOOLS_PATCH" >/dev/null 2>&1; then
        step "applying lwIP app_tools installer patch" \
            git -C "$APP_TOOLS_DIR" apply "$APP_TOOLS_PATCH"
        return
    fi

    if git -C "$APP_TOOLS_DIR" apply --reverse --check "$APP_TOOLS_PATCH" >/dev/null 2>&1; then
        log "app_tools installer patch already applied"
        return
    fi

    die "app_tools installer patch does not apply cleanly"
}

resolve_cedev() {
    if [[ -n "${CEDEV:-}" ]]; then
        printf '%s\n' "$CEDEV"
        return
    fi

    if command -v cedev-config >/dev/null 2>&1; then
        cedev-config --prefix
        return
    fi

    printf '%s\n' "$HOME/CEdev"
}

resolve_tool() {
    local env_name="$1"
    local fallback="$2"
    local command_name="$3"

    local value="${!env_name:-}"
    if [[ -n "$value" ]]; then
        printf '%s\n' "$value"
        return
    fi

    if [[ -x "$fallback" ]]; then
        printf '%s\n' "$fallback"
        return
    fi

    if command -v "$command_name" >/dev/null 2>&1; then
        command -v "$command_name"
        return
    fi

    die "could not find $command_name; set $env_name"
}

resolve_fasmg() {
    if [[ -n "${FASMG:-}" ]]; then
        printf '%s\n' "$FASMG"
        return
    fi

    local candidates=()
    case "$(uname -s)" in
        Darwin)
            candidates+=(
                "$TOOLCHAIN_DIR/tools/fasmg/fasmg-ez80/bin/fasmg"
                "$TOOLCHAIN_DIR/tools/fasmg/fasmg-ez80/fasmg/source/macos/x64/fasmg"
            )
            ;;
        Linux)
            candidates+=(
                "$CEDEV_DIR/bin/fasmg"
                "$TOOLCHAIN_DIR/tools/fasmg/fasmg-ez80/bin/fasmg"
                "$TOOLCHAIN_DIR/tools/fasmg/fasmg-ez80/fasmg/linux/x64/fasmg.x64"
            )
            ;;
    esac

    for candidate in "${candidates[@]}"; do
        if [[ -x "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return
        fi
    done

    if command -v fasmg >/dev/null 2>&1; then
        command -v fasmg
        return
    fi

    local fasmg_tools_dir="$TOOLCHAIN_DIR/tools/fasmg"
    local fasmg_ez80_dir="$fasmg_tools_dir/fasmg-ez80"
    if [[ -f "$fasmg_tools_dir/makefile" && -x "$fasmg_ez80_dir/bin/install_fasmg" ]]; then
        step "building fasmg from toolchain source" bash -c '
            make -C "$1" && ( cd "$2" && ./bin/install_fasmg )
        ' _ "$fasmg_tools_dir" "$fasmg_ez80_dir"
        if [[ -x "$fasmg_ez80_dir/bin/fasmg" ]]; then
            printf '%s\n' "$fasmg_ez80_dir/bin/fasmg"
            return
        fi
    fi

    die "could not find fasmg; set FASMG"
}

resolve_header_python() {
    if [[ -n "${HEADER_PYTHON:-}" ]]; then
        printf '%s\n' "$HEADER_PYTHON"
        return
    fi
    if [[ -x /opt/homebrew/bin/python3.11 ]]; then
        printf '%s\n' /opt/homebrew/bin/python3.11
        return
    fi
    command -v python3
}

stage_ignore_in_toolchain() {
    local exclude_file="$TOOLCHAIN_DIR/.git/info/exclude"
    mkdir -p "$(dirname "$exclude_file")"
    touch "$exclude_file"
    if ! grep -qxF '/src/lwip/' "$exclude_file"; then
        printf '\n/src/lwip/\n' >> "$exclude_file"
    fi
}

root_libload_libs_without_lwip() {
    local lib_dir="$CEDEV_DIR/lib/libload"
    [[ -d "$lib_dir" ]] || return 0

    find "$lib_dir" -maxdepth 1 -type f -name '*.lib' ! -name 'lwip.lib' -print | sort | tr '\n' ' '
}

checkout_dependencies
apply_app_tools_patch

CEDEV_DIR="$(resolve_cedev)"
export CEDEV="$CEDEV_DIR"
export PATH="$CEDEV_DIR/bin:$PATH"
CONVBIN_PATH="$(resolve_tool CONVBIN "$CEDEV_DIR/bin/convbin" convbin)"
FASMG_PATH="$(resolve_fasmg)"
HEADER_PYTHON_PATH="$(resolve_header_python)"
APP_TOOLS_INSTALLER="$APP_TOOLS_DIR/installer"

[[ -f "$TOOLCHAIN_SRC/common.mk" ]] || die "$TOOLCHAIN_SRC does not look like toolchain/src"
[[ -d "$TOOLCHAIN_SRC/include" ]] || die "$TOOLCHAIN_SRC/include missing"
[[ -d "$TOOLCHAIN_SRC/usbdrvce" ]] || die "$TOOLCHAIN_SRC/usbdrvce missing"
[[ -d "$APP_TOOLS_INSTALLER" ]] || die "$APP_TOOLS_INSTALLER missing"

stage_ignore_in_toolchain

step "creating staged toolchain package at $STAGE_DIR" bash -c '
    rm -rf "$1"
    mkdir -p "$1"
    cp "$2" "$1/makefile"
' _ "$STAGE_DIR" "$BUILD_TOOLS_DIR/meta/lwip-libload.makefile"

functable_mode_args=(--append)
functable_message="generating export table and libload stub"
if [[ "$REBUILD_EXPORTS" == "1" ]]; then
    functable_mode_args=()
    functable_message="REBUILD_EXPORTS=1: purging and regenerating the export table (breaking ABI change)"
fi
step "$functable_message" \
    env LWIP_RELEASE_DIR="$STAGE_DIR" python3 "$BUILD_TOOLS_DIR/scripts/generate_lwip_stub.py" "${functable_mode_args[@]}"

step "building lwIP-CE app" \
    env CEDEV="$CEDEV_DIR" LIBLOAD_LIBS="$(root_libload_libs_without_lwip)" \
    make -C "$ROOT_DIR" "$ROOT_MAKE_TARGET"

step "splitting app into installer AppVars" \
    "$CONVBIN_PATH" --iformat 8ek --input "$ROOT_DIR/bin/lwIP.8ek" \
    --oformat 8xv-split --maxvarsize "$DYLIB_APPVAR_SPLIT_SIZE" \
    --name "$DYLIB_APPVAR_PREFIX" --output "$STAGE_DIR/$DYLIB_APPVAR_PREFIX.8xv"

step "building app_tools installer" bash -c '
    make -B -C "$1" APPVAR_PREFIX="$2" APPVAR_SPLIT_SIZE="$3"
    cp "$1/bin/INSTALL.8xp" "$4/lwIPINST.8xp"
' _ "$APP_TOOLS_INSTALLER" "$DYLIB_APPVAR_PREFIX" "$DYLIB_APPVAR_SPLIT_SIZE" "$STAGE_DIR"

step "building libload stub in toolchain source layout" \
    make -C "$STAGE_DIR" FASMG="$FASMG_PATH"

# Overlay the freshly staged package onto RELEASE_DIR rather than wiping it
# first — RELEASE_DIR may hold other release-only content (e.g. bundled
# examples/) that this script doesn't produce and shouldn't delete.
# --checksum skips any file whose content is byte-identical to what's
# already there, so an unchanged rebuild doesn't touch mtimes/zip diffs.
step "copying completed release package to $RELEASE_DIR" bash -c '
    mkdir -p "$1"
    rsync -a --checksum "$2"/ "$1"/
    mkdir -p "$1/appinst"
    shopt -s nullglob
    for artifact in "$1"/"$3".*.8xv "$1"/lwIPINST.8xp; do
        mv "$artifact" "$1/appinst"/
    done
    shopt -u nullglob
' _ "$RELEASE_DIR" "$STAGE_DIR" "$DYLIB_APPVAR_PREFIX"

step "generating curated headers" bash -c '
    mkdir -p "$3/include"
    LWIP_RELEASE_DIR="$1" HEADER_PYTHON="$2" python3 "$4/scripts/generate_lwip_headers.py"
    rsync -a --checksum "$1/lwip/" "$3/include/lwip/"
    [[ -f "$1/lwip.h" ]] && rsync -a --checksum "$1/lwip.h" "$3/include/lwip.h"
    rsync -a --checksum "$1/cryptography.h" "$3/include/cryptography.h"
' _ "$RELEASE_DIR" "$HEADER_PYTHON_PATH" "$CEDEV_DIR" "$BUILD_TOOLS_DIR"

step "installing lwip.lib into $CEDEV_DIR" bash -c '
    mkdir -p "$2/lib/libload"
    rsync -a --checksum "$1/lwip.lib" "$2/lib/libload/lwip.lib"
' _ "$STAGE_DIR" "$CEDEV_DIR"

TESTS_COMMON_DIR="$ROOT_DIR/tests/common"
step "updating tests/common with fresh library files" bash -c '
    mkdir -p "$2"
    rsync -a --checksum "$1/appinst"/ "$2"/
    rsync -a --checksum "$1/lwip.8xv" "$2/lwip.8xv"
    rsync -a --checksum "$1/lwip.lib" "$2/lwip.lib"
' _ "$RELEASE_DIR" "$TESTS_COMMON_DIR"

log "release dylib package ready"

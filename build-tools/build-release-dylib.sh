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

log() {
    printf '==> %s\n' "$*"
}

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

git_checkout() {
    local repo="$1"
    local ref="$2"
    local dir="$3"

    if [[ ! -d "$dir" ]] || ! git -C "$dir" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        rm -rf "$dir"
        git clone --recursive "$repo" "$dir"
    fi

    git -C "$dir" fetch --tags origin "$ref" || git -C "$dir" fetch --tags origin
    git -C "$dir" checkout "$ref"
    git -C "$dir" submodule update --init --recursive
}

checkout_dependencies() {
    mkdir -p "$DEPS_DIR"

    if [[ "${LWIP_SKIP_DEP_CHECKOUT:-0}" == "1" ]]; then
        [[ -d "$APP_TOOLS_DIR" ]] || die "missing app_tools checkout at $APP_TOOLS_DIR"
        [[ -d "$TOOLCHAIN_DIR" ]] || die "missing toolchain checkout at $TOOLCHAIN_DIR"
        return
    fi

    log "checking out app_tools"
    if [[ "$APP_TOOLS_DIR" == "$ROOT_DIR/submodules/app_tools" && -f "$ROOT_DIR/.gitmodules" ]]; then
        git -C "$ROOT_DIR" submodule update --init --recursive submodules/app_tools
    else
        git_checkout "$APP_TOOLS_REPO" "$APP_TOOLS_REF" "$APP_TOOLS_DIR"
    fi

    log "checking out CE toolchain source"
    git_checkout "$TOOLCHAIN_REPO" "$TOOLCHAIN_REF" "$TOOLCHAIN_DIR"
}

apply_app_tools_patch() {
    [[ -f "$APP_TOOLS_PATCH" ]] || return 0

    if git -C "$APP_TOOLS_DIR" apply --check "$APP_TOOLS_PATCH" >/dev/null 2>&1; then
        log "applying lwIP app_tools installer patch"
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
        log "building fasmg from toolchain source" >&2
        make -C "$fasmg_tools_dir" >&2
        ( cd "$fasmg_ez80_dir" && ./bin/install_fasmg ) >&2
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

log "creating staged toolchain package at $STAGE_DIR"
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"
cp "$BUILD_TOOLS_DIR/meta/lwip-libload.makefile" "$STAGE_DIR/makefile"

log "generating export table and libload stub"
LWIP_RELEASE_DIR="$STAGE_DIR" python3 "$BUILD_TOOLS_DIR/scripts/functable.py" --append

log "building lwIP-CE app"
CEDEV="$CEDEV_DIR" LIBLOAD_LIBS="$(root_libload_libs_without_lwip)" \
    make -C "$ROOT_DIR" "$ROOT_MAKE_TARGET"

log "generating curated headers"
LWIP_RELEASE_DIR="$STAGE_DIR" "$HEADER_PYTHON_PATH" "$BUILD_TOOLS_DIR/scripts/header_dump.py"

log "splitting app into installer AppVars"
"$CONVBIN_PATH" --iformat 8ek --input "$ROOT_DIR/bin/lwIP.8ek" \
    --oformat 8xv-split --maxvarsize "$DYLIB_APPVAR_SPLIT_SIZE" \
    --name "$DYLIB_APPVAR_PREFIX" --output "$STAGE_DIR/$DYLIB_APPVAR_PREFIX.8xv"

log "building app_tools installer"
make -B -C "$APP_TOOLS_INSTALLER" \
    APPVAR_PREFIX="$DYLIB_APPVAR_PREFIX" \
    APPVAR_SPLIT_SIZE="$DYLIB_APPVAR_SPLIT_SIZE"
cp "$APP_TOOLS_INSTALLER/bin/INSTALL.8xp" "$STAGE_DIR/lwIPINST.8xp"

log "building libload stub in toolchain source layout"
make -C "$STAGE_DIR" FASMG="$FASMG_PATH"

log "installing lwip.lib and headers into $CEDEV_DIR/$DYLIB_INSTALL_PREFIX"
make -C "$STAGE_DIR" install \
    FASMG="$FASMG_PATH" \
    DESTDIR="$CEDEV_DIR" \
    PREFIX="$DYLIB_INSTALL_PREFIX"

log "copying completed release package to $RELEASE_DIR"
rm -rf "$RELEASE_DIR"
mkdir -p "$RELEASE_DIR"
cp -R "$STAGE_DIR"/. "$RELEASE_DIR"/
mkdir -p "$RELEASE_DIR/appinst"
shopt -s nullglob
for artifact in "$RELEASE_DIR"/"$DYLIB_APPVAR_PREFIX".*.8xv "$RELEASE_DIR"/lwIPINST.8xp; do
    mv "$artifact" "$RELEASE_DIR/appinst"/
done
shopt -u nullglob

log "release dylib package ready"

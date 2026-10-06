#!/usr/bin/env bash
# Syncs the vendored lwIP core paths against a new upstream stable release.
#
# Unlike a plain `git merge`/`git rebase` against upstream, this never merges
# commit graphs: this fork's history diverged thousands of commits before any
# shared ancestor with upstream still reachable from a current stable tag, so
# a real merge/rebase walks (and can conflict on) that whole unrelated history.
# Instead, this treats each upstream tag as a tree snapshot, diffs only the
# vendored paths between the last-synced tag and the new one, and applies
# that diff as a patch onto the current working tree with 3-way merge --
# conflicts then only ever come from lines *we've* also touched in a vendored
# file, never from unrelated upstream history.
#
# Only these paths are touched; they are the ones that exist at the same
# path in upstream lwIP's own tree. Everything else under src/ (parsers,
# drivers, tls, arch, and the altcp_ws addition inside src/apps) has no
# upstream counterpart and is never touched by this script.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REF_FILE="$ROOT_DIR/build-tools/UPSTREAM_LWIP_REF"
UPSTREAM_REPO="${UPSTREAM_LWIP_REPO:-https://github.com/lwip-tcpip/lwip.git}"
UPSTREAM_REMOTE="${UPSTREAM_LWIP_REMOTE:-upstream-lwip-sync}"

VENDORED_PATHS=(
    src/core
    src/netif
    src/include
    src/api
    src/apps
)

log() { printf '==> %s\n' "$*" >&2; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

[[ -f "$REF_FILE" ]] || die "missing $REF_FILE"
OLD_REF="$(tr -d '[:space:]' < "$REF_FILE")"
[[ -n "$OLD_REF" ]] || die "$REF_FILE is empty"

NEW_REF="${1:-}"
if [[ -z "$NEW_REF" ]]; then
    die "usage: $0 <new-upstream-ref>   (e.g. a STABLE-X_Y_Z_RELEASE tag)"
fi

if ! git -C "$ROOT_DIR" remote get-url "$UPSTREAM_REMOTE" >/dev/null 2>&1; then
    log "adding upstream remote $UPSTREAM_REMOTE -> $UPSTREAM_REPO"
    git -C "$ROOT_DIR" remote add "$UPSTREAM_REMOTE" "$UPSTREAM_REPO"
fi
log "fetching upstream tags"
git -C "$ROOT_DIR" fetch "$UPSTREAM_REMOTE" --tags

git -C "$ROOT_DIR" rev-parse --verify "$OLD_REF" >/dev/null 2>&1 \
    || die "old ref '$OLD_REF' (from $REF_FILE) not found -- fetch may be missing it"
git -C "$ROOT_DIR" rev-parse --verify "$NEW_REF" >/dev/null 2>&1 \
    || die "new ref '$NEW_REF' not found on $UPSTREAM_REMOTE"

if [[ "$(git -C "$ROOT_DIR" rev-parse "$OLD_REF")" == "$(git -C "$ROOT_DIR" rev-parse "$NEW_REF")" ]]; then
    log "already synced at $NEW_REF -- nothing to do"
    exit 0
fi

log "diffing vendored paths: $OLD_REF -> $NEW_REF"
PATCH_FILE="$(mktemp)"
trap 'rm -f "$PATCH_FILE"' EXIT

git -C "$ROOT_DIR" diff --no-color "$OLD_REF" "$NEW_REF" -- "${VENDORED_PATHS[@]}" > "$PATCH_FILE"

if [[ ! -s "$PATCH_FILE" ]]; then
    log "no changes to vendored paths between $OLD_REF and $NEW_REF"
else
    log "applying patch (3-way merge; conflicts only on lines we've also modified)"
    if ! git -C "$ROOT_DIR" apply --3way --whitespace=nowarn "$PATCH_FILE"; then
        die "patch did not apply cleanly -- resolve conflicts (look for <<<<<<< markers), then re-run with --continue semantics via 'git add' + manual review before committing"
    fi
fi

log "updating $REF_FILE: $OLD_REF -> $NEW_REF"
printf '%s\n' "$NEW_REF" > "$REF_FILE"

log "done. Review changes with 'git status' / 'git diff --stat' before committing."

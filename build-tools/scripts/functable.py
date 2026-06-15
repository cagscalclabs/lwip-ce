#!/usr/bin/env python3
"""Regenerate src/functable.s from the actual set of public symbols
emitted by every project .c and .s file.

This is invoked by `make functable` (see root makefile).

  - For each .c under the project's source directories, the script
    runs the cedev compiler with `-S` (assembly output) and harvests
    every `.globl _foo` directive.
  - For each .s under the same directories, the script reads the file
    directly and harvests both `.globl _foo` and `globl _foo` (the
    project's hand-written assembly uses the dot-less form).

The union of those symbols, minus EXCLUDE_SYMBOLS, is the set of
public-API entries that an application linking against this library
could call.

Ordering: full regen, grouped by defining source file. libload
resolves imports by name (not slot index), so apps relink against
the freshly emitted table — reordering is safe between releases.

Run from repo root:
    make functable
or directly:
    python3 build-tools/scripts/functable.py
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import csv
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BUILD_TOOLS_DIR = REPO_ROOT / "build-tools"
SRC_DIR = REPO_ROOT / "src"
FUNCTABLE_ASM = SRC_DIR / "functable.s"
PUBLIC_API_MANIFEST = BUILD_TOOLS_DIR / "meta" / "public_api_manifest.csv"

# Symbols that MUST be exported via libload even though they are not in the
# public API manifest (so no header prototype is emitted for them). The
# consumer-side init stub (lwip_init_runtime.asm) calls these by name through
# the trampoline table. Force-kept here so a full `make functable` regenerate
# can't silently drop them and break the ABI.
STUB_REQUIRED_EXPORTS = {
    "_lwip_init_runtime_internal",
}

# Symbols implemented by the libload stub itself, not by the app export table.
# These must appear in lwip.lib so consuming apps can link against them, but
# they must not be added to src/functable.s because they are not app-resident
# functions.
STUB_ONLY_LIBLOAD_EXPORTS = [
    "_lwip_init_runtime_opaque",
]

# The libload library stub. Emitted alongside src/functable.s so the
# two stay in lockstep — both files list the public API in the same order.
RELEASE_DIR = Path(os.environ.get("LWIP_RELEASE_DIR", REPO_ROOT / "build"))
LIBLOAD_STUB_ASM = RELEASE_DIR / "lwip.asm"
LIBLOAD_STUB_LIB = RELEASE_DIR / "lwip.lib"

# Hand-written bootstrap appended verbatim to the bottom of the
# generated lwip.s. This is the part of the stub that humans edit;
# the generator owns everything above it. Living separately means
# regenerating lwip.asm never clobbers the bootstrap body.
INIT_RUNTIME_ASM = BUILD_TOOLS_DIR / "stubs" / "lwip_init_runtime.asm"

# Fixed offset, from the linked app image base, to the lwIP export descriptor.
# linker_script_lwip.ld reserves this slot and asserts _fn_exports_table lands
# here. The runtime bootstrap computes the linked app image base from installed
# app metadata, then adds this offset.
DYLIB_DESCRIPTOR_OFF = 0x40

# Libload identity. The library name MUST match the on-calc appvar name
# (uppercase). The version is LOCKED at 0 and must not be bumped by the
# generator — bumps are a deliberate, breaking-change decision made by
# hand. Keep this value as-is across regenerations.
LIBLOAD_NAME = "LWIP"
LIBLOAD_VERSION = 0

# usbdrvce symbols that lwIP's vtable (struct usb_configurator) needs,
# in the EXACT order the struct's fields appear in src/drivers/usb_ethernet.h.
# The libload build statically initialises fn_imports_table.usb from this
# list; each `dl usb_Foo` slot resolves to the address of usbdrvce's jp
# stub (installed by `include_library '../usbdrvce/usbdrvce.asm'`). The order must
# match `struct usb_configurator` field order or every call site
# dispatches to the wrong function — change both together or not at all.
USB_VTABLE_IMPORTS = [
    "usb_ResetDevice",
    "usb_DisableDevice",
    "usb_RefDevice",
    "usb_UnrefDevice",
    "usb_SetDeviceData",
    "usb_GetDeviceData",
    "usb_GetRole",
    "usb_GetDeviceFlags",
    "usb_ScheduleTransfer",
    "usb_ControlTransfer",
    "usb_GetConfigurationDescriptorTotalLength",
    "usb_GetDescriptor",
    "usb_GetStringDescriptor",
    "usb_SetConfiguration",
    "usb_SetInterface",
    "usb_GetDeviceEndpoint",
    "usb_SetEndpointData",
    "usb_GetEndpointData",
    "usb_SetEndpointFlags",
    "usb_SetEndpointHalt",
    "usb_Init",
    "usb_HandleEvents",
    "usb_Cleanup",
]

# Source directories whose .c files are scanned for public symbols. The
# whole point of the table is to expose library functions to a calling
# app, so we restrict to library code (lwIP core, drivers, TLS, apps).
# Tests, contrib/, and the calculator-side app (src/main.c, etc.) are
# excluded — they're consumers, not part of the library surface.
SCAN_DIRS = [
    SRC_DIR / "core",
    SRC_DIR / "netif",
    SRC_DIR / "drivers",
    SRC_DIR / "tls" / "core",
    SRC_DIR / "apps",
]

# Specific .c files at src/ root that *are* part of the library (vs
# the demo's main.c, which is not).
SCAN_FILES_AT_ROOT: list[Path] = [
    SRC_DIR / "lwIP.c",
]

# Specific hand-written .s files outside SCAN_DIRS that contribute public
# symbols. The x25519 core lives under contrib/ (a vendored submodule) so
# it isn't covered by SCAN_DIRS, but tls_x25519_publickey / _secret are
# real public API. We list the asm file explicitly rather than scanning
# the whole contrib tree, which also carries a standalone test main.c.
SCAN_ASM_FILES_EXTRA: list[Path] = [
    SRC_DIR / "tls" / "contrib" / "x25519" / "src" / "x25519.s",
]

# Per-file excludes — typically generator stubs or duplicate TUs that
# shouldn't contribute symbols.
EXCLUDE_FILES = {
    "src/main.c",                       # demo app entry
    "src/custom_allocator.c",           # generated wrapper, no public API
    "src/runtime_init_symbols.c",       # generated, no public API
    "src/tls/core/handshake.c",         # TLS state machine, private to altcp_tls_ce
}

# Symbols to drop regardless of source. Three flavors:
#
#   1. Toolchain stubs (_main, _main_argc_argv) — emitted by the compiler
#      as entry-point fixtures, not part of any API.
#   2. Internal-only TLS surface — the handshake state machine (driven by
#      altcp_tls_ce) and session-resumption machinery (host-keyed and
#      automatic). Apps interact with TLS through altcp_tls connection
#      setup, not these primitives.
#   3. Hand-written assembly helpers used by the crypto cores — eZ80
#      register-passing conventions, math primitives, the runtime guard.
#      Not callable from C in any meaningful way.
#
# Everything else (ASN.1, X.509, key/PKCS#8 import, RSA, MGF1, AES/SHA/HMAC,
# the truststore) IS public surface and lives in cryptography.h. fileio
# helpers are an exception — cross-TU but not documented for app use.
# Visibility-by-static is preferred over visibility-by-exclusion-list
# wherever the function is genuinely confined to its own TU.
EXCLUDE_SYMBOLS = {
    # compiler-emitted entry-point stubs
    "_main",
    "_main_argc_argv",

    # TLS handshake state machine — driven from altcp_tls_ce internally,
    # not callable from app code. The 5 receive-side handlers and
    # tls_send_alert that USED to live here are now `static` in
    # handshake.c, so the scanner can't see them anyway; this list only
    # carries the cross-TU entry points that altcp_tls_ce.c needs to
    # call but apps don't.
    "_tls_handshake_init",
    "_tls_handshake_cleanup",
    "_tls_send_client_hello",
    "_tls_send_finished",
    "_tls_send_close_notify",
    "_tls_recv_server_hello",
    "_tls_derive_handshake_keys",
    "_tls_derive_application_keys",
    "_tls_set_transport",
    "_tls_process_inner_plaintext_pbuf",
    "_tls_ctx",
    "_tls_init",
    "_tls_cleanup",
    "_tls_rng_start",
    "_tls_rng_cleanup",

    # File I/O helpers — cross-TU (tls.c → x509.c, pkcs8.c, truststore.c)
    # but conceptually internal; not part of the documented public surface.
    "_tls_fileio_alloc",
    "_tls_fileio_free",

    # Ethernet shutdown helpers — cross-TU between the resident app and
    # driver, but not app-facing libload API.
    "_eth_halt_all_endpoints",
    "_eth_prepare_shutdown",
    "_eth_finish_shutdown",
    "_eth_reset_shutdown",

    # Session-resumption helpers — resumption is automatic and host-keyed,
    # apps shouldn't manage sessions manually.
    "_altcp_tls_get_session",
    "_altcp_tls_set_session",
    "_altcp_tls_init_session",
    "_altcp_tls_free_session",

    # Hand-written assembly helpers (used internally by the crypto cores;
    # not callable from app code in any meaningful way).
    "_indcallhl",
    "_rmemcpy",
    "_memrev",
    "_bytelen_to_bitlen",
    "_u64_addi",
    "u64_addi",   # bigint.s declares this without the C mangling underscore
    "_gf128_mul",
    "_powmod_exp_u24",
    "_tls_crypto_guard_enable",
    "_tls_crypto_guard_disable",
    "_tls_random_debug_source_ptr",

    # Sample / demo entry points that ship in the source tree for docs
    # but aren't part of the library surface.
    "_example_https_request",
    "_example_session_resumption",
    "_example_tls_client_connect",
    "_example_tls_server_listen",

    # Compiled-in HTTP fs blobs (httpd /fsdata.c). The byte arrays are
    # link-time data; they're not callable API.
    "_file__404_html",
    "_file__img_sics_gif",
    "_file__index_html",
}

# Compiler invocation. Mirrors what `cedev-config --makefile` would
# produce for a normal CC step; we re-derive it instead of shelling out
# to make so this script stays self-contained.
CEDEV = Path(os.environ.get("CEDEV", os.path.expanduser("~/CEdev")))
CC = CEDEV / "bin" / "ez80-clang"
CFLAGS = [
    "-S",
    "-nostdinc",
    "-Xclang", "-fforce-mangle-main-argc-argv",
    "-fno-autolink",
    "-fno-addrsig",
    "-fno-threadsafe-statics",
    "-fno-aligned-allocation",
    "-mllvm", "-z80-gas-style",
    "-ffunction-sections",
    "-fdata-sections",
    "-fno-math-errno",
    "-D__TICE__=1",
    # NDEBUG matches the real build (-Oz path through cedev's makefile);
    # several lwIP modules `#if !LWIP_NOASSERT` differently with this set,
    # which affects which symbols actually get emitted as externs.
    "-DNDEBUG=1",
    "-isystem", str(CEDEV / "include"),
    "-I", str(SRC_DIR / "include"),
    "-I", str(SRC_DIR),  # cedev's EZLIBCINCLUDE adds -I$(SRCDIR); some
                         # lwIP headers do `#include "drivers/foo.h"`.
    "-Oz",
    "-Wno-everything",  # we don't care about warnings here
]

# Matches the compiler-emitted `.globl _foo` directive (from .c files run
# through ez80-clang -S) and the hand-written `globl _foo` form used in
# the project's .s files (no leading dot — fasmg-ish syntax that the
# gas-style assembler accepts in this toolchain).
GLOBL_RE = re.compile(r"^\s*\.?(?:globl|global)\s+(_[A-Za-z_][A-Za-z0-9_]*)\s*(?:;.*)?$")

# Lines in the existing functable.s that match this regex are entries.
# Current format is a bare `    d24 _foo` (the symbol's offset from the
# app base, since apps link at 0). Older generated files used
# `d24 _foo - app` / `dl _foo - app`; accept both so re-reads of a
# pre-regen table still work.
ENTRY_RE = re.compile(
    r"^\s*(?:d24|dl)\s+(_[A-Za-z_][A-Za-z0-9_]*)\s*(?:-\s*app\s*)?$")


def find_c_files() -> list[Path]:
    """Enumerate every .c file under SCAN_DIRS (recursively), plus any
    explicit roots in SCAN_FILES_AT_ROOT."""
    out: list[Path] = []
    for d in SCAN_DIRS:
        if not d.is_dir():
            continue
        for path in sorted(d.rglob("*.c")):
            rel = path.relative_to(REPO_ROOT).as_posix()
            if rel in EXCLUDE_FILES:
                continue
            out.append(path)
    out.extend(p for p in SCAN_FILES_AT_ROOT if p.exists())
    return out


def find_asm_files() -> list[Path]:
    """Enumerate every .s file under SCAN_DIRS (recursively). Hand-written
    assembly is part of the public surface for several crypto primitives
    (sha256, bigint, the TRNG), so its `globl` directives must contribute
    to the export table — otherwise apps can't call those symbols via
    libload."""
    out: list[Path] = []
    for d in SCAN_DIRS:
        if not d.is_dir():
            continue
        for path in sorted(d.rglob("*.s")):
            rel = path.relative_to(REPO_ROOT).as_posix()
            if rel in EXCLUDE_FILES:
                continue
            out.append(path)
    out.extend(p for p in SCAN_ASM_FILES_EXTRA if p.exists())
    return out


def extract_globals(c_file: Path, scratch: Path) -> set[str]:
    """Compile c_file to assembly and harvest every .globl directive."""
    asm_path = scratch / (c_file.stem + ".src")
    cmd = [str(CC), *CFLAGS, str(c_file), "-o", str(asm_path)]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        # If a single TU fails (e.g. missing third-party include), warn
        # and continue — better to ship a slightly-incomplete table than
        # to break the whole regenerate flow.
        print(f"  warning: {c_file.relative_to(REPO_ROOT)} failed to "
              f"compile: {res.stderr.strip().splitlines()[-1] if res.stderr else 'unknown'}",
              file=sys.stderr)
        return set()
    symbols: set[str] = set()
    with asm_path.open() as fh:
        for line in fh:
            m = GLOBL_RE.match(line)
            if m:
                symbols.add(m.group(1))
    return symbols


def extract_asm_globals(asm_file: Path) -> set[str]:
    """Read a hand-written .s file directly and harvest its globl directives.
    No compile step — the file IS already assembly."""
    symbols: set[str] = set()
    with asm_file.open() as fh:
        for line in fh:
            m = GLOBL_RE.match(line)
            if m:
                symbols.add(m.group(1))
    return symbols


def load_existing_entries(path: Path) -> list[str]:
    """Read existing functable.s and return entry symbols in order.
    Lines that aren't entries (header, blank, comments) are ignored —
    the new file will have a freshly-generated preamble."""
    if not path.exists():
        return []
    entries: list[str] = []
    with path.open() as fh:
        for line in fh:
            m = ENTRY_RE.match(line)
            if m:
                entries.append(m.group(1))
    return entries


def load_public_api_manifest(path: Path) -> list[dict[str, str]]:
    """Read the manually-curated public API allowlist.

    A function is exported only when it appears here and is visible in the
    compile-time symbol scan. Missing manifest symbols are skipped so
    lwipopts can remove features without leaving dead export slots.
    """
    if not path.is_file():
        print(f"ERROR: public API manifest not found at {path}",
              file=sys.stderr)
        sys.exit(1)

    with path.open(newline="") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames != ["symbol", "category", "source_header"]:
            print(f"ERROR: {path} must have columns: "
                  "symbol,category,source_header", file=sys.stderr)
            sys.exit(1)
        rows = [dict(row) for row in reader]

    seen: set[str] = set()
    duplicates: list[str] = []
    for row in rows:
        row["symbol"] = row["symbol"].strip()
        row["category"] = row["category"].strip()
        row["source_header"] = row["source_header"].strip()
        if not row["symbol"] or not row["category"] or not row["source_header"]:
            print(f"ERROR: blank field in {path}: {row}", file=sys.stderr)
            sys.exit(1)
        if row["symbol"] in seen:
            duplicates.append(row["symbol"])
        seen.add(row["symbol"])
    if duplicates:
        print(f"ERROR: duplicate manifest symbols in {path}:",
              file=sys.stderr)
        for symbol in sorted(set(duplicates)):
            print(f"      {symbol}", file=sys.stderr)
        sys.exit(1)
    return rows


def _source_sort_key(rel_path: str) -> tuple[int, str]:
    """Sort key that clusters related modules together. The leading
    integer puts SCAN_DIRS roots in a fixed order (core → netif →
    drivers → tls → apps → root-level); the string keeps files within
    each cluster in a deterministic directory-walk order."""
    order = [
        "src/core/",
        "src/netif/",
        "src/drivers/",
        "src/tls/core/share/",   # share/ helpers before the crypto cores
        "src/tls/core/",
        "src/apps/",
    ]
    for i, prefix in enumerate(order):
        if rel_path.startswith(prefix):
            return (i, rel_path)
    return (len(order), rel_path)


def group_entries(symbol_origins: dict[str, str]) -> list[str]:
    """Return the new ordered entry list, with related modules clustered.

    Symbols are bucketed by the source file that defined them; buckets
    are emitted in `_source_sort_key` order; symbols within a bucket are
    sorted by name. No slot-index preservation across regenerations —
    apps are expected to relink against the current functable.s (libload
    resolves by name, not by slot index, so this is safe even after a
    reorder)."""
    by_source: dict[str, list[str]] = {}
    for sym, src in symbol_origins.items():
        by_source.setdefault(src, []).append(sym)
    out: list[str] = []
    for src in sorted(by_source, key=_source_sort_key):
        for sym in sorted(by_source[src]):
            out.append(sym)
    return out


def render_functable(entries: list[str], origins: dict[str, str]) -> str:
    """Render the final functable.s content using the project's gas-style
    eZ80 syntax. Symbols are grouped by the source file that defined them,
    with a comment header per group, so the table reads as a directory of
    public API by subsystem.

    `.long` in ADL mode emits 24 bits per entry — matches the legacy fasmg
    `dl` directive that this file used before the toolchain switch."""
    lines = [
        "; Auto-generated by build-tools/scripts/functable.py.  Do not edit by hand —",
        "; run `make functable` after adding/removing public API.",
        ";",
        "; Symbols are grouped by defining source file. libload resolves",
        "; by name (not slot index), so reordering across regenerations is",
        "; safe — apps must be relinked, but no silent ABI break.",
        ";",
        "; Layout:",
        ";   db  'L','W','I','P','T','B'   6-byte magic (ascending memory order)",
        ";   d24 <entry count>",
        ";   d24 <relocated address>  ... one per exported symbol",
        ";",
        f"; The linker script pins this section at linked-image offset 0x{DYLIB_DESCRIPTOR_OFF:02X}.",
        "; At load, the libload bootstrap computes the installed linked-image",
        "; base from app metadata, adds the fixed offset, then checks the magic",
        "; and entry count to reject stale/mismatched app+lib pairs.",
        ";",
        "; Each d24 entry is a normal relocatable symbol reference. convbin",
        "; records it in the app relocation table, and the installer patches it",
        "; to the real installed flash address. The libload bootstrap therefore",
        "; copies entries directly into its trampolines; it does not add a base.",
        "",
        ".assume adl=1",
        "; Dedicated, RETAIN-flagged section. Nothing in the app references",
        "; _fn_exports_table (it is consumed only by the external libload",
        "; bootstrap at runtime), so it must survive --gc-sections. The app",
        "; is built in two link stages: a relocatable `ld -i --gc-sections`",
        "; merge (no linker script, so a script KEEP cannot help here),",
        "; followed by the final scripted link. The SHF_GNU_RETAIN flag (R)",
        "; pins the section through GC at BOTH stages, independent of any",
        "; linker script. linker_script_lwip.ld also KEEP(*(.fn_exports)) as",
        "; belt-and-suspenders for the final stage.",
        ".section .fn_exports,\"aR\",@progbits",
        ".globl _fn_exports_table",
        "",
    ]
    # Every symbol referenced in the table must be declared .extern up
    # front. The legacy fasmg syntax auto-resolved cross-TU references;
    # gas-style does not.
    for sym in entries:
        lines.append(f".extern {sym}")
    lines.append("")
    lines.append("_fn_exports_table:")
    lines.append("    db 'L','W','I','P','T','B'    ; magic")
    lines.append(f"    d24 {len(entries)}    ; entry count")
    current_src: str | None = None
    for sym in entries:
        src = origins.get(sym, "?")
        if src != current_src:
            lines.append("")
            lines.append(f"; --- {src} ---")
            current_src = src
        lines.append(f"    d24 {sym}")
    lines.append("")  # trailing newline
    return "\n".join(lines)


def render_libload_stub(entries: list[str]) -> str:
    """Render lwip.asm — the libload library stub.

    The app linker script pins _fn_exports_table at DYLIB_DESCRIPTOR_OFF from
    the linked image base. The bootstrap computes that linked image base from
    installed app metadata at runtime, then validates the table magic/count and
    patches every trampoline with the installer-relocated in-flash addresses.

    The stub has three roles:

      1. Declare the lwIP library identity (`library LWIP, 0`).

      2. Import the usbdrvce symbols that lwIP's internal code calls
         (via `include_library '../usbdrvce/usbdrvce.asm'`). At load time, libload
         resolves each imported symbol to a `jp <real_addr>` stub inside
         this library's image; references to e.g. `usb_ResetDevice` from
         within the stub resolve to the address of that jp.

      3. Define `_fn_imports_table`, the unified import table lwIP's C
         code dispatches through. Layout:
           offset  0: host malloc  (zero, populated by lwip_init_runtime)
           offset  3: host free    (zero, populated by lwip_init_runtime)
           offset  6: host realloc (zero, populated by lwip_init_runtime)
           offset  9: usb_ResetDevice (jp stub from (2))
           offset 12: usb_DisableDevice
           ... (22 USB slots, in struct field order)
         The C side accesses it as `struct lwip_imports fn_imports_table`
         (see drivers/usb_ethernet.h under LWIP_LIBLOAD_BUILD), with
         `usb_fn` aliased to `fn_imports_table.usb`. Each USB slot is the
         address of the jp stub from (2), so calling e.g.
         `usb_fn.reset_device(...)` from C dispatches:
         C -> fn_imports_table.usb.reset_device -> jp stub -> real usb_ResetDevice.

      4. Export the lwIP public API (same list as src/functable.asm).

    The version number is LOCKED — see LIBLOAD_VERSION above.
    """
    from datetime import datetime, timezone
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    author = os.environ.get("LWIP_RELEASE_AUTHOR", "Anthony Cagliano")

    lines = [
        f"; lwip.asm — libload library stub for lwIP. Generated {date_str}.",
        f"; Author: {author}",
        "; Do not edit by hand. Sources: build-tools/scripts/functable.py,",
        "; build-tools/stubs/lwip_init_runtime.asm.",
        "",
        "include '../include/library.inc'",
        "include '../include/include_library.inc'",
        "",
        f"library {LIBLOAD_NAME}, {LIBLOAD_VERSION}",
        "",
        "\tinclude_library '../usbdrvce/usbdrvce.asm'",
        "",
        "; _fn_imports_table is a plain in-library label, not exported: it is",
        "; referenced only by the bootstrap below (intra-file) and reached at",
        "; runtime by the C app via its baked address. fasmg's libload",
        "; library.inc provides no 'public' directive (only 'export'), so",
        "; declaring it public is an illegal instruction here.",
        "_fn_imports_table:",
        "\t; host CRT (populated at load time by lwip_init_runtime)",
        "\tdl 0",
        "\tdl 0",
        "\tdl 0",
        "\t; USB vtable (populated at link time by include_library)",
    ]
    for sym in USB_VTABLE_IMPORTS:
        lines.append(f"\tdl {sym}")
    lines.append("_fn_imports_table_end:")
    lines.append("")
    # `export foo` records the offset to foo's body; lwIP's real bodies live
    # in the flash app, so each export here points at a tiny `jp 0` stub
    # that lwip_init_runtime patches with the real in-app address. Order
    # must match _fn_exports_table so slot N matches entry N.
    for sym in entries:
        # functable entries are mangled (_foo); fasmg `export` takes the
        # unprefixed name.
        name = sym[1:] if sym.startswith("_") else sym
        lines.append(f"\texport {name}")
    lines.append("")
    lines.append("_lwip_jp_table_start:")
    for sym in entries:
        name = sym[1:] if sym.startswith("_") else sym
        lines.append(f"{name}:\tjp 0")
    lines.append("_lwip_jp_table_end:")
    lines.append("")

    # Append the hand-written bootstrap (build-tools/stubs/lwip_init_runtime.asm)
    # verbatim. Living in its own file means regenerating lwip.asm
    # never clobbers the bootstrap body.
    if INIT_RUNTIME_ASM.is_file():
        bootstrap = INIT_RUNTIME_ASM.read_text().rstrip("\n")
        substitutions = [
            (
                r"(__lwip_fn_table_off\s*:=\s*)0x[0-9A-Fa-f]+",
                rf"\g<1>0x{DYLIB_DESCRIPTOR_OFF:06X}",
                "__lwip_fn_table_off",
            ),
            (
                r"(__lwip_expected_export_count\s*:=\s*)0x[0-9A-Fa-f]+",
                rf"\g<1>0x{len(entries):06X}",
                "__lwip_expected_export_count",
            ),
        ]
        for pattern, replacement, label in substitutions:
            new_bootstrap, n = re.subn(pattern, replacement, bootstrap)
            if n != 1:
                print(f"  warning: expected exactly one {label} placeholder "
                      f"in {INIT_RUNTIME_ASM.name}, found {n}; value not "
                      f"substituted", file=sys.stderr)
            else:
                bootstrap = new_bootstrap
        lines.append(bootstrap)
        lines.append("")  # final newline
    else:
        # Missing bootstrap is a build error in practice — the libload
        # build wants this body — but keep generation working so the
        # rest of the table is still valid for diff review.
        print(f"  warning: bootstrap file not found at {INIT_RUNTIME_ASM}; "
              f"libload stub will be incomplete", file=sys.stderr)

    return "\n".join(lines)


def render_libload_import_lib(entries: list[str]) -> str:
    """Render libload's text import-library sidecar.

    fasmg normally emits this while assembling lwip.asm, but generating it from
    the same ordered export list keeps local example builds from accidentally
    linking against an older installed lwip.lib when fasmg is unavailable.
    """
    lines = [
        f"\tlibrary\t{LIBLOAD_NAME}, {LIBLOAD_VERSION}",
        "",
    ]
    for sym in [*entries, *STUB_ONLY_LIBLOAD_EXPORTS]:
        name = sym[1:] if sym.startswith("_") else sym
        lines.append(f"\texport\t{name}")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(
        description="Regenerate the lwIP function/export table and libload stub.")
    ap.add_argument(
        "--append", action="store_true",
        help="Append-only: keep every existing functable.s entry in its "
             "current slot order and only add manifest symbols not already "
             "present. Preserves the export-slot ABI; never reorders or "
             "drops. Default (no flag) is a full regenerate.")
    ap.add_argument(
        "--map", dest="map_path", metavar="lwIP.map", default=None,
        help="Deprecated compatibility option; runtime offsets are now fixed "
             "by linker_script_lwip.ld and app metadata.")
    args = ap.parse_args()

    if args.map_path:
        print("==> --map ignored: dylib runtime uses fixed descriptor offset "
              "and app metadata", file=sys.stderr)

    if not CC.exists():
        print(f"ERROR: ez80-clang not found at {CC} (set CEDEV env var)",
              file=sys.stderr)
        return 1

    c_files = find_c_files()
    asm_files = find_asm_files()
    print(f"==> scanning {len(c_files)} .c files + {len(asm_files)} .s files "
          f"for public symbols", file=sys.stderr)

    # Track which source file defined each symbol — used to cluster related
    # modules together in the regenerated table. If a symbol somehow appears
    # in more than one source file (overload / weak definition), first one
    # wins.
    symbol_origins: dict[str, str] = {}

    with tempfile.TemporaryDirectory(prefix="functable-") as td:
        scratch = Path(td)
        for cf in c_files:
            syms = extract_globals(cf, scratch)
            rel = cf.relative_to(REPO_ROOT).as_posix()
            for s in syms:
                symbol_origins.setdefault(s, rel)

    for af in asm_files:
        syms = extract_asm_globals(af)
        rel = af.relative_to(REPO_ROOT).as_posix()
        for s in syms:
            symbol_origins.setdefault(s, rel)

    # Drop excluded symbols.
    for s in list(symbol_origins):
        if s in EXCLUDE_SYMBOLS:
            del symbol_origins[s]

    print(f"==> found {len(symbol_origins)} unique visible symbols",
          file=sys.stderr)

    manifest = load_public_api_manifest(PUBLIC_API_MANIFEST)
    manifest_entries = [f"_{row['symbol']}" for row in manifest]
    # Force-include stub-required exports (not manifest-listed, so they get no
    # header prototype) ahead of the manifest symbols, but only if the build
    # actually defines them.
    forced = [s for s in sorted(STUB_REQUIRED_EXPORTS)
              if s in symbol_origins and s not in manifest_entries]
    all_entries = forced + manifest_entries
    visible_entries = [sym for sym in all_entries if sym in symbol_origins]
    missing = [sym for sym in manifest_entries if sym not in symbol_origins]
    missing += [s for s in sorted(STUB_REQUIRED_EXPORTS)
                if s not in symbol_origins]

    existing = load_existing_entries(FUNCTABLE_ASM)

    if args.append:
        # Append-only: existing slots keep their indices (the export-slot
        # ABI), and any visible manifest symbol not already present is
        # appended at the end in manifest order. Nothing is reordered or
        # dropped — even a manifest symbol that went missing this build
        # keeps its slot, so the table stays slot-stable across rebuilds.
        existing_order = list(existing)
        existing_set = set(existing)
        appended = [s for s in visible_entries if s not in existing_set]
        new_entries = existing_order + appended
        # symbol_origins may not know where a retained-but-not-visible
        # existing symbol came from; fill a placeholder so grouping works.
        for s in existing_order:
            symbol_origins.setdefault(s, "(retained)")
    else:
        new_entries = visible_entries

    ignored = sorted(set(symbol_origins) - set(new_entries))

    print(f"==> loaded {len(manifest)} manifest symbols from "
          f"{PUBLIC_API_MANIFEST.relative_to(REPO_ROOT)}", file=sys.stderr)
    print(f"==> exporting {len(new_entries)} manifest-approved symbols "
          f"({len(ignored)} visible symbols ignored)", file=sys.stderr)
    if missing:
        print("==> manifest symbols not visible in this build:",
              file=sys.stderr)
        for sym in missing:
            print(f"      {sym[1:]}", file=sys.stderr)

    existing_set = set(existing)
    new_set = set(new_entries)
    added = sorted(new_set - existing_set)
    dropped = sorted(existing_set - new_set)
    mode = "append" if args.append else "regenerate"
    print(f"==> mode={mode} existing={len(existing)} "
          f"new={len(new_entries)} added={len(added)} dropped={len(dropped)}",
          file=sys.stderr)
    if dropped:
        print(f"==> DROPPED (no longer exported):", file=sys.stderr)
        for s in dropped:
            print(f"      {s}", file=sys.stderr)
    if added:
        print(f"==> ADDED:", file=sys.stderr)
        for s in added:
            print(f"      {s}  ({symbol_origins[s]})", file=sys.stderr)

    FUNCTABLE_ASM.write_text(render_functable(new_entries, symbol_origins))
    print(f"==> wrote {FUNCTABLE_ASM} ({len(new_entries)} entries)",
          file=sys.stderr)

    RELEASE_DIR.mkdir(exist_ok=True)
    LIBLOAD_STUB_ASM.write_text(render_libload_stub(new_entries))
    LIBLOAD_STUB_LIB.write_text(render_libload_import_lib(new_entries))
    off_note = (f", __lwip_fn_table_off=0x{DYLIB_DESCRIPTOR_OFF:06X}, "
                f"expected_exports={len(new_entries)}")
    print(f"==> wrote {LIBLOAD_STUB_ASM} ({len(new_entries)} exports, "
          f"library {LIBLOAD_NAME} v{LIBLOAD_VERSION}{off_note})",
          file=sys.stderr)
    print(f"==> wrote {LIBLOAD_STUB_LIB} ({len(new_entries)} exports)",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

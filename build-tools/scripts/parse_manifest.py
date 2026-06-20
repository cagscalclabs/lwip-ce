#!/usr/bin/env python3
"""Manifest-driven release artifact generator.

This is the single implementation entry point for the generated lwIP release
surface. It can regenerate the libload function/export table, the curated
public header tree, or both from build-tools/meta/public_api_manifest.csv.
"""

from __future__ import annotations

import argparse
import sys


def run_functable(argv: list[str] | None = None) -> int:
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
        python3 build-tools/scripts/parse_manifest.py --functable
    """


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
        "_lwip_start_with_crt",
        "_lwip_get_start_errstring",
        "_lwip_is_newer",
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

        expected = ["type", "symbol", "category", "source_header", "output_header"]
        with path.open(newline="") as fh:
            reader = csv.DictReader(fh)
            if reader.fieldnames != expected:
                print(f"ERROR: {path} must have columns: "
                      f"{','.join(expected)}", file=sys.stderr)
                sys.exit(1)
            rows = [dict(row) for row in reader]

        seen: set[str] = set()
        duplicates: list[str] = []
        func_rows: list[dict[str, str]] = []
        for row in rows:
            row["type"] = row["type"].strip()
            row["symbol"] = row["symbol"].strip()
            row["category"] = row["category"].strip()
            row["source_header"] = row["source_header"].strip()
            row["output_header"] = row["output_header"].strip()
            if row["type"] not in {"func", "macro", "typedef", "struct", "enum"}:
                print(f"ERROR: unknown manifest type in {path}: {row}",
                      file=sys.stderr)
                sys.exit(1)
            if not row["symbol"] or not row["category"] or not row["source_header"] or not row["output_header"]:
                print(f"ERROR: blank field in {path}: {row}", file=sys.stderr)
                sys.exit(1)
            if row["type"] != "func":
                continue
            if row["symbol"] in seen:
                duplicates.append(row["symbol"])
            seen.add(row["symbol"])
            func_rows.append(row)
        if duplicates:
            print(f"ERROR: duplicate manifest symbols in {path}:",
                  file=sys.stderr)
            for symbol in sorted(set(duplicates)):
                print(f"      {symbol}", file=sys.stderr)
            sys.exit(1)
        return func_rows


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
            "; Auto-generated by build-tools/scripts/parse_manifest.py.  Do not edit by hand —",
            "; run `make functable` after adding/removing public API.",
            ";",
            "; Symbols are grouped by defining source file. The exported ABI",
            "; is append-only after v1.0: existing slot positions are stable,",
            "; and new public symbols are added at the end.",
            ";",
            "; Layout:",
            ";   db  'L','W','I','P','T','B'   6-byte magic (ascending memory order)",
            ";   d24 <entry count>",
            ";   d24 <relocated address>  ... one per exported symbol",
            ";",
            f"; The linker script pins this section at linked-image offset 0x{DYLIB_DESCRIPTOR_OFF:02X}.",
            "; At load, the libload bootstrap computes the installed linked-image",
            "; base from app metadata, adds the fixed offset, then checks the magic.",
            "; The bootstrap patches the shared prefix of app/stub export counts;",
            "; trailing newer exports simply remain unavailable to that pairing.",
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
        installed app metadata at runtime, then validates the table magic and
        patches the shared export-count prefix with the installer-relocated
        in-flash addresses.

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
            "; Do not edit by hand. Sources: build-tools/scripts/parse_manifest.py,",
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
        # in the flash app, so each export here points at a tiny `jp` stub
        # that lwip_init_runtime patches with the real in-app address. Order
        # must match _fn_exports_table so slot N matches entry N.
        #
        # Default target is lwip_function_jp_unset, not a bare jp 0: a slot
        # beyond min(app_count, stub_count) (the libload/app version-skew
        # case -- see lwip_init_runtime.asm's patch loop) is intentionally
        # left unpatched, and a caller that still invokes it should get a
        # safe "function unsupported, version" errno instead of jumping to
        # address 0.
        for sym in entries:
            # functable entries are mangled (_foo); fasmg `export` takes the
            # unprefixed name.
            name = sym[1:] if sym.startswith("_") else sym
            lines.append(f"\texport {name}")
        lines.append("")
        lines.append("_lwip_jp_table_start:")
        for sym in entries:
            name = sym[1:] if sym.startswith("_") else sym
            lines.append(f"{name}:\tjp lwip_function_jp_unset")
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

        # lwip_init_runtime_internal is called by raw address from the asm
        # bootstrap's fixed-position patch loop (lwip_init_runtime.asm) before
        # any other trampoline is trustworthy, so it must always be exported
        # at slot 0. Only pin it on first introduction — if it already has a
        # slot from a prior build (append mode), leave the existing ABI alone
        # rather than silently reordering a table older binaries depend on.
        pin = "_lwip_init_runtime_internal"
        if pin in new_entries and (not args.append or pin not in existing_set):
            new_entries = [pin] + [s for s in new_entries if s != pin]

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

    old_argv = sys.argv[:]
    try:
        sys.argv = ["parse_manifest.py --functable", *(argv or [])]
        return main()
    finally:
        sys.argv = old_argv


def run_headers(argv: list[str] | None = None) -> int:
    import sys

    if sys.version_info < (3, 9):
        print("ERROR: python 3.9+ required", file=sys.stderr)
        return 1
    """Generate the public-include tree consumed by apps linking against
    libload-shipped lwIP.

    Default layout:

            build/
            lwip.h                   — preferred surface: the socket API (pruned
                                       src/lwIP.h) inlined at the top, then an
                                       aggregate include of the core headers
            cryptography.h           — aggregate include for lwip/cryptography/*.h
            lwip/
            core/<name>.h            — non-crypto source headers with public API
            cryptography/<name>.h    — TLS/crypto source headers with public API

    Pruning strategy:

      1. build-tools/meta/public_api_manifest.csv is the manual allowlist. Its category
         column chooses socket/core/cryptography output placement.
      2. The libload export table (src/functable.s) is the build-filtered
         surface: manifest functions that were visible at compile time.
      3. For each manifest source header, libclang identifies FunctionDecls.
         Any decl whose name is *not* in the export table gets stripped
         out of the copy (along with its preceding doxygen block).
         Macros, types, structs, inline helpers, extern data: untouched.

    That makes the output tree usable directly — apps include
    <lwip.h> / <cryptography.h>
    and see exactly the surface they can link against via libload.

    Run from repo root:

        python3 build-tools/scripts/parse_manifest.py --headers

    A build must have been run first so obj/src/**/*.o exists; otherwise
    the script can't tell which functions are actually defined.
    """


    import re
    import shutil
    import subprocess
    import sys
    import csv
    import hashlib
    import json
    import os
    import platform
    import tempfile
    import glob
    from pathlib import Path

    try:
        import clang.cindex as C       # type: ignore
    except ModuleNotFoundError as exc:
        if exc.name != "clang":
            raise
        header_python = os.environ.get("HEADER_PYTHON")
        if header_python and not os.environ.get("LWIP_PARSE_MANIFEST_HEADER_REEXECED"):
            env = os.environ.copy()
            env["LWIP_PARSE_MANIFEST_HEADER_REEXECED"] = "1"
            cmd = [
                header_python,
                str(Path(__file__).resolve()),
                "--headers",
                *(argv or []),
            ]
            return subprocess.run(
                cmd,
                cwd=Path(__file__).resolve().parents[2],
                env=env,
            ).returncode
        print(
            "ERROR: Python clang bindings not found. "
            "Set HEADER_PYTHON to a Python with clang.cindex installed.",
            file=sys.stderr,
        )
        return 1

    # ---------------------------------------------------------------------
    # libclang setup. The Python `clang` bindings often need an explicit
    # library path. Prefer LIBCLANG_PATH, then known local paths, and finally
    # let clang.cindex try its own discovery.
    # ---------------------------------------------------------------------
    _libclang_candidates: list[str] = []
    if os.environ.get("LIBCLANG_PATH"):
        _libclang_candidates.append(os.environ["LIBCLANG_PATH"])
    _libclang_candidates.extend([
        "/Library/Developer/CommandLineTools/usr/lib/libclang.dylib",
        "/usr/lib/llvm-18/lib/libclang.so",
        "/usr/lib/llvm-17/lib/libclang.so",
        "/usr/lib/llvm-16/lib/libclang.so",
        "/usr/lib/llvm-15/lib/libclang.so",
        "/usr/lib/llvm-14/lib/libclang.so",
    ])
    _libclang_candidates.extend(sorted(glob.glob("/usr/lib/llvm-*/lib/libclang.so"), reverse=True))
    for _candidate in _libclang_candidates:
        if _candidate and Path(_candidate).exists():
            C.Config.set_library_file(_candidate)
            break


    REPO_ROOT = Path(__file__).resolve().parents[2]
    BUILD_TOOLS_DIR = REPO_ROOT / "build-tools"
    SRC_DIR = REPO_ROOT / "src"
    OBJ_DIR = REPO_ROOT / "obj" / "src"
    FUNCTABLE_S = SRC_DIR / "functable.s"
    PUBLIC_API_MANIFEST = BUILD_TOOLS_DIR / "meta" / "public_api_manifest.csv"
    CONN_SRC = SRC_DIR / "lwIP.h"
    TLS_INCLUDES = SRC_DIR / "tls" / "includes"

    OUT_ROOT = Path(os.environ.get("LWIP_RELEASE_DIR", REPO_ROOT / "build"))
    OUT_DIR = OUT_ROOT / "lwip"
    OUT_CORE_INDEX = OUT_ROOT / "lwip.h"
    OUT_CRYPTO_INDEX = OUT_ROOT / "cryptography.h"

    # The socket convenience API is inlined directly at the TOP of lwip.h so it is
    # the visibly-preferred surface (not buried among the core headers). This holds
    # its pruned body between emit time and umbrella assembly.
    _CONN_BODY: str = ""
    DOCSTRING_CACHE_DIR = BUILD_TOOLS_DIR / ".docstring_cache"
    DOCSTRING_PROMPT_VERSION = 1
    DOCSTRING_STATE_FILE = DOCSTRING_CACHE_DIR / "release_tree_state.json"
    RELEASE_SOURCE_MAP_FILE = DOCSTRING_CACHE_DIR / "release_header_sources.json"
    CEDEV_INCLUDE = Path(os.environ.get("CEDEV", os.path.expanduser("~/CEdev"))) / "include"
    UNIFDEF_MISSING_WARNED = False

    # Headers we explicitly don't mirror. opt.h is a giant macro file with
    # no decls; the cmake-template variants are build-system inputs, not
    # headers.
    SKIP_HEADERS = {
        "src/include/lwip/opt.h",
        "src/include/lwip/init.h.cmake.in",
        "src/tls/includes/handshake.h",
    }

    RELEASE_INCLUDE_REPLACEMENTS = {
        "src/apps/altcp_tls/altcp_tls_ce.h": """\
    #include <stddef.h>

    #ifndef TLS_PSK_IDENTITY_MAX_LEN
    #define TLS_PSK_IDENTITY_MAX_LEN 256
    #endif

    struct tls_psk_identity {
        u8_t identity[TLS_PSK_IDENTITY_MAX_LEN];
        size_t identity_len;
        u32_t obfuscated_ticket_age;
    };
    """,
    }

    # X-macro / list headers that are emitted to disk so transitive includes
    # resolve, but must NOT be listed in the umbrella lwip.h/cryptography.h:
    # they are deliberately included multiple times and are not standalone
    # compilable (e.g. memp_std.h's bare LWIP_MEMPOOL(...) entries).
    UMBRELLA_EXCLUDE_BASENAMES = {
        "memp_std.h",
    }

    SOURCE_DECL_OWNER_HEADERS = {
        "src/include/lwip/arch.h",
        "src/include/lwip/err.h",
        "src/include/lwip/ip4_addr.h",
        "src/include/lwip/ip6_addr.h",
        "src/include/lwip/ip_addr.h",
        "src/include/lwip/mem.h",
        "src/include/lwip/pbuf.h",
        "src/include/lwip/tcpbase.h",
        "src/drivers/mem.h",
    }

    FORCE_SOURCE_DECLS_BY_HEADER = {
        "src/drivers/usb_ethernet.h": {"usb_configurator"},
    }

    # CFLAGS used to drive libclang. Mirrors the real build's include path.
    # A small prelude shim teaches libclang the eZ80 24-bit types and pulls
    # in stdbool/stdint/stddef for the lwIP headers that don't include them
    # themselves (rsa.h does this, for example).
    PRELUDE_PATH = Path("/tmp/ez80_prelude_dump.h")
    PRELUDE = """\
    typedef unsigned int uint24_t;
    typedef int int24_t;
    #include <stdbool.h>
    #include <stdint.h>
    #include <stddef.h>
    """

    CFLAGS = [
        "-x", "c",
        "-D__TICE__=1",
        "-DNDEBUG=1",
        "-I", str(SRC_DIR / "include"),
        "-I", str(SRC_DIR),
        "-isystem", str(CEDEV_INCLUDE),
        "-include", str(PRELUDE_PATH),
        "-Wno-everything",
    ]

    ENTRY_RE = re.compile(
        r"^\s*(?:d24|dl)\s+(_[A-Za-z_][A-Za-z0-9_]*)\s*(?:-\s*app\s*)?$")

    STD_HEADER_TYPES = {
        "bool": "<stdbool.h>",
        "size_t": "<stddef.h>",
        "uint8_t": "<stdint.h>",
        "uint16_t": "<stdint.h>",
        "uint32_t": "<stdint.h>",
        "uint64_t": "<stdint.h>",
        "uintptr_t": "<stdint.h>",
        "uint24_t": "<stdint.h>",
        "int8_t": "<stdint.h>",
        "int16_t": "<stdint.h>",
        "int32_t": "<stdint.h>",
        "int64_t": "<stdint.h>",
        "intptr_t": "<stdint.h>",
        "int24_t": "<stdint.h>",
    }

    COMMON_MACRO_SNIPPETS = {
        "LWIP_PBUF_REF_T": """\
    #ifndef LWIP_PBUF_REF_T
    #define LWIP_PBUF_REF_T u8_t
    #endif""",
        "LWIP_PBUF_CUSTOM_DATA": """\
    #ifndef LWIP_PBUF_CUSTOM_DATA
    #define LWIP_PBUF_CUSTOM_DATA
    #endif""",
        "PACK_STRUCT_FIELD": """\
    #ifndef PACK_STRUCT_FIELD
    #define PACK_STRUCT_FIELD(x) x
    #endif""",
        "PACK_STRUCT_FLD_8": """\
    #ifndef PACK_STRUCT_FLD_8
    #define PACK_STRUCT_FLD_8(x) PACK_STRUCT_FIELD(x)
    #endif""",
        "PACK_STRUCT_FLD_S": """\
    #ifndef PACK_STRUCT_FLD_S
    #define PACK_STRUCT_FLD_S(x) PACK_STRUCT_FIELD(x)
    #endif""",
        "PACK_STRUCT_STRUCT": """\
    #ifndef PACK_STRUCT_STRUCT
    #define PACK_STRUCT_STRUCT
    #endif""",
        "PACK_STRUCT_BEGIN": """\
    #ifndef PACK_STRUCT_BEGIN
    #define PACK_STRUCT_BEGIN
    #endif""",
        "PACK_STRUCT_END": """\
    #ifndef PACK_STRUCT_END
    #define PACK_STRUCT_END
    #endif""",
        "PA": """\
    #ifndef PA
    #define PA
    #endif""",
    }

    EMPTY_PUBLIC_MACROS = {
        "IP_PCB_NETIFHINT",
    }

    # Types whose definition lives in a toolchain-provided header rather
    # than the lwIP-CE source tree. When the dependency walker hits one of
    # these, it skips trying to synthesize a definition and instead records
    # the matching #include so the generated file can pick the real type
    # up from the toolchain at consume time.
    #
    # Key is matched as a prefix against identifier names. `usb_endpoint_t`,
    # `usb_transfer_status_t`, `usb_device_t` etc. all map to `<usbdrvce.h>`.
    EXTERNAL_TYPE_PREFIX_HEADERS = (
        ("usb_", "<usbdrvce.h>"),
    )


    def external_header_for(name: str) -> str | None:
        """If `name` is an identifier whose definition lives in a
        toolchain-provided header rather than lwIP, return the #include
        line apps should use to bring it in. Returns None for names this
        project owns."""
        for prefix, header in EXTERNAL_TYPE_PREFIX_HEADERS:
            if name.startswith(prefix):
                return header
        return None


    SOURCE_INCLUDE_RE = re.compile(r"^\s*#\s*include\s+\"([^\"]+)\"")


    def source_include_target(header: Path, include_name: str) -> Path | None:
        candidates: list[Path] = []
        if include_name.startswith("lwip/"):
            candidates.append(SRC_DIR / "include" / include_name)
        elif "/" in include_name:
            candidates.append(SRC_DIR / include_name)
            candidates.append(SRC_DIR / "include" / include_name)
            candidates.append(header.parent / include_name)
        else:
            candidates.append(header.parent / include_name)

        for candidate in candidates:
            if candidate.is_file():
                try:
                    return candidate.resolve()
                except OSError:
                    return None
        return None


    def generated_sibling_includes(
        header: Path,
        source_to_output_name: dict[Path, str],
    ) -> tuple[list[str], set[Path]]:
        """Return generated sibling #includes corresponding to source #includes.

        If src/include/lwip/altcp.h includes lwip/pbuf.h and both are part of the
        generated core set, the release altcp.h should include "pbuf.h" instead of
        synthesizing pbuf's structs locally.
        """
        includes: list[str] = []
        included_sources: set[Path] = set()
        for line in header.read_text().splitlines():
            match = SOURCE_INCLUDE_RE.match(line)
            if not match:
                continue
            target = source_include_target(header, match.group(1))
            if target is None or target == header.resolve():
                continue
            out_name = source_to_output_name.get(target)
            if not out_name:
                continue
            include_line = f'#include "{out_name}"'
            if include_line not in includes:
                includes.append(include_line)
            included_sources.add(target)
        return includes, included_sources


    def add_generated_include_for_source(
        includes: list[str],
        included_sources: set[Path],
        current_header: Path,
        dep_source: Path | None,
        source_to_output_name: dict[Path, str],
    ) -> bool:
        if dep_source is None:
            return False
        try:
            dep_source = dep_source.resolve()
            current = current_header.resolve()
        except OSError:
            return False
        if dep_source == current:
            return False
        out_name = source_to_output_name.get(dep_source)
        if not out_name:
            return False
        include_line = f'#include "{out_name}"'
        if include_line not in includes:
            includes.append(include_line)
        included_sources.add(dep_source)
        return True


    def source_dependency_closure(initial_headers: list[Path]) -> list[Path]:
        """Collect source headers needed by the generated headers.

        This follows source #includes and emits release versions of those same
        headers when they are project-owned. opt.h stays excluded because it is a
        build configuration file, not a stable public declaration owner.
        """
        allowed_roots = [
            (SRC_DIR / "include").resolve(),
            (SRC_DIR / "drivers").resolve(),
            TLS_INCLUDES.resolve(),
            # Contrib x25519 ships tls_x25519_publickey/_secret as public API;
            # its header lives outside src/tls/includes but is part of the
            # exported surface (see build-tools/meta/public_api_manifest.csv).
            (SRC_DIR / "tls" / "contrib" / "x25519" / "src").resolve(),
        ]

        def allowed(path: Path) -> bool:
            try:
                resolved = path.resolve()
            except OSError:
                return False
            if resolved.relative_to(REPO_ROOT).as_posix() in SKIP_HEADERS:
                return False
            return any(
                resolved == root or root in resolved.parents
                for root in allowed_roots
            )

        out: list[Path] = []
        seen: set[Path] = set()
        queue = [hp.resolve() for hp in initial_headers]
        while queue:
            header = queue.pop(0)
            if header in seen or not allowed(header):
                continue
            seen.add(header)
            out.append(header)
            for line in header.read_text().splitlines():
                match = SOURCE_INCLUDE_RE.match(line)
                if not match:
                    continue
                target = source_include_target(header, match.group(1))
                if target is not None and target not in seen and allowed(target):
                    queue.append(target)
        return out


    OPAQUE_TYPEDEF_FALLBACKS = {
        "usb_callback_data_t": "typedef struct usb_callback_data usb_callback_data_t;",
        "usb_device_data_t": "typedef struct usb_device_data usb_device_data_t;",
        "usb_device_t": "typedef void *usb_device_t;",
        "usb_endpoint_t": "typedef void *usb_endpoint_t;",
        "usb_error_t": "typedef int usb_error_t;",
        "usb_event_t": "typedef int usb_event_t;",
        "usb_transfer_status_t": "typedef int usb_transfer_status_t;",
        "usb_descriptor_type_t": "typedef int usb_descriptor_type_t;",
        "usb_control_request_t": "typedef int usb_control_request_t;",
        "usb_string_descriptor_t": "typedef int usb_string_descriptor_t;",
    }

    OPAQUE_STRUCTS = {
        "acd",
        "autoip",
        "netif",
        "tcp_pcb",
        "udp_pcb",
        "altcp_pcb",
        "altcp_functions",
        "raw_pcb",
        "altcp_tls_ce_config",
        "etharp_hdr",
        "eth_addr",
    }


    # ---------------------------------------------------------------------
    # Symbol collection
    # ---------------------------------------------------------------------

    def load_exports() -> set[str]:
        """Read the unmangled symbol names from src/functable.s. The table
        entries are `d24 _foo - app`; we strip the leading underscore so
        the result matches the C function name as libclang reports it."""
        syms: set[str] = set()
        with FUNCTABLE_S.open() as fh:
            for line in fh:
                m = ENTRY_RE.match(line)
                if m:
                    syms.add(m.group(1)[1:])
        return syms


    def load_public_api_manifest() -> list[dict[str, str]]:
        """Read the curated API manifest. The category column controls where
        generated release headers are emitted."""
        if not PUBLIC_API_MANIFEST.is_file():
            print(f"ERROR: public API manifest not found at {PUBLIC_API_MANIFEST}",
                  file=sys.stderr)
            sys.exit(1)

        expected = ["type", "symbol", "category", "source_header", "output_header"]
        with PUBLIC_API_MANIFEST.open(newline="") as fh:
            reader = csv.DictReader(fh)
            if reader.fieldnames != expected:
                print(f"ERROR: {PUBLIC_API_MANIFEST} must have columns: "
                      f"{','.join(expected)}", file=sys.stderr)
                sys.exit(1)
            rows = [dict(row) for row in reader]

        seen: set[str] = set()
        func_rows: list[dict[str, str]] = []
        for row in rows:
            row["type"] = row["type"].strip()
            row["symbol"] = row["symbol"].strip()
            row["category"] = row["category"].strip()
            row["source_header"] = row["source_header"].strip()
            row["output_header"] = row["output_header"].strip()
            if row["type"] not in {"func", "macro", "typedef", "struct", "enum"}:
                print(f"ERROR: unknown manifest type in {PUBLIC_API_MANIFEST}: {row}",
                      file=sys.stderr)
                sys.exit(1)
            if not row["symbol"] or not row["category"] or not row["source_header"] or not row["output_header"]:
                print(f"ERROR: blank field in {PUBLIC_API_MANIFEST}: {row}",
                      file=sys.stderr)
                sys.exit(1)
            if row["type"] != "func":
                continue
            if row["symbol"] in seen:
                print(f"ERROR: duplicate manifest symbol: {row['symbol']}",
                      file=sys.stderr)
                sys.exit(1)
            seen.add(row["symbol"])
            func_rows.append(row)
        return func_rows


    # ---------------------------------------------------------------------
    # Header walking & pruning
    # ---------------------------------------------------------------------

    def declared_functions_in(header: Path) -> dict[str, tuple[int, int]]:
        """Return {function_name: (start_line, end_line)} for every
        FunctionDecl whose definition is located in `header`. Source ranges
        are inclusive and 1-based. Returns {} if parsing fails."""
        idx = C.Index.create()
        try:
            tu = idx.parse(
                str(header),
                args=CFLAGS,
                options=(C.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD |
                         C.TranslationUnit.PARSE_SKIP_FUNCTION_BODIES),
            )
        except C.TranslationUnitLoadError:
            return {}
        out: dict[str, tuple[int, int]] = {}
        target_name = header.name
        for cur in tu.cursor.walk_preorder():
            if cur.kind != C.CursorKind.FUNCTION_DECL:
                continue
            loc = cur.location
            if not loc.file or not loc.file.name.endswith(target_name):
                continue
            # Skip the cursor if it's a static / inline definition — those
            # already have bodies and aren't candidates for pruning.
            if cur.is_definition() and cur.storage_class == C.StorageClass.STATIC:
                continue
            ext = cur.extent
            out[cur.spelling] = (ext.start.line, ext.end.line)
        return out


    def find_doc_block_start(lines: list[str], decl_start_line: int) -> int | None:
        """If a /** ... */ doxygen block immediately precedes the decl
        (only blank lines between), return its 1-based start line.
        Otherwise None."""
        i = decl_start_line - 2  # 0-based, line above the decl
        while i >= 0 and lines[i].strip() == "":
            i -= 1
        if i < 0:
            return None
        if not lines[i].rstrip().endswith("*/"):
            return None
        while i >= 0:
            if "/**" in lines[i] or "/*" in lines[i]:
                return i + 1
            i -= 1
        return None


    def prune_non_exported(header: Path, exports: set[str]) -> str:
        """Read `header`, drop every function decl whose name isn't in
        `exports` (along with its preceding doc block), return the result.
        Everything else passes through untouched — macros, structs, types,
        static inline helpers, extern data declarations all survive."""
        text = header.read_text()
        decls = declared_functions_in(header)
        if not decls:
            return text

        lines = text.splitlines(keepends=True)
        drop_ranges: list[tuple[int, int]] = []
        for name, (start, end) in decls.items():
            if name in exports:
                continue
            doc_start = find_doc_block_start(lines, start)
            drop_ranges.append((doc_start if doc_start is not None else start, end))

        if not drop_ranges:
            return text

        mask = [True] * (len(lines) + 2)   # 1-based, +1 slack
        for s, e in drop_ranges:
            for ln in range(s, e + 1):
                if 0 < ln <= len(lines):
                    if re.match(r"^\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b", lines[ln - 1]):
                        continue
                    mask[ln] = False

        kept = "".join(lines[i] for i in range(len(lines)) if mask[i + 1])
        # Collapse runs of >2 blank lines that the deletion may have created.
        return re.sub(r"\n{3,}", "\n\n", kept)


    def function_count_for(header: Path, symbols: set[str]) -> int:
        return sum(1 for name in declared_functions_in(header) if name in symbols)


    def build_macro_file() -> Path | None:
        compiler = shutil.which("clang") or shutil.which("cc")
        if not compiler:
            return None
        res = subprocess.run(
            [compiler, "-dM", "-E", *CFLAGS, "-"],
            input='#include "lwip/opt.h"\n',
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        )
        if res.returncode != 0:
            print(f"  warning: could not collect build macros: {res.stderr.strip()}",
                  file=sys.stderr)
            return None
        guard_like = re.compile(r"^#define\s+([A-Za-z_][A-Za-z0-9_]*)\b")
        lines: list[str] = []
        for line in res.stdout.splitlines():
            match = guard_like.match(line)
            if match:
                name = match.group(1)
                if (
                    name.startswith("LWIP_HDR_") or
                    name.endswith("_H") or
                    name.endswith("_h") or
                    name.endswith("_INCLUDED")
                ):
                    continue
            lines.append(line)

        path = Path(tempfile.gettempdir()) / "lwip_ce_release_macros.h"
        path.write_text("\n".join(lines) + "\n")
        return path


    def prune_inactive_conditionals(text: str, macro_file: Path | None,
                                    source: Path | None = None) -> str:
        global UNIFDEF_MISSING_WARNED
        if macro_file is None:
            return text
        if not shutil.which("unifdef"):
            if not UNIFDEF_MISSING_WARNED:
                print("  warning: unifdef not found; generated headers keep source #if branches",
                      file=sys.stderr)
                UNIFDEF_MISSING_WARNED = True
            return text
        # unifdef parses // comments as line-terminated; if the input lacks a
        # final newline, it can mis-report "EOF in comment" at the end of a
        # legitimately-closed `//` comment. Force a trailing newline.
        with tempfile.NamedTemporaryFile("w", suffix=".h", delete=False) as tmp:
            tmp.write(text if text.endswith("\n") else text + "\n")
            tmp_path = Path(tmp.name)
        try:
            res = subprocess.run(
                ["unifdef", "-B", "-k", "-x2", f"-f{macro_file}", str(tmp_path)],
                capture_output=True,
                text=True,
                cwd=str(REPO_ROOT),
            )
            if res.returncode != 0:
                origin = (source.relative_to(REPO_ROOT).as_posix()
                          if source is not None else "<unknown>")
                print(f"  warning: unifdef failed for {origin}: "
                      f"{res.stderr.strip()}",
                      file=sys.stderr)
                return text
            return res.stdout
        finally:
            try:
                tmp_path.unlink()
            except OSError:
                pass


    def rewrite_release_includes(
        text: str,
        header: Path,
        source_to_output_name: dict[Path, str],
    ) -> str:
        out: list[str] = []
        for line in text.splitlines(keepends=True):
            match = SOURCE_INCLUDE_RE.match(line)
            if not match:
                out.append(line)
                continue

            include_name = match.group(1)
            target = source_include_target(header, include_name)
            if target is None:
                out.append(line)
                continue

            try:
                rel = target.relative_to(REPO_ROOT).as_posix()
            except ValueError:
                out.append(line)
                continue

            replacement = RELEASE_INCLUDE_REPLACEMENTS.get(rel)
            if replacement is not None:
                out.append(replacement)
                continue

            if rel in SKIP_HEADERS:
                arch_name = source_to_output_name.get(
                    (SRC_DIR / "include" / "lwip" / "arch.h").resolve()
                )
                if arch_name:
                    out.append(f'#include "{arch_name}"\n')
                continue

            out_name = source_to_output_name.get(target)
            if out_name:
                out.append(f'#include "{out_name}"\n')
            else:
                out.append(line)
        return "".join(out)


    def parse_build_macro_definitions(macro_file: Path | None) -> dict[str, str]:
        if macro_file is None or not macro_file.is_file():
            return {}
        out: dict[str, str] = {}
        for line in macro_file.read_text().splitlines():
            match = re.match(r"^#define\s+([A-Za-z_][A-Za-z0-9_]*)(\([^)]*\))?\s*(.*)$", line)
            if not match or match.group(2):
                continue
            if match.group(1) in STD_HEADER_TYPES or match.group(1) in {"true", "false"}:
                continue
            out[match.group(1)] = match.group(3).strip()
        return out


    def text_without_comments(text: str) -> str:
        text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
        return re.sub(r"//.*", " ", text)


    def materialize_referenced_build_macros(text: str, macro_defs: dict[str, str]) -> str:
        if not macro_defs:
            return text

        defined = {
            match.group(1)
            for match in re.finditer(r"^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\b", text, re.MULTILINE)
        }
        referenced = set(IDENT_RE.findall(text_without_comments(text)))
        needed: list[str] = []
        queued = sorted((referenced & set(macro_defs)) - defined)
        seen = set(queued)
        while queued:
            name = queued.pop(0)
            needed.append(name)
            for dep in sorted(set(IDENT_RE.findall(macro_defs[name])) & set(macro_defs)):
                if dep not in seen and dep not in defined:
                    seen.add(dep)
                    queued.append(dep)

        if not needed:
            snippet_names = [
                name for name in COMMON_MACRO_SNIPPETS
                if name in referenced and name not in defined
            ]
            if not snippet_names:
                return text
        else:
            snippet_names = [
                name for name in COMMON_MACRO_SNIPPETS
                if name in referenced and name not in defined and name not in needed
            ]

        block_lines = [
            f"#define {name} {macro_defs[name]}".rstrip()
            for name in needed
        ]
        block_lines.extend(COMMON_MACRO_SNIPPETS[name] for name in snippet_names)
        block = "\n".join(block_lines) + "\n"
        lines = text.splitlines(keepends=True)
        insert_at = 0
        for idx in range(min(len(lines) - 1, 80)):
            if (re.match(r"^\s*#\s*ifndef\s+\w+", lines[idx]) and
                    re.match(r"^\s*#\s*define\s+\w+", lines[idx + 1])):
                insert_at = idx + 2
                break
        if insert_at == 0:
            for idx, line in enumerate(lines[:120]):
                if line.lstrip().startswith("#include "):
                    insert_at = idx + 1
        if insert_at == 0:
            for idx, line in enumerate(lines[:40]):
                if re.match(r"^\s*#\s*define\s+\w+", line):
                    insert_at = idx + 1
                    break
        lines[insert_at:insert_at] = ["\n", block]
        return "".join(lines)


    def add_missing_standard_includes(text: str) -> str:
        visible_text = text_without_comments(text)
        referenced = set(IDENT_RE.findall(visible_text))
        needed_headers = {
            header
            for name, header in STD_HEADER_TYPES.items()
            if name in referenced
        }
        if not needed_headers:
            return text

        existing_headers = {
            match.group(1)
            for match in re.finditer(r"^\s*#\s*include\s+(<[^>]+>)", text, re.MULTILINE)
        }
        missing = [header for header in ["<stdbool.h>", "<stddef.h>", "<stdint.h>"]
                   if header in needed_headers and header not in existing_headers]
        if not missing:
            return text

        lines = text.splitlines(keepends=True)
        insert_at = 0
        for idx, line in enumerate(lines[:120]):
            if line.lstrip().startswith("#include "):
                insert_at = idx + 1
        if insert_at == 0:
            for idx, line in enumerate(lines[:40]):
                if re.match(r"^\s*#\s*define\s+\w+", line):
                    insert_at = idx + 1
                    break
        lines[insert_at:insert_at] = [f"#include {header}\n" for header in missing]
        return "".join(lines)


    def remove_orphan_comment_blocks(text: str) -> str:
        lines = text.splitlines(keepends=True)
        out: list[str] = []
        idx = 0
        while idx < len(lines):
            stripped = lines[idx].lstrip()
            if stripped.startswith("/**") or stripped.startswith("/*"):
                start = idx
                while idx < len(lines) and "*/" not in lines[idx]:
                    idx += 1
                if idx < len(lines):
                    idx += 1
                probe = idx
                while probe < len(lines) and lines[probe].strip() == "":
                    probe += 1
                next_line = lines[probe].lstrip() if probe < len(lines) else ""
                if not next_line or next_line.startswith("#endif"):
                    continue
                out.extend(lines[start:idx])
                continue
            out.append(lines[idx])
            idx += 1
        return re.sub(r"\n{3,}", "\n\n", "".join(out))


    def pruned_copy_header_body(
        header: Path,
        symbols: set[str],
        source_to_output_name: dict[Path, str],
        macro_file: Path | None,
        macro_defs: dict[str, str],
    ) -> tuple[str, int]:
        emitted_functions = function_count_for(header, symbols)
        text = prune_non_exported(header, symbols)
        text = prune_inactive_conditionals(text, macro_file, source=header)
        text = rewrite_release_includes(text, header, source_to_output_name)
        text = add_missing_standard_includes(text)
        text = materialize_referenced_build_macros(text, macro_defs)
        text = remove_orphan_comment_blocks(text)
        return text.rstrip() + "\n", emitted_functions


    # ---------------------------------------------------------------------
    # Synthetic release header generation
    # ---------------------------------------------------------------------

    def parse_header(header: Path) -> C.TranslationUnit | None:
        idx = C.Index.create()
        try:
            return idx.parse(
                str(header),
                args=CFLAGS,
                options=(C.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD |
                         C.TranslationUnit.PARSE_SKIP_FUNCTION_BODIES),
            )
        except C.TranslationUnitLoadError:
            return None


    def cursor_file(cur: C.Cursor) -> Path | None:
        if not cur.location.file:
            return None
        try:
            return Path(cur.location.file.name).resolve()
        except OSError:
            return None


    def cursor_in_file(cur: C.Cursor, path: Path) -> bool:
        cur_path = cursor_file(cur)
        if cur_path is None:
            return False
        try:
            return cur_path == path.resolve()
        except OSError:
            return False


    def source_text_for_extent(extent: C.SourceRange) -> str:
        path = Path(extent.start.file.name)
        lines = path.read_text().splitlines(keepends=True)
        start_line = extent.start.line
        end_line = extent.end.line
        if start_line <= 0 or end_line <= 0 or start_line > len(lines):
            return ""
        chunk = lines[start_line - 1:end_line]
        if not chunk:
            return ""
        chunk[0] = chunk[0][max(extent.start.column - 1, 0):]
        if end_line <= len(lines):
            chunk[-1] = chunk[-1][:max(extent.end.column - 1, 0)]
        text = "".join(chunk).strip()
        if text and not text.endswith(";"):
            text += ";"
        return text


    def synthetic_enum(cur: C.Cursor, typedef_name: str | None = None) -> str:
        enum_name = cur.spelling
        if enum_name.startswith("enum (unnamed"):
            enum_name = ""
        head = "typedef enum" if typedef_name else "enum"
        if enum_name and not typedef_name:
            head = f"enum {enum_name}"
        elif enum_name:
            head = f"typedef enum {enum_name}"

        lines = [f"{head} {{"]
        constants = [
            child for child in cur.get_children()
            if child.kind == C.CursorKind.ENUM_CONSTANT_DECL
        ]
        for idx, child in enumerate(constants):
            suffix = "," if idx + 1 < len(constants) else ""
            lines.append(f"  {child.spelling} = {child.enum_value}{suffix}")
        if typedef_name:
            lines.append(f"}} {typedef_name};")
        else:
            lines.append("};")
        return "\n".join(lines)


    def record_text(cur: C.Cursor, typedef_name: str | None = None) -> str:
        kind = "union" if cur.kind == C.CursorKind.UNION_DECL else "struct"
        name = cur.spelling
        if typedef_name:
            head = f"typedef {kind}" + (f" {name}" if name else "")
            tail = f"}} {typedef_name};"
        else:
            head = f"{kind} {name}" if name else kind
            tail = "};"

        fields = [
            child for child in cur.get_children()
            if child.kind == C.CursorKind.FIELD_DECL
        ]
        if not fields and not cur.is_definition():
            return f"{head};" if not typedef_name else f"typedef {kind} {name} {typedef_name};"

        lines = [head, "{"]
        for field in fields:
            field_text = source_text_for_extent(field.extent).strip()
            field_text = re.sub(r"/\*.*?\*/", "", field_text, flags=re.DOTALL).strip()
            field_text = re.sub(r"/\*.*", "", field_text, flags=re.DOTALL).strip()
            field_text = re.sub(r"//.*", "", field_text).strip()
            field_text = re.sub(r";\s+/;", ";", field_text).strip()
            field_text = re.sub(r"\s+/;", ";", field_text).strip()
            field_text = re.sub(r"\s+/\s*$", "", field_text).strip()
            if not field_text:
                field_text = f"{field.type.spelling} {field.spelling};"
            if not field_text.endswith(";"):
                field_text += ";"
            for line in field_text.splitlines():
                lines.append(f"  {line}" if line.strip() else line)
        lines.append(tail)
        return "\n".join(lines)


    def typedef_text(cur: C.Cursor) -> str:
        children = list(cur.get_children())
        for child in children:
            if child.kind == C.CursorKind.ENUM_DECL:
                return synthetic_enum(child, cur.spelling)
            if child.kind in {C.CursorKind.STRUCT_DECL, C.CursorKind.UNION_DECL}:
                return record_text(child, cur.spelling)
        return source_text_for_extent(cur.extent)


    def decl_name_for(cur: C.Cursor) -> str:
        return cur.spelling


    def collect_decl_maps(tu: C.TranslationUnit) -> tuple[
        dict[str, C.Cursor],
        dict[str, C.Cursor],
        dict[str, C.Cursor],
        dict[str, C.Cursor],
    ]:
        typedefs: dict[str, C.Cursor] = {}
        records: dict[str, C.Cursor] = {}
        enums: dict[str, C.Cursor] = {}
        functions: dict[str, C.Cursor] = {}
        # Only collect decls that live in our own source tree. System
        # headers (Xcode CLT, ~/CEdev/include, etc.) get parsed too because
        # the source headers transitively include them, but their decls are
        # the consumer's responsibility — emitting them ourselves would
        # collide with the toolchain's copies at compile time.
        repo_root_str = str(REPO_ROOT.resolve())
        def in_project(cur: C.Cursor) -> bool:
            if cur.location.file is None:
                return False
            try:
                return str(Path(cur.location.file.name).resolve()).startswith(repo_root_str)
            except OSError:
                return False

        for cur in tu.cursor.walk_preorder():
            if not in_project(cur):
                continue
            if cur.kind == C.CursorKind.TYPEDEF_DECL and cur.spelling:
                typedefs.setdefault(cur.spelling, cur)
            elif cur.kind in {C.CursorKind.STRUCT_DECL, C.CursorKind.UNION_DECL} and cur.spelling:
                if cur.spelling not in records or (
                    not records[cur.spelling].is_definition() and cur.is_definition()
                ):
                    records[cur.spelling] = cur
            elif cur.kind == C.CursorKind.ENUM_DECL and cur.spelling:
                if cur.spelling not in enums or (
                    not enums[cur.spelling].is_definition() and cur.is_definition()
                ):
                    enums[cur.spelling] = cur
            elif cur.kind == C.CursorKind.FUNCTION_DECL and cur.spelling:
                functions.setdefault(cur.spelling, cur)
        return typedefs, records, enums, functions


    def decl_precedes_first_function_in_source(
        cur: C.Cursor,
        functions: dict[str, C.Cursor],
    ) -> bool:
        source = cursor_file(cur)
        if source is None:
            return False
        first_function_line: int | None = None
        for fn in functions.values():
            if cursor_file(fn) != source:
                continue
            line = fn.extent.start.line
            first_function_line = line if first_function_line is None else min(first_function_line, line)
        if first_function_line is None:
            return True
        return cur.extent.start.line < first_function_line


    IDENT_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
    STRUCT_REF_RE = re.compile(r"\b(struct|union)\s+([A-Za-z_][A-Za-z0-9_]*)")
    ENUM_REF_RE = re.compile(r"\benum\s+([A-Za-z_][A-Za-z0-9_]*)")


    def referenced_identifiers(text: str) -> set[str]:
        return set(IDENT_RE.findall(text))


    def function_decl_text(cur: C.Cursor) -> str:
        text = source_text_for_extent(cur.extent)
        text = "\n".join(
            line for line in text.splitlines()
            if not line.lstrip().startswith("#")
        )
        # Cursor extents can include leading attributes/comments on some headers;
        # keep only the declaration tail beginning with the return type/name line.
        return re.sub(r"\n{3,}", "\n\n", text).strip()


    def doc_for_decl(header: Path, cur: C.Cursor) -> str:
        lines = header.read_text().splitlines(keepends=True)
        start = cur.extent.start.line
        if start <= 1:
            return ""
        i = start - 2
        while i >= 0 and lines[i].strip() == "":
            i -= 1
        if i < 0:
            return ""

        if lines[i].lstrip().startswith("///"):
            end = i
            while i >= 0 and lines[i].lstrip().startswith("///"):
                i -= 1
            return "".join(lines[i + 1:end + 1]).rstrip() + "\n"

        if lines[i].lstrip().startswith("/*") and lines[i].rstrip().endswith("*/"):
            end = i
            while i >= 0:
                if "/**" in lines[i] or "/*" in lines[i]:
                    return "".join(lines[i:end + 1]).rstrip() + "\n"
                i -= 1
        return ""


    def source_header_decls_before_functions(header: Path, tu: C.TranslationUnit) -> list[C.Cursor]:
        first_function_line: int | None = None
        decls: list[C.Cursor] = []
        for cur in tu.cursor.get_children():
            if not cursor_in_file(cur, header):
                continue
            if cur.kind == C.CursorKind.FUNCTION_DECL:
                line = cur.extent.start.line
                first_function_line = line if first_function_line is None else min(first_function_line, line)
            elif cur.kind in {
                C.CursorKind.TYPEDEF_DECL,
                C.CursorKind.ENUM_DECL,
                C.CursorKind.STRUCT_DECL,
                C.CursorKind.UNION_DECL,
            }:
                decls.append(cur)
        if first_function_line is None:
            return decls
        return [cur for cur in decls if cur.extent.start.line < first_function_line]


    def _live_macro_definitions(header: Path, tu: C.TranslationUnit) -> list[tuple[int, str, str]]:
        """Return [(line, name, full_text), ...] for every #define that
        libclang's preprocessor leaves *live* in `header` after evaluating
        lwipopts.h-controlled #if branches.

        Only the active branch survives — e.g. an #if/#elif chain that
        picks one of three LWIP_VERSION_STRING_SUFFIX values returns
        exactly one entry, not three.

        Function-style macros are skipped (their bodies often use
        project-specific helper macros that wouldn't compile standalone).
        Empty-value macros are skipped too (they're typically `#define
        PERF_START /* null */` style shims, not API surface).
        """
        out: list[tuple[int, str, str]] = []
        lines = header.read_text().splitlines()
        for cur in tu.cursor.walk_preorder():
            if cur.kind != C.CursorKind.MACRO_DEFINITION:
                continue
            if not cursor_in_file(cur, header):
                continue
            name = cur.spelling
            if not name or name.endswith("_h") or name.startswith("LWIP_HDR_"):
                continue
            line_no = cur.location.line
            if not (0 < line_no <= len(lines)):
                continue
            raw = lines[line_no - 1].strip()
            if not raw.startswith("#define"):
                continue
            # Function-style macros (e.g. `#define FOO(x) ...`) — skip.
            m = re.match(r"^#define\s+([A-Za-z_][A-Za-z0-9_]*)(\()?", raw)
            if not m or m.group(2):
                continue
            body = raw[m.end():].strip()
            if not body and name not in EMPTY_PUBLIC_MACROS:
                continue
            # Macros that span multiple lines via line-continuation \ —
            # gather the continuation lines too so the value is complete.
            text_lines = [raw]
            i = line_no
            while text_lines[-1].rstrip().endswith("\\") and i < len(lines):
                text_lines.append(lines[i].rstrip())
                i += 1
            out.append((line_no, name, "\n".join(text_lines)))
        out.sort(key=lambda t: t[0])
        return out


    def macro_lines_before_functions(header: Path, tu: C.TranslationUnit,
                                     prefixes: tuple[str, ...]) -> list[str]:
        """Live macros whose name starts with any of `prefixes`."""
        return [
            text for (_, name, text) in _live_macro_definitions(header, tu)
            if any(name.startswith(p) for p in prefixes)
        ]


    def public_macro_lines_before_functions(header: Path, tu: C.TranslationUnit) -> list[str]:
        """All live, non-function-style, non-empty `#define`s in `header`."""
        return [text for (_, _, text) in _live_macro_definitions(header, tu)]


    def should_emit_source_decl(group: str, header: Path, cur: C.Cursor) -> bool:
        header_rel = header.relative_to(REPO_ROOT).as_posix()
        if cur.spelling in FORCE_SOURCE_DECLS_BY_HEADER.get(header_rel, set()):
            return cursor_in_file(cur, header)
        if group == "cryptography":
            return cursor_in_file(cur, header)
        if group == "core" and header_rel in SOURCE_DECL_OWNER_HEADERS:
            return cursor_in_file(cur, header)
        if header == CONN_SRC:
            return cursor_in_file(cur, header)
        return False


    def add_decl_once(out: list[str], seen: set[str], key: str, text: str) -> None:
        text = text.strip()
        if not text or key in seen:
            return
        seen.add(key)
        tagged_typedef = re.match(r"\s*typedef\s+(struct|union|enum)\s+([A-Za-z_][A-Za-z0-9_]*)\b", text)
        if tagged_typedef:
            seen.add(f"{tagged_typedef.group(1)}:{tagged_typedef.group(2)}")
        for nested in re.finditer(r"\b(struct|union|enum)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{", text):
            seen.add(f"{nested.group(1)}:{nested.group(2)}")
        for enum_name in ENUM_REF_RE.findall(text):
            seen.add(f"enum:{enum_name}")
        for kind, record_name in STRUCT_REF_RE.findall(text):
            if text.startswith(f"{kind} {record_name}"):
                seen.add(f"{kind}:{record_name}")
        out.append(text)


    def declared_identifiers(text: str) -> set[str]:
        out: set[str] = set()
        tagged_typedef = re.match(r"\s*typedef\s+(struct|union|enum)\s+([A-Za-z_][A-Za-z0-9_]*)\b", text)
        if tagged_typedef:
            out.add(f"{tagged_typedef.group(1)}:{tagged_typedef.group(2)}")
        fnptr_match = re.search(r"\(\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)", text)
        if fnptr_match and text.lstrip().startswith("typedef"):
            out.add(fnptr_match.group(1))
        typedef_match = re.search(r"}\s*([A-Za-z_][A-Za-z0-9_]*)\s*;", text)
        if typedef_match and text.lstrip().startswith("typedef"):
            out.add(typedef_match.group(1))
        typedef_match = re.search(r"\btypedef\b.+\s+([A-Za-z_][A-Za-z0-9_]*)\s*;", text, re.DOTALL)
        if typedef_match:
            out.add(typedef_match.group(1))
        record_match = re.match(r"\s*(struct|union)\s+([A-Za-z_][A-Za-z0-9_]*)\b", text)
        if record_match:
            out.add(f"{record_match.group(1)}:{record_match.group(2)}")
        enum_match = re.match(r"\s*(?:typedef\s+)?enum\s+([A-Za-z_][A-Za-z0-9_]*)\b", text)
        if enum_match:
            out.add(enum_match.group(1))
            out.add(f"enum:{enum_match.group(1)}")
        return out


    def record_ref_needs_definition(text: str, kind: str, name: str) -> bool:
        pattern = re.compile(rf"\b{kind}\s+{re.escape(name)}\b\s*(\*?)")
        saw = False
        for match in pattern.finditer(text):
            saw = True
            if match.group(1) != "*":
                return True
        return not saw


    def order_dependency_decls(texts: list[str]) -> list[str]:
        ordered = list(texts)
        for _ in range(len(ordered) * 2):
            moved = False
            declared_by_index = [declared_identifiers(text) for text in ordered]
            for idx, text in enumerate(ordered):
                refs = referenced_identifiers(text)
                refs.update(f"enum:{name}" for name in ENUM_REF_RE.findall(text))
                refs.update(
                    f"{kind}:{name}" for kind, name in STRUCT_REF_RE.findall(text)
                    if record_ref_needs_definition(text, kind, name)
                )
                for later in range(idx + 1, len(ordered)):
                    if refs & declared_by_index[later]:
                        dep = ordered.pop(later)
                        ordered.insert(idx, dep)
                        moved = True
                        break
                if moved:
                    break
            if not moved:
                break
        return ordered


    def common_support_for(texts: list[str]) -> tuple[list[str], list[str]]:
        needed = set().union(*(referenced_identifiers(text) for text in texts))
        defined_macros = {
            match.group(1)
            for text in texts
            for match in re.finditer(r"^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\b", text, re.MULTILINE)
        }

        include_order = ["<stdbool.h>", "<stddef.h>", "<stdint.h>"]
        includes = {
            header
            for name, header in STD_HEADER_TYPES.items()
            if name in needed
        }

        macro_order = [
            "LWIP_PBUF_REF_T", "LWIP_PBUF_CUSTOM_DATA",
            "PACK_STRUCT_FIELD", "PACK_STRUCT_FLD_8", "PACK_STRUCT_FLD_S",
            "PACK_STRUCT_STRUCT", "PACK_STRUCT_BEGIN", "PACK_STRUCT_END",
            "PA",
        ]
        macro_snippets = [
            COMMON_MACRO_SNIPPETS[name] for name in macro_order
            if name in needed and name not in defined_macros
        ]

        return [f"#include {header}" for header in include_order if header in includes], macro_snippets


    def strip_preprocessor_conditionals(text: str) -> str:
        return "\n".join(
            line for line in text.splitlines()
            if not re.match(r"^\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b", line)
        )


    def synthetic_header_body(
        group: str,
        header: Path,
        symbols: set[str],
        out_path: Path,
        source_to_output_name: dict[Path, str] | None = None,
        support_only: bool = False,
    ) -> tuple[str, int]:
        tu = parse_header(header)
        if tu is None:
            return "", 0
        source_to_output_name = source_to_output_name or {}
        sibling_includes, included_sources = generated_sibling_includes(
            header, source_to_output_name
        )
        typedefs, records, enums, functions = collect_decl_maps(tu)
        typedef_enum_tags = {
            child.spelling
            for typedef in typedefs.values()
            for child in typedef.get_children()
            if child.kind == C.CursorKind.ENUM_DECL and child.spelling
        }
        typedef_record_tags = {
            child.spelling
            for typedef in typedefs.values()
            for child in typedef.get_children()
            if child.kind in {C.CursorKind.STRUCT_DECL, C.CursorKind.UNION_DECL} and child.spelling
        }
        selected = [
            functions[name] for name in symbols
            if name in functions and cursor_in_file(functions[name], header)
        ]
        selected.sort(key=lambda cur: (cur.extent.start.line, cur.spelling))
        if not selected and not support_only:
            return "", 0

        dependency_texts: list[str] = []
        source_decl_texts: list[str] = []
        seen_deps: set[str] = set()
        seen_source_deps: set[str] = set()
        dependency_scan: list[str] = []

        for line in public_macro_lines_before_functions(header, tu):
            if group == "socket" and not line.startswith("#define LWIP_SOCKET_"):
                continue
            add_decl_once(dependency_texts, seen_deps, line, line)

        header_rel = header.relative_to(REPO_ROOT).as_posix()
        if (
            support_only or
            group == "cryptography" or
            header_rel in SOURCE_DECL_OWNER_HEADERS or
            header_rel in FORCE_SOURCE_DECLS_BY_HEADER or
            header == CONN_SRC
        ):
            for cur in sorted(source_header_decls_before_functions(header, tu),
                              key=lambda c: (c.extent.start.line, c.spelling)):
                if cur.kind == C.CursorKind.ENUM_DECL and (
                    cur.spelling in typedefs or cur.spelling in typedef_enum_tags
                ):
                    continue
                if cur.kind in {C.CursorKind.STRUCT_DECL, C.CursorKind.UNION_DECL} and (
                    cur.spelling in typedef_record_tags
                ):
                    continue
                if support_only or should_emit_source_decl(group, header, cur):
                    if cur.kind == C.CursorKind.TYPEDEF_DECL:
                        text = typedef_text(cur)
                    elif cur.kind == C.CursorKind.ENUM_DECL:
                        text = synthetic_enum(cur)
                    elif cur.kind in {C.CursorKind.STRUCT_DECL, C.CursorKind.UNION_DECL}:
                        text = source_text_for_extent(cur.extent)
                    else:
                        text = source_text_for_extent(cur.extent)
                    add_decl_once(source_decl_texts, seen_source_deps, f"{cur.kind}:{cur.spelling}:{cur.extent.start.line}", text)
                    seen_deps.update(declared_identifiers(text))
                    if cur.spelling:
                        seen_deps.add(cur.spelling)
                        if cur.kind in {C.CursorKind.STRUCT_DECL, C.CursorKind.UNION_DECL}:
                            kind_name = "union" if cur.kind == C.CursorKind.UNION_DECL else "struct"
                            seen_deps.add(f"{kind_name}:{cur.spelling}")
                    for enum_name in ENUM_REF_RE.findall(text):
                        seen_deps.add(f"enum:{enum_name}")
                    dependency_scan.append(text)

            for forced_name in FORCE_SOURCE_DECLS_BY_HEADER.get(header_rel, set()):
                forced_cur = (
                    typedefs.get(forced_name) or
                    records.get(forced_name) or
                    enums.get(forced_name)
                )
                if forced_cur is None or not cursor_in_file(forced_cur, header):
                    continue
                if forced_cur.kind == C.CursorKind.TYPEDEF_DECL:
                    text = typedef_text(forced_cur)
                elif forced_cur.kind == C.CursorKind.ENUM_DECL:
                    text = synthetic_enum(forced_cur)
                elif forced_cur.kind in {C.CursorKind.STRUCT_DECL, C.CursorKind.UNION_DECL}:
                    text = source_text_for_extent(forced_cur.extent)
                else:
                    text = source_text_for_extent(forced_cur.extent)
                add_decl_once(source_decl_texts, seen_source_deps,
                              f"{forced_cur.kind}:{forced_cur.spelling}:{forced_cur.extent.start.line}", text)
                seen_deps.update(declared_identifiers(text))
                if forced_cur.spelling:
                    seen_deps.add(forced_cur.spelling)
                    if forced_cur.kind in {C.CursorKind.STRUCT_DECL, C.CursorKind.UNION_DECL}:
                        kind_name = "union" if forced_cur.kind == C.CursorKind.UNION_DECL else "struct"
                        seen_deps.add(f"{kind_name}:{forced_cur.spelling}")
                dependency_scan.append(text)

        function_blocks: list[str] = []
        for cur in selected:
            proto = function_decl_text(cur)
            dependency_scan.append(proto)
            doc = doc_for_decl(header, cur)
            function_blocks.append((doc + proto).strip())

        # Types whose definition lives in a toolchain-provided header
        # (e.g. usb_*) end up here as #include lines, rather than as
        # synthesized typedefs. The walker treats them as "satisfied" once
        # the include is recorded.
        external_includes: set[str] = set()

        needed = set().union(*(referenced_identifiers(text) for text in dependency_scan))
        changed = True
        while changed:
            changed = False
            for name in sorted(needed):
                if name in STD_HEADER_TYPES or name in seen_deps:
                    continue
                # External-type check: only treat as external when the name
                # is NOT defined by our own source tree (i.e. not in any of
                # the TU's typedef/record/enum maps). usb_configurator lives
                # in src/drivers/usb_ethernet.h, so it shouldn't fall into
                # the usbdrvce bucket even though it shares the usb_ prefix.
                ext = external_header_for(name)
                if (ext is not None and
                        name not in typedefs and
                        name not in records and
                        name not in enums):
                    external_includes.add(ext)
                    seen_deps.add(name)
                    continue
                fallback = OPAQUE_TYPEDEF_FALLBACKS.get(name)
                if fallback:
                    add_decl_once(dependency_texts, seen_deps, name, fallback)
                    continue
                cur = typedefs.get(name)
                if cur is not None:
                    dep_source = cursor_file(cur)
                    if dep_source in included_sources or add_generated_include_for_source(
                        sibling_includes, included_sources, header, dep_source, source_to_output_name
                    ):
                        seen_deps.add(name)
                        changed = True
                        continue
                    text = typedef_text(cur)
                    add_decl_once(dependency_texts, seen_deps, name, text)
                    before = len(needed)
                    needed.update(referenced_identifiers(text))
                    changed = changed or len(needed) != before
            for text in list(dependency_scan) + dependency_texts:
                for kind, name in STRUCT_REF_RE.findall(text):
                    key = f"{kind}:{name}"
                    if key in seen_deps:
                        continue
                    ext = external_header_for(name)
                    if (ext is not None and
                            name not in records and
                            name not in typedefs):
                        external_includes.add(ext)
                        seen_deps.add(key)
                        seen_deps.add(name)
                        changed = True
                        continue
                    cur = records.get(name)
                    if (
                        cur is not None and
                        name not in OPAQUE_STRUCTS and
                        cur.semantic_parent.kind == C.CursorKind.TRANSLATION_UNIT
                    ):
                        dep_source = cursor_file(cur)
                        if dep_source in included_sources or add_generated_include_for_source(
                            sibling_includes, included_sources, header, dep_source, source_to_output_name
                        ):
                            seen_deps.add(key)
                            seen_deps.add(name)
                            changed = True
                            continue
                        dep_text = record_text(cur)
                        add_decl_once(dependency_texts, seen_deps, key, dep_text)
                        before = len(needed)
                        needed.update(referenced_identifiers(dep_text))
                        changed = changed or len(needed) != before
                    else:
                        add_decl_once(dependency_texts, seen_deps, key, f"{kind} {name};")
                    changed = True
                for name in ENUM_REF_RE.findall(text):
                    key = f"enum:{name}"
                    if key in seen_deps:
                        continue
                    cur = enums.get(name)
                    if cur is not None:
                        dep_source = cursor_file(cur)
                        if dep_source in included_sources or add_generated_include_for_source(
                            sibling_includes, included_sources, header, dep_source, source_to_output_name
                        ):
                            seen_deps.add(key)
                            seen_deps.add(name)
                            changed = True
                            continue
                        add_decl_once(dependency_texts, seen_deps, key, synthetic_enum(cur))
                    else:
                        add_decl_once(dependency_texts, seen_deps, key, f"enum {name};")
                    changed = True

        if support_only:
            dependency_texts = dependency_texts + source_decl_texts
        elif group == "socket":
            dependency_texts = order_dependency_decls(dependency_texts) + source_decl_texts
        else:
            dependency_texts = order_dependency_decls(dependency_texts + source_decl_texts)

        body_texts = dependency_texts + function_blocks
        if "<usbdrvce.h>" in external_includes:
            body_texts.append("uint24_t")
        std_includes, macro_snippets = common_support_for(body_texts)

        parts = []
        if std_includes:
            parts.append("\n".join(std_includes))
        if sibling_includes:
            parts.append("\n".join(sibling_includes))
        if external_includes:
            parts.append("\n".join(f"#include {inc}" for inc in sorted(external_includes)))
        if macro_snippets:
            parts.append("\n\n".join(macro_snippets))
        if dependency_texts:
            parts.append("\n\n".join(dependency_texts))
        parts.append("\n\n".join(function_blocks))
        body = "\n\n".join(parts).rstrip() + "\n"
        return body, len(selected)


    # ---------------------------------------------------------------------
    # Optional AI docstring rewrite
    # ---------------------------------------------------------------------

    def ai_docstrings_enabled() -> bool:
        return os.environ.get("LWIP_AI_DOCSTRINGS", "").lower() in {"1", "true", "yes"}


    def ai_model_name() -> str:
        return os.environ.get("LWIP_AI_DOCSTRINGS_MODEL", "qwen2.5-coder:7b")


    def require_ollama() -> None:
        """Require Ollama when the optional AI doc pass is enabled."""
        if shutil.which("ollama"):
            return
        if platform.system() == "Darwin":
            print(
                "ERROR: LWIP_AI_DOCSTRINGS=1 requires Ollama, but `ollama` was "
                "not found.\n"
                "Install it on macOS with one of:\n"
                "  brew install ollama\n"
                "  https://ollama.com/download\n"
                "Then start Ollama and rerun make.",
                file=sys.stderr,
            )
        else:
            print(
                "ERROR: LWIP_AI_DOCSTRINGS=1 requires Ollama, but `ollama` was "
                "not found. Install Ollama from https://ollama.com/download "
                "and rerun make.",
                file=sys.stderr,
            )
        sys.exit(1)


    def ensure_ollama_model(model: str) -> bool:
        require_ollama()
        shown = subprocess.run(["ollama", "show", model],
                               capture_output=True, text=True)
        if shown.returncode == 0:
            return True
        print(f"  pulling Ollama model {model} for AI docs", file=sys.stderr)
        pulled = subprocess.run(["ollama", "pull", model])
        return pulled.returncode == 0


    def remove_code_fences(text: str) -> str:
        text = text.strip()
        if text.startswith("```"):
            lines = text.splitlines()
            if lines and lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            return "\n".join(lines).strip()
        return text


    def parse_docstring_json(text: str) -> dict[str, str]:
        text = remove_code_fences(text)
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            start = text.find("{")
            end = text.rfind("}")
            if start < 0 or end < start:
                raise
            data = json.loads(text[start:end + 1])
        if not isinstance(data, dict):
            raise ValueError("AI docstring response must be a JSON object")
        out: dict[str, str] = {}
        for key, value in data.items():
            if isinstance(key, str) and isinstance(value, str):
                block = value.strip()
                if block.startswith("/**") and block.endswith("*/"):
                    out[key] = block + "\n"
        return out


    def parse_docstring_markers(text: str, function_names: list[str]) -> dict[str, str]:
        """Parse model output in the marker format:

            @@DOC function_name
            /** ... */
            @@END

        This is more reliable than JSON for multiline C comments from local
        models, which often emit raw newlines inside string values.
        """
        allowed = set(function_names)
        out: dict[str, str] = {}
        pattern = re.compile(
            r"^@@DOC\s+([A-Za-z_][A-Za-z0-9_]*)\s*\n(.*?)^@@END\s*$",
            re.MULTILINE | re.DOTALL,
        )
        for match in pattern.finditer(remove_code_fences(text)):
            name = match.group(1)
            block = match.group(2).strip()
            if name not in allowed:
                continue
            if block.startswith("/**") and block.endswith("*/"):
                out[name] = block + "\n"
        return out


    def ollama_rewrite_docstrings(header_text: str, function_names: list[str]) -> dict[str, str]:
        model = ai_model_name()
        if not ensure_ollama_model(model):
            return {}

        prompt = (
            "Rewrite the Doxygen comments for the listed public C functions so "
            "they are simpler, clearer, and accurate. Use only facts present in "
            "the header. Do not invent behavior. Keep warnings or notes only when "
            "they matter for ownership, lifetime, blocking/asynchronous behavior, "
            "initialization, state, or security.\n\n"
            "Return only this marker format, repeated once per function. Do not "
            "wrap it in markdown or JSON:\n"
            "@@DOC function_name\n"
            "/**\n"
            " * @brief ...\n"
            " */\n"
            "@@END\n\n"
            "Each block must start with /** and end with */. Include @brief, "
            "@param entries for each parameter, and @return for non-void functions "
            "when the return meaning is clear.\n\n"
            f"Functions: {', '.join(function_names)}\n\n"
            "Header:\n"
            f"{header_text}"
        )
        res = subprocess.run(
            ["ollama", "run", model],
            input=prompt,
            capture_output=True,
            text=True,
            timeout=int(os.environ.get("LWIP_AI_DOCSTRINGS_TIMEOUT", "180")),
        )
        if res.returncode != 0:
            print(f"  warning: Ollama docstring rewrite failed: {res.stderr.strip()}",
                  file=sys.stderr)
            return {}
        docs = parse_docstring_markers(res.stdout, function_names)
        if docs:
            return docs
        try:
            return parse_docstring_json(res.stdout)
        except (json.JSONDecodeError, ValueError) as exc:
            print(f"  warning: could not parse Ollama docstring response: {exc}",
                  file=sys.stderr)
            return {}


    def apply_docstring_blocks(header_text: str, docs: dict[str, str]) -> str:
        if not docs:
            return header_text
        lines = header_text.splitlines(keepends=True)
        decls = declared_functions_in_text(header_text)
        replacements: list[tuple[int, int, str]] = []
        for name, (start, _end) in decls.items():
            block = docs.get(name)
            if not block:
                continue
            doc_start = find_doc_block_start(lines, start)
            if doc_start is None:
                continue
            replacements.append((doc_start, start - 1, block))

        for start, end, block in sorted(replacements, reverse=True):
            lines[start - 1:end] = [block]
        return "".join(lines)


    def declared_functions_in_text(header_text: str) -> dict[str, tuple[int, int]]:
        """Parse generated header text through libclang using a cache file."""
        tmp = DOCSTRING_CACHE_DIR / "_parse_header.h"
        DOCSTRING_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        tmp.write_text(header_text)
        return declared_functions_in(tmp)


    def release_tree_digest() -> str:
        digest = hashlib.sha256()
        paths = [OUT_CORE_INDEX, OUT_CRYPTO_INDEX]
        paths.extend(sorted(OUT_DIR.rglob("*")))
        for path in paths:
            if not path.is_file():
                continue
            rel = path.relative_to(OUT_ROOT).as_posix()
            digest.update(rel.encode("utf-8"))
            digest.update(b"\0")
            digest.update(path.read_bytes())
            digest.update(b"\0")
        return digest.hexdigest()


    def ai_docstring_state_matches(tree_hash: str, model: str) -> bool:
        if not DOCSTRING_STATE_FILE.is_file():
            return False
        try:
            state = json.loads(DOCSTRING_STATE_FILE.read_text())
        except (OSError, json.JSONDecodeError):
            return False
        return (
            state.get("tree_hash") == tree_hash and
            state.get("model") == model and
            state.get("prompt_version") == DOCSTRING_PROMPT_VERSION
        )


    def write_ai_docstring_state(tree_hash: str, model: str) -> None:
        DOCSTRING_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        DOCSTRING_STATE_FILE.write_text(json.dumps({
            "tree_hash": tree_hash,
            "model": model,
            "prompt_version": DOCSTRING_PROMPT_VERSION,
        }, indent=2, sort_keys=True))


    def maybe_rewrite_docstrings(header: Path, body: str, exports: set[str]) -> str:
        decls = declared_functions_in_text(body)
        function_names = [name for name in decls if name in exports]
        if not function_names:
            return body

        model = ai_model_name()
        digest = hashlib.sha256(
            ("\n".join([
                str(DOCSTRING_PROMPT_VERSION),
                model,
                header.relative_to(REPO_ROOT).as_posix(),
                body,
            ])).encode("utf-8")
        ).hexdigest()
        cache_path = DOCSTRING_CACHE_DIR / f"{digest}.json"
        if cache_path.is_file():
            try:
                return apply_docstring_blocks(body, json.loads(cache_path.read_text()))
            except (OSError, json.JSONDecodeError):
                pass

        docs = ollama_rewrite_docstrings(body, function_names)
        if not docs:
            return body
        cache_path.write_text(json.dumps(docs, indent=2, sort_keys=True))
        print(f"  AI docs refreshed: {header.relative_to(REPO_ROOT)}",
              file=sys.stderr)
        return apply_docstring_blocks(body, docs)


    # ---------------------------------------------------------------------
    # Header guard rewriting
    # ---------------------------------------------------------------------

    def derive_guard(out_path: Path) -> str:
        """LWIP_PUBLIC_<relpath>_H, deterministic from the output location.
        Ensures no clashes with the original header guards."""
        rel = out_path.relative_to(OUT_ROOT).as_posix()
        base = re.sub(r"[^A-Za-z0-9]", "_", rel.upper())
        if not base.endswith("_H"):
            base += "_H"
        return f"LWIP_PUBLIC_{base}"


    def rewrite_header_guard(text: str, new_guard: str) -> str:
        """Rename the standard `#ifndef X / #define X / .../ #endif` triplet.
        No-op if no guard is detected."""
        m = re.search(
            r"^\s*#\s*ifndef\s+(\w+)\s*\n\s*#\s*define\s+\1\s*\n",
            text,
            re.MULTILINE,
        )
        if not m:
            return text
        old = m.group(1)
        text = re.sub(rf"#\s*ifndef\s+{old}\b", f"#ifndef {new_guard}", text, count=1)
        text = re.sub(rf"#\s*define\s+{old}\b", f"#define {new_guard}", text, count=1)
        text = re.sub(
            rf"#\s*endif\s*/\*\s*{old}\s*\*/",
            f"#endif /* {new_guard} */",
            text,
        )
        return text


    def source_banner(header: Path) -> str:
        """Return the leading source-file comment block, if present."""
        try:
            text = header.read_text()
        except OSError:
            return ""
        pos = 0
        while pos < len(text) and text[pos] in " \t\r\n":
            pos += 1
        if text.startswith("/*", pos):
            end = text.find("*/", pos + 2)
            if end >= 0:
                return text[pos:end + 2].rstrip() + "\n\n"
        if text.startswith("//", pos):
            lines = text[pos:].splitlines()
            out: list[str] = []
            for line in lines:
                if not line.lstrip().startswith("//"):
                    break
                out.append(line)
            if out:
                return "\n".join(out).rstrip() + "\n\n"
        return ""


    def write_with_guard(path: Path, body: str, banner: str = "") -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        guard = derive_guard(path)
        text = (
            f"#ifndef {guard}\n"
            f"#define {guard}\n\n"
            "#ifdef __cplusplus\n"
            'extern "C" {\n'
            "#endif\n\n"
            f"{body.rstrip()}\n\n"
            "#ifdef __cplusplus\n"
            "}\n"
            "#endif\n\n"
            f"#endif /* {guard} */\n"
        )
        path.write_text(banner + text)


    # ---------------------------------------------------------------------
    # Output emitters
    # ---------------------------------------------------------------------

    def output_group_for(row: dict[str, str]) -> str:
        if row["category"] == "socket":
            return "socket"
        if row["category"] == "cryptography":
            return "cryptography"
        return "core"


    def header_banner(group: str, out_name: str, header: Path) -> str:
        return source_banner(header)


    def grouped_header_name(source_header: Path, group_headers: list[Path]) -> str:
        """Return the filename to use under generated lwip/<group>/.
        If a group has basename clashes, prefix with the source parent."""
        basename = source_header.name
        if sum(1 for hp in group_headers if hp.name == basename) == 1:
            return basename
        return f"{source_header.parent.name}_{basename}"


    def write_group_index(group: str, names: list[str], source_headers: list[Path]) -> None:
        out_path = OUT_CORE_INDEX if group == "core" else OUT_CRYPTO_INDEX
        guard = derive_guard(out_path)
        lines = [
            f"#ifndef {guard}",
            f"#define {guard}",
            "",
        ]
        if group == "core":
            lines.extend([
                "#include <stdbool.h>",
                "#include <stdint.h>",
                "#include <stdlib.h>",
                "",
            ])
        for name in names:
            lines.append(f'#include "lwip/{group}/{name}"')
        if group == "core" and _CONN_BODY:
            lines.extend([
                "",
                "/* ================================================================",
                " * lwIP-CE socket API — the preferred high-level surface.",
                " * Inlined here (rather than a buried subheader) because this is",
                " * the API most apps should use: lwip_socket_create / _connect /",
                " * _write / _read / _close. The core includes above expose",
                " * the lower-level lwIP primitives for advanced use.",
                " * ================================================================ */",
                "",
                _CONN_BODY.rstrip(),
            ])
        if group == "core":
            lines.extend([
                "",
                "#ifdef __cplusplus",
                'extern "C" {',
                "#endif",
                "",
                "/* Bring up the dynamically-loaded lwIP runtime: patches export",
                " * trampolines and brings up stack memory/timers/RNG (no network;",
                " * see lwip_network_up() for that). Returns true on success.",
                " * On failure, call lwip_get_start_errstring() for a human-readable",
                " * reason, and lwip_is_newer() to check whether the resident app",
                " * has more exports than this build expected (informational only,",
                " * not itself a failure). */",
                "bool lwip_start_with_crt(void *malloc_fn, void *free_fn, void *realloc_fn);",
                "char *lwip_get_start_errstring(void);",
                "bool lwip_is_newer(void);",
                "",
                "#define lwip_start() \\",
                "    lwip_start_with_crt(malloc, free, realloc)",
                "",
                "#ifdef __cplusplus",
                "}",
                "#endif",
            ])
        lines.extend(["", f"#endif /* {guard} */", ""])
        out_path.write_text("\n".join(lines))


    def emit_category_headers(manifest: list[dict[str, str]], exports: set[str]) -> tuple[int, int]:
        """Emit release headers from the manifest allowlist.

        Layout is intentionally small:
          - lwip.h leads with the pruned src/lwIP.h socket API (inlined), then
            includes every other lwIP/public core header.
          - cryptography.h includes lwip/cryptography/*.h (TLS/crypto headers).
        """
        by_group_source: dict[str, dict[str, list[str]]] = {}
        missing_symbols: list[str] = []
        for row in manifest:
            symbol = row["symbol"]
            if symbol not in exports:
                missing_symbols.append(symbol)
                continue
            group = output_group_for(row)
            by_group_source.setdefault(group, {}).setdefault(
                row["source_header"], []
            ).append(symbol)

        if missing_symbols:
            print("  manifest symbols skipped by current build:", file=sys.stderr)
            for symbol in missing_symbols:
                print(f"    {symbol}", file=sys.stderr)

        header_count = 0
        function_count = 0
        release_source_map: dict[str, str] = {}
        macro_file = build_macro_file()
        macro_defs = parse_build_macro_definitions(macro_file)

        nonlocal _CONN_BODY
        if "socket" in by_group_source:
            source_map = by_group_source.pop("socket")
            symbols = set(source_map.get(CONN_SRC.relative_to(REPO_ROOT).as_posix(), []))
            if symbols:
                # Inlined into lwip.h at OUT_ROOT, so cross-references resolve as
                # lwip/core/<name> (the socket API pulls in err/ip_addr/pbuf and the
                # unified debug types from logging.h, all emitted into core).
                conn_source_to_output = {
                    (SRC_DIR / "include" / "lwip" / "err.h").resolve(): "lwip/core/err.h",
                    (SRC_DIR / "include" / "lwip" / "ip_addr.h").resolve(): "lwip/core/ip_addr.h",
                    (SRC_DIR / "include" / "lwip" / "pbuf.h").resolve(): "lwip/core/pbuf.h",
                    (SRC_DIR / "include" / "lwip" / "logging.h").resolve(): "lwip/core/logging.h",
                }
                body, emitted_functions = pruned_copy_header_body(
                    CONN_SRC,
                    symbols,
                    conn_source_to_output,
                    macro_file,
                    macro_defs,
                )
                body = body.replace("@file lwIP.h", "@file lwip.h", 1)
                _CONN_BODY = body
                header_count += 1
                function_count += emitted_functions
                print("  socket API (inlined into lwip.h)", file=sys.stderr)

        for group in sorted(by_group_source):
            source_map = by_group_source[group]
            group_dir = OUT_DIR / group
            group_dir.mkdir(parents=True, exist_ok=True)

            manifest_source_headers = [
                REPO_ROOT / rel
                for rel in source_map
                if (REPO_ROOT / rel).is_file()
            ]
            source_headers = source_dependency_closure(manifest_source_headers)
            missing_headers = sorted(
                rel for rel in source_map if not (REPO_ROOT / rel).is_file()
            )
            for rel in missing_headers:
                print(f"  warning: manifest header not found: {rel}",
                      file=sys.stderr)

            source_to_output_name = {
                hp.resolve(): ""
                for hp in source_headers
            }
            manifest_sources = {hp.resolve() for hp in manifest_source_headers}
            manifest_basename_counts: dict[str, int] = {}
            all_basename_counts: dict[str, int] = {}
            for hp in manifest_source_headers:
                manifest_basename_counts[hp.name] = manifest_basename_counts.get(hp.name, 0) + 1
            for hp in source_headers:
                all_basename_counts[hp.name] = all_basename_counts.get(hp.name, 0) + 1

            for hp in source_headers:
                resolved = hp.resolve()
                if resolved in manifest_sources and manifest_basename_counts.get(hp.name, 0) == 1:
                    source_to_output_name[resolved] = hp.name
                elif all_basename_counts.get(hp.name, 0) == 1:
                    source_to_output_name[resolved] = hp.name
                else:
                    source_to_output_name[resolved] = f"{hp.parent.name}_{hp.name}"

            index_names: list[str] = []
            for hp in source_headers:
                rel = hp.relative_to(REPO_ROOT).as_posix()
                if rel in SKIP_HEADERS:
                    print(f"  warning: manifest header is skipped: {rel}",
                          file=sys.stderr)
                    continue

                symbols = set(source_map.get(rel, []))
                out_name = source_to_output_name[hp.resolve()]
                out_path = group_dir / out_name
                body, emitted_functions = pruned_copy_header_body(
                    hp,
                    symbols,
                    source_to_output_name,
                    macro_file,
                    macro_defs,
                )
                is_support_header = rel not in source_map
                if not body.strip() and not is_support_header:
                    continue

                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(body)
                release_source_map[out_path.relative_to(OUT_DIR).as_posix()] = rel
                index_names.append(out_name)
                if emitted_functions > 0:
                    function_count += emitted_functions
                header_count += 1

            index_names = sorted({
                path.name for path in group_dir.glob("*.h")
                if path.name not in UMBRELLA_EXCLUDE_BASENAMES
            })
            write_group_index(group, index_names, [])
            print(f"  {group}/ {len(index_names)} headers", file=sys.stderr)

        DOCSTRING_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        RELEASE_SOURCE_MAP_FILE.write_text(json.dumps(release_source_map, indent=2, sort_keys=True))
        return header_count, function_count


    def apply_ai_docstrings_to_release(manifest: list[dict[str, str]], exports: set[str]) -> None:
        if not ai_docstrings_enabled():
            return

        model = ai_model_name()
        before_hash = release_tree_digest()
        if ai_docstring_state_matches(before_hash, model):
            print("==> AI docs unchanged; release/lwip content hash matched cache",
                  file=sys.stderr)
            return

        require_ollama()
        if not ensure_ollama_model(model):
            print(f"ERROR: unable to prepare Ollama model {model}", file=sys.stderr)
            sys.exit(1)

        source_to_symbols: dict[str, set[str]] = {}
        for row in manifest:
            if row["symbol"] in exports:
                source_to_symbols.setdefault(row["source_header"], set()).add(row["symbol"])
        try:
            release_source_map = json.loads(RELEASE_SOURCE_MAP_FILE.read_text())
        except (OSError, json.JSONDecodeError):
            release_source_map = {}

        rewritten = 0
        for path in sorted(OUT_DIR.rglob("*.h")):
            text = path.read_text()
            source_rel = release_source_map.get(path.relative_to(OUT_DIR).as_posix())
            if not source_rel:
                continue
            updated = maybe_rewrite_docstrings(REPO_ROOT / source_rel, text, source_to_symbols[source_rel])
            if updated != text:
                path.write_text(updated)
                rewritten += 1

        after_hash = release_tree_digest()
        write_ai_docstring_state(after_hash, model)
        print(f"==> AI docs refreshed for {rewritten} headers", file=sys.stderr)


    def test_build_generated_headers() -> bool:
        compiler = shutil.which("clang") or shutil.which("cc")
        if not compiler:
            print("  warning: no clang/cc found; skipped release header syntax test",
                  file=sys.stderr)
            return True

        # Toolchain-provided headers referenced from generated files (usbdrvce.h,
        # tice.h, etc.) live under $CEDEV/include. Add it as a system include path
        # so external includes resolve when we syntax-check.
        if not CEDEV_INCLUDE.is_dir():
            print(f"  warning: {CEDEV_INCLUDE} missing; skipped release header syntax test",
                  file=sys.stderr)
            return True

        public_headers = {OUT_CORE_INDEX, OUT_CRYPTO_INDEX}
        for aggregate in [OUT_CORE_INDEX, OUT_CRYPTO_INDEX]:
            if not aggregate.is_file():
                continue
            for match in re.finditer(r'^\s*#\s*include\s+"([^"]+)"', aggregate.read_text(), re.MULTILINE):
                public_headers.add((aggregate.parent / match.group(1)).resolve())

        failures: list[tuple[Path, str]] = []
        for header in sorted(path for path in public_headers if path.is_file()):
            # The aggregate umbrellas pull in their subheaders via
            # `#include "lwip/<group>/..."`, which resolves relative to OUT_ROOT.
            # Use an absolute include path and -I OUT_ROOT so the syntax test
            # works regardless of where the release tree is staged.
            include = str(header)
            res = subprocess.run(
                [
                    compiler,
                    "-fsyntax-only",
                    "-std=c99",
                    "-Wall",
                    "-Wno-unused-function",
                    "-Wno-unused-parameter",
                    "-Wno-implicit-function-declaration",
                    "-isystem", str(CEDEV_INCLUDE),
                    "-I", str(OUT_ROOT),
                    "-x", "c",
                    "-",
                ],
                capture_output=True,
                text=True,
                cwd=str(OUT_ROOT),
                input=(
                    "typedef unsigned int uint24_t;\n"
                    "typedef int int24_t;\n"
                    f'#include "{include}"\n'
                ),
                timeout=20,
            )
            if res.returncode != 0:
                failures.append((header, res.stderr.strip()))

        if failures:
            print("ERROR: generated release headers failed syntax test:", file=sys.stderr)
            for header, stderr in failures[:10]:
                try:
                    label = header.relative_to(OUT_ROOT).as_posix()
                except ValueError:
                    label = str(header)
                print(f"  {label}", file=sys.stderr)
                for line in stderr.splitlines()[:8]:
                    print(f"    {line}", file=sys.stderr)
            if len(failures) > 10:
                print(f"  ... {len(failures) - 10} more failures", file=sys.stderr)
            return False

        print("==> release header syntax test passed", file=sys.stderr)
        return True


    # ---------------------------------------------------------------------
    # main
    # ---------------------------------------------------------------------

    def main() -> int:
        PRELUDE_PATH.write_text(PRELUDE)

        if not FUNCTABLE_S.is_file():
            print(f"ERROR: {FUNCTABLE_S} not found — run `make functable` first",
                  file=sys.stderr)
            return 1

        exports = load_exports()
        print(f"==> loaded {len(exports)} exports from "
              f"{FUNCTABLE_S.relative_to(REPO_ROOT)}", file=sys.stderr)
        manifest = load_public_api_manifest()
        print(f"==> loaded {len(manifest)} manifest rows from "
              f"{PUBLIC_API_MANIFEST.relative_to(REPO_ROOT)}", file=sys.stderr)

        if OUT_DIR.exists():
            shutil.rmtree(OUT_DIR)
        for aggregate in (OUT_CRYPTO_INDEX,):  # OUT_CORE_INDEX (lwip.h) is hand-maintained
            if aggregate.exists():
                aggregate.unlink()
        OUT_DIR.mkdir(parents=True)

        try:
            out_label = OUT_ROOT.relative_to(REPO_ROOT).as_posix()
        except ValueError:
            out_label = str(OUT_ROOT)
        print(f"==> writing {out_label}/", file=sys.stderr)
        n_headers, n_functions = emit_category_headers(manifest, exports)
        apply_ai_docstrings_to_release(manifest, exports)
        if not test_build_generated_headers():
            return 1
        print(f"  headers         {n_headers}", file=sys.stderr)
        print(f"  functions       {n_functions}", file=sys.stderr)
        print(f"==> done", file=sys.stderr)
        return 0

    old_argv = sys.argv[:]
    try:
        sys.argv = ["parse_manifest.py --headers", *(argv or [])]
        return main()
    finally:
        sys.argv = old_argv


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate lwIP release artifacts from public_api_manifest.csv.")
    parser.add_argument(
        "--append", action="store_true",
        help="Append-only mode for function/export table generation.")
    parser.add_argument(
        "--functable", action="store_true",
        help="Generate src/functable.s and the libload stub.")
    parser.add_argument(
        "--headers", action="store_true",
        help="Generate the curated release header tree.")
    parser.add_argument("--map", dest="map_path", metavar="lwIP.map", default=None,
                        help="Deprecated compatibility option forwarded to functable mode.")
    args = parser.parse_args()

    do_functable = args.functable
    do_headers = args.headers
    if not do_functable and not do_headers:
        do_functable = True
        do_headers = True

    if do_functable:
        functable_args: list[str] = []
        if args.append:
            functable_args.append("--append")
        if args.map_path:
            functable_args.extend(["--map", args.map_path])
        rc = run_functable(functable_args)
        if rc != 0:
            return rc

    if do_headers:
        rc = run_headers([])
        if rc != 0:
            return rc

    return 0


if __name__ == "__main__":
    sys.exit(main())

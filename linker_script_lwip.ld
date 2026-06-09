MEMORY
{
    prgm : ORIGIN = LOAD_ADDR, LENGTH = 0x400000
    bss  : ORIGIN = BSSHEAP_LOW, LENGTH = BSSHEAP_HIGH - BSSHEAP_LOW
}

SECTIONS
{
    . = LOAD_ADDR;

    .header :
    {
        KEEP (*(.header))
        PROVIDE_HIDDEN (___icon_optional = .);
        KEEP (*(.header.icon))
    } >prgm

    .init :
    {
        *(.init)
    } >prgm

    .text :
    {
        *(.text.unlikely .text.*_unlikely .text.unlikely.*)
        *(.text.exit .text.exit.*)
        *(.text.startup .text.startup.*)
        *(.text.hot .text.hot.*)
        *(SORT(.text.sorted.*))
        *(.text .stub .text.* .gnu.linkonce.t.*)
        *(.gnu.warning)
    } >prgm

    .rodata :
    {
        /* The libload export table (src/functable.s) lives in its own
         * .fn_exports section and is referenced only by the external
         * libload bootstrap at runtime, so KEEP it from --gc-sections;
         * its "LWIPTB" magic is the signal the bootstrap locates via
         * __lwip_fn_table_off. */
        KEEP(*(.fn_exports))
        *(.rodata .rodata.* .gnu.linkonce.r.*)
    } >prgm

    .init_array :
    {
        PROVIDE_HIDDEN (__init_array_start = .);
        KEEP (*(.preinit_array))
        KEEP (*(SORT_BY_INIT_PRIORITY(.init_array.*)))
        KEEP (*(.init_array))
        PROVIDE_HIDDEN (__init_array_end = .);
    } >prgm

    .fini_array :
    {
        PROVIDE_HIDDEN (__fini_array_start = .);
        KEEP (*(SORT_BY_INIT_PRIORITY(.fini_array.*)))
        KEEP (*(.fini_array))
        PROVIDE_HIDDEN (__fini_array_end = .);
    } >prgm

    .data :
    {
        ___data_vma = .;
        ___data_lma = . + (LOADADDR(.data) - ADDR(.data));
        *(.data .data.* .gnu.linkonce.d.*)
        SORT(CONSTRUCTORS)
        *(.data1)
        ___data_vma_end = .;
    } >bss AT>prgm
    ___data_len = ___data_vma_end - ___data_vma;

    .bss (NOLOAD) :
    {
        ___bss_low = .;
        *(.dynbss)
        *(.bss .bss.* .gnu.linkonce.b.*)
        *(COMMON)
        ___bss_high = .;
    } >bss :NONE
    ___bss_len = ___bss_high - ___bss_low;

    /* C-visible aliases for the .bss/.data bounds. crt0 (assembly) reads
     * the three-underscore symbols directly, but lwip_init_runtime_internal
     * is C: the compiler prepends a leading underscore, so its `extern
     * ___bss_low` resolves to the object symbol ____bss_low (four). Provide
     * those four-underscore names as aliases. This only matters because the
     * function is now retained (the export table references it); when the
     * table was being garbage-collected, lwip_init_runtime_internal and its
     * undefined references were stripped and the mismatch stayed hidden. */
    PROVIDE(____bss_low  = ___bss_low);
    PROVIDE(____bss_len  = ___bss_len);
    PROVIDE(____data_vma = ___data_vma);
    PROVIDE(____data_lma = ___data_lma);
    PROVIDE(____data_len = ___data_len);

    /* X25519 scratch variables. Uninitialized (NOLOAD) bss, page-aligned
     * so the hot loop can address them by patching only the low byte of
     * each address (R_Z80_BYTE0 relocations against a fixed page). Kept in
     * the bss region; must be placed before the dot jumps to BSSHEAP_HIGH
     * below. See src/tls/contrib/x25519/src/x25519.s. */
    .x25519_data (NOLOAD) :
    {
        . = ALIGN(0x100) + 0xC0;
        KEEP(*(.x25519.data))
        KEEP(*(.x25519.data.*))
        _x25519_data_end = .;
    } >bss

    ASSERT(. <= BSSHEAP_HIGH, "Error: BSS exceed BSSHEAP_HIGH limit")

    ___heap_low = .;
    . = BSSHEAP_HIGH;
    ___heap_high = .;

    /* Phase-2 build hand-off: the libload library bootstrap
     * (release/lwip.s, built separately) needs the runtime offset from
     * the app's loaded base to _fn_exports_table. The phase-2 build
     * step greps this symbol from bin/lwIP.map and injects it as
     * `__lwip_fn_table_off` into the bootstrap source. Applications link
     * at LOAD_ADDR = 0, so a symbol's link-time address already is its
     * offset from the app base — no base subtraction needed. */
    PROVIDE(__lwip_fn_table_off = _fn_exports_table);

    /* Safe-RAM scratch overlay (0xE30800, ti.cursorImage).
     *
     * Two consumers share this address window, never live at the same
     * instant — it is deliberately reused as quick scratch:
     *   - .x25519.reloc : the X25519 hot loop, copied here at the start of
     *     each call (it has a load image in prgm) and run at this VMA.
     *   - .saferam.rng  : the RNG entropy/SHA scratch. No load image — it
     *     is written in place; this member only reserves the VMA span so
     *     the linker knows the window size and flags a collision if either
     *     consumer outgrows it.
     *
     * OVERLAY assigns both members the same VMA (0xE30800) and distinct
     * LMAs. ld auto-creates __load_start_<sec>/__load_stop_<sec>; the
     * PROVIDE aliases below keep the existing asm symbol names working so
     * x25519.s and the RNG code need no edits beyond sourcing the base. */
    OVERLAY 0xE30800 : AT ( LOADADDR(.data) + SIZEOF(.data) )
    {
        .x25519.reloc
        {
            _x25519_reloc_run_start = .;
            KEEP(*(.x25519.reloc))
            KEEP(*(.x25519.reloc.*))
            _x25519_reloc_run_end = .;
        }
        .saferam.rng
        {
            _sprng_entropy_pool = .;
            . = . + 520;   /* total RNG scratch: see virtuals.inc */
        }
    }

    /* Back-compat aliases for the X25519 copy loop in x25519.s. */
    _x25519_reloc_load_start = LOADADDR(.x25519.reloc);
    _x25519_reloc_len        = SIZEOF(.x25519.reloc);

    /* Guard: neither consumer may outgrow the shared window. */
    ASSERT(SIZEOF(.x25519.reloc) <= 0x800,
           "Error: .x25519.reloc exceeds safe-RAM overlay window")
    ASSERT(SIZEOF(.saferam.rng) <= 0x800,
           "Error: .saferam.rng exceeds safe-RAM overlay window")

        /* Debug info (kept out of loadable memory) */
    .debug_info 0 : { KEEP(*(.debug_info .debug_info.*)) }
    .debug_abbrev 0 : { KEEP(*(.debug_abbrev .debug_abbrev.*)) }
    .debug_line 0 : { KEEP(*(.debug_line .debug_line.*)) }
    .debug_line_str 0 : { KEEP(*(.debug_line_str .debug_line_str.*)) }
    .debug_str 0 : { KEEP(*(.debug_str .debug_str.*)) }
    .debug_str_offsets 0 : { KEEP(*(.debug_str_offsets .debug_str_offsets.*)) }
    .debug_addr 0 : { KEEP(*(.debug_addr .debug_addr.*)) }
    .debug_aranges 0 : { KEEP(*(.debug_aranges .debug_aranges.*)) }
    .debug_ranges 0 : { KEEP(*(.debug_ranges .debug_ranges.*)) }
    .debug_rnglists 0 : { KEEP(*(.debug_rnglists .debug_rnglists.*)) }
    .debug_loc 0 : { KEEP(*(.debug_loc .debug_loc.*)) }
    .debug_loclists 0 : { KEEP(*(.debug_loclists .debug_loclists.*)) }
    .debug_frame 0 : { KEEP(*(.debug_frame .debug_frame.*)) }
    .debug_macro 0 : { KEEP(*(.debug_macro .debug_macro.*)) }
    .debug_macinfo 0 : { KEEP(*(.debug_macinfo .debug_macinfo.*)) }
    .debug_names 0 : { KEEP(*(.debug_names .debug_names.*)) }
    .debug_pubnames 0 : { KEEP(*(.debug_pubnames .debug_pubnames.*)) }
    .debug_pubtypes 0 : { KEEP(*(.debug_pubtypes .debug_pubtypes.*)) }
    .debug_types 0 : { KEEP(*(.debug_types .debug_types.*)) }
    .debug_sup 0 : { KEEP(*(.debug_sup .debug_sup.*)) }
    .debug_cu_index 0 : { KEEP(*(.debug_cu_index .debug_cu_index.*)) }
    .debug_tu_index 0 : { KEEP(*(.debug_tu_index .debug_tu_index.*)) }
    .gdb_index 0 : { KEEP(*(.gdb_index)) }
    .debug_gdb_scripts 0 : { KEEP(*(.debug_gdb_scripts)) }

    .debug_abbrev.dwo 0 : { KEEP(*(.debug_abbrev.dwo .debug_abbrev.dwo.*)) }
    .debug_info.dwo 0 : { KEEP(*(.debug_info.dwo .debug_info.dwo.*)) }
    .debug_line.dwo 0 : { KEEP(*(.debug_line.dwo .debug_line.dwo.*)) }
    .debug_loclists.dwo 0 : { KEEP(*(.debug_loclists.dwo .debug_loclists.dwo.*)) }
    .debug_macro.dwo 0 : { KEEP(*(.debug_macro.dwo .debug_macro.dwo.*)) }
    .debug_rnglists.dwo 0 : { KEEP(*(.debug_rnglists.dwo .debug_rnglists.dwo.*)) }
    .debug_str.dwo 0 : { KEEP(*(.debug_str.dwo .debug_str.dwo.*)) }
    .debug_str_offsets.dwo 0 : { KEEP(*(.debug_str_offsets.dwo .debug_str_offsets.dwo.*)) }

    .eh_frame 0 : { KEEP(*(.eh_frame)) }
    .eh_frame_hdr 0 : { KEEP(*(.eh_frame_hdr)) }

    /DISCARD/ :
    {
        *(.runprgm.reloc)
        *(.comment)
        *(.note*)
    }
}

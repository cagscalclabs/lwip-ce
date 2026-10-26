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

    /* Fixed dylib descriptor ABI:
     *
     * The installed flash app has a CE application container before the
     * linker image. The libload bootstrap computes that linked-image base
     * from app metadata at runtime, then adds this fixed offset to reach the
     * export table. Keep the table early and fail the build if the app header
     * ever grows into this reserved slot.
     */
    PROVIDE(__lwip_dylib_descriptor_off = 0x40);
    ASSERT(. <= LOAD_ADDR + __lwip_dylib_descriptor_off,
           "Error: lwIP app header exceeds fixed dylib descriptor offset")

    .lwip_dylib LOAD_ADDR + __lwip_dylib_descriptor_off :
    {
        KEEP(*(.fn_exports))
    } >prgm

    ASSERT(_fn_exports_table == LOAD_ADDR + __lwip_dylib_descriptor_off,
           "Error: lwIP export table is not at fixed dylib descriptor offset")

    /* Stable, relocation-free version string for host tools. Keep it separate
     * from the legacy table header at 0x40 so existing stubs remain valid. */
    PROVIDE(__lwip_version_off = 0x1000);
    ASSERT(. <= LOAD_ADDR + __lwip_version_off,
           "Error: lwIP export table exceeds fixed version offset")

    .lwip_version LOAD_ADDR + __lwip_version_off :
    {
        KEEP(*(.libify_version))
    } >prgm

    ASSERT(_libify_version == LOAD_ADDR + __lwip_version_off,
           "Error: lwIP version string is not at fixed version offset")

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
    } >bss :NONE

    /* General TLS scratch overlay. Each primitive owns a distinct input
     * section, so the linker—not matching hand-written aliases—enforces that
     * their mutually exclusive working sets occupy the same BSS address.
     * Keep the largest member first for a clear map and stable base symbols.
     * X25519 retains its low-byte addressing alignment inside its member. */
    OVERLAY : NOCROSSREFS
    {
        .crypto_scratch.p256
        {
            KEEP(*(.crypto_scratch.p256))
            KEEP(*(.crypto_scratch.p256.*))
        }
        .crypto_scratch.rsa
        {
            __rsa_scratch_start = .;
            KEEP(*(.crypto_scratch.rsa))
            KEEP(*(.crypto_scratch.rsa.*))
            /* Maximum RSA-4096 powmod working set plus transient output. */
            . = __rsa_scratch_start + 1647;
            __rsa_scratch_end = .;
        }
        .crypto_scratch.x25519
        {
            . = ALIGN(0x100) + 0xC0;
            KEEP(*(.crypto_scratch.x25519))
            KEEP(*(.crypto_scratch.x25519.*))
            _x25519_data_end = .;
        }
    } >bss

    ___bss_high = .;
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

    /* Canonical RSA/HKDF aliases point at their explicit overlay member. */
    PROVIDE(__tls_scratch_start  = __rsa_scratch_start);
    PROVIDE(__tls_scratch_end    = __rsa_scratch_end);
    PROVIDE(___tls_scratch_start = __rsa_scratch_start);
    PROVIDE(___tls_scratch_end   = __rsa_scratch_end);
    PROVIDE(__tls_scratch        = __rsa_scratch_start);
    PROVIDE(___tls_scratch       = __rsa_scratch_start);
    /* RSA result/transient buffer: bottom 512 bytes of shared scratch.
     * powmod Lacc/Ltmp occupy the top 2*mod_len bytes and never reach here. */
    PROVIDE(__rsa_transient      = __rsa_scratch_start);
    PROVIDE(___rsa_transient     = __rsa_scratch_start);

    ASSERT(ADDR(.crypto_scratch.p256) == ADDR(.crypto_scratch.rsa),
           "Error: P-256 and RSA scratch are not overlaid")
    ASSERT(ADDR(.crypto_scratch.p256) == ADDR(.crypto_scratch.x25519),
           "Error: P-256 and X25519 scratch are not overlaid")
    ASSERT(SIZEOF(.crypto_scratch.p256) >= SIZEOF(.crypto_scratch.rsa),
           "Error: largest crypto scratch overlay member must be first")
    ASSERT(SIZEOF(.crypto_scratch.p256) >= SIZEOF(.crypto_scratch.x25519),
           "Error: largest crypto scratch overlay member must be first")

    ASSERT(. <= BSSHEAP_HIGH, "Error: BSS exceed BSSHEAP_HIGH limit")

    ___heap_low = .;
    . = BSSHEAP_HIGH;
    ___heap_high = .;

    /* Map/debug alias for the fixed export-table ABI. */
    PROVIDE(__lwip_fn_table_off = _fn_exports_table);

    /* Safe-RAM scratch overlay (0xE30800, ti.cursorImage).
     *
     * Consumers share this address window, never live at the same
     * instant — it is deliberately reused as quick scratch:
     *   - .x25519.reloc : the X25519 hot loop, copied here at the start of
     *     each call (it has a load image in prgm) and run at this VMA.
     *   - .powmod.reloc : the RSA modexp hot loop, same deal (load image in
     *     prgm, copied + run here; relocated because it self-modifies).
     *   - .sha256.reloc : the compact SHA-256 compression-round loop. The
     *     RNG/SHA scratch starts above its reserved 384-byte prefix so these
     *     two members can be live together.
     *   - .saferam.rng  : the RNG entropy/SHA scratch. No load image — it
     *     is written in place; this member only reserves the VMA span so
     *     the linker knows the window size and flags a collision if either
     *     consumer outgrows it.
     *
    */
    OVERLAY 0xE30800 : AT ( LOADADDR(.data) + SIZEOF(.data) )
    {
        .x25519.reloc
        {
            _x25519_reloc_run_start = .;
            /* Relocatable load-image pointer — same fix as .powmod.reloc below:
             * `. + (LOADADDR - ADDR)` is a prgm-section-relative symbol the
             * installer patches, vs a bare LOADADDR() (absolute, never patched
             * → x25519.s copy loop would ldir from the link-time LMA garbage). */
            _x25519_reloc_load_start = . + (LOADADDR(.x25519.reloc) - ADDR(.x25519.reloc));
            KEEP(*(.x25519.reloc))
            KEEP(*(.x25519.reloc.*))
            _x25519_reloc_run_end = .;
        }
        .aes.encrypt.reloc
        {
            _aes_encrypt_reloc_run_start = .;
            /* Relocatable load-image pointer — same fix as .powmod.reloc below:
             * `. + (LOADADDR - ADDR)` is a prgm-section-relative symbol the
             * installer patches, vs a bare LOADADDR() (absolute, never patched
             * → aes.s copy loop would ldir from the link-time LMA garbage). */
            _aes_encrypt_reloc_load_start = . + (LOADADDR(.aes.encrypt.reloc) - ADDR(.aes.encrypt.reloc));
            KEEP(*(.aes.encrypt.reloc))
            KEEP(*(.aes.encrypt.reloc.*))
            _aes_encrypt_reloc_run_end = .;
        }
        .aes.decrypt.reloc
        {
            _aes_decrypt_reloc_run_start = .;
            /* Relocatable load-image pointer — same fix as .powmod.reloc below:
             * `. + (LOADADDR - ADDR)` is a prgm-section-relative symbol the
             * installer patches, vs a bare LOADADDR() (absolute, never patched
             * → aes.s copy loop would ldir from the link-time LMA garbage). */
            _aes_decrypt_reloc_load_start = . + (LOADADDR(.aes.decrypt.reloc) - ADDR(.aes.decrypt.reloc));
            KEEP(*(.aes.decrypt.reloc))
            KEEP(*(.aes.decrypt.reloc.*))
            _aes_decrypt_reloc_run_end = .;
        }
        .powmod.reloc
        {
            _powmod_reloc_run_start = .;
            /* Relocatable load-image pointer. Anchoring (LOADADDR - ADDR) to a
             * section-relative `.` (the .data trick) makes this a prgm-section-
             * relative symbol that convbin records and the installer PATCHES to
             * the real installed flash base. A bare `LOADADDR(.powmod.reloc)`
             * outside any section is an ABSOLUTE symbol (no reloc record), so
             * the trampoline's ldir reads the link-time LMA (~0x04127A, garbage
             * in low/OS flash) instead of base+offset — the powmod crash. */
            _powmod_reloc_load_start = . + (LOADADDR(.powmod.reloc) - ADDR(.powmod.reloc));
            KEEP(*(.powmod.reloc))
            KEEP(*(.powmod.reloc.*))
            _powmod_reloc_run_end = .;
        }
        .sha256.reloc
        {
            _sha256_reloc_run_start = .;
            _sha256_reloc_load_start = . + (LOADADDR(.sha256.reloc) - ADDR(.sha256.reloc));
            KEEP(*(.sha256.reloc))
            KEEP(*(.sha256.reloc.*))
            _sha256_reloc_run_end = .;
        }
        .saferam.rng
        {
            /* Reserve the first 384 bytes for the SHA-256 compression loop.
             * Other overlay consumers may still reuse the whole window. */
            . = . + 0x180;
            _sprng_entropy_pool = .;
            . = . + 520;   /* total RNG scratch: see virtuals.inc */
        }
    }

    /* Back-compat aliases for the X25519 copy loop in x25519.s.
     * NOTE: _x25519_reloc_load_start is defined INSIDE the .x25519.reloc block
     * above (not here) so it is a relocatable/patched symbol, not an absolute
     * LOADADDR. See the comment there. */
    _x25519_reloc_len        = SIZEOF(.x25519.reloc);

    /* Back-compat aliases for the AES copy loop in aes.s. */
    _aes_encrypt_reloc_len   = SIZEOF(.aes.encrypt.reloc);
    _aes_decrypt_reloc_len   = SIZEOF(.aes.decrypt.reloc);

    /* Copy-loop symbols for the powmod trampoline in rsa.s (RSA modexp
     * relocated to writable RAM because it self-modifies). Shares the
     * 0xE30800 overlay VMA with X25519/RNG — sequential, never co-resident.
     * NOTE: _powmod_reloc_load_start is defined INSIDE the .powmod.reloc block
     * above (not here), for the same reason. */
    _powmod_reloc_len        = SIZEOF(.powmod.reloc);
    _sha256_reloc_len        = SIZEOF(.sha256.reloc);

    /* Guard: no consumer may outgrow the 1020-byte shared window. */
    ASSERT(SIZEOF(.x25519.reloc) <= 0x400,
           "Error: .x25519.reloc exceeds safe-RAM overlay window")
    ASSERT(SIZEOF(.aes.encrypt.reloc) <= 0x400,
           "Error: .aes.encrypt.reloc exceeds safe-RAM overlay window")
    ASSERT(SIZEOF(.aes.decrypt.reloc) <= 0x400,
           "Error: .aes.decrypt.reloc exceeds safe-RAM overlay window")
    ASSERT(SIZEOF(.saferam.rng) <= 0x400,
           "Error: .saferam.rng exceeds safe-RAM overlay window")
    ASSERT(SIZEOF(.powmod.reloc) <= 0x400,
           "Error: .powmod.reloc exceeds safe-RAM overlay window")
    ASSERT(SIZEOF(.sha256.reloc) <= 0x180,
           "Error: SHA-256 hot loop exceeds its 384-byte fastMem budget")
    ASSERT(SIZEOF(.saferam.rng) <= 1020,
           "Error: SHA-256 code plus RNG scratch exceeds 1020-byte fastMem")

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

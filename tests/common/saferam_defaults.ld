/* Safe-RAM scratch overlay for standalone unit/profiling test programs.
 *
 * In the real lwIP app, _sprng_entropy_pool / _x25519_reloc_* /
 * _powmod_reloc_* are defined by the safe-RAM OVERLAY in
 * linker_script_lwip.ld. The standalone tests don't build that overlay, so
 * virtuals.inc's `extern _sprng_entropy_pool` and bigint.s/x25519.s's
 * reloc-trampoline symbols would otherwise be undefined at link time.
 *
 * Same safe-RAM overlay as linker_script_lwip.ld's OVERLAY 0xE30800 block,
 * lifted as-is for standalone test programs that assemble x25519.s /
 * bigint.s (powmod). Three consumers share this address window, never live
 * at the same instant:
 *   - .x25519.reloc : X25519 hot loop, copied here at the start of each call.
 *   - .powmod.reloc : RSA modexp hot loop, same deal (self-modifying).
 *   - .saferam.rng  : RNG entropy/SHA scratch, written in place.
 * See linker_script_lwip.ld for the full rationale on the relocatable
 * load-image anchoring trick used below. */
SECTIONS
{
    OVERLAY 0xE30800 : AT ( LOADADDR(.data) + SIZEOF(.data) )
    {
        .x25519.reloc
        {
            _x25519_reloc_run_start = .;
            _x25519_reloc_load_start = . + (LOADADDR(.x25519.reloc) - ADDR(.x25519.reloc));
            KEEP(*(.x25519.reloc))
            KEEP(*(.x25519.reloc.*))
            _x25519_reloc_run_end = .;
        }
        .powmod.reloc
        {
            _powmod_reloc_run_start = .;
            _powmod_reloc_load_start = . + (LOADADDR(.powmod.reloc) - ADDR(.powmod.reloc));
            KEEP(*(.powmod.reloc))
            KEEP(*(.powmod.reloc.*))
            _powmod_reloc_run_end = .;
        }
        .saferam.rng
        {
            _sprng_entropy_pool = .;
            . = . + 520;   /* total RNG scratch: see virtuals.inc */
        }
    }

    _x25519_reloc_len = SIZEOF(.x25519.reloc);
    _powmod_reloc_len = SIZEOF(.powmod.reloc);

    ASSERT(SIZEOF(.x25519.reloc) <= 0x400,
           "Error: .x25519.reloc exceeds safe-RAM overlay window")
    ASSERT(SIZEOF(.saferam.rng) <= 0x400,
           "Error: .saferam.rng exceeds safe-RAM overlay window")
    ASSERT(SIZEOF(.powmod.reloc) <= 0x400,
           "Error: .powmod.reloc exceeds safe-RAM overlay window")
}

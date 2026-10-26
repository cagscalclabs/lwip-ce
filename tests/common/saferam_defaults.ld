/* Safe-RAM scratch overlay for standalone unit/profiling test programs.
 *
 * In the real lwIP app, _sprng_entropy_pool / _powmod_reloc_* are defined by
 * the safe-RAM OVERLAY in linker_script_lwip.ld. The standalone tests don't
 * build that overlay, so virtuals.inc's `extern _sprng_entropy_pool` and
 * rsa.s's powmod-trampoline reloc symbols would otherwise be undefined at
 * link time.
 *
 * Same safe-RAM overlay as linker_script_lwip.ld's OVERLAY 0xE30800 block
 * (minus the .x25519.reloc member -- tls_x25519 is the only test that
 * assembles x25519.s, and it supplies its own placement via
 * x25519_reloc.ld; defining .x25519.reloc here too would collide with that
 * script's LMA). Consumers handled here:
 *   - .powmod.reloc : RSA modexp hot loop, copied to RAM (self-modifying).
 *   - .sha256.reloc : SHA-256 compression-round hot loop, copied to RAM.
 *   - .saferam.rng  : RNG entropy/SHA scratch, written in place.
 * See linker_script_lwip.ld for the full rationale on the relocatable
 * load-image anchoring trick used below. */
SECTIONS
{
    OVERLAY 0xE30800 : AT ( LOADADDR(.data) + SIZEOF(.data) )
    {
        .powmod.reloc
        {
            _powmod_reloc_run_start = .;
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
            . = . + 0x180;
            _sprng_entropy_pool = .;
            . = . + 520;   /* total RNG scratch: see virtuals.inc */
        }
    }

    _powmod_reloc_len = SIZEOF(.powmod.reloc);
    _sha256_reloc_len = SIZEOF(.sha256.reloc);

    ASSERT(SIZEOF(.saferam.rng) <= 0x400,
           "Error: .saferam.rng exceeds safe-RAM overlay window")
    ASSERT(SIZEOF(.powmod.reloc) <= 0x400,
           "Error: .powmod.reloc exceeds safe-RAM overlay window")
    ASSERT(SIZEOF(.sha256.reloc) <= 0x180,
           "Error: SHA-256 hot loop exceeds its 384-byte fastMem budget")
    ASSERT(SIZEOF(.saferam.rng) <= 1020,
           "Error: SHA-256 code plus RNG scratch exceeds 1020-byte fastMem")
}

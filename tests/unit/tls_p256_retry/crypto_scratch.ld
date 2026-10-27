/* Standalone crypto scratch overlay for the static P-256 tests.
 *
 * - .crypto_scratch.* : the production linker script places these in one
 *   overlay and exports the __tls_scratch_start/__tls_scratch_end aliases
 *   that scratch.inc externs.
 * - .p256.reloc : the fast-RAM copy of the field-multiply MAC blocks. The
 *   production script overlays it at 0xE30800 (ti.cursorImage); here the same
 *   VMA is used with the load image placed right after .data, exactly like
 *   the shipped build. NOLOAD for the scratch so nothing is written to the
 *   .8xp. */
SECTIONS
{
    .crypto_scratch (NOLOAD) : ALIGN(4)
    {
        __tls_scratch_start = .;
        KEEP(*(.crypto_scratch.p256))
        KEEP(*(.crypto_scratch.rsa))
        KEEP(*(.crypto_scratch.x25519))
        __tls_scratch_end = .;
    } > bss

    .p256.mul.reloc 0xE30800 : AT (LOADADDR(.sha256.reloc) + SIZEOF(.sha256.reloc))
    {
        KEEP(*(.p256.mul.reloc))
    }
    .p256.sq.reloc 0xE30800 : AT (LOADADDR(.p256.mul.reloc) + SIZEOF(.p256.mul.reloc))
    {
        KEEP(*(.p256.sq.reloc))
    }
    _p256_mul_reloc_load_start = LOADADDR(.p256.mul.reloc);
    _p256_mul_reloc_len = SIZEOF(.p256.mul.reloc);
    _p256_sq_reloc_load_start = LOADADDR(.p256.sq.reloc);
    _p256_sq_reloc_len = SIZEOF(.p256.sq.reloc);
}

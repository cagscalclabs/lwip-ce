/* Standalone crypto scratch overlay: the production linker script places
 * .crypto_scratch.p256/.rsa/.x25519 in one OVERLAY and exports the
 * __tls_scratch_start/__tls_scratch_end aliases that scratch.inc externs.
 * NOLOAD so nothing is written to the .8xp. */
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
}

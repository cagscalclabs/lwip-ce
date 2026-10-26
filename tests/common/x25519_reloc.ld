SECTIONS
{
    .x25519_data : AT(LOADADDR(.powmod.reloc) + SIZEOF(.powmod.reloc))
    {
        . = ALIGN(0x100) + 0xC0;
        KEEP(*(.crypto_scratch.x25519))
        KEEP(*(.crypto_scratch.x25519.*))
        _x25519_data_end = .;
    } >prgm

    _x25519_data_load_end = LOADADDR(.x25519_data) + SIZEOF(.x25519_data);

    .x25519_reloc 0xE30800 : AT(_x25519_data_load_end)
    {
        _x25519_reloc_run_start = .;
        KEEP(*(.x25519.reloc))
        KEEP(*(.x25519.reloc.*))
        _x25519_reloc_run_end = .;
    }

    _x25519_reloc_load_start = LOADADDR(.x25519_reloc);
    _x25519_reloc_len = SIZEOF(.x25519_reloc);
}

SECTIONS
{
    .x25519_data :
    {
        . = ALIGN(0x100) + 0xC0;
        KEEP(*(.x25519.data))
        KEEP(*(.x25519.data.*))
        _x25519_data_end = .;
    } >prgm

    .x25519_reloc 0xE30800 : AT(_x25519_data_end)
    {
        _x25519_reloc_run_start = .;
        KEEP(*(.x25519.reloc))
        KEEP(*(.x25519.reloc.*))
        _x25519_reloc_run_end = .;
    }

    _x25519_reloc_load_start = LOADADDR(.x25519_reloc);
    _x25519_reloc_len = SIZEOF(.x25519_reloc);
}

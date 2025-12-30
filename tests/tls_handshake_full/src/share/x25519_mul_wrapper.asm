; Wrapper to use Karatsuba for x25519_mul
assume adl=1

extern _x25519_mul_karatsuba
extern _x25519_reduce_64

section .text

public _x25519_mul
_x25519_mul:
    push ix
    ld ix, 0
    add ix, sp

    ; Allocate 64 bytes for product
    lea hl, ix-64
    ld sp, hl

    ; Call Karatsuba: karat(temp, a, b)
    ld hl, (ix+9)          ; b
    push hl
    ld hl, (ix+6)          ; a
    push hl
    lea hl, ix-64          ; temp result
    push hl
    call _x25519_mul_karatsuba
    pop hl
    pop hl
    pop hl

    ; Reduce the 64-byte product
    call _x25519_reduce_64

    ; Copy result to output
    ld de, (ix+3)
    lea hl, ix-64
    ld bc, 32
    ldir

    ; Restore stack
    ld sp, ix
    pop ix
    ret

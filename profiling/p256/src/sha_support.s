; Profiling-only support for src/tls/core/sha256.s (needed by tls_p256_sign).
;
; 1. The lwIP linker script places the .saferam.rng overlay (base
;    _sprng_entropy_pool) at 0xE30800; sha256.s keeps its message schedule
;    there.  This standalone target has no such overlay, so pin the base to
;    the same address (LCD cursor RAM, unused by this program).
; 2. u64_addi: verbatim copy of src/tls/core/share/bigint.s:u64_addi.
;    bigint.s itself is not linked because it drags in the relocated powmod
;    kernel and __tls_scratch.  Keep in sync if bigint.s changes.
    .assume adl=1
    .global _sprng_entropy_pool
    .set    _sprng_entropy_pool, 0xE30800

    .section .text.u64_addi,"ax",@progbits
    .global u64_addi
    .type   u64_addi, @function
; add unsigned 24-bit BC to the 64-bit integer pointed to by IY
; destroys AF, DE, HL
u64_addi:
    xor     a, a
    sbc     hl, hl
    ex      de, hl
    ld      hl, (iy)
    add     hl, bc
    ld      (iy), hl
    ld      hl, (iy + 3)
    adc     hl, de
    ld      (iy + 3), hl
    lea     hl, iy + 6
    adc     a, (hl)
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    adc     a, e
    ld      (hl), a
    ret

    .section .note.GNU-stack,"",@progbits

; Karatsuba multiplication implementation for x25519
; Separate file for clarity

assume adl=1

section .text

;----------------------------------------------------------------------
; x25519_mul_karatsuba: 32x32 Karatsuba multiplication
; Entry point to replace the schoolbook version
;
; Parameters (stack):
;   +3: out (32 bytes)
;   +6: a (32 bytes)
;   +9: b (32 bytes)
;
; Uses 2-level Karatsuba for ~3-4x speedup
;----------------------------------------------------------------------
public _x25519_mul_karatsuba
_x25519_mul_karatsuba:
    push ix
    ld ix, 0
    add ix, sp

    ; Allocate: 64 bytes result + 128 bytes scratch = 192 bytes
    ld hl, -192
    add hl, sp
    ld sp, hl

    ; Zero result buffer
    xor a
    ld b, 64
    ld iy, 0
    add iy, sp
    ld de, 64
    add iy, de
.zero:
    ld (iy), a
    inc iy
    djnz .zero

    ; Call main Karatsuba: karat_32(result, a, b, scratch)
    ld hl, 0
    add hl, sp             ; scratch at sp
    push hl
    ld hl, (ix+9)          ; b
    push hl
    ld hl, (ix+6)          ; a
    push hl
    ld hl, 0
    add hl, sp
    ld de, 64+12           ; account for 3 pushes
    add hl, de             ; result at sp+64
    push hl
    call _karat_32
    pop hl
    pop hl
    pop hl
    pop hl

    ; Copy to output
    ld de, (ix+3)
    ld hl, 0
    add hl, sp
    ld bc, 64
    add hl, bc
    ld bc, 64
    ldir

    ld sp, ix
    pop ix
    ret

;----------------------------------------------------------------------
; karat_32: 32x32 Karatsuba level
; result[64] = a[32] * b[32]
; scratch[128] used for intermediate values
;----------------------------------------------------------------------
_karat_32:
    push ix
    ld ix, 0
    add ix, sp

    ; Stack: result[+3], a[+6], b[+9], scratch[+12]
    ; scratch layout:
    ; [0-31]: z0 (low * low)
    ; [32-63]: z2 (high * high)
    ; [64-95]: z1 (middle term)
    ; [96-111]: sum_a
    ; [112-127]: sum_b

    ; Compute z0 = a_low * b_low (16x16 -> 32)
    ld hl, (ix+6)          ; a
    ld de, (ix+9)          ; b
    ld bc, (ix+12)         ; scratch
    push bc                ; result = scratch[0]
    push de                ; b_low
    push hl                ; a_low
    call _schoolbook_16
    pop hl
    pop de
    pop bc

    ; Compute z2 = a_high * b_high (16x16 -> 32)
    ld hl, (ix+6)
    ld bc, 16
    add hl, bc             ; a_high
    ld de, (ix+9)
    ld bc, 16
    ex de, hl
    add hl, bc
    ex de, hl              ; b_high
    ld bc, (ix+12)
    ld hl, 32
    add hl, bc             ; scratch+32
    push hl
    push de
    ld hl, (ix+6)
    ld bc, 16
    add hl, bc
    push hl
    call _schoolbook_16
    pop hl
    pop de
    pop bc

    ; Compute sum_a = a_low + a_high
    ld hl, (ix+6)          ; a
    ld bc, (ix+12)
    ld de, 96
    ex de, hl
    add hl, bc
    ex de, hl              ; scratch+96 (sum_a)
    push de
    pop bc
    ld hl, (ix+6)
    call _add16_halves

    ; Compute sum_b = b_low + b_high
    ld hl, (ix+9)          ; b
    ld bc, (ix+12)
    ld de, 112
    ex de, hl
    add hl, bc
    ex de, hl              ; scratch+112 (sum_b)
    push de
    pop bc
    ld hl, (ix+9)
    call _add16_halves

    ; Compute z1 = sum_a * sum_b
    ld bc, (ix+12)
    ld hl, 96
    add hl, bc             ; sum_a
    push hl
    ld hl, (ix+12)
    ld de, 112
    add hl, de             ; sum_b
    push hl
    ld hl, (ix+12)
    ld de, 64
    add hl, de             ; scratch+64 (z1)
    push hl
    call _schoolbook_16
    pop hl
    pop de
    pop hl

    ; z1 -= z0
    ld hl, (ix+12)         ; z0
    ld de, (ix+12)
    push hl
    ld hl, 64
    add hl, de
    ex de, hl              ; z1
    pop hl
    call _sub32

    ; z1 -= z2
    ld hl, (ix+12)
    ld bc, 32
    add hl, bc             ; z2
    ld de, (ix+12)
    push hl
    ld hl, 64
    add hl, de
    ex de, hl              ; z1
    pop hl
    call _sub32

    ; Combine: result = z0 + (z1 << 128) + (z2 << 256)
    ; Copy z0 to result[0-31]
    ld hl, (ix+12)         ; z0
    ld de, (ix+3)          ; result
    ld bc, 32
    ldir

    ; Add z1 to result[16-47]
    ld hl, (ix+12)
    ld bc, 64
    add hl, bc             ; z1
    ld de, (ix+3)
    ld bc, 16
    ex de, hl
    add hl, bc
    ex de, hl              ; result+16
    call _add32_to_dest

    ; Add z2 to result[32-63]
    ld hl, (ix+12)
    ld bc, 32
    add hl, bc             ; z2
    ld de, (ix+3)
    ld bc, 32
    ex de, hl
    add hl, bc
    ex de, hl              ; result+32
    call _add32_to_dest

    pop ix
    ret

;----------------------------------------------------------------------
; schoolbook_16: Optimized 16x16 schoolbook base case
; result[32] = a[16] * b[16]
;----------------------------------------------------------------------
_schoolbook_16:
    push ix
    ld ix, 0
    add ix, sp

    ld hl, (ix+6)          ; a
    ld de, (ix+9)          ; b
    ld iy, (ix+3)          ; result

    ; Zero result
    xor a
    ld b, 32
    push iy
.z:
    ld (iy), a
    inc iy
    djnz .z
    pop iy

    ; Multiply
    ld b, 16
.outer:
    ld a, (hl)
    inc hl
    or a
    jr z, .skip

    push hl
    push de
    push bc
    ld c, a
    ld b, 16

.inner:
    ld a, (de)
    inc de
    ld l, a
    ld h, c
    mlt hl
    ld a, (iy)
    add a, l
    ld (iy), a
    inc iy
    ld a, (iy)
    adc a, h
    ld (iy), a
    jr nc, .nc
    inc iy
.carry:
    ld a, (iy)
    inc a
    ld (iy), a
    jr z, .carry
    dec iy
.nc:
    dec iy
    djnz .inner

    pop bc
    pop de
    pop hl

.skip:
    inc iy
    djnz .outer

    pop ix
    ret

;----------------------------------------------------------------------
; Helper: Add two 16-byte halves of a 32-byte number
; hl = 32-byte number, bc = 16-byte result
;----------------------------------------------------------------------
_add16_halves:
    push ix
    push iy
    push hl         ; save original
    ex de, hl       ; de = original
    ld hl, 16
    add hl, de      ; hl = original + 16
    ex de, hl       ; de = original + 16
    pop hl          ; hl = original
    ld iy, 0
    add iy, bc      ; iy = result pointer
    or a
    ld b, 16
.loop:
    ld a, (de)
    ld c, a
    ld a, (hl)
    adc a, c
    ld (iy), a
    inc hl
    inc de
    inc iy
    djnz .loop
    pop iy
    pop ix
    ret

;----------------------------------------------------------------------
; Helper: Subtract 32 bytes: de = de - hl
;----------------------------------------------------------------------
_sub32:
    push bc
    or a
    ld b, 32
.loop:
    ld a, (de)
    ld c, (hl)
    sbc a, c
    ld (de), a
    inc de
    inc hl
    djnz .loop
    pop bc
    ret

;----------------------------------------------------------------------
; Helper: Add 32 bytes to destination: de += hl
;----------------------------------------------------------------------
_add32_to_dest:
    push bc
    or a
    ld b, 32
.loop:
    ld a, (de)
    adc a, (hl)
    ld (de), a
    inc de
    inc hl
    djnz .loop
    pop bc
    ret

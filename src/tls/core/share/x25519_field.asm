; X25519 Field Arithmetic - Optimized for ez80
; Prime: p = 2^255 - 19 (much simpler than P-256!)
; All values are 32-byte little-endian

assume adl=1

section .data

; Curve25519 prime: 2^255 - 19 (little-endian)
; = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED
x25519_prime:
    db 0xED, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    db 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    db 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    db 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F

; Curve25519 base point (x-coordinate only, little-endian)
x25519_basepoint:
    db 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00

section .text

; When using Karatsuba wrapper, _x25519_mul is provided externally
extern _x25519_mul

;----------------------------------------------------------------------
; x25519_add: out = (a + b) mod p
; Simple addition with reduction by subtracting p if needed
;----------------------------------------------------------------------
public _x25519_add
_x25519_add:
    push ix
    ld ix, 0
    add ix, sp
    push iy

    ld hl, (ix+6)          ; a
    ld de, (ix+9)          ; b
    ld iy, (ix+3)          ; out

    ; Add a + b
    or a                    ; clear carry
    ld b, 32
.add_loop:
    ld a, (de)
    adc a, (hl)
    ld (iy), a
    inc hl
    inc de
    inc iy
    djnz .add_loop

    ; If carry or result >= p, subtract p
    jr c, .do_reduce

    ; Check if result >= p (simple: check if top bit is set or value >= p)
    ld iy, (ix+3)
    ld a, (iy+31)
    bit 7, a
    jr z, .done             ; top bit clear, definitely < p

.do_reduce:
    ; Subtract p from result
    ; p = 2^255 - 19, so subtracting p is:
    ; Add 19, then clear bit 255
    ld iy, (ix+3)

    ; Add 19 to low bytes
    ld a, (iy)
    add a, 19
    ld (iy), a
    ld b, 31
    inc iy
.carry_loop:
    ld a, (iy)
    adc a, 0
    ld (iy), a
    inc iy
    jr nc, .carry_done
    djnz .carry_loop

.carry_done:
    ; Clear bit 255 (top bit of byte 31)
    ld iy, (ix+3)
    ld a, (iy+31)
    and 0x7F
    ld (iy+31), a

.done:
    pop iy
    pop ix
    ret

;----------------------------------------------------------------------
; x25519_sub: out = (a - b) mod p
;----------------------------------------------------------------------
public _x25519_sub
_x25519_sub:
    push ix
    ld ix, 0
    add ix, sp
    push iy

    ld hl, (ix+6)          ; a
    ld de, (ix+9)          ; b
    ld iy, (ix+3)          ; out

    ; Subtract: a - b
    or a                    ; clear carry
    ld b, 32
.sub_loop:
    ld a, (de)
    ld c, a
    ld a, (hl)
    sbc a, c
    ld (iy), a
    inc hl
    inc de
    inc iy
    djnz .sub_loop

    ; If borrow, add p
    jr nc, .done

    ; Add p (which is 2^255 - 19)
    ; This means: subtract 19, set bit 255
    ld iy, (ix+3)

    ; Subtract 19
    ld a, (iy)
    sub a, 19
    ld (iy), a
    ld b, 31
    inc iy
.borrow_loop:
    ld a, (iy)
    sbc a, 0
    ld (iy), a
    inc iy
    jr nc, .borrow_done
    djnz .borrow_loop

.borrow_done:
    ; Set bit 255
    ld iy, (ix+3)
    ld a, (iy+31)
    or 0x80
    ld (iy+31), a

.done:
    pop iy
    pop ix
    ret

;----------------------------------------------------------------------
; x25519_mul: out = (a * b) mod (2^255-19)
; Uses simple schoolbook multiplication + fast reduction
; Much simpler than P-256!
;----------------------------------------------------------------------
; Old schoolbook multiplication - replaced by Karatsuba in x25519_mul_wrapper.asm
; Renamed to avoid conflict - not called when using Karatsuba wrapper
_x25519_mul_schoolbook:
    push ix
    ld ix, 0
    add ix, sp

    ; Allocate 64 bytes for product
    lea hl, ix-64
    ld sp, hl

    ; Zero product buffer (optimized)
    xor a
    ld b, 64
    lea iy, ix-64
.zero:
    ld (iy), a
    inc iy
    djnz .zero

    ; Multiply a * b (32x32 -> 64 bytes)
    ; HEAVILY optimized: inline, unroll, minimize overhead
    ld hl, (ix+6)          ; a pointer
    ld de, (ix+9)          ; b pointer
    lea iy, ix-64          ; product pointer

    ; Process in chunks of 8 bytes for better code gen
    ; Outer loop: 4 iterations of 8 bytes each
    ld b, 32
.outer:
    ld a, (hl)             ; get a[i]
    inc hl
    or a
    jr z, .skip_zero       ; skip if a[i] = 0

    ; Save registers once instead of in loop
    push hl
    push de
    push bc
    ld c, a                ; c = a[i]

    ; Unrolled inner loop: 4x8 = 32 iterations
    ; First 8 bytes
    call .inner_8
    lea iy, iy+8
    ; Second 8 bytes
    call .inner_8
    lea iy, iy+8
    ; Third 8 bytes
    call .inner_8
    lea iy, iy+8
    ; Fourth 8 bytes
    call .inner_8
    lea iy, iy+8

    pop bc
    pop de
    pop hl
    jr .next

.skip_zero:
    inc iy
.next:
    djnz .outer

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

; Tight inner loop for 8 multiplications
.inner_8:
    ld a, (de)
    inc de
    ld l, a
    ld h, c
    mlt hl                 ; hl = a[i] * b[j]

    ld a, (iy)
    add a, l
    ld (iy), a
    inc iy
    ld a, (iy)
    adc a, h
    ld (iy), a
    jr nc, .nc1
    inc iy
.c1:
    ld a, (iy)
    inc a
    ld (iy), a
    jr z, .c1
    dec iy
.nc1:
    dec iy

    ; Repeat for remaining 7 iterations (unrolled)
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
    jr nc, .nc2
    inc iy
.c2:
    ld a, (iy)
    inc a
    ld (iy), a
    jr z, .c2
    dec iy
.nc2:
    dec iy

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
    jr nc, .nc3
    inc iy
.c3:
    ld a, (iy)
    inc a
    ld (iy), a
    jr z, .c3
    dec iy
.nc3:
    dec iy

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
    jr nc, .nc4
    inc iy
.c4:
    ld a, (iy)
    inc a
    ld (iy), a
    jr z, .c4
    dec iy
.nc4:
    dec iy

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
    jr nc, .nc5
    inc iy
.c5:
    ld a, (iy)
    inc a
    ld (iy), a
    jr z, .c5
    dec iy
.nc5:
    dec iy

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
    jr nc, .nc6
    inc iy
.c6:
    ld a, (iy)
    inc a
    ld (iy), a
    jr z, .c6
    dec iy
.nc6:
    dec iy

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
    jr nc, .nc7
    inc iy
.c7:
    ld a, (iy)
    inc a
    ld (iy), a
    jr z, .c7
    dec iy
.nc7:
    dec iy

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
    jr nc, .nc8
    inc iy
.c8:
    ld a, (iy)
    inc a
    ld (iy), a
    jr z, .c8
    dec iy
.nc8:
    dec iy

    ret

;----------------------------------------------------------------------
; x25519_reduce_64: Reduce 64-byte value mod (2^255-19)
; Input: Stack contains 64-byte value
; Output: First 32 bytes contain reduced result
;
; Algorithm: Since 2^256 ≡ 38 (mod 2^255-19), we can reduce by
; computing: result = low_32_bytes + 38 * high_32_bytes
;----------------------------------------------------------------------
public _x25519_reduce_64
_x25519_reduce_64:
    ; Heavily optimized reduction
    ; Input: 64 bytes on stack at sp
    ; Output: 32 bytes reduced at sp

    ; Strategy: low[0..31] += 38 * high[32..63]
    ; Use direct indexing to avoid pointer arithmetic overhead

    ; Get base pointer
    ld iy, 0
    add iy, sp

    ; Process high bytes: multiply each by 38 and add to low bytes
    ; Start from byte 32 (high[0]) and work forward
    ld b, 32                ; 32 high bytes to process
    lea hl, iy+32           ; hl points to high bytes

.reduce_loop:
    ld a, (hl)              ; get high byte
    inc hl
    or a
    jr z, .skip_zero        ; skip if zero (optimization)

    ; Multiply by 38
    ld e, a
    ld d, 38
    mlt de                  ; de = high_byte * 38

    ; Calculate offset into low bytes (b-1 gives us index)
    push bc
    ld a, 32
    sub a, b                ; a = 32-b = index into low
    ld c, a
    ld b, 0
    push hl
    push iy
    add iy, bc              ; iy points to low[index]

    ; Add de to low bytes with carry
    ld a, (iy)
    add a, e
    ld (iy), a
    inc iy
    ld a, (iy)
    adc a, d
    ld (iy), a

    ; Tight carry propagation
    jr nc, .no_carry
.carry:
    inc iy
    ld a, (iy)
    inc a
    ld (iy), a
    jr z, .carry
.no_carry:
    pop iy
    pop hl
    pop bc

.skip_zero:
    djnz .reduce_loop

    ; Second pass: reduce any overflow in bytes 32+
    ld a, (iy+32)
    or a
    jr z, .final_check

    ld e, a
    ld d, 38
    mlt de

    ld a, (iy)
    add a, e
    ld (iy), a
    ld a, (iy+1)
    adc a, d
    ld (iy+1), a

    jr nc, .clear_high
    lea hl, iy+2
.carry2:
    ld a, (hl)
    inc a
    ld (hl), a
    inc hl
    jr z, .carry2

.clear_high:
    ; Zero out high 32 bytes
    xor a
    ld b, 32
    lea hl, iy+32
.zero_loop:
    ld (hl), a
    inc hl
    djnz .zero_loop

.final_check:
    ; Final reduction if >= p
    ; Quick check: top byte < 0x7F means we're done
    ld a, (iy+31)
    cp 0x7F
    ret c

    ; Top byte >= 0x7F, need to check more carefully
    jr nz, .final_sub

    ; Top byte = 0x7F, check if all middle bytes are 0xFF
    ld b, 30
    lea hl, iy+1
.check_ff:
    ld a, (hl)
    cp 0xFF
    jr nz, .done
    inc hl
    djnz .check_ff

    ; All middle bytes are 0xFF, check low byte
    ld a, (iy)
    cp 0xED
    ret c

.final_sub:
    ; Subtract p (add 19, clear top bit)
    ld a, (iy)
    add a, 19
    ld (iy), a
    lea hl, iy+1
    ld b, 31
.final_carry:
    ld a, (hl)
    adc a, 0
    ld (hl), a
    inc hl
    jr nc, .final_done
    djnz .final_carry

.final_done:
    ld a, (iy+31)
    and 0x7F
    ld (iy+31), a

.done:
    ret

;----------------------------------------------------------------------
; x25519_sqr: out = a^2 mod p
; Can be optimized vs general multiplication
;----------------------------------------------------------------------
public _x25519_sqr
_x25519_sqr:
    push ix
    ld ix, 0
    add ix, sp

    ; For now, just call multiply with same input
    ld hl, (ix+6)
    push hl                ; a
    push hl                ; a again
    ld hl, (ix+3)
    push hl                ; out
    call _x25519_mul
    pop hl
    pop hl
    pop hl

    pop ix
    ret

;----------------------------------------------------------------------
; x25519_inv: out = a^(-1) mod p
; Uses Fermat's little theorem: a^(-1) = a^(p-2) mod p
; where p = 2^255 - 19
;----------------------------------------------------------------------
public _x25519_inv
_x25519_inv:
    push ix
    ld hl, -96
    call __frameset

    ; Stack frame:
    ; ix-96 to ix-65: copy of input a
    ; ix-64 to ix-33: temporary result
    ; ix-32 to ix-1:  accumulator (result)

    ; Copy input to ix-96
    lea hl, ix - 96
    ld de, (ix+6)           ; input a
    ld bc, 32
    ldir

    ; Initialize result to 1 (at ix-32)
    lea hl, ix - 32
    ld b, 32
.zero_loop:
    ld (hl), 0
    inc hl
    djnz .zero_loop

    ld (ix-32), 1           ; result = 1

    ; Exponent is p-2 = 2^255 - 21 (big-endian for bit scanning)
    ld hl, x25519_p_minus_2
    ld b, 32

.byte_loop:
    push bc
    ld a, (hl)              ; get byte of exponent
    ld c, a
    inc hl
    push hl

    ld b, 8                 ; 8 bits per byte

.bit_loop:
    push bc

    ; Square the result
    lea hl, ix - 32
    push hl                 ; input (result)
    lea hl, ix - 64
    push hl                 ; temp output
    call _x25519_sqr
    pop hl
    pop hl

    ; Copy temp back to result
    lea hl, ix - 64
    lea de, ix - 32
    ld bc, 32
    ldir

    ; Check if bit is set
    ld a, c
    rlca                    ; rotate left to get MSB
    ld c, a
    jr nc, .bit_zero

    ; Bit is 1: multiply by a
    lea hl, ix - 96         ; input a
    push hl
    lea hl, ix - 32         ; current result
    push hl
    lea hl, ix - 64         ; temp output
    push hl
    call _x25519_mul
    pop hl
    pop hl
    pop hl

    ; Copy temp back to result
    lea hl, ix - 64
    lea de, ix - 32
    ld bc, 32
    ldir

.bit_zero:
    pop bc
    djnz .bit_loop

    pop hl
    pop bc
    djnz .byte_loop

    ; Copy result to output
    lea hl, ix - 32
    ld de, (ix+3)           ; output pointer
    ld bc, 32
    ldir

    ld sp, ix
    pop ix
    ret

;----------------------------------------------------------------------
; x25519 p-2 constant for inversion (big-endian for bit scanning)
; p-2 = 2^255 - 21 = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEB
;----------------------------------------------------------------------
x25519_p_minus_2:
    db 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    db 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    db 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    db 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xEB

extern __frameset

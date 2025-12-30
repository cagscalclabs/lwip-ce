;----------------------------------------------------------------------
; SECP256R1 (P-256) Field Arithmetic - Optimized for ez80
; All values are 32-byte little-endian
; Prime p = 2^256 - 2^224 + 2^192 + 2^96 - 1
;----------------------------------------------------------------------

assume adl=1

section .data

; P-256 prime (little-endian)
public _p256_prime
_p256_prime:
p256_prime:
    db 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    db 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF

; P-256 order n (little-endian)
public _p256_order
_p256_order:
p256_order:
    db 0x51, 0x25, 0x63, 0xFC, 0xC2, 0xCA, 0xB9, 0xF3
    db 0x84, 0x9E, 0x17, 0xA7, 0xAD, 0xFA, 0xE6, 0xBC
    db 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    db 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF

; Generator point G (little-endian)
public _p256_gx
_p256_gx:
    db 0x96, 0xC2, 0x98, 0xD8, 0x45, 0x39, 0xA1, 0xF4
    db 0xA0, 0x33, 0xEB, 0x2D, 0x81, 0x7D, 0x03, 0x77
    db 0xF2, 0x40, 0xA4, 0x63, 0xE5, 0xE6, 0xBC, 0xF8
    db 0x47, 0x42, 0x2C, 0xE1, 0xF2, 0xD1, 0x17, 0x6B

public _p256_gy
_p256_gy:
    db 0xF5, 0x51, 0xBF, 0x37, 0x68, 0x40, 0xB6, 0xCB
    db 0xCE, 0x5E, 0x31, 0x6B, 0x57, 0x33, 0xCE, 0x2B
    db 0x16, 0x9E, 0x0F, 0x7C, 0x4A, 0xEB, 0xE7, 0x8E
    db 0x9B, 0x7F, 0x1A, 0xFE, 0xE2, 0x42, 0xE3, 0x4F

; Curve parameter b (little-endian)
public _p256_b
_p256_b:
    db 0x4B, 0x60, 0xD2, 0x27, 0x3E, 0x3C, 0xCE, 0x3B
    db 0xF6, 0xB0, 0x53, 0xCC, 0xB0, 0x06, 0x1D, 0x65
    db 0xBC, 0x86, 0x98, 0x76, 0x55, 0xBD, 0xEB, 0xB3
    db 0xE7, 0x93, 0x3A, 0xAA, 0xD8, 0x35, 0xC6, 0x5A

; Exponent p-2 for inversion (big-endian for bit scanning)
p256_p_minus_2:
    db 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF
    db 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFD

section .text

;----------------------------------------------------------------------
; p256_mod_add: out = (a + b) mod p
;----------------------------------------------------------------------
public _p256_mod_add
_p256_mod_add:
    push ix
    ld ix, 0
    add ix, sp
    push iy

    ld hl, (ix+6)
    ld de, (ix+9)
    ld iy, (ix+3)

    or a
    ld b, 32
.add_loop:
    ld a, (de)
    adc a, (hl)
    ld (iy), a
    inc hl
    inc de
    inc iy
    djnz .add_loop

    jr nc, .check_cmp
    jr .do_subtract

.check_cmp:
    ld iy, (ix+3)
    ld a, (iy+31)
    cp 0xFF
    jr c, .done
    jr nz, .do_subtract
    ld a, (iy+30)
    cp 0xFF
    jr c, .done
    jr nz, .do_subtract
    ld a, (iy+28)
    cp 0xFF
    jr c, .done
    jr nz, .do_subtract
    ld a, (iy+24)
    cp 0x01
    jr c, .done
    jr nz, .do_subtract
    ld a, (iy+12)
    cp 0x00
    jr nz, .do_subtract
    ld a, (iy+0)
    cp 0xFF
    jr c, .done

.do_subtract:
    ld iy, (ix+3)
    ld hl, p256_prime
    or a
    ld b, 32
.sub_loop:
    ld a, (iy)
    sbc a, (hl)
    ld (iy), a
    inc iy
    inc hl
    djnz .sub_loop

.done:
    pop iy
    pop ix
    ret

;----------------------------------------------------------------------
; p256_mod_sub: out = (a - b) mod p
;----------------------------------------------------------------------
public _p256_mod_sub
_p256_mod_sub:
    push ix
    ld ix, 0
    add ix, sp
    push iy

    ld hl, (ix+6)
    ld de, (ix+9)
    ld iy, (ix+3)

    or a
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

    jr nc, .done

    ld iy, (ix+3)
    ld hl, p256_prime
    or a
    ld b, 32
.add_loop:
    ld a, (iy)
    adc a, (hl)
    ld (iy), a
    inc iy
    inc hl
    djnz .add_loop

.done:
    pop iy
    pop ix
    ret

;----------------------------------------------------------------------
; p256_mod_mul: out = (a * b) mod p
; Uses Montgomery multiplication
;----------------------------------------------------------------------
public _p256_mod_mul
_p256_mod_mul:
    push ix
    ld hl, -33
    call __frameset

    ld hl, 32
    push hl
    ld hl, 0x01
    push hl
    ld hl, p256_prime
    push hl
    ld hl, (ix+9)
    push hl
    ld hl, (ix+6)
    push hl
    lea hl, ix - 33
    push hl

    call _tls_mont_mul_le

    ld hl, 18
    add hl, sp
    ld sp, hl

    lea hl, ix - 32
    ld de, (ix+3)
    ld bc, 32
    ldir

    ld sp, ix
    pop ix
    ret

;----------------------------------------------------------------------
; p256_mod_sqr: out = a^2 mod p
;----------------------------------------------------------------------
public _p256_mod_sqr
_p256_mod_sqr:
    push ix
    ld ix, 0
    add ix, sp

    ld hl, (ix+6)
    push hl
    push hl
    ld hl, (ix+3)
    push hl
    call _p256_mod_mul
    pop hl
    pop hl
    pop hl

    pop ix
    ret

;----------------------------------------------------------------------
; p256_mod_inv: out = a^{-1} mod p
; Uses Fermat's little theorem: a^{-1} = a^{p-2} mod p
; Binary exponentiation (square-and-multiply)
;----------------------------------------------------------------------
public _p256_mod_inv
_p256_mod_inv:
    push ix
    ld hl, -96
    call __frameset
    ; ix+3: out, ix+6: a
    ; ix-32: result (accumulator)
    ; ix-64: temp (for squaring)
    ; ix-96: base (copy of input)

    ; Copy input to base
    lea de, ix - 96
    ld hl, (ix+6)
    ld bc, 32
    ldir

    ; Initialize result = 1
    lea hl, ix - 32
    xor a
    ld b, 32
.zero_result:
    ld (hl), a
    inc hl
    djnz .zero_result
    ld (ix-32), 1

    ; Binary exponentiation through bits of p-2
    ; p-2 = FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFD

    ; Process from MSB to LSB
    ; Start with bit 255 (MSB of byte 0 in big-endian = byte 31 in little-endian storage)

    ld hl, p256_p_minus_2
    ld b, 32
.byte_loop:
    push bc
    ld a, (hl)
    ld c, a
    inc hl
    push hl

    ld b, 8
.bit_loop:
    push bc

    ; Square result: temp = sqr(result)
    lea hl, ix - 32
    push hl
    lea hl, ix - 64
    push hl
    call _p256_mod_sqr
    pop hl
    pop hl

    ; Copy temp to result
    lea hl, ix - 64
    lea de, ix - 32
    ld bc, 32
    ldir

    ; Check if bit is set
    ld a, c
    rlca
    ld c, a
    jr nc, .bit_zero

    ; Bit is 1: multiply result by base
    ; temp = mul(result, base)
    lea hl, ix - 96
    push hl
    lea hl, ix - 32
    push hl
    lea hl, ix - 64
    push hl
    call _p256_mod_mul
    pop hl
    pop hl
    pop hl

    ; Copy temp to result
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

    ; Copy final result to output
    lea hl, ix - 32
    ld de, (ix+3)
    ld bc, 32
    ldir

    ld sp, ix
    pop ix
    ret

;----------------------------------------------------------------------
; Scalar operations mod n (curve order)
; These are needed for ECDSA signature operations
;----------------------------------------------------------------------

;----------------------------------------------------------------------
; p256_scalar_add_mod_n: out = (a + b) mod n
;----------------------------------------------------------------------
public _p256_scalar_add_mod_n
_p256_scalar_add_mod_n:
    push ix
    ld ix, 0
    add ix, sp
    push iy

    ld hl, (ix+6)
    ld de, (ix+9)
    ld iy, (ix+3)

    or a
    ld b, 32
.add_loop:
    ld a, (de)
    adc a, (hl)
    ld (iy), a
    inc hl
    inc de
    inc iy
    djnz .add_loop

    jr nc, .done

    ld a, (iy-1)
    cp 0xFF
    jr nz, .do_subtract
    ld iy, (ix+3)
    ld a, (iy+31)
    cp 0x00
    jr nz, .do_subtract
    ld a, (iy+0)
    cp 0xFF
    jr c, .done

.do_subtract:
    ld iy, (ix+3)
    ld hl, p256_order
    or a
    ld b, 32
.sub_loop:
    ld a, (iy)
    sbc a, (hl)
    ld (iy), a
    inc iy
    inc hl
    djnz .sub_loop

.done:
    pop iy
    pop ix
    ret

;----------------------------------------------------------------------
; p256_scalar_mul_mod_n: out = (a * b) mod n
;----------------------------------------------------------------------
public _p256_scalar_mul_mod_n
_p256_scalar_mul_mod_n:
    push ix
    ld hl, -33
    call __frameset

    ld hl, 32
    push hl
    ld hl, 0x01
    push hl
    ld hl, p256_order
    push hl
    ld hl, (ix+9)
    push hl
    ld hl, (ix+6)
    push hl
    lea hl, ix - 33
    push hl

    call _tls_mont_mul_le
    ld hl, 24
    add hl, sp
    ld sp, hl

    lea hl, ix - 33
    ld de, (ix+3)
    ld bc, 32
    ldir

    ld sp, ix
    pop ix
    ret

;----------------------------------------------------------------------
; p256_scalar_inv_mod_n: out = a^-1 mod n
; Uses Fermat's little theorem: a^-1 = a^(n-2) mod n
;----------------------------------------------------------------------
public _p256_scalar_inv_mod_n
_p256_scalar_inv_mod_n:
    push ix
    ld hl, -96
    call __frameset

    lea hl, ix - 96
    ld de, (ix+6)
    ld bc, 32
    ldir

    lea hl, ix - 32
    ld b, 32
.zero_loop:
    ld (hl), 0
    inc hl
    djnz .zero_loop

    ld (ix-32), 1

    ld hl, p256_n_minus_2
    ld b, 32
.byte_loop:
    push bc
    ld a, (hl)
    ld c, a
    inc hl
    push hl

    ld b, 8
.bit_loop:
    push bc

    lea hl, ix - 32
    push hl
    lea hl, ix - 64
    push hl
    call _p256_scalar_sqr_mod_n
    pop hl
    pop hl

    lea hl, ix - 64
    lea de, ix - 32
    ld bc, 32
    ldir

    ld a, c
    rlca
    ld c, a
    jr nc, .bit_zero

    lea hl, ix - 96
    push hl
    lea hl, ix - 32
    push hl
    lea hl, ix - 64
    push hl
    call _p256_scalar_mul_mod_n
    pop hl
    pop hl
    pop hl

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

    lea hl, ix - 32
    ld de, (ix+3)
    ld bc, 32
    ldir

    ld sp, ix
    pop ix
    ret

;----------------------------------------------------------------------
; p256_scalar_sqr_mod_n: Helper for inversion - out = a^2 mod n
;----------------------------------------------------------------------
_p256_scalar_sqr_mod_n:
    push ix
    ld ix, 0
    add ix, sp

    ld hl, (ix+6)
    push hl
    ld hl, (ix+6)
    push hl
    ld hl, (ix+3)
    push hl
    call _p256_scalar_mul_mod_n
    pop hl
    pop hl
    pop hl

    pop ix
    ret

;----------------------------------------------------------------------
; n-2 constant for scalar inversion (big-endian for bit scanning)
;----------------------------------------------------------------------
p256_n_minus_2:
    db 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00
    db 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    db 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84
    db 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x4F

extern __frameset
extern _tls_mont_mul_le


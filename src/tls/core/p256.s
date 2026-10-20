; ---------------------------------------------------------------------------
; p256.s -- NIST P-256 (secp256r1) for the TI-84 Plus CE (eZ80, ADL mode).
;
; Public API (C ABI, see ref/p256/p256.h):
;   bool tls_p256_publickey(uint8_t pub[65], const uint8_t priv[32]);
;   bool tls_p256_secret(uint8_t ss[32], const uint8_t priv[32],
;                        const uint8_t peer[65]);
;   bool tls_p256_sign(uint8_t sig[64], const uint8_t hash[32],
;                      const uint8_t priv[32]);
;   bool tls_p256_verify(const uint8_t sig[64], const uint8_t hash[32],
;                        const uint8_t pub[65]);
;
; This is a line-for-line translation of the correctness reference in
; ref/p256/p256.c: radix-2^8 Montgomery arithmetic (n0 = 1 for p, 0x4F for
; n), Jacobian coordinates in the Montgomery domain, a=-3 doubling, the
; "complete wrapper" Jacobian addition and a 256-step Montgomery ladder.
; Every intermediate value is bit-identical to the reference.
;
; The one structural difference is the Montgomery multiply: the reference
; is operand-scanning (CIOS, a 16-bit carry rippled through t[] on every
; MAC); here it is product-scanning (FIPS) with a 24-bit column accumulator
; in HL, so each 8x8 MAC is just `ld d,(ix+n) / ld e,(iy-n) / mlt de /
; add hl,de` with no per-MAC carry handling or t[] traffic.  The output is
; identical (same q digits, same final conditional subtraction).
;
; Non-reentrant: one static scratch block (.bss.__p256_scratch), like the
; X25519 engine.  The scratch is zeroed before every public entry returns.
;
; Internal calling convention (not C ABI):
;   - arguments in registers as documented per routine;
;   - every internal routine preserves IX (the C frame pointer);
;   - AF, BC, DE, HL, IY are clobbered unless stated otherwise.
;
; Constant-time notes: the ladder, field arithmetic, point formulas, cswap
; and select never branch on, or index memory by, secret data.  Branches
; that do exist depend only on public values (loop counters, the public
; exponents p-2 / n-2, input-validation results, and the RFC 6979 retry
; condition, exactly as in the reference).
; ---------------------------------------------------------------------------

    .assume adl=1

; ===========================================================================
; Scratch (.bss).  Layout constraints:
;   r0,r1 contiguous and saved0,saved1 contiguous (single 192-byte ldir).
;   The RFC 6979 state (DK_*) overlays r0.. -- it is dead before the ladder.
; ===========================================================================
    .section .bss.__p256_scratch,"aw",@nobits
__p256_scratch_start:
__p256_q:               .space 32       ; Montgomery quotient digits q[0..31]
__p256_f:               .space 448      ; f[0..13] field temporaries
__p256_r0:              .space 96       ; ladder R0
__p256_r1:              .space 96       ; ladder R1
__p256_saved0:          .space 96       ; point-op input P (fixed)
__p256_saved1:          .space 96       ; point-op input Q (fixed)
__p256_rt:              .space 96       ; point-op result temp
__p256_add_result:      .space 96
__p256_double_result:   .space 96
__p256_pa:              .space 96       ; verify: u1*G
__p256_pq:              .space 96       ; imported peer / public point
__p256_k:               .space 32       ; sign: nonce k (BE); verify: u1 / x(R)
__p256_x:               .space 32       ; sign: x(R) (BE);   verify: u2
; --- routine state (24-bit pointers unless noted) ---
mm_mod:                 .space 3        ; modulus pointer (field context)
mm_n0:                  .space 1        ; -m^-1 mod 256  (field context)
mm_out:                 .space 3
mm_outp:                .space 3        ; phase-2 output cursor
mm_a0:                  .space 3        ; a
mm_xa:                  .space 3        ; phase-1 IX for a-pass: a + k - 31
mm_xq:                  .space 3        ; phase-1 IX for q-pass: q + k - 31
mm_b31:                 .space 3        ; b + 31
mm_bk:                  .space 3        ; phase-2 IY for a-pass: b + k
mm_m31:                 .space 3        ; m + 31
mm_mk:                  .space 3        ; phase-2 IY for q-pass: m + k
mm_cnt:                 .space 1
mm_acc:                 .space 4        ; accumulator shift cell: [acc_lo, acc_mid, acc_hi, 0x00]
p256_di_save:           .space 1        ; IFF1 state saved at public entry (bit 0 = 1 iff ei needed)
pd_out:                 .space 3
pa_out:                 .space 3
pa_pinf:                .space 1
pa_qinf:                .space 1
pa_h:                   .space 1
pa_r:                   .space 1
sm_out:                 .space 3
sm_k:                   .space 3
sm_bit:                 .space 1
sm_prev:                .space 1
sm_cnt:                 .space 1
inv_out:                .space 3
inv_exp:                .space 3
inv_bit:                .space 1
inv_cnt:                .space 1
ae_pt:                  .space 3
ae_x:                   .space 3
ae_y:                   .space 3
pi_src:                 .space 3
hm_out:                 .space 3
hm_key:                 .space 3
hm_msg:                 .space 3
hm_len:                 .space 1
dk_hash:                .space 3
dk_priv:                .space 3
__p256_scratch_end:

; --- symbolic operand names ---
.equ PF0,  __p256_f + 0*32
.equ PF1,  __p256_f + 1*32
.equ PF2,  __p256_f + 2*32
.equ PF3,  __p256_f + 3*32
.equ PF4,  __p256_f + 4*32
.equ PF5,  __p256_f + 5*32
.equ PF6,  __p256_f + 6*32
.equ PF7,  __p256_f + 7*32
.equ PF8,  __p256_f + 8*32
.equ PF9,  __p256_f + 9*32
.equ PF10, __p256_f + 10*32
.equ PF11, __p256_f + 11*32
.equ PF12, __p256_f + 12*32
.equ PS0,  __p256_saved0
.equ PS0X, __p256_saved0 + 0
.equ PS0Y, __p256_saved0 + 32
.equ PS0Z, __p256_saved0 + 64
.equ PS1,  __p256_saved1
.equ PS1X, __p256_saved1 + 0
.equ PS1Y, __p256_saved1 + 32
.equ PS1Z, __p256_saved1 + 64
.equ PRT,  __p256_rt
.equ PRTX, __p256_rt + 0
.equ PRTY, __p256_rt + 32
.equ PRTZ, __p256_rt + 64
.equ PQX,  __p256_pq + 0
.equ PQY,  __p256_pq + 32
.equ PQZ,  __p256_pq + 64
; RFC 6979 overlay on r0.. (672 bytes available, 404 used)
.equ DK_CTX,   __p256_r0 + 0        ; struct tls_sha256_context (105 B)
.equ DK_PAD,   __p256_r0 + 112      ; 64
.equ DK_INNER, __p256_r0 + 176      ; 32
.equ DK_RFC,   __p256_r0 + 208      ; 97
.equ DK_K,     __p256_r0 + 308      ; 32
.equ DK_V,     __p256_r0 + 340      ; 32
.equ DK_H1,    __p256_r0 + 372      ; 32

; --- field-op macros: o = a (op) b.  Expand to BC=o, HL=a, DE=b, call. ---
.macro FMUL o, a, b
    ld      bc, \o
    ld      hl, \a
    ld      de, \b
    call    p256_fe_mul
.endm
.macro FSQ o, a
    FMUL    \o, \a, \a
.endm
.macro FADD o, a, b
    ld      bc, \o
    ld      hl, \a
    ld      de, \b
    call    p256_fe_add
.endm
.macro FSUB o, a, b
    ld      bc, \o
    ld      hl, \a
    ld      de, \b
    call    p256_fe_sub
.endm
.macro OMUL o, a, b
    ld      bc, \o
    ld      hl, \a
    ld      de, \b
    call    p256_ord_mul
.endm
.macro OADD o, a, b
    ld      bc, \o
    ld      hl, \a
    ld      de, \b
    call    p256_ord_add
.endm

; ===========================================================================
; Read-only constants (all 32-byte little-endian unless *_BE).
; ===========================================================================
    .section .rodata.__p256_const,"a",@progbits
__p256_P:
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00
    .db     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    .db     0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF

__p256_P_R2:
    .db     0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0xFB, 0xFF, 0xFF, 0xFF
    .db     0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    .db     0xFD, 0xFF, 0xFF, 0xFF, 0x04, 0x00, 0x00, 0x00

__p256_P_MINUS_2_BE:
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01
    .db     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    .db     0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFD

__p256_P_B_R:
    .db     0xDF, 0xBD, 0xC4, 0x29, 0x62, 0xDF, 0x9C, 0xD8
    .db     0x90, 0x30, 0x84, 0x78, 0xCD, 0x05, 0xF0, 0xAC
    .db     0xD6, 0x2E, 0x21, 0xF7, 0xAB, 0x20, 0xA2, 0xE5
    .db     0x34, 0x48, 0x87, 0x04, 0x1D, 0x06, 0x30, 0xDC

__p256_N:
    .db     0x51, 0x25, 0x63, 0xFC, 0xC2, 0xCA, 0xB9, 0xF3
    .db     0x84, 0x9E, 0x17, 0xA7, 0xAD, 0xFA, 0xE6, 0xBC
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    .db     0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF

__p256_N_R:
    .db     0xAF, 0xDA, 0x9C, 0x03, 0x3D, 0x35, 0x46, 0x0C
    .db     0x7B, 0x61, 0xE8, 0x58, 0x52, 0x05, 0x19, 0x43
    .db     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00

__p256_N_R2:
    .db     0xA2, 0xEE, 0x79, 0xBE, 0x95, 0x4C, 0x24, 0x83
    .db     0xA6, 0x6F, 0xBD, 0x49, 0x9C, 0x79, 0x99, 0x46
    .db     0x59, 0xEC, 0x6B, 0x2B, 0x39, 0xB2, 0x45, 0x28
    .db     0x20, 0x56, 0xD9, 0xF3, 0x94, 0x2D, 0xE1, 0x66

__p256_N_MINUS_2_BE:
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    .db     0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84
    .db     0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x4F

; Generator in Montgomery-Jacobian form: (Gx*R, Gy*R, R).  __p256_P_R (= R mod
; p, also "1" in the Montgomery domain) is the z coordinate, shared.
__p256_G:
    .db     0x3C, 0x14, 0xA9, 0x18, 0xD4, 0x30, 0xE7, 0x79
    .db     0x01, 0xB6, 0xED, 0x5F, 0xFC, 0x95, 0xBA, 0x75
    .db     0x10, 0x25, 0x62, 0x77, 0x2B, 0x73, 0xFB, 0x79
    .db     0xC6, 0x55, 0x37, 0xA5, 0x76, 0x5F, 0x90, 0x18

__p256_G_Y:
    .db     0x0A, 0x56, 0x95, 0xCE, 0x57, 0x53, 0xF2, 0xDD
    .db     0x5C, 0xE4, 0x19, 0xBA, 0xE4, 0xB8, 0x4A, 0x8B
    .db     0x25, 0xF3, 0x21, 0xDD, 0x88, 0x86, 0xE8, 0xD2
    .db     0x85, 0x5D, 0x88, 0x25, 0x18, 0xFF, 0x71, 0x85

__p256_P_R:
    .db     0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    .db     0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    .db     0xFE, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00

; Point at infinity in the reference's encoding: (0, R, 0).
__p256_INF:
    .space  32, 0
    .db     0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    .db     0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    .db     0xFE, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00
    .space  32, 0
; Plain integer 1 (Montgomery-domain exit multiplier).
__p256_ONE:
    .db     0x01
    .space  31, 0

; ===========================================================================
; Field context and thin wrappers
; ===========================================================================
    .section .text.__p256,"ax",@progbits

; p256_ctx_p / p256_ctx_n: select modulus p (n0=1) or n (n0=0x4F).
; In: -  Out: mm_mod, mm_n0.  Clobbers: A, IY.  Preserves BC, DE, HL.
p256_ctx_p:
    ld      iy, __p256_P
    ld      (mm_mod), iy
    ld      a, 0x01
    ld      (mm_n0), a
    ret
p256_ctx_n:
    ld      iy, __p256_N
    ld      (mm_mod), iy
    ld      a, 0x4F
    ld      (mm_n0), a
    ret

; fe_* (mod p) / ord_* (mod n).  In: HL=a, DE=b, BC=out.  Out may alias a/b.
p256_fe_mul:
    call    p256_ctx_p
    jp      p256_mont_core
p256_fe_add:
    call    p256_ctx_p
    jp      p256_modadd_core
p256_fe_sub:
    call    p256_ctx_p
    jr      p256_modsub_core
p256_ord_mul:
    call    p256_ctx_n
    jp      p256_mont_core
p256_ord_add:
    call    p256_ctx_n
    jp      p256_modadd_core

; ===========================================================================
; Small helpers
; ===========================================================================

; p256_modsub_core: out = a - b mod m.   In: HL=a, DE=b, BC=out, mm_mod.
; Out may alias a or b.  Clobbers AF, BC, DE, HL, IY.
p256_modsub_core:
    push    bc
    pop     iy                  ; IY = out
    ex      de, hl              ; HL = b, DE = a
    ld      b, 32
    or      a, a
.Lms_loop:
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 0), a
    inc     hl
    inc     de
    inc     iy
    djnz    .Lms_loop
    sbc     a, a                ; A = borrow ? 0xFF : 0
    ld      c, a
    lea     iy, iy - 32
    ld      hl, (mm_mod)
    jr      p256_addback

; p256_modadd_core: out = a + b mod m.   In: HL=a, DE=b, BC=out, mm_mod.
; Requires a, b < m.  Out may alias a or b.  Clobbers AF, BC, DE, HL, IY.
p256_modadd_core:
    push    bc
    pop     iy                  ; IY = out
    ld      b, 32
    or      a, a
.Lma_loop:
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 0), a
    inc     hl
    inc     de
    inc     iy
    djnz    .Lma_loop
    sbc     a, a                ; A = carry-out ? 0xFF : 0
    ld      c, a
    lea     hl, iy - 32
    ld      de, (mm_mod)
    ; fall through

; p256_reduce_top: x = (top:x >= m) ? top:x - m : x, given top:x < 2m.
; In: HL=x (in place), DE=m, C=top mask (0xFF iff bit 256 set, else 0).
; Clobbers AF, BC, DE, HL, IY.   Branch-free.
p256_reduce_top:
    push    hl
    pop     iy                  ; IY = x
    ex      de, hl              ; HL = m
    push    hl
    ld      b, 32
    or      a, a
.Lrt_sub:
    ld      a, (iy + 0)
    sbc     a, (hl)
    ld      (iy + 0), a
    inc     iy
    inc     hl
    djnz    .Lrt_sub
    sbc     a, a                ; A = borrow ? 0xFF : 0
    ld      b, a
    ld      a, c
    cpl
    and     a, b                ; add back m iff borrow && !top
    ld      c, a
    pop     hl                  ; HL = m
    lea     iy, iy - 32         ; IY = x
    ; fall through

; p256_addback: x += m & mask  (mod 2^256).
; In: IY=x, HL=m, C=mask (0x00/0xFF).  Clobbers AF, BC, DE, HL, IY.
; The mask is applied with MLT (which leaves flags intact) instead of AND
; (which would clear the carry chain).
p256_addback:
    ld      a, c
    and     a, 0x01
    ld      c, a                ; C = 0 or 1
    ld      b, 32
    or      a, a
.Lab_loop:
    ld      d, (hl)
    ld      e, c
    mlt     de                  ; E = m[i] * bit   (flags preserved)
    ld      a, (iy + 0)
    adc     a, e
    ld      (iy + 0), a
    inc     iy
    inc     hl
    djnz    .Lab_loop
    ret

; p256_raw_ge: A = (a >= m) ? 1 : 0.  In: HL=a, DE=m.  Clobbers AF, B, DE, HL.
p256_raw_ge:
    ld      b, 32
    or      a, a
.Lge_loop:
    ld      a, (hl)
    ex      de, hl
    sbc     a, (hl)
    ex      de, hl
    inc     hl
    inc     de
    djnz    .Lge_loop
    sbc     a, a                ; 0xFF iff a < m
    inc     a
    ret

; p256_ct_is_zero: A = 0xFF if the 32 bytes at HL are all zero, else 0x00.
; In: HL.  Clobbers AF, B, HL.  Branch-free on the data.
p256_ct_is_zero:
    ld      b, 32
    xor     a, a
.Lz_loop:
    or      a, (hl)
    inc     hl
    djnz    .Lz_loop
    neg                         ; CF = (A != 0)
    sbc     a, a                ; 0xFF iff nonzero
    cpl                         ; 0xFF iff zero
    ret

; p256_eq32: A = 1 if the 32 bytes at HL equal those at DE, else 0.
; In: HL, DE.  Clobbers AF, BC, DE, HL.  Branch-free on the data.
p256_eq32:
    ld      bc, 32 << 8
.Leq_loop:
    ld      a, (de)
    xor     a, (hl)
    or      a, c
    ld      c, a
    inc     hl
    inc     de
    djnz    .Leq_loop
    ld      a, c
    sub     a, 1                ; CF iff C == 0
    sbc     a, a
    and     a, 0x01
    ret

; p256_rev32: dst[i] = src[31-i].  In: HL=src, DE=dst (must not overlap).
; Clobbers AF, BC, DE, HL.
p256_rev32:
    ld      bc, 31
    add     hl, bc
    ld      b, 32
.Lrv_loop:
    ld      a, (hl)
    ld      (de), a
    dec     hl
    inc     de
    djnz    .Lrv_loop
    ret

; p256_point_select: out = mask ? b : a  (96 bytes).
; In: HL=a, DE=b, IY=out, C=mask (0x00/0xFF).  out may alias a or b.
; Clobbers AF, B, DE, HL, IY.
p256_point_select:
    ld      b, 96
.Lps_loop:
    ld      a, (de)
    xor     a, (hl)
    and     a, c
    xor     a, (hl)
    ld      (iy + 0), a
    inc     hl
    inc     de
    inc     iy
    djnz    .Lps_loop
    ret

; p256_point_cswap: if mask, swap the 96-byte points at HL and DE.
; In: HL=a, DE=b, C=mask (0x00/0xFF).  Clobbers AF, B, DE, HL, IYL.
p256_point_cswap:
    ld      iyl, 96
.Lcs_loop:
    ld      a, (de)
    xor     a, (hl)
    and     a, c                ; t = mask & (a ^ b)
    ld      b, a
    xor     a, (hl)
    ld      (hl), a             ; a ^= t
    ld      a, (de)
    xor     a, b
    ld      (de), a             ; b ^= t
    inc     hl
    inc     de
    dec     iyl
    jr      nz, .Lcs_loop
    ret

; p256_import_be: out = big-endian in[32] as LE; reject if >= m, or (C!=0
; and) zero.  In: HL=out, DE=in, IY=m, C=reject_zero.  Out: A = 1 ok / 0.
; Clobbers AF, BC, DE, HL.  Preserves IY.
p256_import_be:
    push    hl
    push    bc
    ex      de, hl
    call    p256_rev32
    pop     bc
    pop     hl
    push    hl
    push    bc
    lea     de, iy + 0
    call    p256_raw_ge
    pop     bc
    pop     hl
    or      a, a
    jr      nz, .Lib_fail
    ld      a, c
    or      a, a
    jr      z, .Lib_ok
    call    p256_ct_is_zero
    inc     a                   ; zero (0xFF) -> 0 = reject; else 1
    ret
.Lib_ok:
    ld      a, 1
    ret
.Lib_fail:
    xor     a, a
    ret

; ===========================================================================
; Montgomery multiplication  (THE hot path)
;
; p256_mont_core: out = a * b * 2^-256 mod m
;   In:  HL=a, DE=b, BC=out (32-byte LE), mm_mod = m, mm_n0 = -m^-1 mod 256.
;   Out: out fully reduced (< m) whenever a, b < m.  out may alias a and/or b.
;   Clobbers AF, BC, DE, HL, IY.  Preserves IX.  Stack: 12 bytes.
;
; Product scanning (FIPS), radix 2^8, s = 32 digits:
;   acc = 0
;   for k = 0..31:   acc += sum_{i=0..k} a[i]b[k-i] + sum_{i=0..k} q[i]m[k-i]
;                    (q[k] is still 0 here)
;                    q[k] = (acc mod 256) * n0 mod 256;  acc += q[k] m[0]
;                    acc >>= 8                       (low byte is now 0)
;   for k = 32..62:  acc += sum_{i=k-31..31} a[i]b[k-i] + q[i]m[k-i]
;                    out[k-32] = acc mod 256;  acc >>= 8
;   out[31] = acc mod 256;  top = acc >> 8 (0 or 1)
;   conditional subtract of m (p256_reduce_top).
; This yields exactly the reference CIOS result: q[k] is the same digit and
; the final value equals (ab + qm)/2^256 in both formulations.
;
; The accumulator is 24-bit HL.  Worst column (k = 31) is 64 products of
; <= 0xFE01 plus a carry-in < 2^16: < 4.3e6 < 2^24, so no overflow.
;
; Aliasing: phase 2 column k writes out[k-32] and only ever reads a[], b[]
; at indices >= k-31, so out == a and/or out == b is safe.
;
; Each column's sums run through .Lmac_blk, a 32-term unrolled MAC block,
; entered part-way for shorter columns (column lengths are public).
; Term n of the block is  acc += (ix+n) * (iy-n).
;
; INTERRUPT SAFETY: public entry points call di (via tls_crypto_guard_enable
; pattern) before any field work.  The accumulator shift uses mm_acc, a
; 4-byte .bss cell whose byte 3 is always 0 (initialised to 0 by the BSS
; zero-fill and never written beyond byte 2), so ld hl,(mm_acc+1) always
; loads HLU = 0, with no stack manipulation and no interrupt window.
; ===========================================================================
p256_mont_core:
    push    ix
    ld      (mm_out), bc
    ld      (mm_outp), bc
    ld      (mm_a0), hl
    ld      bc, -31
    add     hl, bc
    ld      (mm_xa), hl         ; a - 31
    ex      de, hl              ; HL = b
    ld      bc, 31
    add     hl, bc
    ld      (mm_b31), hl        ; b + 31
    inc     hl
    ld      (mm_bk), hl         ; b + 32
    ld      hl, (mm_mod)
    add     hl, bc
    ld      (mm_m31), hl        ; m + 31
    inc     hl
    ld      (mm_mk), hl         ; m + 32
    ld      hl, __p256_q - 31
    ld      (mm_xq), hl
    ld      hl, __p256_q        ; q[] = 0
    ld      (hl), 0
    ld      de, __p256_q + 1
    ld      bc, 31
    ldir
    ld      hl, 0               ; acc = 0
    ld      bc, .Lmac_end - 9   ; entry for a 1-term column
    ld      a, 32
    ld      (mm_cnt), a

; ---- phase 1: columns 0..31 ----
.Lmm_p1:
    ld      ix, (mm_xa)         ; a + k - 31
    ld      iy, (mm_b31)        ; b + 31
    call    .Lmm_jp_bc          ; acc += sum a[i] b[k-i]
    ld      ix, (mm_xq)         ; q + k - 31
    ld      iy, (mm_m31)        ; m + 31
    call    .Lmm_jp_bc          ; acc += sum q[i] m[k-i]   (q[k] = 0)
    ld      a, (mm_n0)
    ld      d, a
    ld      e, l
    mlt     de                  ; E = q_k = acc * n0 mod 256
    ld      (ix + 31), e        ; q[k] = q_k
    ld      d, (iy - 31)        ; m[0]
    mlt     de
    add     hl, de              ; acc += q_k * m[0]  -> low byte 0
    ; acc >>= 8 via static cell: ld (mm_acc),hl writes bytes 0-2;
    ; ld hl,(mm_acc+1) reloads bytes 1-3.  Byte 3 is always 0 in .bss
    ; (never written), so HLU = 0.  No stack manipulation; interrupt-safe.
    ld      (mm_acc), hl
    ld      hl, (mm_acc + 1)
    inc     ix
    ld      (mm_xq), ix
    ld      ix, (mm_xa)
    inc     ix
    ld      (mm_xa), ix
    ld      iy, -9
    add     iy, bc
    lea     bc, iy + 0          ; one more term next column
    ld      a, (mm_cnt)
    dec     a
    ld      (mm_cnt), a
    jr      nz, .Lmm_p1

; ---- phase 2: columns 32..62 ----
    ld      bc, .Lmac_end - 9*31
    ld      a, 31
    ld      (mm_cnt), a
.Lmm_p2:
    ld      ix, (mm_a0)         ; a
    ld      iy, (mm_bk)         ; b + k
    call    .Lmm_jp_bc
    ld      ix, __p256_q        ; q
    ld      iy, (mm_mk)         ; m + k
    call    .Lmm_jp_bc
    ld      iy, (mm_outp)
    ld      (iy + 0), l         ; out[k-32] = acc mod 256
    inc     iy
    ld      (mm_outp), iy
    ld      (mm_acc), hl        ; acc >>= 8 (same interrupt-safe method)
    ld      hl, (mm_acc + 1)
    ld      iy, (mm_bk)
    inc     iy
    ld      (mm_bk), iy
    ld      iy, (mm_mk)
    inc     iy
    ld      (mm_mk), iy
    ld      iy, 9
    add     iy, bc
    lea     bc, iy + 0          ; one fewer term next column
    ld      a, (mm_cnt)
    dec     a
    ld      (mm_cnt), a
    jr      nz, .Lmm_p2

    ld      iy, (mm_outp)
    ld      (iy + 0), l         ; out[31]
    ld      a, h                ; top bit (0 or 1)
    pop     ix
    neg
    sbc     a, a                ; top mask
    ld      c, a
    ld      hl, (mm_out)
    ld      de, (mm_mod)
    jp      p256_reduce_top

.Lmm_jp_bc:
    push    bc
    ret

; 32-term MAC block: term n is acc += (ix+n) * (iy-n).  Each term is exactly
; 9 bytes (3+3+2+1); the entry for a c-term column is .Lmac_end - 9*c.
; Uses only D, E, HL, IX, IY (read-only).  BC and A are preserved.
.Lmac_blk:
.irp n, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
    ld      d, (ix + \n)
    ld      e, (iy - \n)
    mlt     de
    add     hl, de
.endr
.Lmac_end:
    ret

; ===========================================================================
; Modular inversion by Fermat: out = a^(m-2) (Montgomery domain).
; p256_mod_inv: In: HL=a, BC=out, DE=exponent (BE, public), IY=one_r,
;               mm_mod/mm_n0 already set.  a must not be f[11]/f[12].
; Clobbers AF, BC, DE, HL, IY.  Branches only on the public exponent.
; ===========================================================================
p256_fe_inv:                    ; In: HL=a, BC=out (mod p)
    call    p256_ctx_p
    ld      de, __p256_P_MINUS_2_BE
    ld      iy, __p256_P_R
    jr      p256_mod_inv
p256_ord_inv:                   ; In: HL=a, BC=out (mod n)
    call    p256_ctx_n
    ld      de, __p256_N_MINUS_2_BE
    ld      iy, __p256_N_R
p256_mod_inv:
    ld      (inv_out), bc
    ld      (inv_exp), de
    push    hl
    lea     hl, iy + 0
    ld      de, PF11
    ld      bc, 32
    ldir                        ; f11 = 1 (Montgomery)
    pop     hl
    ld      de, PF12
    ld      bc, 32
    ldir                        ; f12 = a
    xor     a, a
    ld      (inv_cnt), a        ; 256 iterations
    ld      a, 0x80
    ld      (inv_bit), a
.Linv_loop:
    ld      hl, PF11
    ld      de, PF11
    ld      bc, PF11
    call    p256_mont_core
    ld      hl, (inv_exp)
    ld      a, (inv_bit)
    and     a, (hl)
    jr      z, .Linv_skip       ; public exponent bit
    ld      hl, PF11
    ld      de, PF12
    ld      bc, PF11
    call    p256_mont_core
.Linv_skip:
    ld      a, (inv_bit)
    rrca
    ld      (inv_bit), a
    jr      nc, .Linv_same
    ld      hl, (inv_exp)
    inc     hl
    ld      (inv_exp), hl
.Linv_same:
    ld      a, (inv_cnt)
    dec     a
    ld      (inv_cnt), a
    jr      nz, .Linv_loop
    ld      hl, PF11
    ld      de, (inv_out)
    ld      bc, 32
    ldir
    ret

; ===========================================================================
; Point arithmetic (Montgomery-Jacobian, 96-byte points x||y||z)
; ===========================================================================

; p256_point_double: out = 2 * saved0 (a = -3).  In: HL=out.
; Uses f[0..6], rt.  out must not be saved0, rt or f[].
; Clobbers AF, BC, DE, HL, IY.
p256_point_double:
    ld      (pd_out), hl
    FSQ     PF0, PS0Z                   ; delta = Z^2
    FSQ     PF1, PS0Y                   ; gamma = Y^2
    FMUL    PF2, PS0X, PF1              ; beta = X*gamma
    FSUB    PF3, PS0X, PF0
    FADD    PF4, PS0X, PF0
    FMUL    PF3, PF3, PF4
    FADD    PF4, PF3, PF3
    FADD    PF3, PF4, PF3               ; alpha = 3(X-delta)(X+delta)
    FSQ     PRTX, PF3
    FADD    PF4, PF2, PF2
    FADD    PF4, PF4, PF4
    FADD    PF5, PF4, PF4               ; 8 beta
    FSUB    PRTX, PRTX, PF5             ; X3 = alpha^2 - 8 beta
    FADD    PF6, PS0Y, PS0Z
    FSQ     PF6, PF6
    FSUB    PF6, PF6, PF1
    FSUB    PRTZ, PF6, PF0              ; Z3 = (Y+Z)^2 - gamma - delta
    FSUB    PF4, PF4, PRTX
    FMUL    PF4, PF3, PF4
    FSQ     PF1, PF1
    FADD    PF1, PF1, PF1
    FADD    PF1, PF1, PF1
    FADD    PF1, PF1, PF1               ; 8 gamma^2
    FSUB    PRTY, PF4, PF1              ; Y3 = alpha(4beta - X3) - 8gamma^2
    ld      hl, PS0Z
    call    p256_ct_is_zero
    ld      c, a
    ld      hl, PRT
    ld      de, __p256_INF
    ld      iy, (pd_out)
    jp      p256_point_select           ; out = (Z==0) ? inf : rt

; p256_point_add: out = saved0 + saved1 (complete wrapper, as reference).
; In: HL=out.  Uses f[0..12], rt, add_result, double_result.
; out must not be saved0/saved1/rt/add_result/double_result/f[].
; Clobbers AF, BC, DE, HL, IY.
p256_point_add:
    ld      (pa_out), hl
    FSQ     PF0, PS0Z
    FSQ     PF1, PS1Z
    FMUL    PF2, PS0X, PF1              ; U1
    FMUL    PF3, PS1X, PF0              ; U2
    FMUL    PF4, PS1Z, PF1
    FMUL    PF4, PS0Y, PF4              ; S1
    FMUL    PF5, PS0Z, PF0
    FMUL    PF5, PS1Y, PF5              ; S2
    FSUB    PF6, PF3, PF2               ; H
    FADD    PF7, PF6, PF6
    FSQ     PF7, PF7                    ; I
    FMUL    PF8, PF6, PF7               ; J
    FSUB    PF9, PF5, PF4
    FADD    PF9, PF9, PF9               ; r
    FMUL    PF10, PF2, PF7              ; V
    FSQ     PRTX, PF9
    FSUB    PRTX, PRTX, PF8
    FADD    PF11, PF10, PF10
    FSUB    PRTX, PRTX, PF11
    FSUB    PF11, PF10, PRTX
    FMUL    PF11, PF9, PF11
    FMUL    PF12, PF4, PF8
    FADD    PF12, PF12, PF12
    FSUB    PRTY, PF11, PF12
    FADD    PF11, PS0Z, PS1Z
    FSQ     PF11, PF11
    FSUB    PF11, PF11, PF0
    FSUB    PF11, PF11, PF1
    FMUL    PRTZ, PF11, PF6
    ld      hl, PS0Z
    call    p256_ct_is_zero
    ld      (pa_pinf), a
    ld      hl, PS1Z
    call    p256_ct_is_zero
    ld      (pa_qinf), a
    ld      hl, PF6
    call    p256_ct_is_zero
    ld      (pa_h), a
    ld      hl, PF9
    call    p256_ct_is_zero
    ld      (pa_r), a
    ld      hl, PRT
    ld      de, __p256_add_result
    ld      bc, 96
    ldir
    ld      hl, __p256_double_result
    call    p256_point_double           ; always computed (constant work)
    ld      a, (pa_h)
    ld      b, a
    ld      a, (pa_r)
    and     a, b
    ld      c, a                        ; h_zero & r_zero
    ld      hl, __p256_add_result
    ld      de, __p256_double_result
    ld      iy, PRT
    call    p256_point_select
    ld      a, (pa_r)
    cpl
    ld      b, a
    ld      a, (pa_h)
    and     a, b
    ld      c, a                        ; h_zero & ~r_zero
    ld      hl, PRT
    ld      de, __p256_INF
    ld      iy, PRT
    call    p256_point_select
    ld      a, (pa_pinf)
    ld      c, a
    ld      hl, PRT
    ld      de, PS1
    ld      iy, PRT
    call    p256_point_select           ; P = inf -> Q
    ld      a, (pa_qinf)
    ld      c, a
    ld      hl, PRT
    ld      de, PS0
    ld      iy, (pa_out)
    jp      p256_point_select           ; Q = inf -> P

; p256_scalar_mul: out = scalar * point, Montgomery ladder, 256 steps,
; constant sequence of operations independent of the scalar.
; In: HL=out, DE=scalar (32 B big-endian), BC=point (96 B).
; scalar/point must not lie in the ladder scratch (r0,r1,saved*,rt,
; add_result,double_result,f[]).  out may be saved0 or any free buffer.
; Clobbers AF, BC, DE, HL, IY.
p256_scalar_mul:
    ld      (sm_out), hl
    ld      (sm_k), de
    push    bc
    pop     hl
    ld      de, __p256_r1
    ld      bc, 96
    ldir                                ; r1 = point
    ld      hl, __p256_INF
    ld      de, __p256_r0
    ld      bc, 96
    ldir                                ; r0 = inf
    xor     a, a
    ld      (sm_prev), a
    ld      (sm_cnt), a                 ; 256 iterations
    ld      a, 0x80
    ld      (sm_bit), a
.Lsm_loop:
    ld      hl, (sm_k)
    ld      a, (sm_bit)
    and     a, (hl)
    add     a, 0xFF                     ; CF = bit set
    sbc     a, a                        ; A = bit ? 0xFF : 0
    ld      b, a
    ld      a, (sm_prev)
    xor     a, b
    ld      c, a                        ; swap mask = value ^ previous
    ld      a, b
    ld      (sm_prev), a
    ld      hl, __p256_r0
    ld      de, __p256_r1
    call    p256_point_cswap
    ld      hl, __p256_r0
    ld      de, __p256_saved0
    ld      bc, 192
    ldir                                ; saved0 = r0, saved1 = r1
    ld      hl, __p256_r1
    call    p256_point_add              ; r1 = r0 + r1
    ld      hl, __p256_r0
    call    p256_point_double           ; r0 = 2 r0
    ld      a, (sm_bit)                 ; advance to next bit (public index)
    rrca
    ld      (sm_bit), a
    jr      nc, .Lsm_same
    ld      hl, (sm_k)
    inc     hl
    ld      (sm_k), hl
.Lsm_same:
    ld      a, (sm_cnt)
    dec     a
    ld      (sm_cnt), a
    jr      nz, .Lsm_loop
    ld      a, (sm_prev)
    ld      c, a
    ld      hl, __p256_r0
    ld      de, __p256_r1
    call    p256_point_cswap
    ld      hl, __p256_r0
    ld      de, (sm_out)
    ld      bc, 96
    ldir
    ret

; ===========================================================================
; Import / export
; ===========================================================================

; p256_affine_export: x_be (and y_be if non-NULL) of a Jacobian point.
; In: HL=point (not in f[0..4]), DE=x_be, BC=y_be or 0.
; Out: A = 1, or 0 if the point is at infinity.  Uses f[0..3], f[11..12].
p256_affine_export:
    ld      (ae_pt), hl
    ld      (ae_x), de
    ld      (ae_y), bc
    ld      de, 64
    add     hl, de                      ; Z
    push    hl
    call    p256_ct_is_zero
    pop     hl
    inc     a
    ret     z                           ; infinity -> A = 0
    ld      bc, PF0
    call    p256_fe_inv                 ; f0 = Z^-1
    FSQ     PF1, PF0                    ; Z^-2
    ld      hl, (ae_pt)
    ld      de, PF1
    ld      bc, PF2
    call    p256_fe_mul                 ; f2 = X Z^-2
    ld      hl, (ae_y)
    add     hl, de
    or      a, a
    sbc     hl, de
    jr      z, .Lae_noy
    FMUL    PF1, PF1, PF0               ; Z^-3
    ld      hl, (ae_pt)
    ld      de, 32
    add     hl, de
    ld      de, PF1
    ld      bc, PF3
    call    p256_fe_mul                 ; f3 = Y Z^-3
    FMUL    PF3, PF3, __p256_ONE        ; leave Montgomery domain
    ld      hl, PF3
    ld      de, (ae_y)
    call    p256_rev32
.Lae_noy:
    FMUL    PF2, PF2, __p256_ONE
    ld      hl, PF2
    ld      de, (ae_x)
    call    p256_rev32
    ld      a, 1
    ret

; p256_point_import: validate and import an uncompressed SEC1 point into pq.
; In: HL=pub (65 bytes, non-NULL).  Out: A = 1 ok / 0 reject.
; Rejects: prefix != 0x04, x >= p, y >= p, point not on the curve.
p256_point_import:
    ld      a, (hl)
    cp      a, 0x04
    jp      nz, .Lpi_fail
    inc     hl
    ld      (pi_src), hl
    ex      de, hl
    ld      hl, PF0
    ld      iy, __p256_P
    ld      c, 0
    call    p256_import_be
    or      a, a
    jp      z, .Lpi_fail
    ld      hl, (pi_src)
    ld      de, 32
    add     hl, de
    ex      de, hl
    ld      hl, PF1
    ld      iy, __p256_P
    ld      c, 0
    call    p256_import_be
    or      a, a
    jp      z, .Lpi_fail
    FMUL    PQX, PF0, __p256_P_R2
    FMUL    PQY, PF1, __p256_P_R2
    ld      hl, __p256_P_R
    ld      de, PQZ
    ld      bc, 32
    ldir
    FSQ     PF2, PQY                    ; y^2
    FSQ     PF3, PQX
    FMUL    PF3, PF3, PQX               ; x^3
    FADD    PF4, PQX, PQX
    FADD    PF4, PF4, PQX               ; 3x
    FSUB    PF3, PF3, PF4
    FADD    PF3, PF3, __p256_P_B_R      ; x^3 - 3x + b
    ld      hl, PF2
    ld      de, PF3
    jp      p256_eq32
.Lpi_fail:
    xor     a, a
    ret

; p256_order_import: out = (be mod n) * R mod n.  In: HL=out, DE=be.
; Uses f[0].  Clobbers AF, BC, DE, HL, IY.
p256_order_import:
    push    hl
    ex      de, hl
    ld      de, PF0
    call    p256_rev32
    ld      hl, PF0
    ld      de, __p256_N
    ld      c, 0
    call    p256_reduce_top
    pop     bc
    ld      hl, PF0
    ld      de, __p256_N_R2
    jp      p256_ord_mul

; p256_order_export: be = a * R^-1 mod n, big-endian.  In: HL=a, DE=be.
; Uses f[1].  Clobbers AF, BC, DE, HL, IY.
p256_order_export:
    push    de
    ld      de, __p256_ONE
    ld      bc, PF1
    call    p256_ord_mul
    pop     de
    ld      hl, PF1
    jp      p256_rev32

; p256_di: save IFF1 into p256_di_save (bit 0) then disable interrupts.
; Must be called once per public entry, before any field work.
; Clobbers AF.  Preserves BC, DE, HL, IX, IY.
; ld a,i sets PV = IFF2 = IFF1 (outside an NMI); jp pe tests PV immediately.
p256_di:
    ld      a, i            ; PV = IFF1
    jp      pe, .Lpd_on     ; PV set = interrupts enabled
    xor     a
    ld      (p256_di_save), a   ; save 0: ei not needed on exit
    di
    ret
.Lpd_on:
    ld      a, 1
    ld      (p256_di_save), a   ; save 1: ei needed on exit
    di
    ret

; p256_wipe: zero the whole scratch block.  Clobbers BC, DE, HL.
p256_wipe:
    ld      hl, __p256_scratch_start
    ld      (hl), 0
    ld      de, __p256_scratch_start + 1
    ld      bc, __p256_scratch_end - __p256_scratch_start - 1
    ldir
    ret

; p256_exit: common public-API epilogue.  In: A = result.  Expects the
; stack to hold only the caller's saved IX above the return address.
; Restores interrupts (re-enables them iff they were enabled on entry).
; The IFF1 save is the byte we stashed at entry in mm_n0+4 (p256_di_save).
p256_exit:
    push    af
    ld      a, (p256_di_save)   ; save before wipe zeroes it
    push    af                  ; stash di_save below result
    call    p256_wipe
    pop     af                  ; A = di_save
    bit     0, a
    jr      z, .Lpx_noei
    ei
.Lpx_noei:
    pop     af                  ; A = result
    pop     ix
    ret

; p256_null: Z set iff HL == 0.  Clobbers F.  Preserves HL, DE.
p256_null:
    add     hl, de
    or      a, a
    sbc     hl, de
    ret

; ===========================================================================
; Public API: publickey / secret / verify
; ===========================================================================
    globl   _tls_p256_publickey
    .type   _tls_p256_publickey, @function
    globl   _tls_p256_secret
    .type   _tls_p256_secret, @function
    globl   _tls_p256_verify
    .type   _tls_p256_verify, @function

; bool tls_p256_publickey(uint8_t pub[65], const uint8_t priv[32])
; Stack: (ix+6)=pub, (ix+9)=priv.  Out: A = 1/0.
_tls_p256_publickey:
    push    ix
    ld      ix, 0
    add     ix, sp
    call    p256_di
    ld      hl, (ix + 6)
    call    p256_null
    jr      z, .Lpk_fail
    ld      hl, (ix + 9)
    call    p256_null
    jr      z, .Lpk_fail
    ld      hl, PF0
    ld      de, (ix + 9)
    ld      iy, __p256_N
    ld      c, 1
    call    p256_import_be              ; 1 <= priv < n
    or      a, a
    jr      z, .Lpk_fail
    ld      hl, __p256_saved0
    ld      de, (ix + 9)
    ld      bc, __p256_G
    call    p256_scalar_mul
    ld      hl, (ix + 6)
    ld      (hl), 0x04
    inc     hl
    ex      de, hl                      ; DE = pub + 1
    ld      hl, 32
    add     hl, de
    push    hl
    pop     bc                          ; BC = pub + 33
    ld      hl, __p256_saved0
    call    p256_affine_export
    jp      p256_exit
.Lpk_fail:
    xor     a, a
    jp      p256_exit

; bool tls_p256_secret(uint8_t ss[32], const uint8_t priv[32],
;                      const uint8_t peer[65])
; Stack: (ix+6)=ss, (ix+9)=priv, (ix+12)=peer.  Out: A = 1/0.
_tls_p256_secret:
    push    ix
    ld      ix, 0
    add     ix, sp
    call    p256_di
    ld      hl, (ix + 6)
    call    p256_null
    jr      z, .Lss_fail
    ld      hl, (ix + 9)
    call    p256_null
    jr      z, .Lss_fail
    ld      hl, PF0
    ld      de, (ix + 9)
    ld      iy, __p256_N
    ld      c, 1
    call    p256_import_be
    or      a, a
    jr      z, .Lss_fail
    ld      hl, (ix + 12)
    call    p256_null
    jr      z, .Lss_fail
    call    p256_point_import
    or      a, a
    jr      z, .Lss_fail
    ld      hl, __p256_saved0
    ld      de, (ix + 9)
    ld      bc, __p256_pq
    call    p256_scalar_mul
    ld      hl, __p256_saved0
    ld      de, (ix + 6)
    ld      bc, 0
    call    p256_affine_export
    jp      p256_exit
.Lss_fail:
    xor     a, a
    jp      p256_exit

; bool tls_p256_verify(const uint8_t sig[64], const uint8_t hash[32],
;                      const uint8_t pub[65])
; Stack: (ix+6)=sig, (ix+9)=hash, (ix+12)=pub.  Out: A = 1/0.
_tls_p256_verify:
    push    ix
    ld      ix, 0
    add     ix, sp
    call    p256_di
    ld      hl, (ix + 6)
    call    p256_null
    jp      z, .Lvf_fail
    ld      hl, (ix + 9)
    call    p256_null
    jp      z, .Lvf_fail
    ld      hl, (ix + 12)
    call    p256_null
    jp      z, .Lvf_fail
    call    p256_point_import           ; Q -> pq
    or      a, a
    jp      z, .Lvf_fail
    ld      hl, PF0
    ld      de, (ix + 6)
    ld      iy, __p256_N
    ld      c, 1
    call    p256_import_be              ; 1 <= r < n
    or      a, a
    jp      z, .Lvf_fail
    ld      hl, (ix + 6)
    ld      de, 32
    add     hl, de
    ex      de, hl
    ld      hl, PF1
    ld      iy, __p256_N
    ld      c, 1
    call    p256_import_be              ; 1 <= s < n
    or      a, a
    jp      z, .Lvf_fail
    ld      hl, PF2
    ld      de, (ix + 6)
    call    p256_order_import           ; f2 = r
    ld      hl, (ix + 6)
    ld      de, 32
    add     hl, de
    ex      de, hl
    ld      hl, PF3
    call    p256_order_import           ; f3 = s
    ld      hl, PF4
    ld      de, (ix + 9)
    call    p256_order_import           ; f4 = e
    ld      hl, PF3
    ld      bc, PF5
    call    p256_ord_inv                ; f5 = s^-1
    OMUL    PF6, PF4, PF5               ; u1 = e/s
    OMUL    PF7, PF2, PF5               ; u2 = r/s
    ld      hl, PF6
    ld      de, __p256_k
    call    p256_order_export
    ld      hl, PF7
    ld      de, __p256_x
    call    p256_order_export
    ld      hl, __p256_pa
    ld      de, __p256_k
    ld      bc, __p256_G
    call    p256_scalar_mul             ; A = u1 G
    ld      hl, __p256_saved0
    ld      de, __p256_x
    ld      bc, __p256_pq
    call    p256_scalar_mul             ; B = u2 Q   (into saved0)
    ld      hl, __p256_saved0
    ld      de, __p256_saved1
    ld      bc, 96
    ldir                                ; saved1 = B
    ld      hl, __p256_pa
    ld      de, __p256_saved0
    ld      bc, 96
    ldir                                ; saved0 = A
    ld      hl, __p256_r0
    call    p256_point_add              ; r0 = A + B
    ld      hl, __p256_r0
    ld      de, __p256_k
    ld      bc, 0
    call    p256_affine_export
    or      a, a
    jr      z, .Lvf_fail
    ld      hl, __p256_k
    ld      de, PF8
    call    p256_rev32
    ld      hl, PF8
    ld      de, __p256_N
    ld      c, 0
    call    p256_reduce_top             ; x mod n
    ld      hl, (ix + 6)
    ld      de, PF9
    call    p256_rev32                  ; r as LE
    ld      hl, PF8
    ld      de, PF9
    call    p256_eq32
    jp      p256_exit
.Lvf_fail:
    xor     a, a
    jp      p256_exit

; ===========================================================================
; ECDSA signing with RFC 6979 deterministic nonces (HMAC-SHA-256).
; Kept in its own section so links that never sign can drop it (and its
; dependency on tls_sha256_*) with --gc-sections.
; ===========================================================================
    .section .text.__p256_sign,"ax",@progbits

    extern  _tls_sha256_init
    extern  _tls_sha256_update
    extern  _tls_sha256_digest

    globl   _tls_p256_sign
    .type   _tls_p256_sign, @function

; p256_hmac: out = HMAC-SHA256(key[32], msg[len]).
; In: HL=out, DE=key, BC=msg, A=len (<= 255).  out may alias key or msg.
; Uses DK_CTX, DK_PAD, DK_INNER.  Clobbers AF, BC, DE, HL, IY.
p256_hmac:
    ld      (hm_out), hl
    ld      (hm_key), de
    ld      (hm_msg), bc
    ld      (hm_len), a
    ld      a, 0x36
    call    .Lhm_keyed_init             ; H(K ^ ipad ...
    ld      a, (hm_len)
    or      a, a
    sbc     hl, hl
    ld      l, a
    push    hl
    ld      hl, (hm_msg)
    push    hl
    ld      hl, DK_CTX
    push    hl
    call    _tls_sha256_update          ;   ... || msg)
    pop     hl
    pop     hl
    pop     hl
    ld      hl, DK_INNER
    push    hl
    ld      hl, DK_CTX
    push    hl
    call    _tls_sha256_digest
    pop     hl
    pop     hl
    ld      a, 0x5C
    call    .Lhm_keyed_init             ; H(K ^ opad ...
    ld      hl, 32
    push    hl
    ld      hl, DK_INNER
    push    hl
    ld      hl, DK_CTX
    push    hl
    call    _tls_sha256_update          ;   ... || inner)
    pop     hl
    pop     hl
    pop     hl
    ld      hl, (hm_out)
    push    hl
    ld      hl, DK_CTX
    push    hl
    call    _tls_sha256_digest
    pop     hl
    pop     hl
    ret
; In: A = pad byte.  DK_PAD = (key || 0^32) ^ A^64; init ctx; absorb pad.
.Lhm_keyed_init:
    ld      hl, DK_PAD
    ld      b, 64
.Lhm_fill:
    ld      (hl), a
    inc     hl
    djnz    .Lhm_fill
    ld      hl, (hm_key)
    ld      de, DK_PAD
    ld      b, 32
.Lhm_xor:
    ld      a, (de)
    xor     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    djnz    .Lhm_xor
    ld      hl, DK_CTX
    push    hl
    call    _tls_sha256_init
    pop     hl
    ld      hl, 64
    push    hl
    ld      hl, DK_PAD
    push    hl
    ld      hl, DK_CTX
    push    hl
    call    _tls_sha256_update
    pop     hl
    pop     hl
    pop     hl
    ret

; p256_det_k: RFC 6979 section 3.2 nonce for (dk_hash, dk_priv) -> __p256_k
; (big-endian, 1 <= k < n).  Uses the DK_* overlay and f[0].
p256_det_k:
    ld      hl, DK_K
    ld      (hl), 0
    ld      de, DK_K + 1
    ld      bc, 31
    ldir                                ; K = 0x00..
    ld      hl, DK_V
    ld      (hl), 1
    ld      de, DK_V + 1
    ld      bc, 31
    ldir                                ; V = 0x01..
    ld      hl, (dk_hash)
    ld      de, PF0
    call    p256_rev32
    ld      hl, PF0
    ld      de, __p256_N
    ld      c, 0
    call    p256_reduce_top             ; bits2octets: h mod n
    ld      hl, PF0
    ld      de, DK_H1
    call    p256_rev32
    xor     a, a
    call    .Ldk_round                  ; step d/e
    ld      a, 1
    call    .Ldk_round                  ; step f/g
.Ldk_gen:
    ld      hl, DK_V
    ld      de, DK_K
    ld      bc, DK_V
    ld      a, 32
    call    p256_hmac                   ; V = HMAC(K, V)
    ld      hl, DK_V
    ld      de, __p256_k
    ld      bc, 32
    ldir
    ld      hl, PF0
    ld      de, __p256_k
    ld      iy, __p256_N
    ld      c, 1
    call    p256_import_be              ; accept iff 1 <= k < n
    or      a, a
    ret     nz
    ld      hl, DK_V
    ld      de, DK_RFC
    ld      bc, 32
    ldir
    xor     a, a
    ld      (de), a                     ; V || 0x00
    ld      hl, DK_K
    ld      de, DK_K
    ld      bc, DK_RFC
    ld      a, 33
    call    p256_hmac                   ; K = HMAC(K, V || 0x00)
    ld      hl, DK_V
    ld      de, DK_K
    ld      bc, DK_V
    ld      a, 32
    call    p256_hmac                   ; V = HMAC(K, V)
    jr      .Ldk_gen
; In: A = separator byte.  K = HMAC(K, V||A||priv||h1); V = HMAC(K, V).
.Ldk_round:
    push    af
    ld      hl, DK_V
    ld      de, DK_RFC
    ld      bc, 32
    ldir
    pop     af
    ld      (de), a
    inc     de
    ld      hl, (dk_priv)
    ld      bc, 32
    ldir
    ld      hl, DK_H1
    ld      bc, 32
    ldir
    ld      hl, DK_K
    ld      de, DK_K
    ld      bc, DK_RFC
    ld      a, 97
    call    p256_hmac
    ld      hl, DK_V
    ld      de, DK_K
    ld      bc, DK_V
    ld      a, 32
    jp      p256_hmac

; bool tls_p256_sign(uint8_t sig[64], const uint8_t hash[32],
;                    const uint8_t priv[32])
; Stack: (ix+6)=sig, (ix+9)=hash, (ix+12)=priv.  Out: A = 1/0.
_tls_p256_sign:
    push    ix
    ld      ix, 0
    add     ix, sp
    call    p256_di
    ld      hl, (ix + 6)
    call    p256_null
    jp      z, .Lsg_fail
    ld      hl, (ix + 9)
    call    p256_null
    jp      z, .Lsg_fail
    ld      hl, (ix + 12)
    call    p256_null
    jp      z, .Lsg_fail
    ld      hl, PF0
    ld      de, (ix + 12)
    ld      iy, __p256_N
    ld      c, 1
    call    p256_import_be              ; 1 <= d < n
    or      a, a
    jp      z, .Lsg_fail
    ld      hl, (ix + 9)
    ld      (dk_hash), hl
    ld      hl, (ix + 12)
    ld      (dk_priv), hl
    call    p256_det_k                  ; k -> __p256_k
    ld      hl, __p256_saved0
    ld      de, __p256_k
    ld      bc, __p256_G
    call    p256_scalar_mul             ; R = k G
    ld      hl, __p256_saved0
    ld      de, __p256_x
    ld      bc, 0
    call    p256_affine_export
    or      a, a
    jp      z, .Lsg_fail
    ld      hl, PF2
    ld      de, __p256_x
    call    p256_order_import           ; f2 = r = x mod n
    ld      hl, PF3
    ld      de, (ix + 12)
    call    p256_order_import           ; f3 = d
    ld      hl, PF4
    ld      de, (ix + 9)
    call    p256_order_import           ; f4 = e
    ld      hl, PF5
    ld      de, __p256_k
    call    p256_order_import           ; f5 = k
    OMUL    PF6, PF2, PF3               ; r d
    OADD    PF6, PF6, PF4               ; e + r d
    ld      hl, PF5
    ld      bc, PF7
    call    p256_ord_inv                ; k^-1
    OMUL    PF6, PF6, PF7               ; s
    ld      hl, PF2
    call    p256_ct_is_zero
    inc     a
    jp      z, .Lsg_fail                ; r == 0
    ld      hl, PF6
    call    p256_ct_is_zero
    inc     a
    jp      z, .Lsg_fail                ; s == 0
    ld      hl, PF2
    ld      de, (ix + 6)
    call    p256_order_export
    ld      hl, (ix + 6)
    ld      de, 32
    add     hl, de
    ex      de, hl
    ld      hl, PF6
    call    p256_order_export
    ld      a, 1
    jp      p256_exit
.Lsg_fail:
    xor     a, a
    jp      p256_exit

; ===========================================================================
; Test/profiling shims (C ABI) -- assembled only with --defsym P256_TEST=1.
; ===========================================================================
.ifdef P256_TEST
    .section .text.__p256_test,"ax",@progbits
    globl   _p256_test_mont_mul
    .type   _p256_test_mont_mul, @function
    globl   _p256_test_mod_add
    .type   _p256_test_mod_add, @function
    globl   _p256_test_mod_sub
    .type   _p256_test_mod_sub, @function
    globl   _p256_test_inv
    .type   _p256_test_inv, @function
    globl   _p256_test_point_double
    .type   _p256_test_point_double, @function
    globl   _p256_test_point_add
    .type   _p256_test_point_add, @function
    globl   _p256_test_scalar_mul
    .type   _p256_test_scalar_mul, @function

.Lt_ctx:                        ; A = 0 -> p, else n
    or      a, a
    jp      z, p256_ctx_p
    jp      p256_ctx_n

; void p256_test_mont_mul(uint8_t *out, const uint8_t *a, const uint8_t *b,
;                         uint8_t use_n)     (likewise mod_add, mod_sub)
_p256_test_mont_mul:
    ld      iy, p256_mont_core
    jr      .Lt_binop
_p256_test_mod_add:
    ld      iy, p256_modadd_core
    jr      .Lt_binop
_p256_test_mod_sub:
    ld      iy, p256_modsub_core
.Lt_binop:
    push    ix
    ld      ix, 0
    add     ix, sp
    push    iy
    ld      a, (ix + 15)
    call    .Lt_ctx
    pop     iy
    ld      bc, (ix + 6)
    ld      hl, (ix + 9)
    ld      de, (ix + 12)
    call    .Lt_jp_iy
    pop     ix
    ret
.Lt_jp_iy:
    jp      (iy)

; void p256_test_inv(uint8_t *out, const uint8_t *a, uint8_t use_n)
_p256_test_inv:
    push    ix
    ld      ix, 0
    add     ix, sp
    ld      bc, (ix + 6)
    ld      hl, (ix + 9)
    ld      a, (ix + 12)
    or      a, a
    jr      nz, .Lti_n
    call    p256_fe_inv
    pop     ix
    ret
.Lti_n:
    call    p256_ord_inv
    pop     ix
    ret

; void p256_test_point_double(uint8_t out[96], const uint8_t in[96])
_p256_test_point_double:
    push    ix
    ld      ix, 0
    add     ix, sp
    ld      hl, (ix + 9)
    ld      de, __p256_saved0
    ld      bc, 96
    ldir
    ld      hl, (ix + 6)
    call    p256_point_double
    pop     ix
    ret

; void p256_test_point_add(uint8_t out[96], const uint8_t p[96],
;                          const uint8_t q[96])
_p256_test_point_add:
    push    ix
    ld      ix, 0
    add     ix, sp
    ld      hl, (ix + 9)
    ld      de, __p256_saved0
    ld      bc, 96
    ldir
    ld      hl, (ix + 12)
    ld      de, __p256_saved1
    ld      bc, 96
    ldir
    ld      hl, (ix + 6)
    call    p256_point_add
    pop     ix
    ret

; void p256_test_scalar_mul(uint8_t out[96], const uint8_t k_be[32],
;                           const uint8_t point[96])
; out, k_be and point must be caller buffers (not p256 scratch).
_p256_test_scalar_mul:
    push    ix
    ld      ix, 0
    add     ix, sp
    ld      hl, (ix + 6)
    ld      de, (ix + 9)
    ld      bc, (ix + 12)
    call    p256_scalar_mul
    pop     ix
    ret
.endif

    .section .note.GNU-stack,"",@progbits

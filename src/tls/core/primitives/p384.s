; ---------------------------------------------------------------------------
; p384.s -- NIST P-384 (secp384r1) for the TI-84 Plus CE (eZ80, ADL mode).
;
; Public API (C ABI, see src/tls/includes/p384.h):
;   bool tls_p384_publickey(uint8_t pub[97], const uint8_t priv[48]);
;   bool tls_p384_secret(uint8_t ss[48], const uint8_t priv[48],
;                        const uint8_t peer[97]);
;   bool tls_p384_sign(uint8_t sig[96], const uint8_t hash[48],
;                      const uint8_t priv[48]);
;   bool tls_p384_verify(const uint8_t sig[96], const uint8_t hash[48],
;                        const uint8_t pub[97]);
;
; Representation: radix 2^8, 48 bytes little-endian for internal values.
; Inputs/outputs are big-endian SEC1 / raw ECDSA as above.
;
; Field/order arithmetic is product-scanning Montgomery multiplication with a
; 24-bit column accumulator (identical formulation to p256.s, scaled from 32
; to 48 digits).  The constant-time scalar multiplication is the same co-Z
; Montgomery ladder used by p256.s: per bit one XYcZ-ADDC (5M+3S) and one
; XYcZ-ADDU (4M+2S), with Z recovered once at the end.  Jacobian point
; formulas use a = -3.  ECDSA verification is variable-time with respect to
; its (public) inputs: it computes u1*G and u2*Q with the constant-time
; ladder and adds them with the complete Jacobian wrapper, then checks x(R)
; against r or r+n by affine export.
;
; ECDSA nonces are derived deterministically with RFC 6979 using HMAC-SHA-384
; (tls_sha384_init/update/digest).  Signing performs the RFC 6979 retry
; (r=0/s=0) exactly as specified.
;
; Non-reentrant: one static scratch block (.crypto_scratch.p384), shared with
; P-256/RSA/X25519 through the linker overlay.  It is zeroed on entry and
; before every return; IFF1 is saved at entry and restored on return.
;
; Internal calling convention (not C ABI):
;   - arguments in registers as documented per routine;
;   - every internal routine preserves IX (the C frame pointer);
;   - AF, BC, DE, HL, IY are clobbered unless stated otherwise.
;
; Constant-time notes: the ladder, field arithmetic, point formulas, cswap
; and select never branch on or index memory by secret data.  Branches exist
; only for public loop counters, the fixed public exponent used by inversion,
; public input-validation results, the public x(P)=0 fallback, and the
; RFC 6979 r=0/s=0 retry (as in p256.s).  Verification is the documented
; exception: all of its inputs are public.
; ---------------------------------------------------------------------------

    .assume adl=1

.include "scratch.inc"

; ===========================================================================
; Scratch (.bss).  This buffer is one member of the linker-enforced crypto
; scratch overlay; P-384, P-256, RSA/HKDF and X25519 are mutually exclusive
; at runtime.
; ===========================================================================
globl __p384_scratch_start
globl __p384_scratch_end
    .section .crypto_scratch.p384,"aw",@nobits
__p384_scratch_start:
mm_u:                   .space 48       ; q[0..47]  (Montgomery reduction)
mm_acc2:                .space 4        ; shift cell (byte 3 always 0)
__p384_f:               .space 14*48    ; f[0..13] field temporaries
__p384_tmp:             .space 48       ; generic 48-byte temporary
__p384_tmp2:            .space 48       ; second 48-byte temporary (scalar BE)
__p384_red:             .space 48       ; conditional-subtraction temp
__p384_r0:              .space 144      ; co-Z ladder R0
__p384_r1:              .space 144      ; co-Z ladder R1
__p384_saved0:          .space 144      ; point-op input P
__p384_saved1:          .space 144      ; point-op input Q
__p384_rt:              .space 144      ; point-op result temp
__p384_add_result:      .space 144      ; verify/scalar: -P (or 3Q)
__p384_double_result:   .space 144      ; verify/scalar: -2P (or 5Q)
__p384_pq:              .space 144      ; imported peer/public point
__p384_acc:             .space 144      ; verify: persistent u1*G
__p384_k:               .space 48       ; sign: nonce k (BE); verify: u1 (LE)
__p384_x:               .space 48       ; sign: x(R) (BE);   verify: u2 (LE)
; --- routine state ---
mm_out:                 .space 3
mm_a0:                  .space 3
mm_b0:                  .space 3
mm_mod:                 .space 3
mm_n0:                  .space 1
mm_k:                   .space 1
mm_qk:                  .space 1
mm_cnt:                 .space 1
mm_acc:                 .space 4        ; [acc_lo, acc_mid, acc_hi, 0]
rt_x:                   .space 3
rt_m:                   .space 3
rt_top:                 .space 1
p384_di_save:           .space 1
pd_out:                 .space 3
pa_out:                 .space 3
pa_pinf:                .space 1
pa_qinf:                .space 1
pa_h:                   .space 1
pa_r:                   .space 1
pa_lad:                 .space 1
sm_out:                 .space 3
sm_k:                   .space 3
sm_pt:                  .space 3
sm_kp:                  .space 48
sm_bit:                 .space 1
sm_prev:                .space 1
sm_cnt:                 .space 3
sm_e0:                  .space 1
sm_e1:                  .space 1
sm_em1:                 .space 1
sm_em2:                 .space 1
inv_out:                .space 3
inv_exp:                .space 3
inv_cnt:                .space 3
inv_bit:                .space 1
ae_pt:                  .space 3
ae_x:                   .space 3
ae_y:                   .space 3
pi_src:                 .space 3
hm_out:                 .space 3
hm_key:                 .space 3
hm_msg:                 .space 3
hm_len:                 .space 3
dk_hash:                .space 3
dk_priv:                .space 3
vs_inf:                 .space 1
vs_t:                   .space 1
__p384_scratch_end:

; --- field-temporary names ---
.equ PF0,  __p384_f + 0*48
.equ PF1,  __p384_f + 1*48
.equ PF2,  __p384_f + 2*48
.equ PF3,  __p384_f + 3*48
.equ PF4,  __p384_f + 4*48
.equ PF5,  __p384_f + 5*48
.equ PF6,  __p384_f + 6*48
.equ PF7,  __p384_f + 7*48
.equ PF8,  __p384_f + 8*48
.equ PF9,  __p384_f + 9*48
.equ PF10, __p384_f + 10*48
.equ PF11, __p384_f + 11*48
.equ PF12, __p384_f + 12*48
.equ PF13, __p384_f + 13*48
; --- point names ---
.equ PS0,  __p384_saved0
.equ PS0X, __p384_saved0 + 0
.equ PS0Y, __p384_saved0 + 48
.equ PS0Z, __p384_saved0 + 96
.equ PS1,  __p384_saved1
.equ PS1X, __p384_saved1 + 0
.equ PS1Y, __p384_saved1 + 48
.equ PS1Z, __p384_saved1 + 96
.equ PRT,  __p384_rt
.equ PRTX, __p384_rt + 0
.equ PRTY, __p384_rt + 48
.equ PRTZ, __p384_rt + 96
.equ PQX,  __p384_pq + 0
.equ PQY,  __p384_pq + 48
.equ PQZ,  __p384_pq + 96
.equ CZXA, __p384_r0
.equ CZYA, __p384_r0 + 48
.equ CZXB, __p384_r1
.equ CZYB, __p384_r1 + 48
.equ PZERO, __p384_INF
; RFC 6979 K/V live in the verify-only pq tail; they must survive the ladder.
.equ DK_K,     __p384_pq + 0
.equ DK_V,     __p384_pq + 48
; The remaining RFC 6979 state overlays the ladder scratch and is dead before
; the ladder runs.  Sizes: ctx 224, pad 128, inner 48, msg 160, h1 48.
.equ DK_CTX,   __p384_r0 + 0
.equ DK_PAD,   __p384_r0 + 224
.equ DK_INNER, __p384_r0 + 352
.equ DK_RFC,   __p384_r0 + 400
.equ DK_H1,    __p384_r0 + 560

; --- field-op macros ---
.macro FMUL o, a, b
    ld      bc, \o
    ld      hl, \a
    ld      de, \b
    call    p384_mul_p
.endm
.macro FSQ o, a
    ld      bc, \o
    ld      hl, \a
    call    p384_sq_p
.endm
.macro FADD o, a, b
    ld      bc, \o
    ld      hl, \a
    ld      de, \b
    call    p384_fe_add
.endm
.macro FSUB o, a, b
    ld      bc, \o
    ld      hl, \a
    ld      de, \b
    call    p384_fe_sub
.endm
.macro OMUL o, a, b
    ld      bc, \o
    ld      hl, \a
    ld      de, \b
    call    p384_ord_mul
.endm
.macro OADD o, a, b
    ld      bc, \o
    ld      hl, \a
    ld      de, \b
    call    p384_ord_add
.endm

; ===========================================================================
; Read-only constants (48-byte little-endian unless noted).
; ===========================================================================
    .section .rodata.__p384_const,"a",@progbits
__p384_P:
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00
    .db     0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF
    .db     0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF

__p384_N:
    .db     0x73, 0x29, 0xC5, 0xCC, 0x6A, 0x19, 0xEC, 0xEC
    .db     0x7A, 0xA7, 0xB0, 0x48, 0xB2, 0x0D, 0x1A, 0x58
    .db     0xDF, 0x2D, 0x37, 0xF4, 0x81, 0x4D, 0x63, 0xC7
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF

__p384_P_R:
    .db     0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00
    .db     0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    .db     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    .db     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    .db     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00

__p384_P_R2:
    .db     0x01, 0x00, 0x00, 0x00, 0xFE, 0xFF, 0xFF, 0xFF
    .db     0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00
    .db     0x00, 0x00, 0x00, 0x00, 0xFE, 0xFF, 0xFF, 0xFF
    .db     0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00
    .db     0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    .db     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00

__p384_N_R:
    .db     0x8D, 0xD6, 0x3A, 0x33, 0x95, 0xE6, 0x13, 0x13
    .db     0x85, 0x58, 0x4F, 0xB7, 0x4D, 0xF2, 0xE5, 0xA7
    .db     0x20, 0xD2, 0xC8, 0x0B, 0x7E, 0xB2, 0x9C, 0x38
    .db     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    .db     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    .db     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00

__p384_N_R2:
    .db     0xA9, 0x09, 0xB4, 0x19, 0x24, 0x9B, 0x31, 0x2D
    .db     0x19, 0xA4, 0x1A, 0xDF, 0xE5, 0x81, 0x3D, 0xFF
    .db     0x47, 0x29, 0xB8, 0xFC, 0x3A, 0x48, 0x3E, 0xBC
    .db     0xC5, 0x1C, 0xAB, 0x4A, 0x17, 0x49, 0x0D, 0xD4
    .db     0x95, 0x68, 0x26, 0x28, 0x7A, 0x5B, 0xB0, 0x3F
    .db     0x21, 0xBF, 0x39, 0x2B, 0x01, 0xEE, 0x84, 0x0C

__p384_P_B_R:
    .db     0xCC, 0x2D, 0x41, 0x9D, 0x71, 0x88, 0x11, 0x08
    .db     0xEC, 0x32, 0x4C, 0x7A, 0xD8, 0xAD, 0x29, 0xF7
    .db     0x2E, 0x02, 0x20, 0x19, 0x9B, 0x20, 0xF2, 0x77
    .db     0xE2, 0x8A, 0x93, 0x94, 0xEE, 0x4B, 0x37, 0xE3
    .db     0x94, 0x20, 0x02, 0x1F, 0xF4, 0x21, 0x2B, 0xB6
    .db     0xF9, 0xBF, 0x4F, 0x60, 0x4B, 0x11, 0x08, 0xCD

; Generator in Montgomery-Jacobian form: (Gx*R, Gy*R, R).
__p384_G:
    .db     0x28, 0xB5, 0xC0, 0x49, 0x66, 0x75, 0xD0, 0x3D
    .db     0x38, 0xCE, 0xD6, 0xA0, 0xE2, 0x78, 0xE3, 0x20
    .db     0x6E, 0x4D, 0x1B, 0x54, 0xFC, 0x3A, 0x9C, 0x87
    .db     0xFF, 0x0E, 0xA3, 0x59, 0x84, 0x86, 0x54, 0x64
    .db     0x2B, 0xDE, 0x4E, 0x61, 0x23, 0xF7, 0x2F, 0x81
    .db     0x13, 0x15, 0x9E, 0x29, 0xC2, 0xAD, 0x3A, 0x4D
__p384_G_Y:
    .db     0xFE, 0xA4, 0x03, 0x4B, 0xAD, 0x3D, 0x04, 0x23
    .db     0xAC, 0xA9, 0xB4, 0x7B, 0xBF, 0xA8, 0xBF, 0xA1
    .db     0x50, 0xB0, 0x83, 0x2E, 0x56, 0xE7, 0xAD, 0x8B
    .db     0xD9, 0xFF, 0xF4, 0x68, 0x19, 0x52, 0xC3, 0xC6
    .db     0x40, 0xA8, 0x69, 0x39, 0x26, 0x02, 0x80, 0xDD
    .db     0xE9, 0xC5, 0x15, 0x5A, 0xC2, 0xAB, 0x78, 0x2B
__p384_G_Z:
    .db     0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00
    .db     0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    .db     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    .db     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    .db     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00

__p384_INF:
    .space  48, 0                  ; X = 0
    .db     0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00
    .db     0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    .db     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    .db     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    .db     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    .space  48, 0                  ; Z = 0

__p384_N2:
    .db     0xE6, 0x52, 0x8A, 0x99, 0xD5, 0x32, 0xD8, 0xD9
    .db     0xF5, 0x4E, 0x61, 0x91, 0x64, 0x1B, 0x34, 0xB0
    .db     0xBE, 0x5B, 0x6E, 0xE8, 0x03, 0x9B, 0xC6, 0x8E
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
__p384_NM1:
    .db     0x72, 0x29, 0xC5, 0xCC, 0x6A, 0x19, 0xEC, 0xEC
    .db     0x7A, 0xA7, 0xB0, 0x48, 0xB2, 0x0D, 0x1A, 0x58
    .db     0xDF, 0x2D, 0x37, 0xF4, 0x81, 0x4D, 0x63, 0xC7
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
__p384_NM2:
    .db     0x71, 0x29, 0xC5, 0xCC, 0x6A, 0x19, 0xEC, 0xEC
    .db     0x7A, 0xA7, 0xB0, 0x48, 0xB2, 0x0D, 0x1A, 0x58
    .db     0xDF, 0x2D, 0x37, 0xF4, 0x81, 0x4D, 0x63, 0xC7
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
__p384_PM2:
    .db     0xFD, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00
    .db     0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF
    .db     0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
__p384_ONE:
    .db     0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    .db     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    .db     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    .db     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    .db     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    .db     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
; Big-endian copies of the public exponents used by Fermat inversion.
__p384_PM2_BE:
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00
    .db     0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFD
__p384_NM2_BE:
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    .db     0xC7, 0x63, 0x4D, 0x81, 0xF4, 0x37, 0x2D, 0xDF
    .db     0x58, 0x1A, 0x0D, 0xB2, 0x48, 0xB0, 0xA7, 0x7A
    .db     0xEC, 0xEC, 0x19, 0x6A, 0xCC, 0xC5, 0x29, 0x71

; ===========================================================================
; Field context and thin wrappers
; ===========================================================================
    .section .text.__p384,"ax",@progbits

p384_ctx_p:
    ld      iy, __p384_P
    ld      (mm_mod), iy
    ld      a, 0x01
    ld      (mm_n0), a
    ret
p384_ctx_n:
    ld      iy, __p384_N
    ld      (mm_mod), iy
    ld      a, 0x45
    ld      (mm_n0), a
    ret

p384_mul_p:
    call    p384_ctx_p
    jp      p384_mont_core
p384_sq_p:
    push    hl
    pop     de
    call    p384_ctx_p
    jp      p384_mont_core
p384_ord_mul:
    call    p384_ctx_n
    jp      p384_mont_core
p384_ord_add:
    call    p384_ctx_n
    jp      p384_modadd_core

; ===========================================================================
; Small helpers
; ===========================================================================

; out = a - b mod m.  In: HL=a, DE=b, BC=out, mm_mod.  Out may alias a/b.
p384_modsub_core:
    push    ix
    push    hl
    pop     ix
    ex      de, hl
    push    bc
    pop     de
    push    de
    ld      b, 48
    or      a, a
.Lms_loop:
    ld      a, (ix + 0)
    sbc     a, (hl)
    ld      (de), a
    inc     ix
    inc     hl
    inc     de
    djnz    .Lms_loop
    sbc     a, a
    ld      c, a
    pop     hl
    ld      de, (mm_mod)
    call    p384_reduce_top
    pop     ix
    ret

; out = a + b mod m.  In: HL=a, DE=b, BC=out, mm_mod.  Requires a,b < m.
p384_modadd_core:
    push    ix
    push    hl
    pop     ix
    ex      de, hl
    push    bc
    pop     de
    push    de
    ld      b, 48
    or      a, a
.Lma_loop:
    ld      a, (ix + 0)
    adc     a, (hl)
    ld      (de), a
    inc     ix
    inc     hl
    inc     de
    djnz    .Lma_loop
    sbc     a, a
    ld      c, a
    pop     hl
    ld      de, (mm_mod)
    call    p384_reduce_top
    pop     ix
    ret

; x = (top:x >= m) ? top:x - m : x, given top:x < 2m.
; In: HL=x, DE=m, C=top mask (0x00/0xFF).  Branch-free.
p384_reduce_top:
    ld      (rt_x), hl
    ld      (rt_m), de
    ld      a, c
    ld      (rt_top), a
    push    hl
    pop     iy
    ex      de, hl                  ; HL = m
    ld      de, __p384_red
    ld      b, 48
    or      a, a
.Lrt_sub:
    ld      a, (iy + 0)
    sbc     a, (hl)
    ld      (de), a
    inc     iy
    inc     hl
    inc     de
    djnz    .Lrt_sub
    sbc     a, a                    ; borrow ? 0xFF : 0
    cpl                             ; no-borrow ? 0xFF : 0
    ld      b, a
    ld      a, (rt_top)
    or      a, b
    ld      c, a                    ; select mask: use (x-m) when top|!borrow
    ld      hl, (rt_x)
    ld      de, __p384_red
    ld      b, 48
.Lrt_sel:
    ld      a, (de)
    xor     a, (hl)
    and     a, c
    xor     a, (hl)
    ld      (hl), a
    inc     hl
    inc     de
    djnz    .Lrt_sel
    ret

; out = a + b mod p.  In: HL=a, DE=b, BC=out; a,b < p.  Out may alias.
p384_fe_add:
    push    ix
    push    hl
    pop     ix
    ex      de, hl
    push    bc
    pop     de
    push    de
    ld      b, 48
    or      a, a
.Lfa_loop:
    ld      a, (ix + 0)
    adc     a, (hl)
    ld      (de), a
    inc     ix
    inc     hl
    inc     de
    djnz    .Lfa_loop
    sbc     a, a
    ld      c, a
    pop     hl
    ld      de, __p384_P
    call    p384_reduce_top
    pop     ix
    ret

; out = a - b mod p.  In: HL=a, DE=b, BC=out; a,b < p.  Out may alias.
p384_fe_sub:
    push    ix
    push    hl
    pop     ix
    ex      de, hl
    push    bc
    pop     de
    push    de
    ld      b, 48
    or      a, a
.Lfs_loop:
    ld      a, (ix + 0)
    sbc     a, (hl)
    ld      (de), a
    inc     ix
    inc     hl
    inc     de
    djnz    .Lfs_loop
    sbc     a, a
    ld      c, a                    ; borrow mask
    pop     hl
    ld      (rt_x), hl
    ld      ix, __p384_P
    ld      iy, __p384_red
    ld      b, 48
    or      a, a
.Lfs_add:
    ld      a, (hl)
    adc     a, (ix + 0)
    ld      (iy + 0), a
    inc     hl
    inc     ix
    inc     iy
    djnz    .Lfs_add
    ld      hl, (rt_x)
    ld      de, __p384_red
    ld      b, 48
.Lfs_sel:
    ld      a, (de)
    xor     a, (hl)
    and     a, c
    xor     a, (hl)
    ld      (hl), a
    inc     hl
    inc     de
    djnz    .Lfs_sel
    pop     ix
    ret

; A = (a >= m) ? 1 : 0.  In: HL=a, DE=m.
p384_raw_ge:
    ld      b, 48
    or      a, a
.Lge_loop:
    ld      a, (hl)
    ex      de, hl
    sbc     a, (hl)
    ex      de, hl
    inc     hl
    inc     de
    djnz    .Lge_loop
    sbc     a, a
    inc     a
    ret

; A = 0xFF if the 48 bytes at HL are all zero, else 0x00.
p384_ct_is_zero:
    ld      b, 48
    xor     a, a
.Lz_loop:
    or      a, (hl)
    inc     hl
    djnz    .Lz_loop
    neg
    sbc     a, a
    cpl
    ret

; A = 1 if the 48 bytes at HL equal those at DE, else 0.
p384_eq48:
    ld      bc, 48 << 8
.Leq_loop:
    ld      a, (de)
    xor     a, (hl)
    or      a, c
    ld      c, a
    inc     hl
    inc     de
    djnz    .Leq_loop
    ld      a, c
    sub     a, 1
    sbc     a, a
    and     a, 0x01
    ret

; dst[i] = src[47-i].  In: HL=src, DE=dst (must not overlap).
p384_rev48:
    ld      bc, 47
    add     hl, bc
    ld      b, 48
.Lrv_loop:
    ld      a, (hl)
    ld      (de), a
    dec     hl
    inc     de
    djnz    .Lrv_loop
    ret

; out = mask ? b : a  (B bytes).  In: HL=a, DE=b, IY=out, C=mask.
p384_select_b:
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

; if mask, swap B bytes at HL and DE.  In: C=mask, B=count.
p384_cswap_b:
    ld      iyl, b
.Lcs_loop:
    ld      a, (de)
    xor     a, (hl)
    and     a, c
    ld      b, a
    xor     a, (hl)
    ld      (hl), a
    ld      a, (de)
    xor     a, b
    ld      (de), a
    inc     hl
    inc     de
    dec     iyl
    jr      nz, .Lcs_loop
    ret
p384_point_cswap:
    ld      b, 144
    jr      p384_cswap_b
p384_point_cswap64:
    ld      b, 96
    jr      p384_cswap_b

; out = big-endian in[48] as LE; reject if >= m, or (C != 0 and) zero.
; In: HL=out, DE=in, IY=m, C=reject_zero.  Out: A = 1 ok / 0.
p384_import_be:
    push    hl
    push    bc
    ex      de, hl
    call    p384_rev48
    pop     bc
    pop     hl
    push    hl
    push    bc
    push    iy
    pop     de
    call    p384_raw_ge
    pop     bc
    pop     hl
    or      a, a
    jr      nz, .Lib_fail
    ld      a, c
    or      a, a
    jr      z, .Lib_ok
    call    p384_ct_is_zero
    inc     a
    ret
.Lib_ok:
    ld      a, 1
    ret
.Lib_fail:
    xor     a, a
    ret

; ===========================================================================
; Montgomery multiplication (generic, product scanning, 48 digits)
;
; p384_mont_core: out = a * b * 2^-384 mod m
;   In: HL=a, DE=b, BC=out (48-byte LE), mm_mod=m, mm_n0=-m^-1 mod 256.
;   Out fully reduced.  out may alias a and/or b.  Preserves IX.
; ===========================================================================
p384_mont_core:
    push    ix
    ld      (mm_out), bc
    ld      (mm_a0), hl
    ld      (mm_b0), de
    call    p384_mul_reloc_load
    ld      hl, mm_u                ; q[0..47] = 0
    ld      (hl), 0
    ld      de, mm_u + 1
    ld      bc, 47
    ldir
    xor     a, a
    ld      (mm_k), a
    ld      hl, 0                   ; acc = 0 (carries across columns)
.Lmm_p1:
    ld      ix, (mm_a0)
    ld      a, (mm_k)
    ld      de, 0
    ld      e, a
    ld      iy, (mm_b0)
    add     iy, de                  ; b + k
    ld      a, (mm_k)
    inc     a
    ld      b, a
    call    p384_mul_mac
    ld      ix, mm_u
    ld      a, (mm_k)
    ld      de, 0
    ld      e, a
    ld      iy, (mm_mod)
    add     iy, de                  ; m + k
    ld      a, (mm_k)
    inc     a
    ld      b, a
    call    p384_mul_mac
    ld      a, (mm_n0)
    ld      d, a
    ld      e, l
    mlt     de                      ; E = q_k
    ld      a, e
    ld      (mm_qk), a
    push    hl
    ld      a, (mm_k)
    ld      bc, 0
    ld      c, a
    ld      ix, mm_u
    add     ix, bc
    ld      a, (mm_qk)
    ld      (ix + 0), a              ; q[k]
    ld      hl, (mm_mod)
    ld      d, (hl)                 ; m[0]
    ld      e, a
    mlt     de                      ; DE = q_k * m[0]
    pop     hl
    add     hl, de
    ld      (mm_acc), hl
    ld      hl, (mm_acc + 1)        ; acc >>= 8
    ld      a, (mm_k)
    inc     a
    ld      (mm_k), a
    cp      a, 48
    jp      nz, .Lmm_p1

    ld      a, 48
    ld      (mm_k), a
.Lmm_p2:
    ld      a, (mm_k)
    sub     a, 47
    ld      bc, 0
    ld      c, a
    ld      ix, (mm_a0)
    add     ix, bc                  ; a + k - 47
    ld      iy, (mm_b0)
    ld      de, 47
    add     iy, de                  ; b + 47
    ld      a, (mm_k)
    ld      c, a
    ld      a, 95
    sub     a, c
    ld      b, a                    ; 95 - k terms
    call    p384_mul_mac
    ld      a, (mm_k)
    sub     a, 47
    ld      bc, 0
    ld      c, a
    ld      ix, mm_u
    add     ix, bc
    ld      iy, (mm_mod)
    ld      de, 47
    add     iy, de
    ld      a, (mm_k)
    ld      c, a
    ld      a, 95
    sub     a, c
    ld      b, a
    call    p384_mul_mac
    ld      a, l
    push    af
    ld      a, (mm_k)
    sub     a, 48
    ld      bc, 0
    ld      c, a
    ld      ix, (mm_out)
    add     ix, bc
    pop     af
    ld      (ix + 0), a             ; out[k-48]
    ld      (mm_acc), hl
    ld      hl, (mm_acc + 1)
    ld      a, (mm_k)
    inc     a
    ld      (mm_k), a
    cp      a, 95
    jp      nz, .Lmm_p2

    ld      c, l
    ld      a, h
    push    af
    ld      hl, (mm_out)
    ld      de, 47
    add     hl, de
    ld      (hl), c                 ; out[47]
    pop     af
    neg
    sbc     a, a
    ld      c, a
    pop     ix
    ld      hl, (mm_out)
    ld      de, (mm_mod)
    jp      p384_reduce_top

; acc += sum_{i=0..B-1} (IX+i)*(IY-i).   In: IX,IY,B.  Accumulator HL.
p384_mac:
    ld      d, (ix + 0)
    ld      e, (iy + 0)
    mlt     de
    add     hl, de
    inc     ix
    dec     iy
    djnz    p384_mac
    ret

; ===========================================================================
; Modular inversion by Fermat: out = a^(m-2) in the Montgomery domain.
; Fixed public exponent, constant instruction sequence w.r.t. the input.
; ===========================================================================
; p384_fe_inv: In: HL=a, BC=out.  Uses PF12 (base), PF13 (result).
p384_fe_inv:
    ld      (inv_out), bc
    push    hl
    pop     de
    ld      hl, PF12
    ex      de, hl
    ld      bc, 48
    ldir                            ; PF12 = a
    ld      hl, __p384_P_R
    ld      de, PF13
    ld      bc, 48
    ldir                            ; PF13 = R
    ld      hl, __p384_PM2_BE
    ld      (inv_exp), hl
    ld      a, 0x80
    ld      (inv_bit), a
    ld      hl, 384
    ld      (inv_cnt), hl
.Lfi_loop:
    FSQ     PF13, PF13
    ld      hl, (inv_exp)
    ld      a, (inv_bit)
    and     a, (hl)
    jr      z, .Lfi_skip
    FMUL    PF13, PF13, PF12
.Lfi_skip:
    ld      a, (inv_bit)
    rrca
    ld      (inv_bit), a
    jr      nc, .Lfi_same
    ld      hl, (inv_exp)
    inc     hl
    ld      (inv_exp), hl
.Lfi_same:
    ld      hl, (inv_cnt)
    dec     hl
    ld      (inv_cnt), hl
    ld      a, h
    or      a, l
    jr      nz, .Lfi_loop
    ld      hl, PF13
    ld      de, (inv_out)
    ld      bc, 48
    ldir
    ret

; p384_ord_inv: In: HL=a, BC=out.  Uses PF12 (base), PF13 (result).
p384_ord_inv:
    ld      (inv_out), bc
    push    hl
    pop     de
    ld      hl, PF12
    ex      de, hl
    ld      bc, 48
    ldir                            ; PF12 = a
    ld      hl, __p384_N_R
    ld      de, PF13
    ld      bc, 48
    ldir
    ld      hl, __p384_NM2_BE
    ld      (inv_exp), hl
    ld      a, 0x80
    ld      (inv_bit), a
    ld      hl, 384
    ld      (inv_cnt), hl
.Loi_loop:
    OMUL    PF13, PF13, PF13
    ld      hl, (inv_exp)
    ld      a, (inv_bit)
    and     a, (hl)
    jr      z, .Loi_skip
    OMUL    PF13, PF13, PF12
.Loi_skip:
    ld      a, (inv_bit)
    rrca
    ld      (inv_bit), a
    jr      nc, .Loi_same
    ld      hl, (inv_exp)
    inc     hl
    ld      (inv_exp), hl
.Loi_same:
    ld      hl, (inv_cnt)
    dec     hl
    ld      (inv_cnt), hl
    ld      a, h
    or      a, l
    jr      nz, .Loi_loop
    ld      hl, PF13
    ld      de, (inv_out)
    ld      bc, 48
    ldir
    ret

; ===========================================================================
; Import / export / order conversion
; ===========================================================================
; out = (be mod n) * R mod n.  In: HL=out, DE=be (48-byte BE).
p384_order_import:
    push    hl
    ex      de, hl
    ld      de, __p384_tmp
    call    p384_rev48
    ld      hl, __p384_tmp
    ld      de, __p384_N
    ld      c, 0
    call    p384_reduce_top
    pop     bc
    ld      hl, __p384_tmp
    ld      de, __p384_N_R2
    jp      p384_ord_mul

; be = a * R^-1 mod n.  In: HL=a, DE=be.
p384_order_export:
    push    de
    ld      de, __p384_ONE
    ld      bc, __p384_tmp
    call    p384_ord_mul
    pop     de
    ld      hl, __p384_tmp
    jp      p384_rev48

; Validate and import an uncompressed SEC1 point into pq.
; In: HL=pub (97 bytes).  Out: A=1 ok / 0 reject.
p384_point_import:
    ld      a, (hl)
    cp      a, 0x04
    jp      nz, .Lpi_fail
    inc     hl
    ld      (pi_src), hl
    ex      de, hl
    ld      hl, PF0
    ld      iy, __p384_P
    ld      c, 0
    call    p384_import_be
    or      a, a
    jp      z, .Lpi_fail
    ld      hl, (pi_src)
    ld      de, 48
    add     hl, de
    ex      de, hl
    ld      hl, PF1
    ld      iy, __p384_P
    ld      c, 0
    call    p384_import_be
    or      a, a
    jp      z, .Lpi_fail
    FMUL    PQX, PF0, __p384_P_R2
    FMUL    PQY, PF1, __p384_P_R2
    ld      hl, __p384_P_R
    ld      de, PQZ
    ld      bc, 48
    ldir
    FSQ     PF2, PQY
    FSQ     PF3, PQX
    FMUL    PF3, PF3, PQX
    FADD    PF4, PQX, PQX
    FADD    PF4, PF4, PQX
    FSUB    PF3, PF3, PF4
    FADD    PF3, PF3, __p384_P_B_R
    ld      hl, PF2
    ld      de, PF3
    jp      p384_eq48
.Lpi_fail:
    xor     a, a
    ret

; out = mask ? b : a (144-byte point).  In: HL=a, DE=b, IY=out, C=mask.
p384_point_select:
    ld      b, 144
    jp      p384_select_b

; ===========================================================================
; Point arithmetic (Montgomery-Jacobian, 144-byte points x||y||z, a = -3)
; ===========================================================================

; p384_point_double: out = 2 * saved0.  In: HL=out.
p384_point_double:
    ld      (pd_out), hl
    FSQ     PF0, PS0Z
    FSQ     PF1, PS0Y
    FMUL    PF2, PS0X, PF1
    FSUB    PF3, PS0X, PF0
    FADD    PF4, PS0X, PF0
    FMUL    PF3, PF3, PF4
    FADD    PF4, PF3, PF3
    FADD    PF3, PF4, PF3
    FSQ     PRTX, PF3
    FADD    PF4, PF2, PF2
    FADD    PF4, PF4, PF4
    FADD    PF5, PF4, PF4
    FSUB    PRTX, PRTX, PF5
    FADD    PF6, PS0Y, PS0Z
    FSQ     PF6, PF6
    FSUB    PF6, PF6, PF1
    FSUB    PRTZ, PF6, PF0
    FSUB    PF4, PF4, PRTX
    FMUL    PF4, PF3, PF4
    FSQ     PF1, PF1
    FADD    PF1, PF1, PF1
    FADD    PF1, PF1, PF1
    FADD    PF1, PF1, PF1
    FSUB    PRTY, PF4, PF1
    ld      hl, PS0Z
    call    p384_ct_is_zero
    ld      c, a
    ld      hl, PRT
    ld      de, __p384_INF
    ld      iy, (pd_out)
    jp      p384_point_select

; p384_point_add: out = saved0 + saved1 (complete wrapper).
; In: HL=out.  Runs saved0/saved1; out must not alias them/rt/f[].
p384_point_add_ladder:
    ld      a, 1
    jr      .Lpa_entry
p384_point_add:
    xor     a, a
.Lpa_entry:
    ld      (pa_lad), a
    ld      (pa_out), hl
    FSQ     PF0, PS0Z
    FSQ     PF1, PS1Z
    FMUL    PF2, PS0X, PF1
    FMUL    PF3, PS1X, PF0
    FMUL    PF4, PS1Z, PF1
    FMUL    PF4, PS0Y, PF4
    FMUL    PF5, PS0Z, PF0
    FMUL    PF5, PS1Y, PF5
    FSUB    PF6, PF3, PF2
    FADD    PF7, PF6, PF6
    FSQ     PF7, PF7
    FMUL    PF8, PF6, PF7
    FSUB    PF9, PF5, PF4
    FADD    PF9, PF9, PF9
    FMUL    PF10, PF2, PF7
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
    call    p384_ct_is_zero
    ld      (pa_pinf), a
    ld      hl, PS1Z
    call    p384_ct_is_zero
    ld      (pa_qinf), a
    ld      hl, PF6
    call    p384_ct_is_zero
    ld      (pa_h), a
    ld      hl, PF9
    call    p384_ct_is_zero
    ld      (pa_r), a
    ld      a, (pa_lad)
    or      a, a
    jr      nz, .Lpa_nodbl
    ld      hl, PRT
    ld      de, __p384_add_result
    ld      bc, 144
    ldir
    ld      hl, __p384_double_result
    call    p384_point_double
    ld      a, (pa_h)
    ld      b, a
    ld      a, (pa_r)
    and     a, b
    ld      c, a
    ld      hl, __p384_add_result
    ld      de, __p384_double_result
    ld      iy, PRT
    call    p384_point_select
.Lpa_nodbl:
    ld      a, (pa_r)
    cpl
    ld      b, a
    ld      a, (pa_h)
    and     a, b
    ld      c, a
    ld      hl, PRT
    ld      de, __p384_INF
    ld      iy, PRT
    call    p384_point_select
    ld      a, (pa_pinf)
    ld      c, a
    ld      hl, PRT
    ld      de, PS1
    ld      iy, PRT
    call    p384_point_select
    ld      a, (pa_qinf)
    ld      c, a
    ld      hl, PRT
    ld      de, PS0
    ld      iy, (pa_out)
    jp      p384_point_select

; p384_scalar_mul_ml: out = scalar * point, full Jacobian ladder (fallback
; for the public x(P) = 0 case).  In: HL=out, DE=scalar (48 B BE), BC=point.
p384_scalar_mul_ml:
    ld      (sm_out), hl
    ld      (sm_k), de
    push    bc
    pop     hl
    ld      de, __p384_r1
    ld      bc, 144
    ldir
    ld      hl, __p384_INF
    ld      de, __p384_r0
    ld      bc, 144
    ldir
    xor     a, a
    ld      (sm_prev), a
    ld      hl, 384
    ld      (sm_cnt), hl
    ld      a, 0x80
    ld      (sm_bit), a
.Lsm_loop:
    ld      hl, (sm_k)
    ld      a, (sm_bit)
    and     a, (hl)
    add     a, 0xFF
    sbc     a, a
    ld      b, a
    ld      a, (sm_prev)
    xor     a, b
    ld      c, a
    ld      a, b
    ld      (sm_prev), a
    ld      hl, __p384_r0
    ld      de, __p384_r1
    call    p384_point_cswap
    ld      hl, __p384_r0
    ld      de, __p384_saved0
    ld      bc, 288
    ldir
    ld      hl, __p384_r1
    call    p384_point_add_ladder
    ld      hl, __p384_r0
    call    p384_point_double
    ld      a, (sm_bit)
    rrca
    ld      (sm_bit), a
    jr      nc, .Lsm_same
    ld      hl, (sm_k)
    inc     hl
    ld      (sm_k), hl
.Lsm_same:
    ld      hl, (sm_cnt)
    dec     hl
    ld      (sm_cnt), hl
    ld      a, h
    or      a, l
    jr      nz, .Lsm_loop
    ld      a, (sm_prev)
    ld      c, a
    ld      hl, __p384_r0
    ld      de, __p384_r1
    call    p384_point_cswap
    ld      hl, __p384_r0
    ld      de, (sm_out)
    ld      bc, 144
    ldir
    ret

; ===========================================================================
; Constant-time co-Z Montgomery ladder
; ===========================================================================
p384_scalar_mul:
    ld      (sm_out), hl
    ld      (sm_k), de
    ld      (sm_pt), bc
    push    bc
    pop     hl
    call    p384_ct_is_zero
    inc     a
    jr      nz, .Lcz_go
    ld      hl, (sm_out)
    ld      de, (sm_k)
    ld      bc, (sm_pt)
    jp      p384_scalar_mul_ml
.Lcz_go:
    ld      hl, (sm_k)
    ld      de, PF10
    call    p384_rev48              ; PF10 = k (LE)
    ld      de, PZERO
    call    .Lcz_eqk
    ld      (sm_e0), a
    ld      de, __p384_ONE
    call    .Lcz_eqk
    ld      (sm_e1), a
    ld      de, __p384_NM1
    call    .Lcz_eqk
    ld      (sm_em1), a
    ld      de, __p384_NM2
    call    .Lcz_eqk
    ld      (sm_em2), a
    ld      hl, PF10
    ld      de, __p384_N
    ld      iy, PF11
    call    p384_add48              ; k + n
    push    af
    ld      hl, PF10
    ld      de, __p384_N2
    ld      iy, PF12
    call    p384_add48              ; k + 2n
    pop     af
    ld      c, a
    ld      hl, PF12
    ld      de, PF11
    ld      iy, PF12
    ld      b, 48
    call    p384_select_b
    ld      hl, PF12
    ld      de, sm_kp
    call    p384_rev48              ; k' (BE)
    ld      hl, (sm_pt)
    ld      de, __p384_saved1
    ld      bc, 144
    ldir                            ; saved1 = P
    ; XYcZ-IDBL
    FSQ     PF1, PS1Y
    FMUL    CZXA, PS1X, PF1
    FADD    CZXA, CZXA, CZXA
    FADD    CZXA, CZXA, CZXA
    FSQ     PF1, PF1
    FADD    PF1, PF1, PF1
    FADD    PF1, PF1, PF1
    FADD    CZYA, PF1, PF1
    FSQ     PF2, PS1X
    FSUB    PF2, PF2, __p384_P_R
    FADD    PF3, PF2, PF2
    FADD    PF2, PF3, PF2
    FSQ     CZXB, PF2
    FSUB    CZXB, CZXB, CZXA
    FSUB    CZXB, CZXB, CZXA
    FSUB    PF3, CZXA, CZXB
    FMUL    PF3, PF2, PF3
    FSUB    CZYB, PF3, CZYA
    ; exceptional-k results
    ld      hl, PS1X
    ld      de, __p384_add_result
    ld      bc, 48
    ldir
    FSUB    __p384_add_result + 48, PZERO, PS1Y
    ld      hl, __p384_P_R
    ld      de, __p384_add_result + 96
    ld      bc, 48
    ldir
    ld      hl, CZXB
    ld      de, __p384_double_result
    ld      bc, 48
    ldir
    FSUB    __p384_double_result + 48, PZERO, CZYB
    FADD    __p384_double_result + 96, PS1Y, PS1Y
    ; ladder over bits 383..1
    ld      hl, sm_kp
    ld      (sm_k), hl
    xor     a, a
    ld      (sm_prev), a
    ld      hl, 383
    ld      (sm_cnt), hl
    ld      a, 0x80
    ld      (sm_bit), a
.Lcz_loop:
    call    .Lcz_bit
    call    p384_coz_addc
    call    p384_coz_addu
    ld      a, (sm_bit)
    rrca
    ld      (sm_bit), a
    jr      nc, .Lcz_same
    ld      hl, (sm_k)
    inc     hl
    ld      (sm_k), hl
.Lcz_same:
    ld      hl, (sm_cnt)
    dec     hl
    ld      (sm_cnt), hl
    ld      a, h
    or      a, l
    jr      nz, .Lcz_loop
    ; bit 0 with Z recovery
    call    .Lcz_bit
    call    p384_coz_addc
    FSUB    PF7, PZERO, PS1Y
    ld      a, (sm_prev)
    ld      c, a
    ld      hl, PF7
    ld      de, PS1Y
    ld      iy, PF7
    ld      b, 48
    call    p384_select_b
    FMUL    PF7, PF7, CZXA
    FMUL    PF8, PS1X, CZYA
    FSUB    PF9, CZXB, CZXA
    FMUL    PF8, PF8, PF9
    call    p384_coz_addu
    ld      a, (sm_prev)
    ld      c, a
    ld      hl, __p384_r0
    ld      de, __p384_r1
    call    p384_point_cswap64
    FSQ     PF9, PF7
    FMUL    PRTX, CZXA, PF9
    FMUL    PF9, PF9, PF7
    FMUL    PRTY, CZYA, PF9
    ld      hl, PF8
    ld      de, PRTZ
    ld      bc, 48
    ldir
    ld      a, (sm_e1)
    ld      de, __p384_saved1
    call    .Lcz_fix
    ld      a, (sm_em1)
    ld      de, __p384_add_result
    call    .Lcz_fix
    ld      a, (sm_em2)
    ld      de, __p384_double_result
    call    .Lcz_fix
    ld      a, (sm_e0)
    ld      de, __p384_INF
    call    .Lcz_fix
    ld      hl, PRT
    ld      de, (sm_out)
    ld      bc, 144
    ldir
    ret
.Lcz_fix:
    ld      c, a
    ld      hl, PRT
    ld      iy, PRT
    jp      p384_point_select
.Lcz_eqk:
    ld      hl, PF10
    call    p384_eq48
    neg
    ret
.Lcz_bit:
    ld      hl, (sm_k)
    ld      a, (sm_bit)
    and     a, (hl)
    add     a, 0xFF
    sbc     a, a
    ld      b, a
    ld      a, (sm_prev)
    xor     a, b
    ld      c, a
    ld      a, b
    ld      (sm_prev), a
    ld      hl, __p384_r0
    ld      de, __p384_r1
    jp      p384_point_cswap64

; (IY) = (HL) + (DE), 48 bytes; A = carry ? 0xFF : 0.
p384_add48:
    ld      b, 48
    or      a, a
.Ladd_loop:
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 0), a
    inc     hl
    inc     de
    inc     iy
    djnz    .Ladd_loop
    sbc     a, a
    ret

; XYcZ-ADDC: B = A + B, A = A - B.  5M + 3S.
p384_coz_addc:
    FSUB    PF0, CZXA, CZXB
    FSQ     PF0, PF0
    FMUL    PF1, CZXA, PF0
    FMUL    PF2, CZXB, PF0
    FSUB    PF3, CZYA, CZYB
    FADD    PF4, CZYA, CZYB
    FSUB    PF5, PF1, PF2
    FMUL    PF5, CZYA, PF5
    FSQ     PF6, PF3
    FSUB    PF6, PF6, PF1
    FSUB    CZXB, PF6, PF2
    FSUB    PF6, PF1, CZXB
    FMUL    PF6, PF3, PF6
    FSUB    CZYB, PF6, PF5
    FSQ     PF6, PF4
    FSUB    PF6, PF6, PF1
    FSUB    CZXA, PF6, PF2
    FSUB    PF6, PF1, CZXA
    FMUL    PF6, PF4, PF6
    FSUB    CZYA, PF6, PF5
    ret

; XYcZ-ADDU: A = B + A, B rescaled.  4M + 2S.
p384_coz_addu:
    FSUB    PF0, CZXB, CZXA
    FSQ     PF0, PF0
    FMUL    PF2, CZXA, PF0
    FMUL    CZXB, CZXB, PF0
    FSUB    PF3, CZYB, CZYA
    FSUB    PF6, CZXB, PF2
    FMUL    CZYB, CZYB, PF6
    FSQ     PF6, PF3
    FSUB    PF6, PF6, CZXB
    FSUB    CZXA, PF6, PF2
    FSUB    PF6, CZXB, CZXA
    FMUL    PF6, PF3, PF6
    FSUB    CZYA, PF6, CZYB
    ret

; ===========================================================================
; Affine export, interrupt handling, public entry points
; ===========================================================================
; x_be (and y_be if non-NULL) of a Jacobian point.
; In: HL=point, DE=x_be, BC=y_be or 0.  Out: A=1, or 0 if infinity.
p384_affine_export:
    ld      (ae_pt), hl
    ld      (ae_x), de
    ld      (ae_y), bc
    ld      de, 96
    add     hl, de
    push    hl
    call    p384_ct_is_zero
    pop     hl
    inc     a
    ret     z
    ld      bc, PF0
    call    p384_fe_inv
    FSQ     PF1, PF0
    ld      hl, (ae_pt)
    ld      de, PF1
    ld      bc, PF2
    call    p384_mul_p
    ld      hl, (ae_y)
    ld      a, h
    or      a, l
    jr      z, .Lae_noy
    FMUL    PF1, PF1, PF0
    ld      hl, (ae_pt)
    ld      de, 48
    add     hl, de
    ld      de, PF1
    ld      bc, PF3
    call    p384_mul_p
    FMUL    PF3, PF3, __p384_ONE
    ld      hl, PF3
    ld      de, (ae_y)
    call    p384_rev48
.Lae_noy:
    FMUL    PF2, PF2, __p384_ONE
    ld      hl, PF2
    ld      de, (ae_x)
    call    p384_rev48
    ld      a, 1
    ret

; Zero the scratch, save IFF1, disable interrupts.
p384_di:
    call    p384_wipe
    ld      a, i
    jp      pe, .Lpd_on
    xor     a, a
    ld      (p384_di_save), a
    di
    ret
.Lpd_on:
    ld      a, 1
    ld      (p384_di_save), a
    di
    ret

p384_wipe:
    ld      hl, __p384_scratch_start
    ld      (hl), 0
    ld      de, __p384_scratch_start + 1
    ld      bc, __p384_scratch_end - __p384_scratch_start - 1
    ldir
    ret

; Common public-API epilogue.  In: A = result.
p384_exit:
    push    af
    ld      a, (p384_di_save)
    push    af
    call    p384_wipe
    pop     af
    bit     0, a
    jr      z, .Lpx_noei
    ei
.Lpx_noei:
    pop     af
    pop     ix
    ret

p384_null:
    add     hl, de
    or      a, a
    sbc     hl, de
    ret

; ===========================================================================
; Public API: publickey / secret / verify
; ===========================================================================
    globl   _tls_p384_publickey
    .type   _tls_p384_publickey, @function
    globl   _tls_p384_secret
    .type   _tls_p384_secret, @function
    globl   _tls_p384_verify
    .type   _tls_p384_verify, @function

; bool tls_p384_publickey(uint8_t pub[97], const uint8_t priv[48])
_tls_p384_publickey:
    push    ix
    ld      ix, 0
    add     ix, sp
    call    p384_di
    ld      hl, (ix + 6)
    call    p384_null
    jr      z, .Lpk_fail
    ld      hl, (ix + 9)
    call    p384_null
    jr      z, .Lpk_fail
    ld      hl, PF0
    ld      de, (ix + 9)
    ld      iy, __p384_N
    ld      c, 1
    call    p384_import_be
    or      a, a
    jr      z, .Lpk_fail
    ld      hl, __p384_saved0
    ld      de, (ix + 9)
    ld      bc, __p384_G
    call    p384_scalar_mul
    ld      hl, (ix + 6)
    ld      (hl), 0x04
    inc     hl
    ex      de, hl
    ld      hl, 48
    add     hl, de
    push    hl
    pop     bc
    ld      hl, __p384_saved0
    call    p384_affine_export
    jp      p384_exit
.Lpk_fail:
    xor     a, a
    jp      p384_exit

; bool tls_p384_secret(uint8_t ss[48], const uint8_t priv[48],
;                      const uint8_t peer[97])
_tls_p384_secret:
    push    ix
    ld      ix, 0
    add     ix, sp
    call    p384_di
    ld      hl, (ix + 6)
    call    p384_null
    jr      z, .Lss_fail
    ld      hl, (ix + 9)
    call    p384_null
    jr      z, .Lss_fail
    ld      hl, PF0
    ld      de, (ix + 9)
    ld      iy, __p384_N
    ld      c, 1
    call    p384_import_be
    or      a, a
    jr      z, .Lss_fail
    ld      hl, (ix + 12)
    call    p384_null
    jr      z, .Lss_fail
    call    p384_point_import
    or      a, a
    jr      z, .Lss_fail
    ld      hl, __p384_saved0
    ld      de, (ix + 9)
    ld      bc, __p384_pq
    call    p384_scalar_mul
    ld      hl, __p384_saved0
    ld      de, (ix + 6)
    ld      bc, 0
    call    p384_affine_export
    jp      p384_exit
.Lss_fail:
    xor     a, a
    jp      p384_exit

; bool tls_p384_verify(const uint8_t sig[96], const uint8_t hash[48],
;                      const uint8_t pub[97])
_tls_p384_verify:
    push    ix
    ld      ix, 0
    add     ix, sp
    call    p384_di
    ld      hl, (ix + 6)
    call    p384_null
    jp      z, .Lvf_fail
    ld      hl, (ix + 9)
    call    p384_null
    jp      z, .Lvf_fail
    ld      hl, (ix + 12)
    call    p384_null
    jp      z, .Lvf_fail
    call    p384_point_import
    or      a, a
    jp      z, .Lvf_fail
    ld      hl, PF0
    ld      de, (ix + 6)
    ld      iy, __p384_N
    ld      c, 1
    call    p384_import_be
    or      a, a
    jp      z, .Lvf_fail
    ld      hl, (ix + 6)
    ld      de, 48
    add     hl, de
    ex      de, hl
    ld      hl, PF1
    ld      iy, __p384_N
    ld      c, 1
    call    p384_import_be
    or      a, a
    jp      z, .Lvf_fail
    ld      hl, (ix + 9)
    ld      de, PF2
    call    p384_rev48
    ld      hl, PF2
    ld      de, __p384_N
    ld      c, 0
    call    p384_reduce_top
    ; w = s^-1 in the Montgomery domain (order_import takes big-endian)
    ld      hl, (ix + 6)
    ld      de, 48
    add     hl, de
    ex      de, hl
    ld      hl, PF7
    call    p384_order_import
    ld      hl, PF7
    ld      bc, PF8
    call    p384_ord_inv
    OMUL    __p384_k, PF8, PF2
    OMUL    __p384_x, PF8, PF0
    ld      hl, __p384_k
    ld      de, __p384_tmp
    call    p384_rev48
    ld      hl, __p384_x
    ld      de, __p384_tmp2
    call    p384_rev48
    ld      hl, __p384_acc
    ld      de, __p384_tmp
    ld      bc, __p384_G
    call    p384_scalar_mul
    ld      hl, __p384_saved0
    ld      de, __p384_tmp2
    ld      bc, __p384_pq
    call    p384_scalar_mul
    ld      hl, __p384_acc
    ld      de, __p384_saved1
    ld      bc, 144
    ldir
    ld      hl, __p384_rt
    call    p384_point_add
    ld      hl, PRTZ
    call    p384_ct_is_zero
    or      a, a
    jp      nz, .Lvf_fail
    ld      hl, __p384_rt
    ld      de, PF12
    ld      bc, 0
    call    p384_affine_export
    or      a, a
    jp      z, .Lvf_fail
    ld      hl, PF12
    ld      de, (ix + 6)
    call    p384_eq48
    or      a, a
    jp      nz, p384_exit
    ld      hl, PF0
    ld      de, __p384_N
    ld      iy, PF13
    call    p384_add48
    or      a, a
    jp      nz, .Lvf_fail
    ld      hl, PF13
    ld      de, __p384_P
    call    p384_raw_ge
    or      a, a
    jp      nz, .Lvf_fail
    ld      hl, PF13
    ld      de, PF12
    call    p384_rev48
    ld      hl, PF12
    ld      de, (ix + 6)
    call    p384_eq48
    jp      p384_exit
.Lvf_fail:
    xor     a, a
    jp      p384_exit

; ===========================================================================
; ECDSA signing with RFC 6979 deterministic nonces (HMAC-SHA-384).
; ===========================================================================
    .section .text.__p384_sign,"ax",@progbits

    extern  _tls_sha384_init
    extern  _tls_sha384_update
    extern  _tls_sha384_digest
    extern  _tls_crypto_guard_enable
    extern  _tls_crypto_guard_disable

    globl   _tls_p384_sign
    .type   _tls_p384_sign, @function

; p384_hmac: out = HMAC-SHA384(key[48], msg[len]).
; In: HL=out, DE=key, BC=msg, A=len (<=255).  out may alias key or msg.
p384_hmac:
    ld      (hm_out), hl
    ld      (hm_key), de
    ld      (hm_msg), bc
    ld      (hm_len), a
    ld      a, 0x36
    call    .Lhm_keyed_init
    ld      a, (hm_len)
    or      a, a
    sbc     hl, hl
    ld      l, a
    push    hl
    ld      hl, (hm_msg)
    push    hl
    ld      hl, DK_CTX
    push    hl
    call    _tls_sha384_update
    pop     hl
    pop     hl
    pop     hl
    ld      hl, DK_INNER
    push    hl
    ld      hl, DK_CTX
    push    hl
    call    _tls_sha384_digest
    pop     hl
    pop     hl
    ld      a, 0x5C
    call    .Lhm_keyed_init
    ld      hl, 48
    push    hl
    ld      hl, DK_INNER
    push    hl
    ld      hl, DK_CTX
    push    hl
    call    _tls_sha384_update
    pop     hl
    pop     hl
    pop     hl
    ld      hl, (hm_out)
    push    hl
    ld      hl, DK_CTX
    push    hl
    call    _tls_sha384_digest
    pop     hl
    pop     hl
    ret
; In: A = pad byte.  DK_PAD = (key || 0^128) ^ A^128; init ctx; absorb pad.
.Lhm_keyed_init:
    ld      hl, DK_PAD
    ld      b, 128
.Lhm_fill:
    ld      (hl), a
    inc     hl
    djnz    .Lhm_fill
    ld      hl, (hm_key)
    ld      de, DK_PAD
    ld      b, 48
.Lhm_xor:
    ld      a, (de)
    xor     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    djnz    .Lhm_xor
    ld      hl, DK_CTX
    push    hl
    call    _tls_sha384_init
    pop     hl
    ld      hl, 128
    push    hl
    ld      hl, DK_PAD
    push    hl
    ld      hl, DK_CTX
    push    hl
    call    _tls_sha384_update
    pop     hl
    pop     hl
    pop     hl
    ret

; RFC 6979 section 3.2 nonce for (dk_hash, dk_priv) -> __p384_k (BE).
p384_det_k:
    ld      hl, DK_K
    ld      (hl), 0
    ld      de, DK_K + 1
    ld      bc, 47
    ldir
    ld      hl, DK_V
    ld      (hl), 1
    ld      de, DK_V + 1
    ld      bc, 47
    ldir
    ld      hl, (dk_hash)
    ld      de, __p384_tmp
    call    p384_rev48
    ld      hl, __p384_tmp
    ld      de, __p384_N
    ld      c, 0
    call    p384_reduce_top
    ld      hl, __p384_tmp
    ld      de, DK_H1
    call    p384_rev48
    xor     a, a
    call    .Ldk_round
    ld      a, 1
    call    .Ldk_round
.Ldk_gen:
    ld      hl, DK_V
    ld      de, DK_K
    ld      bc, DK_V
    ld      a, 48
    call    p384_hmac
    ld      hl, DK_V
    ld      de, __p384_k
    ld      bc, 48
    ldir
    ld      hl, __p384_tmp
    ld      de, __p384_k
    ld      iy, __p384_N
    ld      c, 1
    call    p384_import_be
    or      a, a
    ret     nz
p384_det_k_continue:
    ld      hl, DK_V
    ld      de, DK_RFC
    ld      bc, 48
    ldir
    xor     a, a
    ld      (de), a
    ld      hl, DK_K
    ld      de, DK_K
    ld      bc, DK_RFC
    ld      a, 49
    call    p384_hmac
    ld      hl, DK_V
    ld      de, DK_K
    ld      bc, DK_V
    ld      a, 48
    call    p384_hmac
    jr      .Ldk_gen
; In: A = separator byte.  K = HMAC(K, V||A||priv||h1); V = HMAC(K, V).
.Ldk_round:
    push    af
    ld      hl, DK_V
    ld      de, DK_RFC
    ld      bc, 48
    ldir
    pop     af
    ld      (de), a
    inc     de
    ld      hl, (dk_priv)
    ld      bc, 48
    ldir
    ld      hl, DK_H1
    ld      bc, 48
    ldir
    ld      hl, DK_K
    ld      de, DK_K
    ld      bc, DK_RFC
    ld      a, 145
    call    p384_hmac
    ld      hl, DK_V
    ld      de, DK_K
    ld      bc, DK_V
    ld      a, 48
    jp      p384_hmac

; bool tls_p384_sign(uint8_t sig[96], const uint8_t hash[48],
;                    const uint8_t priv[48])
_tls_p384_sign:
    push    ix
    ld      ix, 0
    add     ix, sp
    call    p384_di
    ld      hl, (ix + 6)
    call    p384_null
    jp      z, .Lsg_fail
    ld      hl, (ix + 9)
    call    p384_null
    jp      z, .Lsg_fail
    ld      hl, (ix + 12)
    call    p384_null
    jp      z, .Lsg_fail
    ld      hl, PF0
    ld      de, (ix + 12)
    ld      iy, __p384_N
    ld      c, 1
    call    p384_import_be
    or      a, a
    jp      z, .Lsg_fail
    ld      hl, (ix + 9)
    ld      (dk_hash), hl
    ld      hl, (ix + 12)
    ld      (dk_priv), hl
.Lsg_try:
    call    _tls_crypto_guard_enable
    call    p384_det_k
    call    _tls_crypto_guard_disable
.Lsg_scalar:
    ld      hl, __p384_saved0
    ld      de, __p384_k
    ld      bc, __p384_G
    call    p384_scalar_mul
    ld      hl, __p384_saved0
    ld      de, __p384_x
    ld      bc, 0
    call    p384_affine_export
    or      a, a
    jp      z, .Lsg_fail
    ld      hl, PF2
    ld      de, __p384_x
    call    p384_order_import
    ld      hl, PF3
    ld      de, (ix + 12)
    call    p384_order_import
    ld      hl, PF4
    ld      de, (ix + 9)
    call    p384_order_import
    ld      hl, PF5
    ld      de, __p384_k
    call    p384_order_import
    OMUL    PF6, PF2, PF3
    OADD    PF6, PF6, PF4
    ld      hl, PF5
    ld      bc, PF7
    call    p384_ord_inv
    OMUL    PF6, PF6, PF7
    ld      hl, PF2
    call    p384_ct_is_zero
    inc     a
    jp      z, .Lsg_retry
    ld      hl, PF6
    call    p384_ct_is_zero
    inc     a
    jp      z, .Lsg_retry
    ld      hl, PF2
    ld      de, (ix + 6)
    call    p384_order_export
    ld      hl, (ix + 6)
    ld      de, 48
    add     hl, de
    ex      de, hl
    ld      hl, PF6
    call    p384_order_export
    ld      a, 1
    jp      p384_exit
.Lsg_retry:
    call    _tls_crypto_guard_enable
    call    p384_det_k_continue
    call    _tls_crypto_guard_disable
    jp      .Lsg_scalar
.Lsg_fail:
    xor     a, a
    jp      p384_exit


; Copy the 48-term MAC loop into the fast-RAM window.  The loop is tiny, so
; an unconditional copy costs a few hundred cycles per field operation.
p384_mul_reloc_load:
    ld      hl, _p384_mul_reloc_load_start
    ld      de, _p384_mul_reloc_run_start
    ld      bc, _p384_mul_reloc_len
    ldir
    ret

    .section .p384.mul.reloc,"ax",@progbits
_p384_mul_reloc_run_start:
p384_mul_mac:
    ld      d, (ix + 0)
    ld      e, (iy + 0)
    mlt     de
    add     hl, de
    inc     ix
    dec     iy
    djnz    p384_mul_mac
    ret
_p384_mul_reloc_run_end:

    .section .text.__p384,"ax",@progbits

    .section .note.GNU-stack,"",@progbits

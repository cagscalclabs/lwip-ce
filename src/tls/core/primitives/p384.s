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
; 24-bit column accumulator (same formulation as p256.s, scaled from 32 to 48
; digits).  Field (mod p) multiply/square use fully unrolled column code with
; the q*p pass replaced by p's sparse signed-digit structure and the MAC
; blocks run from the fast-RAM window (p384_mul_p / p384_sq_p); the order
; (mod n) path keeps the generic p384_mont_core.  Field inversion uses a fixed
; addition chain.  The constant-time variable-base scalar multiplication
; (ECDH, p384_ws_mul) is a width-4 fixed window with Joye-Tunstall signed
; regular recoding over an 8-entry Jacobian table of odd multiples of Q.
; Jacobian point formulas use a = -3.  ECDSA verification is variable-time
; with respect to its (public) inputs: s^-1 by binary extended Euclid
; (p384_ord_inv_vt), then u1*G + u2*Q in one interleaved doubling chain
; (u2: width-4 NAF over Q, 3Q, 5Q, 7Q; u1: the fixed-base comb table folded
; into the last 96 positions), and x(R) mod n == r checked projectively
; (X == r Z^2, also r + n when r + n < p) with no field inversion.  That
; engine must never be given secret data.
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
; Fixed-base k*G (keygen and signing) uses p384_comb_mul instead: a
; constant-time w = 4, d = 96 comb over a 15-entry affine ROM table
; (__p384_COMB), 95 doublings + 96 mixed additions.  Verify reuses the same
; ROM table (not the routine) for the public u1*G inside its Shamir chain.
;
; Constant-time notes: the comb, the windowed ECDH multiply, field
; arithmetic, point formulas, table lookups and selects never branch on or
; index memory by secret data.  Branches exist only for public loop
; counters / digit indices, the fixed public exponent used by inversion,
; public input-validation results, and the RFC 6979 r=0/s=0 retry (as in
; p256.s).  Verification is the documented exception: all of its inputs
; are public.
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
; mm_acopy | mm_u | mm_bcopy | mm_acc2 must stay contiguous and in this
; order: p384_mul_p / p384_sq_p reach all four through IX/IY displacements
; whose ranges (-128..127) were derived for exactly this layout.
mm_acopy:               .space 48       ; mul_p/sq_p: copy of a
mm_u:                   .space 48       ; q[0..47], then t[0..47] in place
__p384_red:                             ; reduce_top temp (ord path), aliases
mm_bcopy:               .space 48       ; mul_p: copy of b
mm_acc2:                .space 4        ; shift cell (byte 3 always 0)
__p384_f:               .space 14*48    ; f[0..13] field temporaries
__p384_tmp:             .space 48       ; generic 48-byte temporary
__p384_tmp2:            .space 48       ; second 48-byte temporary (scalar BE)
__p384_r0:              .space 144      ; ECDH: table 3Q; verify: wNAF codes
__p384_r1:              .space 144      ; ECDH: table 5Q; verify: wNAF work
__p384_saved0:          .space 144      ; point-op input P
__p384_saved1:          .space 144      ; point-op input Q
__p384_rt:              .space 144      ; point-op result temp
__p384_add_result:      .space 144      ; point_add temp; ECDH 7Q; verify 3Q
__p384_double_result:   .space 144      ; point_add temp; ECDH 9Q; verify 5Q
__p384_pq:              .space 144      ; imported peer/public point (= T[0])
__p384_acc:             .space 144      ; ECDH: table 11Q; verify: 7Q
__p384_k:               .space 48       ; sign: nonce k (BE); verify: u1 (LE)
__p384_x:               .space 48       ; sign: x(R) (BE);   verify: u2 (LE)
                                        ; ECDH: k||x = 96 recoded digits
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
sm_kp:                  .space 48       ; ECDH: k' = k or n - k (LE), recoded
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
vs_i:                   .space 3        ; verify: position 384..0 / wNAF index
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

; --- parameters of the shared curve layer (share/ecc_curve.inc) ---
.equ FIELD_BYTES, 48                    ; field / scalar width in bytes
.equ SCALAR_BITS, 384
.equ COMB_D,      96                    ; fixed-base comb strip length (bits)
.equ COMB_W,      4                     ; fixed-base comb width (strips)
.equ WS_DIGITS,   96                    ; ECDH signed fixed-window digits
.include "ecc_curve.inc"

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

; P384 fixed-base comb table, w = 4, d = 96: entry j (1..15) at
; __p384_COMB + 96*(j-1) = sum over set bits s of j of 2^(96s) G,
; affine, Montgomery form (x R, y R mod p), 48-byte LE x || y.
; Generated by gen_comb_table.py; each entry checked against an
; independent Jacobian double-and-add of the integer scalar.
__p384_COMB:
    ; j =  1: 1 G
    .db     0x28, 0xB5, 0xC0, 0x49, 0x66, 0x75, 0xD0, 0x3D
    .db     0x38, 0xCE, 0xD6, 0xA0, 0xE2, 0x78, 0xE3, 0x20
    .db     0x6E, 0x4D, 0x1B, 0x54, 0xFC, 0x3A, 0x9C, 0x87
    .db     0xFF, 0x0E, 0xA3, 0x59, 0x84, 0x86, 0x54, 0x64
    .db     0x2B, 0xDE, 0x4E, 0x61, 0x23, 0xF7, 0x2F, 0x81
    .db     0x13, 0x15, 0x9E, 0x29, 0xC2, 0xAD, 0x3A, 0x4D
    .db     0xFE, 0xA4, 0x03, 0x4B, 0xAD, 0x3D, 0x04, 0x23
    .db     0xAC, 0xA9, 0xB4, 0x7B, 0xBF, 0xA8, 0xBF, 0xA1
    .db     0x50, 0xB0, 0x83, 0x2E, 0x56, 0xE7, 0xAD, 0x8B
    .db     0xD9, 0xFF, 0xF4, 0x68, 0x19, 0x52, 0xC3, 0xC6
    .db     0x40, 0xA8, 0x69, 0x39, 0x26, 0x02, 0x80, 0xDD
    .db     0xE9, 0xC5, 0x15, 0x5A, 0xC2, 0xAB, 0x78, 0x2B
    ; j =  2: 2^96 G
    .db     0xF9, 0xEE, 0x6F, 0xF2, 0x57, 0x0C, 0x48, 0x24
    .db     0x40, 0x12, 0x0E, 0x3A, 0x94, 0x26, 0x1A, 0xC3
    .db     0xC7, 0x2B, 0x3E, 0x27, 0xC3, 0x02, 0x50, 0x73
    .db     0x4C, 0xED, 0xF1, 0x3E, 0xC5, 0xE9, 0x42, 0x8C
    .db     0xE8, 0x48, 0x49, 0x7F, 0xF6, 0xAB, 0x8B, 0x02
    .db     0x32, 0x86, 0x97, 0x8A, 0x43, 0x2F, 0x50, 0x6A
    .db     0xFE, 0x36, 0x45, 0xB7, 0x46, 0x3A, 0xF1, 0xF5
    .db     0xEB, 0xF0, 0xA9, 0xD8, 0xAB, 0x8B, 0x21, 0x1D
    .db     0x68, 0x27, 0x23, 0x37, 0xCC, 0x6B, 0xF3, 0x30
    .db     0x18, 0x8C, 0x6E, 0x57, 0x31, 0x7B, 0x31, 0xC5
    .db     0x66, 0xB7, 0xBC, 0x9B, 0xA6, 0x57, 0x1D, 0xEF
    .db     0xDC, 0xD4, 0xE3, 0xB3, 0x30, 0x49, 0x7C, 0x91
    ; j =  3: 1 + 2^96 G
    .db     0xD0, 0xDD, 0x49, 0xE3, 0x2E, 0x6E, 0x42, 0x11
    .db     0x50, 0xC2, 0x2F, 0x9B, 0xF9, 0x7E, 0x11, 0x9F
    .db     0xA6, 0x74, 0x01, 0xEC, 0x80, 0xB4, 0x36, 0xFF
    .db     0x66, 0x84, 0x45, 0x18, 0x76, 0xDE, 0x4B, 0x4F
    .db     0x49, 0x60, 0x80, 0x05, 0x6D, 0xDB, 0x2E, 0x2F
    .db     0x92, 0xCA, 0xDF, 0x19, 0xD1, 0x75, 0xDC, 0x8A
    .db     0xCE, 0xA7, 0xD5, 0xB7, 0x97, 0xD0, 0x19, 0xA6
    .db     0xE9, 0x11, 0x44, 0xA3, 0xE5, 0x75, 0x42, 0x87
    .db     0xEF, 0xB4, 0xA4, 0x0D, 0x47, 0xE0, 0x03, 0x54
    .db     0x8F, 0x1D, 0x90, 0x77, 0xD9, 0xAF, 0xBA, 0x2E
    .db     0x0F, 0x17, 0x47, 0xA7, 0xCE, 0xEB, 0x63, 0x5E
    .db     0x36, 0x80, 0x9D, 0x7F, 0x44, 0x69, 0xA3, 0x12
    ; j =  4: 2^192 G
    .db     0x67, 0xBE, 0x9F, 0x2F, 0xDE, 0x05, 0x82, 0x37
    .db     0x44, 0x8E, 0x72, 0x7F, 0x83, 0xCB, 0xAF, 0xC4
    .db     0xF1, 0x00, 0x2E, 0x68, 0x6C, 0xC0, 0xCE, 0xDB
    .db     0x23, 0x54, 0x4D, 0x11, 0xC3, 0x45, 0xA1, 0xF2
    .db     0x3E, 0x46, 0x52, 0x7A, 0x74, 0x98, 0x1D, 0xA0
    .db     0x0A, 0x7B, 0x71, 0x7D, 0xB1, 0x35, 0x09, 0xFC
    .db     0x95, 0x1F, 0xD0, 0xD4, 0x4F, 0xBC, 0x53, 0x96
    .db     0x34, 0xAD, 0x60, 0x95, 0xA8, 0x3E, 0xA8, 0x9A
    .db     0x3F, 0x3F, 0x8E, 0xAF, 0xDC, 0x43, 0x79, 0xF7
    .db     0x6E, 0xE1, 0x6F, 0xE8, 0x10, 0x4A, 0x77, 0x70
    .db     0xCF, 0xFD, 0x9F, 0xBF, 0xF1, 0xE6, 0x62, 0x6B
    .db     0xC9, 0x45, 0x87, 0x58, 0x9E, 0xF3, 0x72, 0x8A
    ; j =  5: 1 + 2^192 G
    .db     0x42, 0xC3, 0x41, 0x23, 0xDA, 0xE4, 0xAD, 0x73
    .db     0x22, 0x44, 0x70, 0xEA, 0x54, 0x6E, 0x32, 0xDD
    .db     0xF3, 0xCE, 0x41, 0x37, 0x98, 0x7D, 0x6C, 0x33
    .db     0x49, 0x15, 0xE6, 0x59, 0x0D, 0xA0, 0xAF, 0x1E
    .db     0xFD, 0x3E, 0x9A, 0xBD, 0x92, 0xD8, 0x3E, 0xCD
    .db     0xE4, 0xC7, 0xC6, 0xC5, 0x6C, 0xF2, 0xFA, 0x03
    .db     0xAC, 0xF8, 0x45, 0x30, 0xCF, 0x2F, 0x7E, 0x08
    .db     0x73, 0x1E, 0x4F, 0x17, 0x32, 0x55, 0xA6, 0x14
    .db     0xA7, 0xF9, 0x0A, 0xFE, 0x28, 0x4F, 0xF8, 0x2C
    .db     0x5B, 0x93, 0xDC, 0x2C, 0x84, 0x7A, 0xFD, 0xDD
    .db     0x95, 0xC8, 0x29, 0x69, 0x7B, 0x11, 0x0F, 0x4C
    .db     0xCC, 0xCF, 0x8B, 0x4C, 0xD6, 0x72, 0x65, 0x35
    ; j =  6: 2^96 + 2^192 G
    .db     0x6F, 0x23, 0x3B, 0x3F, 0x07, 0x86, 0xB0, 0xFA
    .db     0xDA, 0x21, 0xE2, 0x81, 0x1D, 0xD4, 0xE9, 0x19
    .db     0x28, 0xB4, 0x27, 0x39, 0x1E, 0x57, 0xF6, 0xF3
    .db     0xF6, 0xF1, 0x50, 0x75, 0x33, 0xA9, 0x48, 0x43
    .db     0xF0, 0x62, 0x5E, 0xA8, 0x96, 0xB9, 0x67, 0x71
    .db     0xBF, 0x52, 0x54, 0x7F, 0x59, 0x37, 0xD4, 0x62
    .db     0x26, 0x59, 0x95, 0xF2, 0x9E, 0xEB, 0x5F, 0xD8
    .db     0x53, 0x83, 0xF7, 0x6D, 0x1F, 0x56, 0x0A, 0x44
    .db     0x59, 0x6B, 0xA3, 0x9C, 0xEC, 0x68, 0x96, 0x38
    .db     0x16, 0xA0, 0x2D, 0xA2, 0xA1, 0xF1, 0x2B, 0x05
    .db     0x54, 0x32, 0x09, 0xF6, 0x72, 0xFF, 0xFB, 0xBD
    .db     0xF3, 0x09, 0x22, 0xE2, 0x28, 0x0F, 0xE5, 0x94
    ; j =  7: 1 + 2^96 + 2^192 G
    .db     0xAF, 0xE8, 0x62, 0x30, 0xB3, 0xE5, 0xB2, 0x90
    .db     0x69, 0xD3, 0xA3, 0xE8, 0x75, 0x23, 0x57, 0xA8
    .db     0xB1, 0xB7, 0x1D, 0x20, 0x0B, 0xB0, 0xE1, 0x3F
    .db     0xA2, 0x1A, 0x65, 0xEE, 0xF0, 0xDE, 0x26, 0xE9
    .db     0xD7, 0x0A, 0xB1, 0xB9, 0xBE, 0xC9, 0x42, 0x65
    .db     0x74, 0xBE, 0xFC, 0xA2, 0x9B, 0x30, 0x8E, 0x09
    .db     0x3F, 0xD6, 0xF1, 0xFF, 0xB3, 0xEE, 0x9D, 0x77
    .db     0x74, 0xD3, 0xBF, 0x20, 0x0A, 0xE8, 0xD0, 0x23
    .db     0x97, 0xF7, 0x68, 0x87, 0x3B, 0xBB, 0x52, 0x84
    .db     0x56, 0x28, 0x95, 0x1F, 0x4D, 0xBB, 0x75, 0xCF
    .db     0xAA, 0x3F, 0xEA, 0x29, 0x00, 0xB4, 0xE6, 0x8F
    .db     0x53, 0x3A, 0x37, 0x81, 0x40, 0x3E, 0xBD, 0x12
    ; j =  8: 2^288 G
    .db     0xF4, 0x3C, 0x97, 0x16, 0xE1, 0x34, 0x0D, 0x07
    .db     0xF7, 0x34, 0x4F, 0x7E, 0x8B, 0xE0, 0xAE, 0x20
    .db     0x29, 0xAD, 0xB8, 0x5E, 0xB9, 0xF9, 0x9A, 0x26
    .db     0xDA, 0x5D, 0xA4, 0xA6, 0x36, 0xA0, 0xE0, 0xDD
    .db     0xE0, 0x41, 0xDF, 0x63, 0x8E, 0x52, 0x8B, 0xA1
    .db     0x2A, 0xDF, 0x60, 0xA2, 0xB2, 0x71, 0xCC, 0x03
    .db     0xD7, 0x1D, 0x6B, 0xA0, 0x0A, 0x77, 0xA6, 0x24
    .db     0xD3, 0x75, 0x26, 0x9D, 0x11, 0x9C, 0xFA, 0x5B
    .db     0x32, 0x44, 0x84, 0x96, 0xA1, 0xE2, 0xC1, 0x73
    .db     0xF0, 0x6C, 0x1A, 0x13, 0x8D, 0x55, 0x60, 0x36
    .db     0x54, 0x94, 0xE7, 0x2E, 0x83, 0x9C, 0x28, 0xB0
    .db     0xCD, 0xDD, 0xD8, 0xC6, 0x01, 0xFB, 0xAE, 0xA6
    ; j =  9: 1 + 2^288 G
    .db     0x45, 0x52, 0xAB, 0x01, 0xB4, 0x64, 0x14, 0xBA
    .db     0xFF, 0x93, 0x8D, 0xC4, 0x6D, 0x0B, 0x8D, 0x9B
    .db     0x2C, 0x27, 0xAD, 0x93, 0xDC, 0x67, 0x98, 0x93
    .db     0x77, 0xDC, 0x9F, 0xAE, 0x5E, 0x08, 0xBE, 0xBE
    .db     0xBD, 0xA8, 0x4E, 0x89, 0x03, 0x51, 0xAE, 0x73
    .db     0xE1, 0x22, 0xAC, 0x39, 0x9A, 0xC8, 0x0F, 0x74
    .db     0x23, 0x3B, 0xE2, 0x28, 0xA3, 0xB0, 0x28, 0x5E
    .db     0xD0, 0x04, 0x31, 0xE1, 0x2E, 0x72, 0x52, 0x23
    .db     0x0D, 0x64, 0xA2, 0xB0, 0x18, 0x7A, 0x66, 0xF4
    .db     0xC3, 0x37, 0xBB, 0x49, 0x2E, 0xA7, 0x74, 0xAC
    .db     0x3A, 0x18, 0x1E, 0xE8, 0xF0, 0x34, 0xF7, 0x79
    .db     0xEB, 0xC0, 0xD9, 0x3F, 0x6C, 0x5B, 0xFE, 0xBF
    ; j = 10: 2^96 + 2^288 G
    .db     0x3B, 0x3F, 0x62, 0x00, 0x22, 0x29, 0xCF, 0x03
    .db     0xFF, 0xEB, 0x29, 0x5F, 0x11, 0x71, 0x5C, 0x09
    .db     0x23, 0x68, 0xAA, 0x80, 0x47, 0x22, 0xD7, 0x42
    .db     0xB0, 0xC0, 0x58, 0x74, 0xA1, 0x7B, 0x4C, 0x04
    .db     0x20, 0xEC, 0x59, 0x09, 0xEF, 0xF7, 0x62, 0xCA
    .db     0x9F, 0x92, 0xCA, 0xF8, 0xB7, 0x2A, 0xAE, 0x40
    .db     0x02, 0xB1, 0x27, 0xA9, 0x7A, 0x37, 0xC5, 0xB8
    .db     0x71, 0x17, 0x03, 0xDC, 0xA0, 0x86, 0x8A, 0x39
    .db     0x06, 0xA4, 0x16, 0xC2, 0x9D, 0x8F, 0x90, 0x04
    .db     0x00, 0x33, 0x8D, 0x91, 0x3A, 0xA7, 0x23, 0xB4
    .db     0x39, 0x47, 0xB9, 0xE0, 0xF1, 0x0F, 0x4B, 0x63
    .db     0x97, 0xF6, 0x69, 0x2D, 0x25, 0xE7, 0x9D, 0xE2
    ; j = 11: 1 + 2^96 + 2^288 G
    .db     0x04, 0xAF, 0x35, 0x84, 0x00, 0x14, 0x4D, 0x74
    .db     0xDA, 0x92, 0xC1, 0xFE, 0x1D, 0x5B, 0x25, 0x5F
    .db     0x42, 0xC5, 0x6D, 0x33, 0x12, 0xDC, 0x17, 0x1F
    .db     0xA8, 0x68, 0x6A, 0x63, 0xA7, 0xC2, 0x90, 0x5C
    .db     0x1E, 0xCA, 0x04, 0x77, 0xB7, 0x9E, 0x0C, 0x96
    .db     0x5A, 0xD6, 0xB3, 0x6F, 0x1E, 0xCF, 0xE8, 0x9D
    .db     0x06, 0x3D, 0x1D, 0x51, 0x0D, 0xEE, 0x0F, 0xC6
    .db     0xC7, 0x52, 0xEB, 0xF9, 0x13, 0x23, 0x6E, 0x46
    .db     0x14, 0x09, 0x6B, 0x20, 0x5F, 0x0F, 0x3C, 0x74
    .db     0x4D, 0xAA, 0x91, 0x21, 0xAC, 0x5B, 0xF5, 0x42
    .db     0xC2, 0xDB, 0xEB, 0xFF, 0x8F, 0x7C, 0xFC, 0xCE
    .db     0x1C, 0xED, 0xE8, 0xE6, 0x81, 0x60, 0xFA, 0xD4
    ; j = 12: 2^192 + 2^288 G
    .db     0x86, 0x31, 0x68, 0x98, 0x39, 0xB6, 0x7D, 0x86
    .db     0xA9, 0x4E, 0xCC, 0xDD, 0x24, 0xF4, 0x5C, 0xFB
    .db     0xBD, 0xE7, 0xF0, 0xD4, 0xFE, 0x7F, 0x9A, 0xCC
    .db     0x7E, 0x9F, 0x77, 0x7A, 0x1C, 0xF7, 0x57, 0x7C
    .db     0xF2, 0x5E, 0xB2, 0xD6, 0x79, 0x40, 0x77, 0x90
    .db     0x80, 0x16, 0x08, 0xB4, 0x03, 0xE9, 0xEA, 0x90
    .db     0xEB, 0xFC, 0xE1, 0x0E, 0x5E, 0xAE, 0x2A, 0xDF
    .db     0x1F, 0x1A, 0x6C, 0xE8, 0x24, 0xDA, 0xF1, 0x3F
    .db     0xDF, 0x3E, 0x19, 0xCA, 0xD6, 0x87, 0xF5, 0x80
    .db     0x6A, 0x9D, 0x9B, 0xDC, 0x23, 0x55, 0x69, 0xA5
    .db     0x03, 0x03, 0x92, 0x85, 0x00, 0x09, 0x84, 0x7B
    .db     0xEF, 0xBD, 0x6D, 0xBA, 0xFC, 0x4D, 0xFA, 0x1E
    ; j = 13: 1 + 2^192 + 2^288 G
    .db     0x15, 0x00, 0x54, 0xE0, 0xF9, 0x38, 0xD8, 0xFB
    .db     0xDC, 0x77, 0x90, 0xC3, 0x46, 0x39, 0x32, 0x2C
    .db     0x24, 0x91, 0x61, 0xAD, 0xE6, 0xB9, 0x1F, 0x8B
    .db     0xA8, 0x2E, 0xA6, 0x0C, 0x0C, 0x44, 0x12, 0x96
    .db     0xFF, 0x00, 0xBE, 0x2D, 0x2C, 0xB5, 0xD9, 0x9A
    .db     0x43, 0x76, 0x19, 0xAE, 0xA1, 0xBA, 0x2A, 0xF5
    .db     0xAD, 0x32, 0xAC, 0x2C, 0x94, 0x98, 0xE8, 0xD0
    .db     0x91, 0x8F, 0xA9, 0x62, 0x42, 0x9E, 0xB7, 0xDF
    .db     0xCB, 0x55, 0x6F, 0x27, 0xCF, 0x2E, 0x45, 0x65
    .db     0x12, 0x3E, 0xD2, 0x7A, 0xD2, 0xC0, 0x1A, 0xDB
    .db     0xF0, 0x86, 0x49, 0xDE, 0x6A, 0x5F, 0x8C, 0xF6
    .db     0x7D, 0x32, 0xCE, 0x82, 0x7B, 0xC3, 0x9A, 0x38
    ; j = 14: 2^96 + 2^192 + 2^288 G
    .db     0xC9, 0xE8, 0xA9, 0xB8, 0x6D, 0x86, 0x96, 0xCD
    .db     0x1E, 0x09, 0xB8, 0x5B, 0xB8, 0x63, 0x19, 0xA1
    .db     0xD2, 0x3C, 0x5B, 0x04, 0x53, 0x0D, 0xF9, 0xC7
    .db     0x04, 0x65, 0xF3, 0x80, 0xB5, 0x72, 0x5A, 0x75
    .db     0x1C, 0x75, 0xD3, 0x21, 0x99, 0xB3, 0xF8, 0x46
    .db     0xDE, 0x93, 0xC1, 0x53, 0x91, 0xDC, 0xFF, 0x4B
    .db     0xE7, 0x54, 0x95, 0xB8, 0x49, 0xC0, 0x15, 0xCD
    .db     0xE6, 0x6B, 0xA2, 0xF7, 0x54, 0x67, 0x3C, 0x35
    .db     0x70, 0xD9, 0x41, 0xBD, 0x70, 0x23, 0x60, 0x79
    .db     0xC0, 0x76, 0xB1, 0x12, 0x0B, 0x47, 0x16, 0xDE
    .db     0x9D, 0x80, 0xC8, 0x40, 0x75, 0x11, 0xBA, 0x56
    .db     0x1E, 0xFB, 0x35, 0xE4, 0xC3, 0x35, 0xDB, 0xE2
    ; j = 15: 1 + 2^96 + 2^192 + 2^288 G
    .db     0x3F, 0xE3, 0x28, 0x63, 0xAB, 0x4A, 0x1E, 0xD7
    .db     0xD1, 0x36, 0x81, 0xAF, 0x2B, 0x78, 0x86, 0x54
    .db     0x31, 0x72, 0xD5, 0x86, 0x5F, 0x99, 0xA4, 0x07
    .db     0x68, 0xA9, 0x51, 0x16, 0xBD, 0xA5, 0xF0, 0xF1
    .db     0x6D, 0x3B, 0x80, 0x76, 0x24, 0x5B, 0xDC, 0xA5
    .db     0x35, 0xA9, 0xDD, 0x42, 0xBC, 0x7C, 0x58, 0x5C
    .db     0xC0, 0xB4, 0xE8, 0xBA, 0x32, 0xDB, 0x6C, 0x2B
    .db     0x38, 0x11, 0x33, 0xB1, 0x8B, 0x59, 0xD1, 0x66
    .db     0x14, 0x96, 0x7E, 0x5D, 0xD2, 0xB2, 0x23, 0x4A
    .db     0x5D, 0xC0, 0xA8, 0x74, 0xA6, 0x02, 0xE4, 0x93
    .db     0x2E, 0xE8, 0x7C, 0xDA, 0xE6, 0x94, 0xAC, 0x45
    .db     0x65, 0xD4, 0x63, 0xE4, 0x81, 0x82, 0x9F, 0xEB

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

p384_ord_mul:
    call    p384_ctx_n
    jp      p384_mont_core
p384_ord_add:
    call    p384_ctx_n
    jp      p384_modadd_core

; ===========================================================================
; Small helpers
; ===========================================================================

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

; ===========================================================================
; p-specific add / sub / conditional subtraction (unrolled, branch-free).
;
; With c = 2^384 - p = 2^128 + 2^96 - 2^32 + 1, whose LE bytes are only
;   c[0] = 01, c[4..11] = FF, c[16] = 01, all others 00,
; reduction by p never needs p itself:
;   top:t >= p  <=>  top | carry(t + c),   and then  top:t - p = (t + c) mod 2^384
;   (a - b) + p = (a - b) - c  mod 2^384   (used when a - b borrowed).
; All passes touch all 48 bytes; data reach only adc/sbc/and/or.
; ===========================================================================

; out = a + b mod p.  In: HL=a, DE=b, BC=out; a,b < p.  Out may alias a/b.
; Clobbers AF, BC, DE, HL, IY.  Preserves IX.
p384_fe_add:
    push    bc
    pop     iy                      ; IY = out
    ex      de, hl                  ; HL = b, DE = a
    or      a, a
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 0), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 1), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 2), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 3), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 4), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 5), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 6), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 7), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 8), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 9), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 10), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 11), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 12), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 13), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 14), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 15), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 16), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 17), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 18), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 19), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 20), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 21), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 22), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 23), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 24), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 25), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 26), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 27), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 28), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 29), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 30), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 31), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 32), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 33), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 34), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 35), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 36), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 37), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 38), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 39), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 40), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 41), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 42), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 43), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 44), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 45), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 46), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 47), a
    sbc     a, a                    ; top mask
    push    iy
    pop     hl
    push    hl
    pop     de
    jp      p384_redp

; out = a - b mod p.  In: HL=a, DE=b, BC=out; a,b < p.  Out may alias a/b.
; Clobbers AF, BC, DE, HL, IY.  Preserves IX.
p384_fe_sub:
    push    bc
    pop     iy                      ; IY = out
    ex      de, hl                  ; HL = b, DE = a
    or      a, a
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 0), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 1), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 2), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 3), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 4), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 5), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 6), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 7), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 8), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 9), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 10), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 11), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 12), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 13), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 14), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 15), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 16), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 17), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 18), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 19), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 20), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 21), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 22), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 23), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 24), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 25), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 26), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 27), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 28), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 29), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 30), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 31), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 32), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 33), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 34), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 35), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 36), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 37), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 38), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 39), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 40), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 41), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 42), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 43), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 44), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 45), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 46), a
    inc     hl
    inc     de
    ld      a, (de)
    sbc     a, (hl)
    ld      (iy + 47), a
    sbc     a, a                    ; M = borrow ? 0xFF : 0
    ld      c, a                    ; C = M        (c[4..11] & M)
    and     a, 0x01
    ld      b, a                    ; B = M & 1    (c[0], c[16] & M)
    ld      de, 0                   ; D = 0        (other c bytes)
    push    iy
    pop     hl
    ld      a, (hl)
    sub     a, b
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, d
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, d
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, d
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, c
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, c
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, c
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, c
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, c
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, c
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, c
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, c
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, d
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, d
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, d
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, d
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, b
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, d
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, d
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, d
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, d
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, d
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, d
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, d
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, d
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, d
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, d
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, d
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, d
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, d
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, d
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, d
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, d
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, d
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, d
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, d
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, d
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, d
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, d
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, d
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, d
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, d
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, d
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, d
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, d
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, d
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, d
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    sbc     a, d
    ld      (hl), a
    ret

; p384_redp: x = (top:t >= p) ? top:t - p : top:t, given top:t < 2p.
;   In: HL = t (48 bytes), DE = x (may equal HL), A = top mask (0x00/0xFF).
;   Clobbers AF, BC, DE, HL, IY.  Preserves IX.
;   Pass 1 computes only carry(t + c); pass 2 writes t + (c & mask).
p384_redp:
    ld      iyh, a                  ; top mask
    push    hl
    ld      bc, 0x0000FF            ; B = 0, C = 0xFF
    ld      a, (hl)
    add     a, 0x01
    inc     hl
    ld      a, (hl)
    adc     a, b
    inc     hl
    ld      a, (hl)
    adc     a, b
    inc     hl
    ld      a, (hl)
    adc     a, b
    inc     hl
    ld      a, (hl)
    adc     a, c
    inc     hl
    ld      a, (hl)
    adc     a, c
    inc     hl
    ld      a, (hl)
    adc     a, c
    inc     hl
    ld      a, (hl)
    adc     a, c
    inc     hl
    ld      a, (hl)
    adc     a, c
    inc     hl
    ld      a, (hl)
    adc     a, c
    inc     hl
    ld      a, (hl)
    adc     a, c
    inc     hl
    ld      a, (hl)
    adc     a, c
    inc     hl
    ld      a, (hl)
    adc     a, b
    inc     hl
    ld      a, (hl)
    adc     a, b
    inc     hl
    ld      a, (hl)
    adc     a, b
    inc     hl
    ld      a, (hl)
    adc     a, b
    inc     hl
    ld      a, (hl)
    adc     a, 0x01
    inc     hl
    ld      a, (hl)
    adc     a, b
    inc     hl
    ld      a, (hl)
    adc     a, b
    inc     hl
    ld      a, (hl)
    adc     a, b
    inc     hl
    ld      a, (hl)
    adc     a, b
    inc     hl
    ld      a, (hl)
    adc     a, b
    inc     hl
    ld      a, (hl)
    adc     a, b
    inc     hl
    ld      a, (hl)
    adc     a, b
    inc     hl
    ld      a, (hl)
    adc     a, b
    inc     hl
    ld      a, (hl)
    adc     a, b
    inc     hl
    ld      a, (hl)
    adc     a, b
    inc     hl
    ld      a, (hl)
    adc     a, b
    inc     hl
    ld      a, (hl)
    adc     a, b
    inc     hl
    ld      a, (hl)
    adc     a, b
    inc     hl
    ld      a, (hl)
    adc     a, b
    inc     hl
    ld      a, (hl)
    adc     a, b
    inc     hl
    ld      a, (hl)
    adc     a, b
    inc     hl
    ld      a, (hl)
    adc     a, b
    inc     hl
    ld      a, (hl)
    adc     a, b
    inc     hl
    ld      a, (hl)
    adc     a, b
    inc     hl
    ld      a, (hl)
    adc     a, b
    inc     hl
    ld      a, (hl)
    adc     a, b
    inc     hl
    ld      a, (hl)
    adc     a, b
    inc     hl
    ld      a, (hl)
    adc     a, b
    inc     hl
    ld      a, (hl)
    adc     a, b
    inc     hl
    ld      a, (hl)
    adc     a, b
    inc     hl
    ld      a, (hl)
    adc     a, b
    inc     hl
    ld      a, (hl)
    adc     a, b
    inc     hl
    ld      a, (hl)
    adc     a, b
    inc     hl
    ld      a, (hl)
    adc     a, b
    inc     hl
    ld      a, (hl)
    adc     a, b
    inc     hl
    ld      a, (hl)
    adc     a, b
    sbc     a, a                    ; carry(t + c) mask
    or      a, iyh                  ; | top
    ld      c, a                    ; C = mask        (c[4..11] & mask)
    and     a, 0x01
    ld      iyl, a                  ; IYL = mask & 1  (c[0], c[16] & mask)
    pop     hl
    ld      a, (hl)
    add     a, iyl
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, b
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, b
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, b
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, c
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, c
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, c
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, c
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, c
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, c
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, c
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, c
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, b
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, b
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, b
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, b
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, iyl
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, b
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, b
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, b
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, b
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, b
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, b
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, b
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, b
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, b
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, b
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, b
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, b
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, b
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, b
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, b
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, b
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, b
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, b
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, b
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, b
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, b
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, b
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, b
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, b
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, b
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, b
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, b
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, b
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, b
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, b
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (hl)
    adc     a, b
    ld      (de), a
    ret

; p384_raw_ge (A = a >= m), p384_ct_is_zero (A = 0xFF iff zero),
; p384_eq48 (A = 1 iff equal), p384_rev48 (byte reverse): ecc_curve.inc,
; ECC_UTILS.  All 48-byte, branch-free on the data.
    ECC_UTILS p384, 48

; p384_select_b: out = mask ? b : a  (B bytes).  In: HL=a, DE=b, IY=out,
; C=mask (ecc_curve.inc, ECC_SELECT_B).
    ECC_SELECT_B p384

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

; ===========================================================================
; p-specific Montgomery multiply / square  (THE hot path for the ladder)
;
; p384_mul_p: out = a * b * 2^-384 mod p      In: HL=a, DE=b, BC=out.
; p384_sq_p:  out = a * a * 2^-384 mod p      In: HL=a, BC=out (DE ignored).
;   a, b < p.  Out fully reduced and bit-identical to p384_mont_core with
;   m = p (same q digits, same final conditional subtraction).  out may
;   alias a and/or b (inputs are copied first).  Clobbers AF, BC, DE, HL,
;   IY.  Preserves IX.  Needs no field context.
;   REQUIRES the .p384.mul.reloc image to be resident in fast RAM: it is
;   loaded by p384_di at every public entry and reloaded after RFC 6979
;   (whose SHA-384 reuses the window) -- see p384_reloc_load_all.
;
; Same product-scanning column loop as p384_mont_core, but the q*p pass is
; replaced by at most four byte adds per column, exploiting
;   p = 2^384 - 2^128 - 2^96 + 2^32 - 1   (n0 = -p^-1 mod 256 = 1).
; Column c of q*p is  q[c-48] - q[c-16] - q[c-12] + q[c-4] - q[c]; the -q[c]
; term only annihilates the low byte (q[c] = that byte), so with the carry H
; kept biased by +2 the recurrence is
;   X_c = H_{c-1} + B_c + AB_c + q[c-4] + q[c-48] - q[c-12] - q[c-16]
;   q[c] = X_c & 0xFF (c < 48),  t[c-48] = X_c & 0xFF (c >= 48),
;   H_c = X_c >> 8,   top = H_95 - 2  (0 or 1),
; with q[j] = 0 outside 0..47, H_{-1} = 0, B_c = 0 for c < 12 (no negative
; term yet, H unbiased), B_12 = 512 (enter the +2 bias), B_c = 510 after.
; The negative terms are folded into the bias as 255 - q = cpl(q), so the
; accumulator is only ever added to and never goes negative.  The q[c-48]
; slot is read for the last time in column c, so t[c-48] overwrites it.
; Bounds: X <= 47*0xFE01 + carry + 4*255 + 512 < 3.2e6 < 2^24.
; Validated (scratchpad model + instruction-level eZ80 emulation of this
; exact code) against integer a*b*R^-1 mod p and against p384_mont_core.
;
; Squaring: column k adds each off-diagonal product twice (24-term doubling
; MAC block) and, for even k, the diagonal a[k/2]^2 (< 2*24*0xFE01 + 0xFE01
; + carry + 1022 < 2^24).  Columns are processed in even/odd pairs j = k>>1.
;
; Every branch, entry offset and address depends only on the (public)
; column index; data reach only mlt/add/cpl.
; ===========================================================================
; P384_SHIFT r, d: HL >>= 8 via mm_acc2 = (r + d), whose byte 3 is never
; written (always 0 after the entry wipe).
.macro P384_SHIFT r, d
    ld      (\r + (\d)), hl
    ld      hl, (\r + (\d) + 1)
.endm
; P384_RED r, d, k: add column k's reduction terms; q[x] is at (r + d + x).
;   B_k is split as 255 per negative term (folded into cpl) + remainder:
;   k=12: 257, 13..15: 255, 16..59: 0, 60..63: 255, 64..95: 510.
.macro P384_RED r, d, k
  .if \k < 12
    .if \k >= 4
    ld      de, 0
    ld      e, (\r + (\d) + \k - 4)
    add     hl, de
    .endif
  .else
    .if (\k >= 16) && (\k <= 59)
    ld      de, 0
    .else
    ld      de, 255
    add     hl, de
      .if \k == 12
    inc     hl
    inc     hl
      .endif
      .if \k >= 64
    add     hl, de
      .endif
    .endif
    .if \k <= 51
    ld      e, (\r + (\d) + \k - 4)
    add     hl, de
    .endif
    .if \k >= 48
    ld      e, (\r + (\d) + \k - 48)
    add     hl, de
    .endif
    .if \k <= 59
    ld      a, (\r + (\d) + \k - 12)
    cpl
    ld      e, a
    add     hl, de
    .endif
    .if (\k >= 16) && (\k <= 63)
    ld      a, (\r + (\d) + \k - 16)
    cpl
    ld      e, a
    add     hl, de
    .endif
  .endif
.endm
; P384_STORE r, d, k: q[k] (k < 48) or t[k-48] (k >= 48) = L.
.macro P384_STORE r, d, k
  .if \k < 48
    ld      (\r + (\d) + \k), l
  .else
    ld      (\r + (\d) + \k - 48), l
  .endif
.endm
; mul column k: IX = acopy + k - 47 (phase 1) / acopy (phase 2),
;               IY = bcopy + 47 (phase 1) / bcopy + k (phase 2).
.macro P384_MCOL k
  .if \k < 48
    call    p384_mac_mul_end - 9*(\k + 1)
    P384_RED ix, (mm_u - (mm_acopy + \k - 47)), \k
    P384_STORE ix, (mm_u - (mm_acopy + \k - 47)), \k
    P384_SHIFT iy, (mm_acc2 - (mm_bcopy + 47))
    inc     ix
  .else
    .if \k < 95
    call    p384_mac_mul_end - 9*(95 - \k)
    .endif
    P384_RED iy, (mm_u - (mm_bcopy + \k)), \k
    P384_STORE iy, (mm_u - (mm_bcopy + \k)), \k
    P384_SHIFT iy, (mm_acc2 - (mm_bcopy + \k))
    inc     iy
  .endif
.endm
; sq column pair j (k = 2j, 2j+1): IX = acopy + j - 48 (+1 for odd),
; IY = acopy + 48 + j; q[x] at (iy + mm_u - (acopy + 48 + j) + x).
.macro P384_SCOL j
  .if \j < 24
    .if \j > 0
    call    p384_mac_sq_end - 10*\j
    .endif
  .else
    .if \j < 47
    call    p384_mac_sq_end - 10*(47 - \j)
    .endif
  .endif
    ld      d, (iy - 48)            ; a[j]
    ld      e, d
    mlt     de
    add     hl, de                  ; + a[j]^2
    P384_RED iy, (mm_u - (mm_acopy + 48 + \j)), (2*\j)
    P384_STORE iy, (mm_u - (mm_acopy + 48 + \j)), (2*\j)
    P384_SHIFT iy, (mm_acc2 - (mm_acopy + 48 + \j))
    inc     ix
  .if \j < 24
    call    p384_mac_sq_end - 10*(\j + 1)
  .else
    .if \j < 47
    call    p384_mac_sq_end - 10*(47 - \j)
    .endif
  .endif
    P384_RED iy, (mm_u - (mm_acopy + 48 + \j)), (2*\j + 1)
    P384_STORE iy, (mm_u - (mm_acopy + 48 + \j)), (2*\j + 1)
    P384_SHIFT iy, (mm_acc2 - (mm_acopy + 48 + \j))
    inc     iy
.endm

p384_mul_p:
    push    ix
    ld      (mm_out), bc
    push    de                      ; b
    ld      de, mm_acopy
    ld      bc, 48
    ldir                            ; acopy = a
    pop     hl
    ld      de, mm_bcopy
    ld      c, 48                   ; BC = 0 after ldir
    ldir                            ; bcopy = b
    ld      ix, mm_acopy - 47
    ld      iy, mm_bcopy + 47
    or      a, a
    sbc     hl, hl                  ; H = 0
.irp k, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47
    P384_MCOL \k
.endr
    ld      ix, mm_acopy
    ld      iy, mm_bcopy + 48
.irp k, 48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95
    P384_MCOL \k
.endr
.Lpm384_final:                      ; In: L = H_95 = top + 2, t in mm_u
    ld      a, l
    sub     a, 2
    neg                             ; A = top ? 0xFF : 0
    ld      hl, mm_u
    ld      de, (mm_out)
    call    p384_redp               ; out = t mod p
    pop     ix
    ret

p384_sq_p:
    push    ix
    ld      (mm_out), bc
    ld      de, mm_acopy
    ld      bc, 48
    ldir                            ; acopy = a
    ld      ix, mm_acopy - 48       ; IX = acopy + j - 48 (even column)
    ld      iy, mm_acopy + 48       ; IY = acopy + 48 + j
    or      a, a
    sbc     hl, hl                  ; H = 0
.irp j, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47
    P384_SCOL \j
.endr
    jp      .Lpm384_final

; ===========================================================================
; Modular inversion by Fermat: out = a^(m-2) in the Montgomery domain.
; Fixed public exponent, constant instruction sequence w.r.t. the input.
; ===========================================================================
; p384_fe_inv: In: HL=a, BC=out.  Out = a^(p-2).  Clobbers PF4..PF13.
; Fixed addition chain for p-2 = 2^384 - 2^128 - 2^96 + 2^32 - 3, whose
; bits (MSB first) are 1^255 0 1^32 0^64 1^30 0 1.  With x_n = a^(2^n - 1):
;   x2 x3 x6 x12 x15 x30 x32 x60 x120 x240 x255, then
;   t = x255 * 2^33 + x32,  t *= 2^64,  t = t * 2^30 + x30,  t = t * 2^2 + x1.
; 385 squarings + 14 multiplications (was 384 S + 318 M).  The sequence is
; a constant of p, independent of a.
; INV_STEP dst, src, n, m:  dst = src^(2^n) * m   (dst may equal src).
.macro INV_STEP dst, src, n, m
    FSQ     \dst, \src
  .if \n > 1
    ld      hl, \dst
    ld      a, \n - 1
    call    p384_fe_sqn
  .endif
    FMUL    \dst, \dst, \m
.endm
p384_fe_inv:
    ld      (inv_out), bc
    ld      de, PF12
    ld      bc, 48
    ldir                            ; PF12 = x1 = a
    INV_STEP PF4,  PF12, 1,   PF12  ; x2
    INV_STEP PF5,  PF4,  1,   PF12  ; x3
    INV_STEP PF9,  PF5,  3,   PF5   ; x6
    INV_STEP PF10, PF9,  6,   PF9   ; x12
    INV_STEP PF6,  PF10, 3,   PF5   ; x15
    INV_STEP PF7,  PF6,  15,  PF6   ; x30
    INV_STEP PF8,  PF7,  2,   PF4   ; x32
    INV_STEP PF9,  PF7,  30,  PF7   ; x60
    INV_STEP PF10, PF9,  60,  PF9   ; x120
    INV_STEP PF13, PF10, 120, PF10  ; x240
    INV_STEP PF13, PF13, 15,  PF6   ; x255
    INV_STEP PF13, PF13, 33,  PF8   ; 1^255 0 1^32
    FSQ     PF13, PF13
    ld      hl, PF13
    ld      a, 63
    call    p384_fe_sqn             ; 0^64
    INV_STEP PF13, PF13, 30,  PF7   ; 1^30
    INV_STEP PF13, PF13, 2,   PF12  ; 0 1
    ld      hl, PF13
    ld      de, (inv_out)
    ld      bc, 48
    ldir
    ret

; t = t^(2^n), in place.  In: HL = t, A = n (1..255).  Clobbers inv_exp,
; inv_bit and everything p384_sq_p clobbers.
p384_fe_sqn:
    ld      (inv_exp), hl
    ld      (inv_bit), a
.Lsqn_loop:
    ld      hl, (inv_exp)
    push    hl
    pop     bc
    call    p384_sq_p
    ld      hl, inv_bit
    dec     (hl)
    jr      nz, .Lsqn_loop
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

;
; p384_ord_inv_vt: out = a^-1 mod n on PLAIN integers (not Montgomery),
; binary extended Euclid.  Port of p256_ord_inv_vt to 48-byte operands.
; VARIABLE TIME: public a only (verify's s).
; In: HL = a (1 <= a < n; a = 0 would not terminate), BC = out (not f3..f6).
; Uses f3..f6.  Clobbers AF, BC, DE, HL, IY.  Preserves IX.
; Invariants: x1 a = u, x2 a = v (mod n); u, v > 0 until u -= v hits 0,
; at which point v = gcd(a, n) = 1 and x2 = a^-1.  x1, x2 < n throughout
; (halving: x even -> x/2, odd -> (x + n)/2 with the carry shifted back in;
; x1 - x2 mod n adds n back on borrow).
; Uses its own mod-n subtraction (.Liv_subn: subtract, add n back on
; borrow).  P-384 has no generic modsub_core: the earlier one routed the
; borrow through p384_reduce_top (subtracting m instead of adding it back)
; and had no callers, so it was removed.
.equ IVU,  PF3
.equ IVV,  PF4
.equ IVX1, PF5
.equ IVX2, PF6                          ; must follow IVX1
p384_ord_inv_vt:
    push    bc
    ld      de, IVU
    ld      bc, 48
    ldir                                ; u = a
    ld      hl, __p384_N
    ld      de, IVV
    ld      c, 48
    ldir                                ; v = n
    ld      hl, IVX1
    ld      (hl), 0
    ld      de, IVX1 + 1
    ld      c, 95
    ldir                                ; x1 = x2 = 0
    ld      a, 1
    ld      (IVX1), a                   ; x1 = 1
.Liv_loop:
    ld      a, (IVU)
    rrca
    jr      c, .Liv_v
    ld      hl, IVU
    ld      de, IVX1
    call    .Liv_halve
    jr      .Liv_loop
.Liv_v:
    ld      a, (IVV)
    rrca
    jr      c, .Liv_cmp
    ld      hl, IVV
    ld      de, IVX2
    call    .Liv_halve
    jr      .Liv_v
.Liv_cmp:                               ; u, v odd: compare from the top
    ld      hl, IVU + 47
    ld      de, IVV + 47
    ld      b, 48
.Liv_c:
    ld      a, (de)
    cp      a, (hl)                     ; v - u
    jr      nz, .Liv_cd
    dec     hl
    dec     de
    djnz    .Liv_c
.Liv_cd:
    jr      c, .Liv_usub                ; u > v
    jr      nz, .Liv_vsub               ; v > u   (equal falls through)
.Liv_usub:
    ld      hl, IVU
    ld      de, IVV
    call    .Liv_sub48                  ; u -= v
    ld      hl, IVX1
    ld      de, IVX2
    call    .Liv_subn                   ; x1 -= x2 (mod n)
    ld      hl, IVU
    call    p384_ct_is_zero
    inc     a
    jr      nz, .Liv_loop
    pop     de                          ; u = 0: v = 1, out = x2
    ld      hl, IVX2
    ld      bc, 48
    ldir
    ret
.Liv_vsub:
    ld      hl, IVV
    ld      de, IVU
    call    .Liv_sub48                  ; v -= u
    ld      hl, IVX2
    ld      de, IVX1
    call    .Liv_subn                   ; x2 -= x1 (mod n)
    jp      .Liv_loop
; (HL) = (HL) - (DE) mod n, both < n.  Clobbers AF, B, DE, HL.
.Liv_subn:
    push    hl
    call    .Liv_sub48                  ; CF = borrow
    pop     hl
    ret     nc
    ld      de, __p384_N                ; borrowed: add n back (mod 2^384)
    ld      b, 48
    or      a, a
.Liv_an:
    ld      a, (de)
    adc     a, (hl)
    ld      (hl), a
    inc     hl
    inc     de
    djnz    .Liv_an
    ret
; (HL) -= (DE), 48 bytes; CF = borrow.  Clobbers AF, B, DE, HL.
.Liv_sub48:
    ld      b, 48
    or      a, a
.Liv_s:
    ld      a, (hl)
    ex      de, hl
    sbc     a, (hl)
    ex      de, hl
    ld      (hl), a
    inc     hl
    inc     de
    djnz    .Liv_s
    ret
; (HL) >>= 1 (even value); (DE) = (DE) even ? (DE)/2 : ((DE) + n)/2.
.Liv_halve:
    push    de
    push    hl
    pop     iy
    or      a, a
    call    .Liv_rsh                    ; u >>= 1
    pop     hl
    push    hl
    pop     iy                          ; IY = x
    bit     0, (hl)
    jr      z, .Liv_hev
    ld      de, __p384_N
    ld      b, 48
    or      a, a
.Liv_hadd:
    ld      a, (de)
    adc     a, (hl)
    ld      (hl), a
    inc     hl
    inc     de
    djnz    .Liv_hadd                   ; x += n, CF = bit 384
    jr      .Liv_rsh
.Liv_hev:
    or      a, a
; (IY..IY+47) >>= 1, CF into bit 383.  Clobbers B, IY; flags only via rr.
.Liv_rsh:
    lea     iy, iy + 47
    ld      b, 48
.Liv_r:
    rr      (iy + 0)
    dec     iy
    djnz    .Liv_r
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

; p384_point_import: validate and import an uncompressed SEC1 point (97
; bytes) into pq (ecc_curve.inc, ECC_POINT_IMPORT).
    ECC_POINT_IMPORT p384, 48

; out = mask ? b : a (144-byte point).  In: HL=a, DE=b, IY=out, C=mask.
p384_point_select:
    ld      b, 144
    jp      p384_select_b

; ===========================================================================
; Point arithmetic (Montgomery-Jacobian, 144-byte points x||y||z, a = -3)
; ===========================================================================

; p384_point_double (out = 2 saved0), p384_point_add (complete wrapper,
; out = saved0 + saved1) and p384_point_add_ladder (same without the
; always-computed doubling): ecc_curve.inc, ECC_POINT_DOUBLE_ADD.
; In: HL = out.  Uses f[0..12], rt, add_result, double_result.
    ECC_POINT_DOUBLE_ADD p384

; p384_add48: (IY) = (HL) + (DE), 48 bytes; A = carry ? 0xFF : 0.
    ECC_ADDN p384, 48

; ===========================================================================
; p384_ws_mul: pq = k * Q, constant-time width-4 fixed window with the
; Joye-Tunstall signed regular recoding (96 odd digits), plus its table
; lookup p384_ws_lookup and the exception-free addition p384_ws_add.
; Shared code: ecc_curve.inc, ECC_WS_MUL (table slot 5 = __p384_acc).
;
; In: DE = k (48 B big-endian, 1 <= k < n), pq = Q (validated affine, Z = R).
; Out: pq = k Q (Jacobian).  Clobbers AF, BC, DE, HL, IY and every scratch
; buffer except the mm_* field state.  Preserves IX.
;
; P-384 specifics of the exactness argument: for i >= 1, 0 < 16 m + 15 <
; 2^380 + 16 < n, so the plain addition is exact; for i = 0 the wrap
; 16 m = n + d_0 (k' = n + 2 d_0, e.g. k' = n - 6) IS reachable and the last
; step uses the complete p384_point_add.  Cost: 1 D + 7 A (table) + 380 D +
; 95 A + 1 complete A, versus 384 co-Z ladder steps (9M+5S each).
; Validated by a Python model of this exact sequence (ws_model.py, agent
; scratchpad, not committed).
; ===========================================================================
    ECC_WS_MUL p384, 48, __p384_acc

; ===========================================================================
; Variable-time ECDSA verification engine (port of the p256.s engine).
;
; EVERYTHING IN THIS SECTION OPERATES ON PUBLIC DATA ONLY (signature, hash,
; public key and values derived from them) and is deliberately NOT constant
; time: it branches on scalar digits, skips zero digits and branches on the
; exceptional cases of the addition formulas.  It must never see a secret
; scalar: keygen, ECDH and signing use only the constant-time paths.
;
; R = u1 G + u2 Q by one shared doubling chain over positions 384 .. 0
; (Straus / Shamir):
;   u2 (Q): width-4 NAF, digits 0, +-1, +-3, +-5, +-7, recoded right to left
;           into nibble codes (VS_DIG); table Q (affine, = pq), 3Q, 5Q, 7Q
;           (Jacobian, computed per call).  +-Q uses mixed addition.
;   u1 (G): the fixed-base comb table __p384_COMB (w = 4, d = 96) folded
;           into the last 96 positions: at position i < 96 add
;           T[u1_i | u1_{i+96} << 1 | u1_{i+192} << 2 | u1_{i+288} << 3]
;           (skipped when the index is 0), always mixed addition.  This
;           replaces the separate 95-doubling comb pass.
;
; Scratch use: accumulator = saved0 (vs_inf = 1 means O; its bytes are then
; don't-care), add operand = saved1, 3Q / 5Q / 7Q = add_result /
; double_result / acc, wNAF codes and work copy in r0/r1, u1 = __p384_k,
; u2 = __p384_x (LE).  The point routines used here (point_double,
; point_add_ladder, point_add_affine) touch only f[], rt, saved0, saved1
; and their state bytes.
; ===========================================================================
.equ VS_DIG, __p384_r0                  ; 193 B: wNAF(u2) code i at nibble i
.equ VS_WK,  __p384_r0 + 200            ; 49 B: wNAF work copy of u2
.equ VS_T3,  __p384_add_result
.equ VS_T5,  __p384_double_result
.equ VS_T7,  __p384_acc

; p384_point_add_affine / p384_dbl_acc / p384_point_add_vt: VARIABLE-TIME
; mixed and Jacobian accumulation for the verify engine (ecc_curve.inc,
; ECC_VT_ADD).  acc = saved0 (O iff vs_inf != 0).
    ECC_VT_ADD p384

; p384_vs_table (3Q, 5Q, 7Q into VS_T3 / VS_T5 / VS_T7) and p384_vs_wnaf
; (width-4 NAF of u2, positions 0..384): ecc_curve.inc, ECC_VS_TABLE_WNAF.
; VARIABLE TIME, public data only.
    ECC_VS_TABLE_WNAF p384

; p384_vs_qadd: acc += d Q for the wNAF code in A (1..15).
p384_vs_qadd:
    ld      (vs_t), a
    and     a, 7
    cp      a, 1
    jr      nz, .Lqa_jac
    ld      hl, __p384_pq               ; |d| = 1: Q itself is affine (Z = 1)
    ld      de, PS1
    ld      bc, 96
    ldir
    call    .Lqa_neg
    jp      p384_point_add_affine
.Lqa_jac:                               ; |d| = 3, 5, 7
    ld      hl, VS_T3
    cp      a, 3
    jr      z, .Lqa_cp
    ld      hl, VS_T5
    cp      a, 5
    jr      z, .Lqa_cp
    ld      hl, VS_T7
.Lqa_cp:
    ld      de, PS1
    ld      bc, 144
    ldir
    call    .Lqa_neg
    jp      p384_point_add_vt
.Lqa_neg:                               ; d < 0: saved1 Y = -Y
    ld      a, (vs_t)
    and     a, 8
    ret     z
    FSUB    PS1Y, PZERO, PS1Y
    ret

; p384_vs_cidx: A = comb index at position i (0..95) of u1 (__p384_k, LE):
; bit i | bit (i+96) << 1 | bit (i+192) << 2 | bit (i+288) << 3.
; In: A = i.  Clobbers AF, BC, DE, HL.
p384_vs_cidx:
    ld      b, a
    and     a, 7
    inc     a
    ld      c, a
    ld      a, 0x80
.Lci_m:
    rlca
    dec     c
    jr      nz, .Lci_m                  ; A = 1 << (i & 7)
    ld      c, a
    ld      a, b
    rrca
    rrca
    rrca
    and     a, 0x1F                     ; i >> 3 (also clears CF)
    sbc     hl, hl
    ld      l, a
    ld      de, __p384_k + 36           ; strip 3 byte
    add     hl, de
    ld      de, -12
    ld      b, 0
.rept 4
    ld      a, (hl)
    and     a, c
    add     a, 0xFF                     ; CF = bit
    rl      b
    add     hl, de                      ; next lower strip
.endr
    ld      a, b
    ret

; p384_verify_shamir: saved0 / vs_inf = u1 G + u2 Q.   VARIABLE TIME.
; In: __p384_k = u1, __p384_x = u2 (48-byte LE plain integers, < n), pq = Q
; (validated, Z = 1).  Clobbers AF, BC, DE, HL, IY; preserves IX.
p384_verify_shamir:
    call    p384_vs_table
    call    p384_vs_wnaf
    ld      a, 1
    ld      (vs_inf), a                 ; acc = O
    ld      hl, 384
    ld      (vs_i), hl
.Lvs_loop:
    ld      a, (vs_inf)
    or      a, a
    call    z, p384_dbl_acc             ; acc = 2 acc (skipped while O)
    ; ---- u2: wNAF digit i ----
    ld      hl, (vs_i)
    srl     h
    rr      l
    ld      de, VS_DIG
    add     hl, de
    ld      a, (hl)
    ld      hl, vs_i
    bit     0, (hl)
    jr      z, .Lvs_lo
    rrca
    rrca
    rrca
    rrca
.Lvs_lo:
    and     a, 0x0F
    call    nz, p384_vs_qadd
    ; ---- u1: comb column i (positions 95..0 only) ----
    ld      hl, (vs_i)
    ld      de, 96
    or      a, a
    sbc     hl, de
    jr      nc, .Lvs_next               ; i >= 96
    ld      a, (vs_i)
    call    p384_vs_cidx
    or      a, a
    jr      z, .Lvs_next                ; idx = 0: nothing to add
    dec     a
    sbc     hl, hl
    ld      l, a
    add     hl, hl
    add     hl, hl
    add     hl, hl
    add     hl, hl
    add     hl, hl                      ; (idx - 1) * 32
    push    hl
    pop     de
    add     hl, hl                      ; (idx - 1) * 64
    add     hl, de                      ; (idx - 1) * 96
    ld      de, __p384_COMB
    add     hl, de
    ld      de, PS1
    ld      bc, 96
    ldir
    call    p384_point_add_affine
.Lvs_next:
    ld      hl, (vs_i)
    ld      a, h
    or      a, l
    ret     z                           ; position 0 done
    dec     hl
    ld      (vs_i), hl
    jp      .Lvs_loop


; ===========================================================================
; p384_comb_mul: out = k * G, constant-time fixed-base comb (Lim-Lee),
; w = 4, d = 96, over __p384_COMB; p384_comb_madd is its constant-time mixed
; addition step.  Shared code: ecc_curve.inc, ECC_COMB.
;
; k (384 bits) is split into four 96-bit strips k = k0 + k1 2^96 + k2 2^192
; + k3 2^288.  Cost: 95 doublings (3M+5S) + 96 mixed additions (7M+4S) + 96
; table scans, versus 384 steps of a (9M+5S) co-Z ladder.
; Completeness: with acc != O and idx != 0, acc != +-T[idx], so H != 0
; (same argument as p256_comb_mul: before the add at step i, acc = A G and
; T = B G with A = sum_s (k_s >> i & ~1) 2^(96s), B = sum_s k_s[i] 2^(96s);
; A, B, A + B < n, and A = B or A + B = 0 force A = B = 0).  Checked in a
; buffer-level Python model of this sequence (agent scratchpad, not
; committed).  cb_cnt is the low byte of the 3-byte sm_cnt.
; ===========================================================================
    ECC_COMB p384

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
    add     hl, de
    or      a, a
    sbc     hl, de
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

; p384_di / p384_wipe / p384_exit / p384_null: shared prologue/epilogue
; (ecc_curve.inc, ECC_DI_EXIT).  p384_di tail-calls p384_reloc_load_all so
; the field-multiply blocks are loaded into fast RAM with interrupts off
; (nothing can touch the window until p384_exit).
    ECC_DI_EXIT p384, p384_reloc_load_all

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
    call    p384_comb_mul           ; saved0 = priv G (fixed-base comb)
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
    ld      de, (ix + 9)
    call    p384_ws_mul             ; pq = priv Q (constant-time window)
    ld      hl, __p384_pq
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
    ; w = s^-1 by binary extended Euclid on the plain integer s (public:
    ; variable time is fine), then u1 = e w, u2 = r w as plain integers.
    ld      hl, PF1
    ld      bc, PF7
    call    p384_ord_inv_vt             ; f7 = w = s^-1 (plain)
    OMUL    PF8, PF7, __p384_N_R2       ; f8 = w R
    OMUL    __p384_k, PF2, PF8          ; u1 = e w   (plain, < n)
    OMUL    __p384_x, PF0, PF8          ; u2 = r w   (plain, < n)
    call    p384_verify_shamir          ; saved0 = u1 G + u2 Q
    ld      a, (vs_inf)
    or      a, a
    jp      nz, .Lvf_fail               ; R = O
    ; Fail closed independently of vs_inf: field elements are canonical
    ; (< p), so Z == 0 mod p iff all 48 bytes are zero; with Z = 0 the
    ; projective test below would degenerate to X == 0.
    ld      hl, PS0Z
    call    p384_ct_is_zero
    or      a, a
    jp      nz, .Lvf_fail
    ; x(R) mod n == r  <=>  x(R) = r  or  x(R) = r + n (only if r + n < p),
    ; checked projectively as X == r' Z^2 (mod p): no field inversion.
    ; r is re-read from sig (f0 has been clobbered by the scalar multiplies).
    ld      hl, (ix + 6)
    ld      de, PF8
    call    p384_rev48                  ; f8 = r (LE, < n < p)
    call    .Lvf_xchk
    or      a, a
    jp      nz, p384_exit               ; A = 1
    ld      hl, PF8
    ld      de, __p384_N
    ld      iy, PF8
    call    p384_add48                  ; f8 = r + n
    or      a, a
    jp      nz, .Lvf_fail               ; >= 2^384
    ld      hl, PF8
    ld      de, __p384_P
    call    p384_raw_ge
    or      a, a
    jp      nz, .Lvf_fail               ; >= p
    call    .Lvf_xchk
    jp      p384_exit
; A = 1 iff X(saved0) == f8 * Z(saved0)^2 (mod p), f8 < p.  Uses f9, f10.
.Lvf_xchk:
    FMUL    PF9, PF8, __p384_P_R2       ; f8 into the Montgomery domain
    FSQ     PF10, PS0Z
    FMUL    PF9, PF9, PF10
    ld      hl, PF9
    ld      de, PS0X
    jp      p384_eq48
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
    ; RFC 6979's SHA-384 (.sha384.reloc) reuses the fast-RAM window.
    call    p384_reloc_load_all
    ld      hl, __p384_saved0
    ld      de, __p384_k
    call    p384_comb_mul           ; R = k G (fixed-base comb)
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


; p384_mul_reloc_load: copy only the generic djnz MAC loop (the first 16
; bytes of the block) for p384_mont_core, which keeps working stand-alone.
; The prefix is identical to the full image, so this never disturbs the
; unrolled blocks.  Clobbers BC, DE, HL.
p384_mul_reloc_load:
    ld      hl, _p384_mul_reloc_load_start
    ld      de, _p384_mul_reloc_run_start
    ld      bc, p384_mul_mac_end - _p384_mul_reloc_run_start
    ldir
    ret

; p384_reloc_load_all: copy the whole .p384.mul.reloc member (generic loop +
; 48-term MAC + 24-term doubling MAC) into the fast-RAM window.  Called from
; p384_di (every public entry, interrupts off) and after RFC 6979 in signing.
; Any other overlay consumer (.sha384.reloc, .sha256.reloc, RNG, AES, ...)
; that runs in between MUST be followed by another call.  Clobbers BC, DE, HL.
p384_reloc_load_all:
    ld      hl, _p384_mul_reloc_load_start
    ld      de, _p384_mul_reloc_run_start
    ld      bc, _p384_mul_reloc_len
    ldir
    ret

; ===========================================================================
; Relocated field-multiply inner blocks (fast RAM at 0xE30800).
; Entries are addressed through their run-time labels, which resolve against
; the run VMA, so the copied image is callable as-is.
; ===========================================================================
    .section .p384.mul.reloc,"ax",@progbits
_p384_mul_reloc_run_start:
; Generic loop for p384_mont_core: acc += sum (IX+i)*(IY-i), B terms.
p384_mul_mac:
    ld      d, (ix + 0)
    ld      e, (iy + 0)
    mlt     de
    add     hl, de
    inc     ix
    dec     iy
    djnz    p384_mul_mac
    ret
p384_mul_mac_end:
; 48-term MAC block: term n is acc += (ix+n) * (iy-n).  Each term is exactly
; 9 bytes; the entry for a c-term column is p384_mac_mul_end - 9*c.
; Uses only D, E, HL, IX, IY (read-only).  A and BC are preserved.
p384_mac_mul:
    ld      d, (ix + 0)
    ld      e, (iy - 0)
    mlt     de
    add     hl, de
    ld      d, (ix + 1)
    ld      e, (iy - 1)
    mlt     de
    add     hl, de
    ld      d, (ix + 2)
    ld      e, (iy - 2)
    mlt     de
    add     hl, de
    ld      d, (ix + 3)
    ld      e, (iy - 3)
    mlt     de
    add     hl, de
    ld      d, (ix + 4)
    ld      e, (iy - 4)
    mlt     de
    add     hl, de
    ld      d, (ix + 5)
    ld      e, (iy - 5)
    mlt     de
    add     hl, de
    ld      d, (ix + 6)
    ld      e, (iy - 6)
    mlt     de
    add     hl, de
    ld      d, (ix + 7)
    ld      e, (iy - 7)
    mlt     de
    add     hl, de
    ld      d, (ix + 8)
    ld      e, (iy - 8)
    mlt     de
    add     hl, de
    ld      d, (ix + 9)
    ld      e, (iy - 9)
    mlt     de
    add     hl, de
    ld      d, (ix + 10)
    ld      e, (iy - 10)
    mlt     de
    add     hl, de
    ld      d, (ix + 11)
    ld      e, (iy - 11)
    mlt     de
    add     hl, de
    ld      d, (ix + 12)
    ld      e, (iy - 12)
    mlt     de
    add     hl, de
    ld      d, (ix + 13)
    ld      e, (iy - 13)
    mlt     de
    add     hl, de
    ld      d, (ix + 14)
    ld      e, (iy - 14)
    mlt     de
    add     hl, de
    ld      d, (ix + 15)
    ld      e, (iy - 15)
    mlt     de
    add     hl, de
    ld      d, (ix + 16)
    ld      e, (iy - 16)
    mlt     de
    add     hl, de
    ld      d, (ix + 17)
    ld      e, (iy - 17)
    mlt     de
    add     hl, de
    ld      d, (ix + 18)
    ld      e, (iy - 18)
    mlt     de
    add     hl, de
    ld      d, (ix + 19)
    ld      e, (iy - 19)
    mlt     de
    add     hl, de
    ld      d, (ix + 20)
    ld      e, (iy - 20)
    mlt     de
    add     hl, de
    ld      d, (ix + 21)
    ld      e, (iy - 21)
    mlt     de
    add     hl, de
    ld      d, (ix + 22)
    ld      e, (iy - 22)
    mlt     de
    add     hl, de
    ld      d, (ix + 23)
    ld      e, (iy - 23)
    mlt     de
    add     hl, de
    ld      d, (ix + 24)
    ld      e, (iy - 24)
    mlt     de
    add     hl, de
    ld      d, (ix + 25)
    ld      e, (iy - 25)
    mlt     de
    add     hl, de
    ld      d, (ix + 26)
    ld      e, (iy - 26)
    mlt     de
    add     hl, de
    ld      d, (ix + 27)
    ld      e, (iy - 27)
    mlt     de
    add     hl, de
    ld      d, (ix + 28)
    ld      e, (iy - 28)
    mlt     de
    add     hl, de
    ld      d, (ix + 29)
    ld      e, (iy - 29)
    mlt     de
    add     hl, de
    ld      d, (ix + 30)
    ld      e, (iy - 30)
    mlt     de
    add     hl, de
    ld      d, (ix + 31)
    ld      e, (iy - 31)
    mlt     de
    add     hl, de
    ld      d, (ix + 32)
    ld      e, (iy - 32)
    mlt     de
    add     hl, de
    ld      d, (ix + 33)
    ld      e, (iy - 33)
    mlt     de
    add     hl, de
    ld      d, (ix + 34)
    ld      e, (iy - 34)
    mlt     de
    add     hl, de
    ld      d, (ix + 35)
    ld      e, (iy - 35)
    mlt     de
    add     hl, de
    ld      d, (ix + 36)
    ld      e, (iy - 36)
    mlt     de
    add     hl, de
    ld      d, (ix + 37)
    ld      e, (iy - 37)
    mlt     de
    add     hl, de
    ld      d, (ix + 38)
    ld      e, (iy - 38)
    mlt     de
    add     hl, de
    ld      d, (ix + 39)
    ld      e, (iy - 39)
    mlt     de
    add     hl, de
    ld      d, (ix + 40)
    ld      e, (iy - 40)
    mlt     de
    add     hl, de
    ld      d, (ix + 41)
    ld      e, (iy - 41)
    mlt     de
    add     hl, de
    ld      d, (ix + 42)
    ld      e, (iy - 42)
    mlt     de
    add     hl, de
    ld      d, (ix + 43)
    ld      e, (iy - 43)
    mlt     de
    add     hl, de
    ld      d, (ix + 44)
    ld      e, (iy - 44)
    mlt     de
    add     hl, de
    ld      d, (ix + 45)
    ld      e, (iy - 45)
    mlt     de
    add     hl, de
    ld      d, (ix + 46)
    ld      e, (iy - 46)
    mlt     de
    add     hl, de
    ld      d, (ix + 47)
    ld      e, (iy - 47)
    mlt     de
    add     hl, de
p384_mac_mul_end:
    ret
; 24-term doubling MAC block for p384_sq_p: term n (24..47) is
; acc += 2 * (ix+n) * (iy-n).  10 bytes per term; entry for an m-term
; column is p384_mac_sq_end - 10*m.  Uses D, E, HL; preserves A, BC, IX, IY.
p384_mac_sq:
    ld      d, (ix + 24)
    ld      e, (iy - 24)
    mlt     de
    add     hl, de
    add     hl, de
    ld      d, (ix + 25)
    ld      e, (iy - 25)
    mlt     de
    add     hl, de
    add     hl, de
    ld      d, (ix + 26)
    ld      e, (iy - 26)
    mlt     de
    add     hl, de
    add     hl, de
    ld      d, (ix + 27)
    ld      e, (iy - 27)
    mlt     de
    add     hl, de
    add     hl, de
    ld      d, (ix + 28)
    ld      e, (iy - 28)
    mlt     de
    add     hl, de
    add     hl, de
    ld      d, (ix + 29)
    ld      e, (iy - 29)
    mlt     de
    add     hl, de
    add     hl, de
    ld      d, (ix + 30)
    ld      e, (iy - 30)
    mlt     de
    add     hl, de
    add     hl, de
    ld      d, (ix + 31)
    ld      e, (iy - 31)
    mlt     de
    add     hl, de
    add     hl, de
    ld      d, (ix + 32)
    ld      e, (iy - 32)
    mlt     de
    add     hl, de
    add     hl, de
    ld      d, (ix + 33)
    ld      e, (iy - 33)
    mlt     de
    add     hl, de
    add     hl, de
    ld      d, (ix + 34)
    ld      e, (iy - 34)
    mlt     de
    add     hl, de
    add     hl, de
    ld      d, (ix + 35)
    ld      e, (iy - 35)
    mlt     de
    add     hl, de
    add     hl, de
    ld      d, (ix + 36)
    ld      e, (iy - 36)
    mlt     de
    add     hl, de
    add     hl, de
    ld      d, (ix + 37)
    ld      e, (iy - 37)
    mlt     de
    add     hl, de
    add     hl, de
    ld      d, (ix + 38)
    ld      e, (iy - 38)
    mlt     de
    add     hl, de
    add     hl, de
    ld      d, (ix + 39)
    ld      e, (iy - 39)
    mlt     de
    add     hl, de
    add     hl, de
    ld      d, (ix + 40)
    ld      e, (iy - 40)
    mlt     de
    add     hl, de
    add     hl, de
    ld      d, (ix + 41)
    ld      e, (iy - 41)
    mlt     de
    add     hl, de
    add     hl, de
    ld      d, (ix + 42)
    ld      e, (iy - 42)
    mlt     de
    add     hl, de
    add     hl, de
    ld      d, (ix + 43)
    ld      e, (iy - 43)
    mlt     de
    add     hl, de
    add     hl, de
    ld      d, (ix + 44)
    ld      e, (iy - 44)
    mlt     de
    add     hl, de
    add     hl, de
    ld      d, (ix + 45)
    ld      e, (iy - 45)
    mlt     de
    add     hl, de
    add     hl, de
    ld      d, (ix + 46)
    ld      e, (iy - 46)
    mlt     de
    add     hl, de
    add     hl, de
    ld      d, (ix + 47)
    ld      e, (iy - 47)
    mlt     de
    add     hl, de
    add     hl, de
p384_mac_sq_end:
    ret
_p384_mul_reloc_run_end:

    .section .text.__p384,"ax",@progbits

    .section .note.GNU-stack,"",@progbits

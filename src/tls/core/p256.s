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
; The field/order arithmetic, point formulas and the fallback ladder are
; translations of the correctness reference in ref/p256/p256.c: radix-2^8
; Montgomery arithmetic (n0 = 1 for p, 0x4F for n), Jacobian coordinates
; in the Montgomery domain, a=-3 doubling and the "complete wrapper"
; Jacobian addition; those intermediates are bit-identical to the reference.
;
; Scalar multiplication (p256_scalar_mul) is NOT the reference's 256-step
; Jacobian ladder: it is a co-Z Montgomery ladder (Goundar-Joye-Miyaji
; 2010 / Rivain 2011, (X,Y)-only XYcZ-ADDC + XYcZ-ADDU per bit, Z recovered
; once at the end).  Its intermediates differ from ref/p256/p256.c; only
; the final point agrees.  Preconditions: scalar k < n (0 allowed; k in
; {0, 1, n-2, n-1} handled in constant time) and input point Z = Montgomery
; 1 (an imported affine point or G).  The public case x(P) = 0 falls back
; to the reference-equivalent ladder p256_scalar_mul_ml.  Python oracle for
; the co-Z buffer-level sequence (coz_seq.py, imports coz.py) lives in an
; agent session scratchpad and is NOT committed to the repository:
;   /private/tmp/claude-501/-Users-acagliano-CEdev-source-lwip-ce/48f9ef2d-f514-4722-adac-d1a2d6c4a6c6/scratchpad/model/
;
; The structural differences are in the Montgomery multiply: the reference
; is operand-scanning (CIOS, a 16-bit carry rippled through t[] on every
; MAC); here it is product-scanning (FIPS) with a 24-bit column accumulator
; in HL, so each 8x8 MAC is just `ld d,(ix+n) / ld e,(iy-n) / mlt de /
; add hl,de` with no per-MAC carry handling or t[] traffic.  For the field
; (mod p) the q*p pass is replaced by four byte adds per column using the
; shape of p (p256_mul_p / p256_sq_p, unrolled, dedicated squaring), and
; fe_add/fe_sub/final subtraction are p-specific.  The output is identical
; (same q digits, same final conditional subtraction); mod n still uses
; the generic p256_mont_core.  The fallback Jacobian ladder
; (p256_scalar_mul_ml) uses p256_point_add_ladder, which omits the
; complete-addition doubling case (unreachable in a ladder).
;
; ECDSA verification (tls_p256_verify) uses a separate VARIABLE-TIME engine
; because all of its inputs are public: s^-1 by binary extended Euclid
; (p256_ord_inv_vt), u1 G + u2 Q by interleaved double-and-add (u2: width-4
; NAF over Q, 3Q, 5Q, 7Q; u1: w = 5 sliding window over a ROM table of
; affine odd multiples of G; mixed Jacobian-affine additions), and the
; final x(R) mod n == r test done projectively (X == r Z^2, also r + n when
; r + n < p) with no field inversion.  That engine must never be given
; secret data; keygen, ECDH and signing use only the constant-time paths.
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
; that do exist depend only on public values (loop counters, the fixed
; addition chain for a^(p-2), the public exponent n-2, the public x(P) = 0
; fallback test, input-validation results, and the RFC 6979 retry
; condition, exactly as in the reference).  The verify engine is the
; documented exception (public inputs only, see above).
; ---------------------------------------------------------------------------

    .assume adl=1

; _sprng_sha_mbuffer (SHA-256 message schedule, wiped after RFC 6979) and
; the _sprng_entropy_pool overlay-base extern it is defined against.
.include "virtuals.inc"

; ===========================================================================
; Scratch (.bss).  Layout constraints:
;   r0,r1 contiguous and saved0,saved1 contiguous (single 192-byte ldir).
;   The RFC 6979 state (DK_*) overlays r0.. -- it is dead before the ladder.
;
; This buffer is the single shared scratch for P-256, powmod, and HKDF/RSA.
; All consumers are mutually exclusive at runtime.  The linker provides
; __tls_scratch_start/__tls_scratch_end aliases to __p256_scratch_start/_end.
; ===========================================================================
.include "scratch.inc"
globl __p256_scratch_start
globl __p256_scratch_end
    .section .bss.__p256_scratch,"aw",@nobits
__p256_scratch_start:
; --- p256_mul_p / p256_sq_p working set.  The index displacements are
; computed by the assembler from these labels (it rejects any that leave
; -128..127), but they only fit for this order: u | acopy | bcopy | acc. ---
mm_u:                   .space 64       ; column low bytes: q[0..31] || t[0..31]
mm_acopy:               .space 32       ; copy of a
mm_bcopy:               .space 32       ; copy of b
mm_acc2:                .space 4        ; shift cell: bytes 0-2 written, byte 3 always 0
__p256_f:               .space 448      ; f[0..13] field temporaries
__p256_r0:              .space 96       ; ladder R0
__p256_r1:              .space 96       ; ladder R1
__p256_saved0:          .space 96       ; point-op input P (fixed)
__p256_saved1:          .space 96       ; point-op input Q (fixed)
__p256_rt:              .space 96       ; point-op result temp
__p256_add_result:      .space 96       ; verify: 3Q   (add_result, double_result,
__p256_double_result:   .space 96       ; verify: 5Q    pa must stay contiguous)
__p256_pa:              .space 96       ; verify: 7Q
__p256_pq:              .space 96       ; imported peer / public point
__p256_k:               .space 32       ; sign: nonce k (BE); verify: u1 (LE)
__p256_x:               .space 32       ; sign: x(R) (BE);   verify: u2 (LE)
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
pa_lad:                 .space 1        ; 1 = ladder add (doubling case unreachable)
sm_out:                 .space 3
sm_k:                   .space 3
sm_bit:                 .space 1
sm_prev:                .space 1
sm_cnt:                 .space 1
sm_pt:                  .space 3        ; co-Z ladder: input point
sm_kp:                  .space 32       ; co-Z ladder: k' = k + n or k + 2n (BE, bit 256 implicit)
sm_e0:                  .space 1        ; masks: k == 0, 1, n-1, n-2
sm_e1:                  .space 1
sm_em1:                 .space 1
sm_em2:                 .space 1
inv_out:                .space 3
inv_exp:                .space 3
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
; --- variable-time verify engine (public data only) ---
vs_i:                   .space 3        ; bit position 256..0 / wNAF index 0..256
vs_inf:                 .space 1        ; 1 = accumulator (saved0) is O
vs_gpend:               .space 1        ; 1 = a u1 window is pending
vs_gpos:                .space 1        ; pending window: position of its low bit
vs_gval:                .space 1        ; pending window: odd value 1..31
vs_t:                   .space 1
__p256_scratch_end:

; --- symbolic operand names ---
.equ __p256_q, mm_u                    ; mont_core q[] (mod n) reuses mm_u
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
; co-Z ladder operands: A = (XA, YA) in r0, B = (XB, YB) in r1 (no Z)
.equ CZXA, __p256_r0
.equ CZYA, __p256_r0 + 32
.equ CZXB, __p256_r1
.equ CZYB, __p256_r1 + 32
.equ PZERO, __p256_INF                  ; 32 zero bytes
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
    call    p256_mul_p
.endm
.macro FSQ o, a
    ld      bc, \o
    ld      hl, \a
    call    p256_sq_p
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

__p256_N_R2:
    .db     0xA2, 0xEE, 0x79, 0xBE, 0x95, 0x4C, 0x24, 0x83
    .db     0xA6, 0x6F, 0xBD, 0x49, 0x9C, 0x79, 0x99, 0x46
    .db     0x59, 0xEC, 0x6B, 0x2B, 0x39, 0xB2, 0x45, 0x28
    .db     0x20, 0x56, 0xD9, 0xF3, 0x94, 0x2D, 0xE1, 0x66

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
; 2n mod 2^256, n-1, n-2 (co-Z ladder scalar recoding / exceptional k).
__p256_N2:
    .db     0xA2, 0x4A, 0xC6, 0xF8, 0x85, 0x95, 0x73, 0xE7
    .db     0x09, 0x3D, 0x2F, 0x4E, 0x5B, 0xF5, 0xCD, 0x79
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    .db     0x01, 0x00, 0x00, 0x00, 0xFE, 0xFF, 0xFF, 0xFF
__p256_NM1:
    .db     0x50, 0x25, 0x63, 0xFC, 0xC2, 0xCA, 0xB9, 0xF3
    .db     0x84, 0x9E, 0x17, 0xA7, 0xAD, 0xFA, 0xE6, 0xBC
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    .db     0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF
__p256_NM2:
    .db     0x4F, 0x25, 0x63, 0xFC, 0xC2, 0xCA, 0xB9, 0xF3
    .db     0x84, 0x9E, 0x17, 0xA7, 0xAD, 0xFA, 0xE6, 0xBC
    .db     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    .db     0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF
; Plain integer 1 (Montgomery-domain exit multiplier).
__p256_ONE:
    .db     0x01
    .space  31, 0
; Odd multiples (2i+1)G, i = 0..15, affine, Montgomery form (x*R, y*R mod p),
; 32-byte LE each: entry i = x || y at __p256_GTAB + 64*i.  Generated by an
; affine Python reference; entry 0 equals __p256_G/__p256_G_Y.  Used only by
; the variable-time verify engine (u1*G sliding window, w = 5).
; p256_ord_inv schedule for the low 128 bits of n - 2 (w = 4 left-to-right
; sliding window): pairs (squarings, slot), slot k holding a^(2k+1);
; 0-terminated.  Generated and checked (exponent == n - 2) offline.
__p256_N2_CHAIN:
    .db     4, 5, 2, 1, 5, 3, 6, 6, 4, 7, 4, 2, 5, 5, 5, 6, 5, 3, 7, 5, 2, 1
    .db     6, 7, 2, 0, 8, 4, 3, 3, 5, 3, 4, 3, 5, 3, 5, 2, 3, 1, 8, 5, 4, 7
    .db     5, 1, 5, 1, 6, 4, 4, 2, 6, 7, 0

__p256_GTAB:
    ; 1G
    .db     0x3C, 0x14, 0xA9, 0x18, 0xD4, 0x30, 0xE7, 0x79
    .db     0x01, 0xB6, 0xED, 0x5F, 0xFC, 0x95, 0xBA, 0x75
    .db     0x10, 0x25, 0x62, 0x77, 0x2B, 0x73, 0xFB, 0x79
    .db     0xC6, 0x55, 0x37, 0xA5, 0x76, 0x5F, 0x90, 0x18
    .db     0x0A, 0x56, 0x95, 0xCE, 0x57, 0x53, 0xF2, 0xDD
    .db     0x5C, 0xE4, 0x19, 0xBA, 0xE4, 0xB8, 0x4A, 0x8B
    .db     0x25, 0xF3, 0x21, 0xDD, 0x88, 0x86, 0xE8, 0xD2
    .db     0x85, 0x5D, 0x88, 0x25, 0x18, 0xFF, 0x71, 0x85
    ; 3G
    .db     0x27, 0xC1, 0xEB, 0x4E, 0x90, 0x3F, 0xAC, 0xFF
    .db     0xFB, 0x81, 0x7D, 0x08, 0x4A, 0xF8, 0x27, 0xB0
    .db     0x98, 0xBC, 0xCB, 0x87, 0xDD, 0x77, 0xAD, 0x66
    .db     0x7E, 0x74, 0xFF, 0xB6, 0x3F, 0x6A, 0x93, 0x26
    .db     0xEB, 0xA7, 0x83, 0xC9, 0x1F, 0x5C, 0x4C, 0xB0
    .db     0x1A, 0xFE, 0x61, 0x08, 0xAD, 0x47, 0x3E, 0x58
    .db     0x8E, 0xE9, 0x2E, 0x1A, 0x31, 0x08, 0x82, 0x78
    .db     0x07, 0xCC, 0x87, 0xE5, 0x29, 0x6A, 0xF0, 0xD5
    ; 5G
    .db     0xF5, 0x61, 0x5C, 0xC4, 0xAE, 0x8A, 0x1B, 0xBE
    .db     0x7D, 0x53, 0xB9, 0x94, 0x9A, 0x64, 0xEC, 0x90
    .db     0x0C, 0xC2, 0x76, 0xD0, 0xAA, 0xB5, 0x1C, 0x94
    .db     0xC8, 0x23, 0x05, 0x89, 0x05, 0x96, 0x07, 0xC9
    .db     0x10, 0x4F, 0xBA, 0xE7, 0x4A, 0x9B, 0x30, 0xEB
    .db     0x2B, 0x88, 0xEB, 0xE5, 0xEF, 0x68, 0xC5, 0x73
    .db     0x68, 0x1F, 0x7A, 0x7E, 0x87, 0xA9, 0x40, 0x35
    .db     0x16, 0xE9, 0xD1, 0x2D, 0xBB, 0x76, 0xA0, 0x73
    ; 7G
    .db     0x4F, 0x3B, 0x17, 0xA0, 0x4E, 0x35, 0x46, 0x07
    .db     0xF7, 0x00, 0x3C, 0xD2, 0x13, 0x02, 0xD2, 0x2B
    .db     0x08, 0xBB, 0x23, 0x0C, 0xB5, 0xAA, 0x3E, 0xF4
    .db     0x03, 0x3E, 0x12, 0xC3, 0x19, 0x51, 0xBA, 0x13
    .db     0x4D, 0x9D, 0x5B, 0x3F, 0x30, 0xD0, 0x47, 0x28
    .db     0xDD, 0x7B, 0xA6, 0x5D, 0xF2, 0xF2, 0x42, 0x67
    .db     0x95, 0x41, 0xC9, 0x77, 0xDC, 0x3B, 0x93, 0xEF
    .db     0x67, 0x08, 0x24, 0x6E, 0x15, 0xD9, 0xED, 0xEA
    ; 9G
    .db     0xE8, 0x20, 0x4E, 0x26, 0x8F, 0x6E, 0xC9, 0x75
    .db     0x41, 0xA8, 0xA7, 0x59, 0xED, 0xBF, 0xE6, 0xAB
    .db     0x00, 0xEB, 0xC8, 0x44, 0x04, 0x9C, 0xC0, 0x2C
    .db     0x6B, 0xE1, 0xC4, 0xF0, 0x80, 0x30, 0x5B, 0xE0
    .db     0x14, 0x33, 0x5F, 0xA4, 0x7A, 0x77, 0xB7, 0x1E
    .db     0xE3, 0x45, 0x5D, 0xCE, 0xED, 0x7B, 0xAF, 0x56
    .db     0x1A, 0x2F, 0xB1, 0x88, 0x9A, 0x01, 0x6E, 0x2B
    .db     0x9B, 0x5F, 0x83, 0xFD, 0xCD, 0x59, 0x66, 0x08
    ; 11G
    .db     0x04, 0xE4, 0x45, 0x62, 0x0A, 0x26, 0x7D, 0xEA
    .db     0xE0, 0xDF, 0x7F, 0x6E, 0x95, 0x07, 0xE4, 0x9D
    .db     0xB5, 0x1A, 0xAC, 0x8D, 0x15, 0xA4, 0xF3, 0x1F
    .db     0x73, 0x90, 0x9C, 0x64, 0xF1, 0x90, 0x70, 0x3E
    .db     0x88, 0x4E, 0x94, 0x2B, 0x61, 0x85, 0x76, 0x1A
    .db     0xC8, 0x61, 0x7F, 0xE5, 0x9E, 0x93, 0x0F, 0x25
    .db     0x3D, 0x64, 0xAD, 0x1E, 0x89, 0xAA, 0x0D, 0x0C
    .db     0x8E, 0xB8, 0x25, 0xE1, 0x23, 0x00, 0x93, 0x68
    ; 13G
    .db     0x09, 0xD7, 0x2E, 0x4B, 0x63, 0x25, 0xC4, 0xCC
    .db     0x0D, 0xD3, 0x6F, 0x85, 0x69, 0x67, 0x35, 0x0E
    .db     0x11, 0x98, 0x9E, 0x55, 0x3F, 0xD4, 0xBC, 0xBC
    .db     0x59, 0xB7, 0x95, 0x53, 0xAC, 0x77, 0x84, 0x73
    .db     0x7F, 0xE1, 0x0E, 0xC0, 0x90, 0x2B, 0x75, 0x35
    .db     0xE3, 0xD2, 0x2E, 0x74, 0x90, 0x83, 0x74, 0x68
    .db     0xC1, 0x5B, 0x1F, 0xBD, 0x22, 0x64, 0xD0, 0x7C
    .db     0x97, 0xB7, 0xE7, 0xC9, 0x69, 0x87, 0xC0, 0xFB
    ; 15G
    .db     0x5B, 0x05, 0x60, 0xBC, 0xB7, 0xD8, 0xBC, 0x72
    .db     0x4B, 0x7E, 0xE2, 0x56, 0xEE, 0x23, 0xCC, 0x03
    .db     0x70, 0x93, 0x81, 0xE4, 0x24, 0x74, 0x33, 0xEE
    .db     0x09, 0xDA, 0xD3, 0x0A, 0x43, 0x0E, 0xAA, 0xE2
    .db     0x5D, 0xC4, 0x83, 0x63, 0x4F, 0x52, 0xB8, 0x40
    .db     0x25, 0x1B, 0xA4, 0x42, 0x54, 0x35, 0x66, 0xD7
    .db     0x97, 0x47, 0x8A, 0x77, 0xDE, 0xA6, 0xEF, 0x64
    .db     0xF4, 0xAD, 0x79, 0x70, 0x0A, 0x17, 0x42, 0x20
    ; 17G
    .db     0x9D, 0x5C, 0x3C, 0xD5, 0xCB, 0x1D, 0x09, 0x97
    .db     0x7B, 0x17, 0x0A, 0xAC, 0xB6, 0x24, 0x76, 0xF1
    .db     0xFF, 0x2D, 0xFE, 0x2C, 0x75, 0x39, 0xF1, 0xB0
    .db     0x4E, 0x57, 0x7A, 0x6C, 0x0A, 0x5C, 0xA3, 0xC1
    .db     0x87, 0x99, 0xE7, 0x93, 0x46, 0x31, 0x7D, 0x22
    .db     0x0E, 0xB8, 0x9C, 0xE8, 0x30, 0xBF, 0x75, 0x05
    .db     0xBB, 0x83, 0x18, 0x0D, 0x7F, 0x24, 0x4E, 0x2F
    .db     0xD0, 0xC3, 0x74, 0x32, 0x26, 0x12, 0xD5, 0xEB
    ; 19G
    .db     0xE8, 0x9A, 0x65, 0xA5, 0xBA, 0x12, 0xA9, 0xFE
    .db     0x6E, 0xA1, 0xE1, 0x25, 0xBA, 0x3A, 0x36, 0x68
    .db     0xAC, 0x41, 0x2C, 0x75, 0x77, 0x22, 0x84, 0xB8
    .db     0xFC, 0xC3, 0x97, 0x28, 0x28, 0x5C, 0x54, 0xFE
    .db     0x6B, 0x69, 0x4C, 0xDC, 0xE7, 0xE9, 0x36, 0x2D
    .db     0xC5, 0x77, 0xA9, 0xFB, 0x4A, 0x24, 0x06, 0x58
    .db     0xC1, 0x08, 0x95, 0xE3, 0x9B, 0x5E, 0x66, 0x85
    .db     0x7B, 0x59, 0x12, 0x6D, 0x25, 0xEE, 0x20, 0xF7
    ; 21G
    .db     0x08, 0xB2, 0x35, 0xC1, 0xEC, 0x4C, 0x2E, 0x56
    .db     0x7D, 0xF4, 0x83, 0x47, 0x65, 0xB2, 0xE1, 0x74
    .db     0x30, 0x3B, 0x3F, 0x5A, 0x6C, 0x50, 0x2A, 0x6D
    .db     0xFC, 0x62, 0x67, 0xC1, 0xF4, 0xD9, 0xEA, 0xEC
    .db     0xB9, 0xE5, 0x86, 0xE2, 0xB2, 0xD4, 0x9D, 0xF2
    .db     0x61, 0x3C, 0xBB, 0x83, 0xC0, 0xAD, 0x0F, 0x1B
    .db     0xA4, 0x29, 0xAC, 0x7F, 0x3E, 0x02, 0x75, 0x7A
    .db     0xA3, 0x7F, 0x47, 0xC9, 0xF1, 0xD5, 0x86, 0xC0
    ; 23G
    .db     0x68, 0x50, 0xE4, 0x2D, 0x53, 0x76, 0xF8, 0xF4
    .db     0x6E, 0x1F, 0x2E, 0x9E, 0xE8, 0xA7, 0xC7, 0x37
    .db     0x69, 0x40, 0x58, 0xA3, 0xA2, 0x5F, 0x82, 0xD0
    .db     0x42, 0xBF, 0x27, 0x17, 0x7C, 0xEA, 0x2C, 0xAF
    .db     0xA9, 0x85, 0x47, 0x9E, 0xFB, 0xA4, 0x60, 0x03
    .db     0x4A, 0x9F, 0x29, 0x27, 0x9C, 0xA4, 0xFD, 0xE5
    .db     0x71, 0x2F, 0xAC, 0x71, 0x13, 0x8E, 0x06, 0x48
    .db     0x6F, 0x66, 0x77, 0x90, 0x7B, 0x68, 0xD0, 0x83
    ; 25G
    .db     0x9F, 0x87, 0x37, 0xD8, 0xAC, 0x19, 0xA3, 0xA4
    .db     0xB0, 0x67, 0x6B, 0xED, 0x9E, 0xB4, 0xC1, 0x6F
    .db     0xAF, 0xF3, 0xF1, 0x32, 0x33, 0x99, 0x95, 0xE3
    .db     0x2E, 0x2A, 0x43, 0x65, 0xEB, 0x42, 0x67, 0x96
    .db     0x28, 0x62, 0x96, 0xB4, 0xFE, 0xC9, 0x8D, 0x4B
    .db     0x50, 0x39, 0xF4, 0x43, 0x12, 0x63, 0xCC, 0x96
    .db     0xEE, 0x31, 0xB7, 0xC9, 0x59, 0x88, 0x06, 0x12
    .db     0x68, 0x99, 0xF7, 0x56, 0xC3, 0x8D, 0x94, 0x7B
    ; 27G
    .db     0xB4, 0xFE, 0xE2, 0x97, 0xF4, 0x2A, 0x2C, 0x04
    .db     0x13, 0x73, 0xBF, 0xAE, 0xD7, 0x42, 0x6A, 0xD3
    .db     0xD7, 0xFD, 0x4F, 0x08, 0xEB, 0xC9, 0xD2, 0x49
    .db     0x6A, 0xC7, 0xF7, 0x2E, 0x4B, 0xA5, 0x8A, 0x9F
    .db     0x70, 0x5E, 0x89, 0x09, 0xBA, 0xB7, 0x00, 0x92
    .db     0x58, 0xFB, 0xB7, 0xDD, 0x6F, 0xC6, 0xD0, 0x3B
    .db     0xBB, 0x4C, 0xEB, 0x78, 0x08, 0xD1, 0x97, 0x2D
    .db     0x31, 0xDE, 0x4B, 0xD8, 0x68, 0x10, 0x43, 0x2D
    ; 29G
    .db     0x32, 0xE1, 0x66, 0xCB, 0x6A, 0xB4, 0x5D, 0x5E
    .db     0x80, 0x58, 0x92, 0x0D, 0x3A, 0x96, 0xBE, 0xF1
    .db     0xE2, 0xB9, 0x17, 0x03, 0x27, 0x70, 0x4A, 0x94
    .db     0x48, 0x3D, 0x60, 0x48, 0x59, 0xF9, 0x66, 0xE2
    .db     0x99, 0x88, 0x20, 0x5C, 0x73, 0x66, 0xDB, 0x98
    .db     0xA3, 0x18, 0xFB, 0xA2, 0x47, 0x24, 0x47, 0x90
    .db     0x9F, 0x61, 0x7C, 0x77, 0x39, 0x69, 0x96, 0x8A
    .db     0x1B, 0xE2, 0x3B, 0x2A, 0x2A, 0x14, 0x98, 0x37
    ; 31G
    .db     0x89, 0xFF, 0x55, 0x67, 0x69, 0x3C, 0xF7, 0xE2
    .db     0xE6, 0x17, 0x30, 0x47, 0xE7, 0xF7, 0x3C, 0xDD
    .db     0x0D, 0x60, 0xF7, 0x3C, 0x9D, 0x68, 0xF5, 0x8E
    .db     0xB4, 0x87, 0xFC, 0xB1, 0xF8, 0xC4, 0x8D, 0x94
    .db     0x99, 0x32, 0xA5, 0x4E, 0x81, 0xFE, 0xE9, 0xD9
    .db     0x28, 0x60, 0xEB, 0x98, 0xA2, 0x1C, 0x92, 0x2D
    .db     0xFC, 0x03, 0x98, 0x0C, 0xFD, 0xED, 0xEC, 0xFA
    .db     0x45, 0x47, 0x7B, 0x4D, 0x91, 0xE8, 0x8A, 0xF3

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
; Field multiply/square mod p are p256_mul_p / p256_sq_p (no context needed).
.equ p256_fe_mul, p256_mul_p
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
p256_select_b:                  ; same, B = byte count (1..255)
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
    jr      .Lcs_loop
p256_point_cswap64:             ; same, first 64 bytes (X, Y) only
    ld      iyl, 64
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
; INTERRUPT SAFETY: every public entry point calls p256_di (saves IFF1,
; then di) before any field work; p256_exit restores it.  This is p256's
; own di/ei pair, not tls_crypto_guard_enable (the sign path additionally
; nests a crypto guard around RFC 6979, see _tls_p256_sign).
; The accumulator shift uses mm_acc, a 4-byte .bss cell whose byte 3 is
; always 0 (zeroed by p256_di's scratch wipe at every public entry and
; never written beyond byte 2), so ld hl,(mm_acc+1) always
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
; p-specific Montgomery multiply / square  (THE hot path for the ladder)
;
; p256_mul_p: out = a * b * 2^-256 mod p      In: HL=a, DE=b, BC=out.
; p256_sq_p:  out = a * a * 2^-256 mod p      In: HL=a, BC=out (DE ignored).
;   a, b < p.  Out fully reduced, bit-identical to p256_mont_core with
;   m = p (same q digits, same final reduction).  out may alias a and/or b
;   (inputs are copied first).  Clobbers AF, BC, DE, HL, IY.  Preserves
;   IX.  Stack: 9 bytes.  Needs no field context.
;
; Same product-scanning column loop as p256_mont_core, but the q*m pass is
; replaced by four byte adds per column, exploiting the shape of p:
;   p bytes (LE): 0xFF x12, 0x00 x12, 0x01, 0x00 x3, 0xFF x4;  n0 = 1.
; Column c of sum_j q_j p_{c-j} is 255*W_c + q_{c-24}, where
;   W_c = sum q_{c-11..c} + sum q_{c-31..c-28}  (q_j = 0 outside 0..31).
; Writing 255*W = 256*W - W and pushing the 256*W into the next column's
; carry, the carry that is actually kept, H, satisfies
;   H_c = (H_{c-1} + AB_c + b_c + q_{c-12} + q_{c-24} + q_{c-32}
;          - q_{c-28}) >> 8        (exact, never negative)
; with H_{-1} = 0, where the low byte of the bracket is q_c (c < 32) or
; t[c-32] (c = 32..63), and H_63 - 1 is the top bit.  H is the true carry
; minus W_c, plus a +1 bias from column 28 on (b_28 = 256, b_c = 255 for
; c > 28, else 0): before column 28 there is no negative term so the
; bracket is >= 0 unbiased; afterwards true-carry - W_c >= -1 by
; induction and the bias keeps the bracket >= 0.  Column 63 has no a*b
; terms.  The loops are fully unrolled, so out-of-range q terms are simply
; not emitted and every MAC entry is a constant.
; Bounds: bracket <= 12.3e3 + 32*0xFE01 + 4*255 < 2.2e6 < 2^24.
; Validated against the integer definition by a Python model of this
; exact column recurrence and bias schedule (accumulator range asserted
; after every term), and on-target against p256_mont_core.
;
; Squaring: column k adds each off-diagonal product twice (a dedicated
; 16-term doubling MAC block, .Lsqmac_blk) and, for even k, the diagonal
; a[k/2]^2: <= 2*16*0xFE01 + 0xFE01 + carry + 1020 < 2.2e6.
; Columns are processed in even/odd pairs j = k>>1, so IX/IY move once per
; pair; the per-column u[] displacements are assembly-time constants.
;
; Every branch, entry offset and address depends only on the (public)
; column index; data reach only mlt/add/adc.
; ===========================================================================
; --- unrolled column helpers (all arguments are assembly-time constants) ---
; P256_SHIFT r, d: HL >>= 8 via mm_acc2 = (r + d), whose byte 3 is never
; written (always 0) -- 12 memory accesses vs 14 for absolute addressing;
; interrupt-safe.
.macro P256_SHIFT r, d
    ld      (\r + (\d)), hl
    ld      hl, (\r + (\d) + 1)
.endm
; P256_RED r, d, k: add column k's p-reduction terms; u[x] is at (r + d + x).
;   k < 28:  + q[k-12] + q[k-24]                       (H = true carry - W)
;   k >= 28: + bias + q[k-12] + q[k-24] + q[k-32] - q[k-28]
;            bias = 256 at k = 28 (enter +1-biased H), else 255
; Terms with an index outside 0..31 are omitted (q_j = 0 there).  The add
; chain cannot overflow 24 bits, so CF = 0 before the final sbc.
.macro P256_RED r, d, k
  .if \k < 28
    .if \k >= 12
    ld      de, 0
    ld      e, (\r + (\d) + \k - 12)
    add     hl, de
      .if \k >= 24
    ld      e, (\r + (\d) + \k - 24)
    add     hl, de
      .endif
    .endif
  .else
    ld      de, 255
    add     hl, de
    .if \k == 28
    inc     hl
    .endif
    .if \k <= 43
    ld      e, (\r + (\d) + \k - 12)
    add     hl, de
    .endif
    .if \k <= 55
    ld      e, (\r + (\d) + \k - 24)
    add     hl, de
    .endif
    .if \k >= 32
    ld      e, (\r + (\d) + \k - 32)
    add     hl, de
    .endif
    .if \k <= 59
    ld      e, (\r + (\d) + \k - 28)
    sbc     hl, de
    .endif
  .endif
.endm
; mul column k: IX = acopy + k - 31 (phase 1) / acopy (phase 2),
;               IY = bcopy + 31 (phase 1) / bcopy + k (phase 2).
.macro P256_MCOL k
  .if \k < 32
    call    .Lmac_end - 9*(\k + 1)
    P256_RED ix, (mm_u - (mm_acopy + \k - 31)), \k
    ld      (ix + (mm_u - (mm_acopy - 31))), l      ; q[k]
    P256_SHIFT iy, (mm_acc2 - (mm_bcopy + 31))
    inc     ix
  .else
    .if \k < 63
    call    .Lmac_end - 9*(63 - \k)
    .endif
    P256_RED iy, (mm_u - (mm_bcopy + \k)), \k
    ld      (iy + (mm_u - mm_bcopy)), l             ; t[k-32]
    P256_SHIFT ix, (mm_acc2 - mm_acopy)
    inc     iy
  .endif
.endm
; sq column pair j (k = 2j, 2j+1): IX = acopy + j - 32 (+1 for odd),
; IY = acopy + 32 + j; u[x] at (iy + mm_u - (acopy + 32 + j) + x).
.macro P256_SCOL j
  .if \j < 16
    .if \j > 0
    call    .Lsqmac_end - 10*\j
    .endif
  .else
    .if \j < 31
    call    .Lsqmac_end - 10*(31 - \j)
    .endif
  .endif
    ld      d, (iy - 32)        ; a[j]
    ld      e, d
    mlt     de
    add     hl, de              ; + a[j]^2
    P256_RED iy, (mm_u - (mm_acopy + 32 + \j)), (2*\j)
    ld      (iy + (mm_u - (mm_acopy + 32 + \j)) + 2*\j), l
    P256_SHIFT iy, (mm_acc2 - (mm_acopy + 32 + \j))
    inc     ix
  .if \j < 16
    call    .Lsqmac_end - 10*(\j + 1)
  .else
    .if \j < 31
    call    .Lsqmac_end - 10*(31 - \j)
    .endif
  .endif
    P256_RED iy, (mm_u - (mm_acopy + 32 + \j)), (2*\j + 1)
    ld      (iy + (mm_u - (mm_acopy + 32 + \j)) + 2*\j + 1), l
    P256_SHIFT iy, (mm_acc2 - (mm_acopy + 32 + \j))
    inc     iy
.endm

p256_mul_p:
    push    ix
    ld      (mm_out), bc
    push    de
    ld      de, mm_acopy
    ld      bc, 32
    ldir                        ; acopy = a
    pop     hl
    ld      de, mm_bcopy
    ld      c, 32               ; BC = 0 after ldir
    ldir                        ; bcopy = b
    ld      ix, mm_acopy - 31
    ld      iy, mm_bcopy + 31
    or      a, a
    sbc     hl, hl              ; H = 0
.irp k, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
    P256_MCOL \k
.endr
    ld      ix, mm_acopy
    ld      iy, mm_bcopy + 32
.irp k, 32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63
    P256_MCOL \k
.endr
.Lpm_final:                     ; In: HL = H_63 = top + 1, t in u[32..63]
    ld      a, l
    dec     a
    neg                         ; A = top ? 0xFF : 0
    ld      hl, mm_u + 32
    ld      de, (mm_out)
    call    p256_redp           ; out = t mod p
    pop     ix
    ret

p256_sq_p:
    push    ix
    ld      (mm_out), bc
    ld      de, mm_acopy
    ld      bc, 32
    ldir                        ; acopy = a
    ld      ix, mm_acopy - 32   ; IX = acopy + j - 32 (even column)
    ld      iy, mm_acopy + 32   ; IY = acopy + 32 + j
    or      a, a
    sbc     hl, hl              ; H = 0
.irp j, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
    P256_SCOL \j
.endr
    jp      .Lpm_final

; 16-term doubling MAC block for p256_sq_p: term n (16..31) is
; acc += 2 * (ix+n) * (iy-n).  10 bytes per term; entry for an m-term
; column is .Lsqmac_end - 10*m.  Uses D, E, HL; preserves A, BC, IX, IY.
.Lsqmac_blk:
.irp n, 16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
    ld      d, (ix + \n)
    ld      e, (iy - \n)
    mlt     de
    add     hl, de
    add     hl, de
.endr
.Lsqmac_end:
    ret


; ===========================================================================
; p-specific conditional subtraction / add-back (unrolled, branch-free).
;
; p256_redp: x = (top:t >= p) ? top:t - p : top:t, given top:t < 2p.
;   In: HL = t (32 bytes), DE = x (may equal HL), A = top mask (0x00/0xFF).
;   Clobbers AF, BC, DE, HL, IY.  Preserves IX.
;   With c = 2^256 - p:  top:t >= p  <=>  top | carry(t + c), and then
;   top:t - p = (t + c) mod 2^256.  Pass 1 computes only carry(t + c);
;   pass 2 adds (c & mask).  c bytes are only 00/01/FE/FF: c & mask comes
;   from B = 0, C = mask, IYL = mask & 0xFE (byte 0, 0x01, is folded into
;   the first add).  Pointer-increment passes: 4 / 7 accesses per byte.
; ===========================================================================
p256_redp:
    ld      iyh, a              ; top mask
    push    hl
    ld      bc, 0x0000FF        ; B = 0, C = 0xFF
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
    adc     a, 0xFE
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
    sbc     a, a                ; carry(t + c) mask
    or      a, iyh              ; | top
    ld      c, a                ; C = mask
    and     a, 0xFE
    ld      iyl, a              ; IYL = mask & 0xFE
    ld      a, c
    and     a, 0x01             ; mask & c[0]
    pop     hl
    add     a, (hl)
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
    adc     a, iyl
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
    ret

; p256_fe_add: out = a + b mod p.  In: HL=a, DE=b, BC=out; a, b < p.
; out may alias a and/or b.  Clobbers AF, BC, DE, HL, IY.  Preserves IX.
p256_fe_add:
    push    ix
    push    hl
    pop     ix                  ; IX = a
    ex      de, hl              ; HL = b
    push    bc
    pop     de                  ; DE = out
    push    de
    or      a, a
    ld      a, (ix + 0)
    adc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 1)
    adc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 2)
    adc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 3)
    adc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 4)
    adc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 5)
    adc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 6)
    adc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 7)
    adc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 8)
    adc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 9)
    adc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 10)
    adc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 11)
    adc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 12)
    adc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 13)
    adc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 14)
    adc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 15)
    adc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 16)
    adc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 17)
    adc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 18)
    adc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 19)
    adc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 20)
    adc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 21)
    adc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 22)
    adc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 23)
    adc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 24)
    adc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 25)
    adc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 26)
    adc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 27)
    adc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 28)
    adc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 29)
    adc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 30)
    adc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 31)
    adc     a, (hl)
    ld      (de), a
    sbc     a, a                ; top mask
    pop     hl                  ; HL = out
    push    hl
    pop     de                  ; DE = out (reduce in place)
    call    p256_redp
    pop     ix
    ret

; p256_fe_sub: out = a - b mod p.  In: HL=a, DE=b, BC=out; a, b < p.
; out may alias a and/or b.  Clobbers AF, BC, DE, HL, IY.  Preserves IX.
; out = (a - b) + (p & borrow mask); p bytes are only 00/01/FF.
p256_fe_sub:
    push    ix
    push    hl
    pop     ix                  ; IX = a
    ex      de, hl              ; HL = b
    push    bc
    pop     de                  ; DE = out
    push    de
    or      a, a
    ld      a, (ix + 0)
    sbc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 1)
    sbc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 2)
    sbc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 3)
    sbc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 4)
    sbc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 5)
    sbc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 6)
    sbc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 7)
    sbc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 8)
    sbc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 9)
    sbc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 10)
    sbc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 11)
    sbc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 12)
    sbc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 13)
    sbc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 14)
    sbc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 15)
    sbc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 16)
    sbc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 17)
    sbc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 18)
    sbc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 19)
    sbc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 20)
    sbc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 21)
    sbc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 22)
    sbc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 23)
    sbc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 24)
    sbc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 25)
    sbc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 26)
    sbc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 27)
    sbc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 28)
    sbc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 29)
    sbc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 30)
    sbc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
    ld      a, (ix + 31)
    sbc     a, (hl)
    ld      (de), a
    sbc     a, a                ; borrow mask
    ld      c, a                ; C = mask (p byte 0xFF)
    and     a, 0x01
    ld      d, a                ; D = mask & 0x01 (p byte 0x01)
    ld      b, 0                ; B = 0 (p byte 0x00)
    pop     hl                  ; HL = out
    ld      a, (hl)
    add     a, c
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    adc     a, c
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    adc     a, c
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    adc     a, c
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    adc     a, c
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    adc     a, c
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    adc     a, c
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    adc     a, c
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    adc     a, c
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    adc     a, c
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    adc     a, c
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    adc     a, c
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    adc     a, b
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    adc     a, b
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    adc     a, b
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    adc     a, b
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    adc     a, b
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    adc     a, b
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    adc     a, b
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    adc     a, b
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    adc     a, b
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    adc     a, b
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    adc     a, b
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    adc     a, b
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    adc     a, d
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    adc     a, b
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    adc     a, b
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    adc     a, b
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    adc     a, c
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    adc     a, c
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    adc     a, c
    ld      (hl), a
    inc     hl
    ld      a, (hl)
    adc     a, c
    ld      (hl), a
    pop     ix
    ret

; ===========================================================================
; Modular inversion by Fermat: out = a^(m-2) (Montgomery domain), by fixed
; addition chains (p256_fe_inv mod p, p256_ord_inv mod n).
; ===========================================================================
; p256_fe_inv: out = a^(p-2) (mod p, Montgomery domain) by a fixed
; addition chain: 255 squarings + 12 multiplications (vs 255 + 128 for the
; binary method).  x_k denotes a^(2^k - 1).
;   x2, x3, x6, x12, x15, x30, x32;  t = x32
;   t = t^(2^32) x1;  t = t^(2^128) x32;  t = t^(2^32) x32;
;   t = t^(2^30) x30;  t = t^(2^2) x1   ->  a^(p-2)
; In: HL=a, BC=out.  Uses f5..f12 (a and out must not be f5..f12; a may be
; f12).  Clobbers AF, BC, DE, HL, IY.  The exponent is public.
.equ IX1,  PF12
.equ IX2,  PF10
.equ IX3,  PF9
.equ IX6,  PF8
.equ IX15, PF7
.equ IX30, PF6
.equ IX32, PF5
.equ IT,   __p256_f + 11*32
.macro INV_STEP dst, src, n, m
    ld      hl, \src
    ld      bc, \dst
    ld      a, \n
    ld      de, \m
    call    .Linv_sqn_mul
.endm
p256_fe_inv:
    ld      (inv_out), bc
    ld      de, IX1
    ld      bc, 32
    ldir                                ; x1 = a
    INV_STEP IX2,  IX1,  1,  IX1
    INV_STEP IX3,  IX2,  1,  IX1
    INV_STEP IX6,  IX3,  3,  IX3
    INV_STEP IT,   IX6,  6,  IX6        ; x12
    INV_STEP IX15, IT,   3,  IX3
    INV_STEP IX30, IX15, 15, IX15
    INV_STEP IX32, IX30, 2,  IX2
    INV_STEP IT,   IX32, 32, IX1
    INV_STEP IT,   IT,   128, IX32
    INV_STEP IT,   IT,   32, IX32
    INV_STEP IT,   IT,   30, IX30
    ld      hl, IT
    ld      bc, IT
    ld      a, 2
    call    .Linv_sqn
    ld      hl, IT
    ld      de, IX1
    ld      bc, (inv_out)
    jp      p256_mul_p                  ; out = t^(2^2) * x1
; dst = src^(2^A) * (DE).  A >= 1.
.Linv_sqn_mul:
    push    de
    push    bc
    call    .Linv_sqn
    pop     hl                          ; HL = dst
    pop     de
    push    hl
    pop     bc                          ; BC = dst
    jp      p256_mul_p
; dst(BC) = src(HL)^(2^A), A >= 1.  Preserves BC.
.Linv_sqn:
    ld      (inv_cnt), a
    ld      (inv_exp), bc               ; (scratch: dst pointer)
    call    p256_sq_p
.Linv_sqn_loop:
    ld      a, (inv_cnt)
    dec     a
    ld      (inv_cnt), a
    ld      bc, (inv_exp)
    ret     z
    push    bc
    pop     hl
    call    p256_sq_p
    jr      .Linv_sqn_loop
; p256_ord_inv: out = a^(n-2) mod n (Montgomery domain) by a fixed
; addition chain: 253 squarings + 39 multiplications (vs 256 + 169 for the
; binary method), all through the constant-time p256_mont_core.  The
; sequence of operations and addresses depends only on the public exponent
; n - 2, never on a.  Bit-identical to the binary method (both yield the
; fully reduced Montgomery form of a^(n-2)).
;   o_v = a^v, v = 1, 3, .., 15 (slots 0..7; o_3 = x2, o_15 = x4),
;   x8, x16, x32 (slots 8..10; x_k = a^(2^k - 1)), t (slot 11):
;   t = x32^(2^64) x32;  t = t^(2^32) x32       -> top 128 bits 1^32 0^32 1^64
;   low 128 bits: w = 4 left-to-right sliding window, __p256_N2_CHAIN.
; In: HL = a, BC = out (may alias; neither in r0..saved1).  Uses r0, r1,
; saved0, saved1 as twelve 32-byte slots.  Clobbers AF, BC, DE, HL, IY.
.equ OIS, __p256_r0                     ; slot i at OIS + 32 i
.macro ORI_STEP dst, src, n, m
    ld      hl, \src
    ld      bc, \dst
    ld      a, \n
    ld      de, \m
    call    .Loi_sqn_mul
.endm
p256_ord_inv:
    ld      (inv_out), bc
    ld      de, OIS
    ld      bc, 32
    ldir                                ; o_1 = a
    call    p256_ctx_n
    ld      hl, OIS
    ld      bc, OIS + 32*11
    ld      a, 1
    call    .Loi_sqn                    ; t = a^2
    ld      hl, OIS
    ld      b, 7
.Loi_odd:                               ; o_(v+2) = o_v a^2
    push    bc
    push    hl
    push    hl
    pop     iy
    lea     bc, iy + 32
    ld      de, OIS + 32*11
    call    p256_mont_core
    pop     hl
    ld      de, 32
    add     hl, de
    pop     bc
    djnz    .Loi_odd
    ORI_STEP OIS + 32*8,  OIS + 32*7,  4,  OIS + 32*7     ; x8
    ORI_STEP OIS + 32*9,  OIS + 32*8,  8,  OIS + 32*8     ; x16
    ORI_STEP OIS + 32*10, OIS + 32*9,  16, OIS + 32*9     ; x32
    ORI_STEP OIS + 32*11, OIS + 32*10, 64, OIS + 32*10
    ORI_STEP OIS + 32*11, OIS + 32*11, 32, OIS + 32*10
    ld      hl, __p256_N2_CHAIN
.Loi_tab:                               ; t = t^(2^s) o_v  (public schedule)
    ld      a, (hl)
    or      a, a
    jr      z, .Loi_done
    inc     hl
    ld      c, (hl)
    inc     hl
    push    hl
    push    af
    or      a, a
    sbc     hl, hl
    ld      l, c
    add     hl, hl
    add     hl, hl
    add     hl, hl
    add     hl, hl
    add     hl, hl
    ld      de, OIS
    add     hl, de
    ex      de, hl                      ; DE = o_v
    pop     af
    ld      hl, OIS + 32*11
    ld      bc, OIS + 32*11
    call    .Loi_sqn_mul
    pop     hl
    jr      .Loi_tab
.Loi_done:
    ld      hl, OIS + 32*11
    ld      de, (inv_out)
    ld      bc, 32
    ldir
    ret
; dst(BC) = src(HL)^(2^A) * (DE), A >= 1, mod-n context.
.Loi_sqn_mul:
    push    de
    push    bc
    call    .Loi_sqn
    pop     hl
    pop     de
    push    hl
    pop     bc
    jp      p256_mont_core
; dst(BC) = src(HL)^(2^A), A >= 1, mod-n context.
.Loi_sqn:
    ld      (inv_cnt), a
    ld      (inv_exp), bc
    push    hl
    pop     de
    call    p256_mont_core
.Loi_sq_loop:
    ld      a, (inv_cnt)
    dec     a
    ld      (inv_cnt), a
    ret     z
    ld      hl, (inv_exp)
    push    hl
    pop     de
    push    hl
    pop     bc
    call    p256_mont_core
    jr      .Loi_sq_loop

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
;
; p256_point_add_ladder: same, but omits the always-computed doubling and
; its select.  ONLY valid inside the Montgomery ladder: there saved0 = mP
; and saved1 = (m+1)P, so the doubling case (both finite, h = r = 0, i.e.
; saved0 == saved1) would need P = O, which cannot happen (P is G or a
; validated affine point, and the group order n is prime).  The infinity
; and P = -Q selects are kept, so the result is identical for every
; reachable input.  The choice is a public, per-call constant: every
; ladder step executes the same instruction sequence.
p256_point_add_ladder:
    ld      a, 1
    jr      .Lpa_entry
p256_point_add:
    xor     a, a
.Lpa_entry:
    ld      (pa_lad), a
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
    ld      a, (pa_lad)
    or      a, a
    jr      nz, .Lpa_nodbl      ; public: ladder variant
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
.Lpa_nodbl:
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

; p256_scalar_mul_ml: out = scalar * point, Montgomery ladder, 256 steps,
; constant sequence of operations independent of the scalar.  Complete
; formulas; used by p256_scalar_mul only for the (public) x(P) = 0 case.
; In: HL=out, DE=scalar (32 B big-endian), BC=point (96 B).
; scalar/point must not lie in the ladder scratch (r0,r1,saved*,rt,
; add_result,double_result,f[]).  out may be saved0 or any free buffer.
; Clobbers AF, BC, DE, HL, IY.
p256_scalar_mul_ml:
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
    call    p256_point_add_ladder       ; r1 = r0 + r1
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
; p256_scalar_mul: out = scalar * point.  Co-Z Montgomery ladder
; (Goundar-Joye-Miyaji 2010 / Rivain 2011, "(X,Y)-only"): per bit one
; XYcZ-ADDC (5M+3S) and one XYcZ-ADDU (4M+2S) = 9M+5S, versus 14M+10S for
; the Jacobian ladder.  Z is never tracked; it is recovered once at the end
; from the known difference R1 - R0 = P.
;
; In: HL=out, DE=scalar (32 B big-endian, < n; 0 allowed), BC=point (96 B,
;     Jacobian with Z = 1 in the Montgomery domain, i.e. an imported affine
;     point or G).  out may be saved0 or any free buffer; scalar/point must
;     not lie in the ladder scratch (r0, r1, saved1, rt, add_result,
;     double_result, f[]).  Out: Jacobian k*point (Z = 0 for infinity).
; Clobbers AF, BC, DE, HL, IY.
;
; Scalar recoding: k' = k + n if that is >= 2^256, else k + 2n, so k' has
; exactly 257 bits (bit 256 = 1) and k'P = kP.  The ladder starts from
; (R0, R1) = (P, 2P) (XYcZ-IDBL) and walks bits 255..0.
; Exceptional scalars: an intermediate R0 or R1 is O only for k in
; {0, 1, n-2, n-1} (proof: a prefix m of k' >= 2^256 with m = 0 or
; m = -1 mod n forces k' in {2n-2 .. 2n+1}); for those the result is
; replaced, in constant time, by O, P, -2P, -P respectively.
; Z recovery: after the last ADDC, A = R_b - R_{1-b} = (b ? P : -P) in the
; co-Z frame, so lambda = 1/Z = s*y_P*X_A / (x_P*Y_A) with s = b ? 1 : -1;
; the last ADDU multiplies Z by (X_B - X_A).  The output is the Jacobian
; point (X0*num^2, Y0*num^3, den) with num = s*y_P*X_A and
; den = x_P*Y_A*(X_B - X_A): no inversion here (affine_export does one).
; x_P = 0 (two valid points, since b is a QR mod p) would make den = 0, so
; that PUBLIC condition falls back to p256_scalar_mul_ml.
; Constant time: same instruction sequence for every scalar; the bit only
; reaches cswap/select masks.  Validated by a Python model of this exact
; buffer-level sequence (all exceptional k, random k, G and random P);
; see the file header for its (uncommitted) location.
; ===========================================================================
p256_scalar_mul:
    ld      (sm_out), hl
    ld      (sm_k), de
    ld      (sm_pt), bc
    push    bc
    pop     hl
    call    p256_ct_is_zero             ; x(P) == 0 ?  (public)
    inc     a
    jr      nz, .Lcz_go
    ld      hl, (sm_out)
    ld      de, (sm_k)
    ld      bc, (sm_pt)
    jp      p256_scalar_mul_ml
.Lcz_go:
    ld      hl, (sm_k)
    ld      de, PF10
    call    p256_rev32                  ; f10 = k (LE)
    ld      de, PZERO
    call    .Lcz_eqk
    ld      (sm_e0), a
    ld      de, __p256_ONE
    call    .Lcz_eqk
    ld      (sm_e1), a
    ld      de, __p256_NM1
    call    .Lcz_eqk
    ld      (sm_em1), a
    ld      de, __p256_NM2
    call    .Lcz_eqk
    ld      (sm_em2), a
    ld      hl, PF10
    ld      de, __p256_N
    ld      iy, PF11
    call    .Lcz_add32                  ; f11 = k + n, A = carry mask
    push    af
    ld      hl, PF10
    ld      de, __p256_N2
    ld      iy, PF12
    call    .Lcz_add32                  ; f12 = k + 2n (mod 2^256)
    pop     af
    ld      c, a
    ld      hl, PF12
    ld      de, PF11
    ld      iy, PF12
    ld      b, 32
    call    p256_select_b               ; f12 = carry ? k + n : k + 2n
    ld      hl, PF12
    ld      de, sm_kp
    call    p256_rev32                  ; k' (BE, low 256 bits)
    ld      hl, (sm_pt)
    ld      de, __p256_saved1
    ld      bc, 96
    ldir                                ; saved1 = P = (x, y, 1)
; ---- XYcZ-IDBL: A = P = (4xy^2, 8y^4), B = 2P, common Z = 2y ----
    FSQ     PF1, PS1Y
    FMUL    CZXA, PS1X, PF1
    FADD    CZXA, CZXA, CZXA
    FADD    CZXA, CZXA, CZXA            ; S = 4xy^2
    FSQ     PF1, PF1
    FADD    PF1, PF1, PF1
    FADD    PF1, PF1, PF1
    FADD    CZYA, PF1, PF1              ; 8y^4
    FSQ     PF2, PS1X
    FSUB    PF2, PF2, __p256_P_R
    FADD    PF3, PF2, PF2
    FADD    PF2, PF3, PF2               ; M = 3(x^2 - 1)
    FSQ     CZXB, PF2
    FSUB    CZXB, CZXB, CZXA
    FSUB    CZXB, CZXB, CZXA            ; X(2P) = M^2 - 2S
    FSUB    PF3, CZXA, CZXB
    FMUL    PF3, PF2, PF3
    FSUB    CZYB, PF3, CZYA             ; Y(2P) = M(S - X) - 8y^4
; ---- exceptional-k results: add_result = -P, double_result = -2P ----
    ld      hl, PS1X
    ld      de, __p256_add_result
    ld      bc, 32
    ldir
    FSUB    __p256_add_result + 32, PZERO, PS1Y
    ld      hl, __p256_P_R
    ld      de, __p256_add_result + 64
    ld      bc, 32
    ldir
    ld      hl, CZXB
    ld      de, __p256_double_result
    ld      bc, 32
    ldir
    FSUB    __p256_double_result + 32, PZERO, CZYB
    FADD    __p256_double_result + 64, PS1Y, PS1Y
; ---- ladder over bits 255..1 ----
    ld      hl, sm_kp
    ld      (sm_k), hl
    xor     a, a
    ld      (sm_prev), a
    dec     a
    ld      (sm_cnt), a                 ; 255 iterations
    ld      a, 0x80
    ld      (sm_bit), a
.Lcz_loop:
    call    .Lcz_bit                    ; A = R_b, B = R_{1-b}
    call    p256_coz_addc               ; B = A + B, A = A - B
    call    p256_coz_addu               ; A = B + A (= 2 R_b), B rescaled
    ld      a, (sm_bit)                 ; advance to next bit (public index)
    rrca
    ld      (sm_bit), a
    jr      nc, .Lcz_same
    ld      hl, (sm_k)
    inc     hl
    ld      (sm_k), hl
.Lcz_same:
    ld      a, (sm_cnt)
    dec     a
    ld      (sm_cnt), a
    jr      nz, .Lcz_loop
; ---- bit 0 with Z recovery ----
    call    .Lcz_bit
    call    p256_coz_addc               ; A = (b ? P : -P) in the co-Z frame
    FSUB    PF7, PZERO, PS1Y
    ld      a, (sm_prev)
    ld      c, a
    ld      hl, PF7
    ld      de, PS1Y
    ld      iy, PF7
    ld      b, 32
    call    p256_select_b               ; f7 = b ? y : -y
    FMUL    PF7, PF7, CZXA              ; num = s*y*X_A
    FMUL    PF8, PS1X, CZYA
    FSUB    PF9, CZXB, CZXA
    FMUL    PF8, PF8, PF9               ; den = x*Y_A*(X_B - X_A)
    call    p256_coz_addu
    ld      a, (sm_prev)
    ld      c, a
    ld      hl, __p256_r0
    ld      de, __p256_r1
    call    p256_point_cswap64          ; r0 = R0 = k'P (co-Z X, Y)
    FSQ     PF9, PF7
    FMUL    PRTX, CZXA, PF9             ; X0 * num^2
    FMUL    PF9, PF9, PF7
    FMUL    PRTY, CZYA, PF9             ; Y0 * num^3
    ld      hl, PF8
    ld      de, PRTZ
    ld      bc, 32
    ldir                                ; Z = den
    ld      a, (sm_e1)
    ld      de, __p256_saved1           ; k = 1   -> P
    call    .Lcz_fix
    ld      a, (sm_em1)
    ld      de, __p256_add_result       ; k = n-1 -> -P
    call    .Lcz_fix
    ld      a, (sm_em2)
    ld      de, __p256_double_result    ; k = n-2 -> -2P
    call    .Lcz_fix
    ld      a, (sm_e0)
    ld      de, __p256_INF              ; k = 0   -> O
    call    .Lcz_fix
    ld      hl, PRT
    ld      de, (sm_out)
    ld      bc, 96
    ldir
    ret
; rt = mask ? (DE) : rt.  In: A = mask, DE = point.
.Lcz_fix:
    ld      c, a
    ld      hl, PRT
    ld      iy, PRT
    jp      p256_point_select
; A = (f10 == (DE)) ? 0xFF : 0.  Branch-free.
.Lcz_eqk:
    ld      hl, PF10
    call    p256_eq32
    neg
    ret
; (IY) = (HL) + (DE), 32 bytes; A = carry ? 0xFF : 0.
.Lcz_add32:
    ld      b, 32
    or      a, a
.Lcz_add_loop:
    ld      a, (de)
    adc     a, (hl)
    ld      (iy + 0), a
    inc     hl
    inc     de
    inc     iy
    djnz    .Lcz_add_loop
    sbc     a, a
    ret
; Current bit -> mask; swap r0/r1 (X, Y) iff it differs from the previous.
.Lcz_bit:
    ld      hl, (sm_k)
    ld      a, (sm_bit)
    and     a, (hl)
    add     a, 0xFF                     ; CF = bit set
    sbc     a, a
    ld      b, a
    ld      a, (sm_prev)
    xor     a, b
    ld      c, a
    ld      a, b
    ld      (sm_prev), a
    ld      hl, __p256_r0
    ld      de, __p256_r1
    jp      p256_point_cswap64

; p256_coz_addc: (A, B) co-Z -> B = A + B, A = A - B (co-Z).  5M + 3S.
; Uses f0..f6.
p256_coz_addc:
    FSUB    PF0, CZXA, CZXB
    FSQ     PF0, PF0                    ; C = (XA - XB)^2
    FMUL    PF1, CZXA, PF0              ; W1
    FMUL    PF2, CZXB, PF0              ; W2
    FSUB    PF3, CZYA, CZYB
    FADD    PF4, CZYA, CZYB
    FSUB    PF5, PF1, PF2
    FMUL    PF5, CZYA, PF5              ; A1 = YA (W1 - W2)
    FSQ     PF6, PF3
    FSUB    PF6, PF6, PF1
    FSUB    CZXB, PF6, PF2              ; X(A+B) = D - W1 - W2
    FSUB    PF6, PF1, CZXB
    FMUL    PF6, PF3, PF6
    FSUB    CZYB, PF6, PF5              ; Y(A+B)
    FSQ     PF6, PF4
    FSUB    PF6, PF6, PF1
    FSUB    CZXA, PF6, PF2              ; X(A-B) = D' - W1 - W2
    FSUB    PF6, PF1, CZXA
    FMUL    PF6, PF4, PF6
    FSUB    CZYA, PF6, PF5              ; Y(A-B)
    ret

; p256_coz_addu: (A, B) co-Z -> A = B + A, B = B in the new frame.
; 4M + 2S.  Uses f0, f2, f3, f6.
p256_coz_addu:
    FSUB    PF0, CZXB, CZXA
    FSQ     PF0, PF0                    ; C
    FMUL    PF2, CZXA, PF0              ; W2
    FMUL    CZXB, CZXB, PF0             ; W1 (= new XB)
    FSUB    PF3, CZYB, CZYA
    FSUB    PF6, CZXB, PF2
    FMUL    CZYB, CZYB, PF6             ; A1 (= new YB)
    FSQ     PF6, PF3
    FSUB    PF6, PF6, CZXB
    FSUB    CZXA, PF6, PF2              ; X(B+A)
    FSUB    PF6, CZXB, CZXA
    FMUL    PF6, PF3, PF6
    FSUB    CZYA, PF6, CZYB             ; Y(B+A)
    ret

; ===========================================================================
; Variable-time ECDSA verification engine.
;
; EVERYTHING IN THIS SECTION OPERATES ON PUBLIC DATA ONLY (signature, hash,
; public key and values derived from them) and is deliberately NOT constant
; time: it branches on scalar bits, skips zero digits and branches on the
; exceptional cases of the addition formulas.  It must never see a secret
; scalar: keygen, ECDH and signing keep using the constant-time co-Z ladder
; and p256_ord_inv.
;
; R = u1*G + u2*Q by interleaved (Straus/Shamir) double-and-add, one shared
; doubling chain over bit positions 256..0:
;   u2 (Q): width-4 NAF, digits 0, +-1, +-3, +-5, +-7, recoded right-to-left
;           into nibble codes (VS_DIG); table Q (affine, = pq), 3Q, 5Q, 7Q
;           (Jacobian, computed per call).  +-Q uses mixed addition.
;   u1 (G): left-to-right sliding window, w = 5, recoded on the fly (no
;           digit storage); table (2i+1)G, i = 0..15, affine in ROM
;           (__p256_GTAB), always mixed addition.
; Expected cost (random scalars): ~254 doublings, ~38 Jacobian additions,
; ~50 mixed additions, versus 2 x 256 co-Z ladder steps.
;
; Scratch use: accumulator = saved0 (vs_inf = 1 means O; its bytes are then
; don't-care), add operand = saved1, table 3Q/5Q/7Q = add_result /
; double_result / pa (must stay contiguous, in that order), wNAF codes and
; work copy in r0/r1, u1 = __p256_k, u2 = __p256_x.  The point routines used
; here (point_double, point_add_ladder, point_add_affine) touch only f[],
; rt, saved0, saved1 and their state bytes.
; ===========================================================================
.equ VS_DIG, __p256_r0                  ; 129 B: wNAF(u2) code i at nibble i
.equ VS_WK,  __p256_r0 + 136            ; 33 B: wNAF work copy of u2

; p256_point_add_affine: acc += A (mixed Jacobian + affine), VARIABLE TIME.
;   acc = saved0 (Jacobian, Montgomery; O iff vs_inf != 0).
;   A   = saved1 X||Y (affine, Montgomery), a finite curve point.
; madd-2007-bl, 7M + 4S.  Exceptional cases (public): acc = O -> acc = A;
; H = 0 and S2 = Y1 (acc = A) -> doubling; H = 0 otherwise (acc = -A) -> O.
; Uses f0..f8 (and f0..f6, rt via point_double).  Clobbers AF, BC, DE, HL, IY.
p256_point_add_affine:
    ld      a, (vs_inf)
    or      a, a
    jr      z, .Lmd_go
    ld      hl, PS1
    ld      de, PS0
    ld      bc, 64
    ldir                                ; acc = (x, y, ...)
    ld      hl, __p256_P_R
    ld      c, 32                       ; BC = 0 after ldir
    ldir                                ; ... , 1)
    xor     a, a
    ld      (vs_inf), a
    ret
.Lmd_go:
    FSQ     PF0, PS0Z                   ; Z1Z1 = Z1^2
    FMUL    PF1, PS1X, PF0              ; U2 = x2 Z1Z1
    FMUL    PF2, PS0Z, PF0
    FMUL    PF2, PS1Y, PF2              ; S2 = y2 Z1 Z1Z1
    FSUB    PF1, PF1, PS0X              ; H = U2 - X1
    FSUB    PF2, PF2, PS0Y              ; S2 - Y1
    ld      hl, PF1
    call    p256_ct_is_zero
    inc     a
    jp      z, .Lmd_hzero               ; public: exceptional case
    FADD    PF2, PF2, PF2               ; r = 2 (S2 - Y1)
    FSQ     PF3, PF1                    ; HH = H^2
    FADD    PF4, PF3, PF3
    FADD    PF4, PF4, PF4               ; I = 4 HH
    FMUL    PF5, PF1, PF4               ; J = H I
    FMUL    PF6, PS0X, PF4              ; V = X1 I
    FMUL    PF7, PS0Y, PF5              ; Y1 J
    FSQ     PS0X, PF2                   ; r^2           (X1 dead from here)
    FSUB    PS0X, PS0X, PF5
    FSUB    PS0X, PS0X, PF6
    FSUB    PS0X, PS0X, PF6             ; X3 = r^2 - J - 2V
    FSUB    PF6, PF6, PS0X
    FMUL    PF6, PF2, PF6
    FADD    PF7, PF7, PF7
    FSUB    PS0Y, PF6, PF7              ; Y3 = r (V - X3) - 2 Y1 J
    FADD    PF8, PS0Z, PF1
    FSQ     PF8, PF8
    FSUB    PF8, PF8, PF0
    FSUB    PS0Z, PF8, PF3              ; Z3 = (Z1 + H)^2 - Z1Z1 - HH
    ret
.Lmd_hzero:
    ld      hl, PF2
    call    p256_ct_is_zero
    inc     a
    jr      z, p256_dbl_acc             ; acc == A: 2 acc
.Lvt_inf:
    ld      a, 1                        ; acc == -A: O
    ld      (vs_inf), a
    ret

; p256_dbl_acc: saved0 = 2 saved0.  point_double reads saved0 only before its
; final select (which reads rt/INF and writes out byte by byte), so
; out = saved0 is safe here.
p256_dbl_acc:
    ld      hl, __p256_saved0
    jp      p256_point_double

; p256_point_add_vt: acc += saved1 (Jacobian, finite), VARIABLE TIME.
; Same acc conventions as p256_point_add_affine.  Uses the ladder variant of
; the Jacobian addition (11M + 5S, no always-computed doubling) and handles
; its omitted case explicitly: H = 0 and r = 0 (acc == saved1) -> doubling.
; out = saved0 is safe for point_add_ladder: saved0 is only read by the
; final select, at the same byte index it writes.
p256_point_add_vt:
    ld      a, (vs_inf)
    or      a, a
    jr      z, .Lav_go
    ld      hl, PS1
    ld      de, PS0
    ld      bc, 96
    ldir                                ; O + T = T
    xor     a, a
    ld      (vs_inf), a
    ret
.Lav_go:
    ld      hl, __p256_saved0
    call    p256_point_add_ladder
    ld      a, (pa_h)
    or      a, a
    ret     z                           ; generic case
    ld      a, (pa_r)
    or      a, a
    jr      z, .Lvt_inf                 ; acc == -T (saved0 already O)
    ld      hl, PS1
    ld      de, PS0
    ld      bc, 96
    ldir                                ; acc == T: acc = 2 T
    jr      p256_dbl_acc

; p256_bit_k: A = bit j of u1 (__p256_k, LE).  In: A = j.  Out: A = 0/1,
; Z iff 0.  Clobbers AF, BC, DE, HL.
p256_bit_k:
    ld      c, a
    rrca
    rrca
    rrca
    and     a, 0x1F                     ; byte index (also clears CF)
    sbc     hl, hl
    ld      l, a
    ld      de, __p256_k
    add     hl, de
    ld      a, c
    and     a, 7
    ld      b, a
    inc     b
    ld      a, (hl)
    jr      .Lbk_ent
.Lbk_rot:
    rrca
.Lbk_ent:
    djnz    .Lbk_rot
    and     a, 1
    ret

; p256_vs_table: add_result = 3Q, double_result = 5Q, pa = 7Q (Jacobian).
; The ladder-variant addition is valid: its omitted case would need
; Q + 2Q, 3Q + 2Q or 5Q + 2Q with equal operands, i.e. Q, 3Q or 5Q = O,
; impossible for a validated Q (n is a large prime).
p256_vs_table:
    ld      hl, __p256_pq
    ld      de, PS0
    ld      bc, 96
    ldir
    ld      hl, PS1
    call    p256_point_double           ; saved1 = 2Q
    ld      hl, __p256_add_result
    call    p256_point_add_ladder       ; 3Q
    ld      hl, __p256_add_result
    ld      de, PS0
    ld      bc, 96
    ldir
    ld      hl, __p256_double_result
    call    p256_point_add_ladder       ; 5Q
    ld      hl, __p256_double_result
    ld      de, PS0
    ld      bc, 96
    ldir
    ld      hl, __p256_pa
    jp      p256_point_add_ladder       ; 7Q

; p256_vs_wnaf: width-4 NAF of u2 (__p256_x) into VS_DIG, positions 0..256
; (u2 < 2^256, so 257 digits suffice and the work value ends at 0).
; Code for digit d: 0 if d = 0, else |d| | (d < 0 ? 8 : 0).
p256_vs_wnaf:
    ld      hl, VS_DIG
    ld      (hl), 0
    ld      de, VS_DIG + 1
    ld      bc, VS_WK + 32 - VS_DIG
    ldir                                ; codes = 0, work[32] = 0
    ld      hl, __p256_x
    ld      de, VS_WK
    ld      bc, 32
    ldir                                ; work = u2
    or      a, a
    sbc     hl, hl
    ld      (vs_i), hl
.Lwn_loop:
    ld      a, (VS_WK)
    rrca
    jr      nc, .Lwn_shift              ; even: digit 0
    rlca
    and     a, 0x0F                     ; k mod 16 (odd)
    cp      a, 8
    jr      c, .Lwn_pos
    ld      c, a
    ld      a, 16
    sub     a, c                        ; |d| = 16 - (k mod 16); d < 0
    ld      c, a
    ld      hl, VS_WK
    add     a, (hl)
    ld      (hl), a                     ; k += |d|  (low nibble -> 0)
    ld      b, 32
.Lwn_carry:
    inc     hl
    ld      a, (hl)
    adc     a, 0
    ld      (hl), a
    djnz    .Lwn_carry
    ld      a, c
    or      a, 8
    jr      .Lwn_store
.Lwn_pos:
    ld      c, a
    ld      a, (VS_WK)
    sub     a, c                        ; k -= d  (low nibble -> 0, no borrow)
    ld      (VS_WK), a
    ld      a, c
.Lwn_store:
    ld      c, a
    ld      hl, (vs_i)
    srl     h
    rr      l
    ld      de, VS_DIG
    add     hl, de                      ; byte i >> 1
    ld      a, (vs_i)
    rrca                                ; CF = i & 1
    ld      a, c
    jr      nc, .Lwn_lo
    rlca
    rlca
    rlca
    rlca                                ; odd i: high nibble
.Lwn_lo:
    or      a, (hl)
    ld      (hl), a
.Lwn_shift:
    ld      hl, VS_WK + 32
    ld      b, 33
    or      a, a
.Lwn_sh:
    rr      (hl)                        ; k >>= 1
    dec     hl
    djnz    .Lwn_sh
    ld      hl, (vs_i)
    inc     hl
    ld      (vs_i), hl
    ld      de, 257
    or      a, a
    sbc     hl, de
    jr      nz, .Lwn_loop
    ret

; p256_vs_qadd: acc += d Q for the wNAF code in A (1..15).
p256_vs_qadd:
    ld      (vs_t), a
    and     a, 7
    dec     a
    jr      nz, .Lqa_jac
    ld      hl, __p256_pq               ; |d| = 1: Q itself is affine (Z = 1)
    ld      de, PS1
    ld      bc, 64
    ldir
    call    .Lqa_neg
    jp      p256_point_add_affine
.Lqa_jac:                               ; A = |d| - 1 = 2, 4, 6
    ld      hl, __p256_add_result - 96
    ld      de, 96
.Lqa_idx:
    add     hl, de
    sub     a, 2
    jr      nz, .Lqa_idx                ; 3Q, 5Q, 7Q
    ld      de, PS1
    ld      bc, 96
    ldir
    call    .Lqa_neg
    jp      p256_point_add_vt
.Lqa_neg:                               ; d < 0: saved1 Y = -Y
    ld      a, (vs_t)
    and     a, 8
    ret     z
    FSUB    PS1Y, PZERO, PS1Y
    ret

; p256_verify_shamir: saved0 / vs_inf = u1 G + u2 Q.   VARIABLE TIME.
; In: __p256_k = u1, __p256_x = u2 (32-byte LE plain integers), pq = Q
; (validated, Z = 1).  Clobbers AF, BC, DE, HL, IY; preserves IX.
p256_verify_shamir:
    call    p256_vs_table
    call    p256_vs_wnaf
    ld      a, 1
    ld      (vs_inf), a                 ; acc = O
    xor     a, a
    ld      (vs_gpend), a
    ld      hl, 256
    ld      (vs_i), hl
.Lvs_loop:
    ld      a, (vs_inf)
    or      a, a
    call    z, p256_dbl_acc             ; acc = 2 acc (skipped while O)
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
    call    nz, p256_vs_qadd
    ; ---- u1: sliding window over bits 255..0 ----
    ld      a, (vs_i + 1)
    or      a, a
    jp      nz, .Lvs_next               ; i = 256: no u1 bit
    ld      a, (vs_gpend)
    or      a, a
    jr      nz, .Lvs_gchk
    ld      a, (vs_i)
    call    p256_bit_k
    jr      z, .Lvs_next
    ld      a, (vs_i)                   ; open a window at bit i
    sub     a, 4
    jr      nc, .Lvs_find
    xor     a, a                        ; low end max(i - 4, 0)
.Lvs_find:                              ; j = lowest set bit in [low, i]
    ld      (vs_gpos), a
    call    p256_bit_k
    jr      nz, .Lvs_val0
    ld      a, (vs_gpos)
    inc     a
    jr      .Lvs_find
.Lvs_val0:
    xor     a, a
    ld      (vs_gval), a
    ld      a, (vs_i)
.Lvs_val:                               ; gval = bits i..j of u1 (odd)
    ld      (vs_t), a
    call    p256_bit_k
    ld      b, a
    ld      a, (vs_gval)
    add     a, a
    or      a, b
    ld      (vs_gval), a
    ld      a, (vs_gpos)
    ld      hl, vs_t
    cp      a, (hl)
    jr      z, .Lvs_vdone
    ld      a, (hl)
    dec     a
    jr      .Lvs_val
.Lvs_vdone:
    ld      a, 1
    ld      (vs_gpend), a
.Lvs_gchk:                              ; add the window at its low bit
    ld      a, (vs_gpos)
    ld      hl, vs_i
    cp      a, (hl)
    jr      nz, .Lvs_next
    xor     a, a
    ld      (vs_gpend), a
    ld      a, (vs_gval)
    srl     a                           ; (gval - 1) / 2, CF := 1 (cleared below)
    or      a, a
    sbc     hl, hl
    ld      l, a
    add     hl, hl
    add     hl, hl
    add     hl, hl
    add     hl, hl
    add     hl, hl
    add     hl, hl                      ; * 64
    ld      de, __p256_GTAB
    add     hl, de
    ld      de, PS1
    ld      bc, 64
    ldir
    call    p256_point_add_affine
.Lvs_next:
    ld      hl, (vs_i)
    ld      a, h
    or      a, l
    ret     z                           ; position 0 done
    dec     hl
    ld      (vs_i), hl
    jp      .Lvs_loop

; p256_ord_inv_vt: out = a^-1 mod n on PLAIN integers (not Montgomery),
; binary extended Euclid.  VARIABLE TIME: public a only (verify's s).
; In: HL = a (1 <= a < n; a = 0 would not terminate), BC = out.
; Uses f3..f6.  Clobbers AF, BC, DE, HL, IY; sets the mod-n context.
; Invariants: x1 a = u, x2 a = v (mod n); u, v > 0 until u -= v hits 0,
; at which point v = gcd(a, n) = 1 and x2 = a^-1.  x1, x2 < n throughout
; (halving: x even -> x/2, odd -> (x + n)/2 with the carry shifted back in).
.equ IVU,  PF3
.equ IVV,  PF4
.equ IVX1, PF5
.equ IVX2, PF6                          ; must follow IVX1
p256_ord_inv_vt:
    push    bc
    ld      de, IVU
    ld      bc, 32
    ldir                                ; u = a
    ld      hl, __p256_N
    ld      de, IVV
    ld      c, 32
    ldir                                ; v = n
    ld      hl, IVX1
    ld      (hl), 0
    ld      de, IVX1 + 1
    ld      c, 63
    ldir                                ; x1 = x2 = 0
    ld      a, 1
    ld      (IVX1), a                   ; x1 = 1
    call    p256_ctx_n
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
    ld      hl, IVU + 31
    ld      de, IVV + 31
    ld      b, 32
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
    call    .Liv_sub32                  ; u -= v
    ld      hl, IVX1
    ld      de, IVX2
    ld      bc, IVX1
    call    p256_modsub_core            ; x1 -= x2 (mod n)
    ld      hl, IVU
    call    p256_ct_is_zero
    inc     a
    jr      nz, .Liv_loop
    pop     de                          ; u = 0: v = 1, out = x2
    ld      hl, IVX2
    ld      bc, 32
    ldir
    ret
.Liv_vsub:
    ld      hl, IVV
    ld      de, IVU
    call    .Liv_sub32                  ; v -= u
    ld      hl, IVX2
    ld      de, IVX1
    ld      bc, IVX2
    call    p256_modsub_core            ; x2 -= x1 (mod n)
    jp      .Liv_loop
; (HL) -= (DE), 32 bytes.  Clobbers AF, B, DE, HL.
.Liv_sub32:
    ld      b, 32
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
    ld      de, __p256_N
    ld      b, 32
    or      a, a
.Liv_hadd:
    ld      a, (de)
    adc     a, (hl)
    ld      (hl), a
    inc     hl
    inc     de
    djnz    .Liv_hadd                   ; x += n, CF = bit 256
    jr      .Liv_rsh
.Liv_hev:
    or      a, a
; (IY..IY+31) >>= 1, CF into bit 255.  Clobbers B, IY; flags only via rr.
.Liv_rsh:
    lea     iy, iy + 31
    ld      b, 32
.Liv_r:
    rr      (iy + 0)
    dec     iy
    djnz    .Liv_r
    ret

; ===========================================================================
; Import / export
; ===========================================================================

; p256_affine_export: x_be (and y_be if non-NULL) of a Jacobian point.
; In: HL=point (not in f[]), DE=x_be, BC=y_be or 0.
; Out: A = 1, or 0 if the point is at infinity.  Uses f[0..3], f[5..12].
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

; p256_di: zero the scratch block, save IFF1 into p256_di_save (bit 0),
; then disable interrupts.  Must be called once per public entry, before
; any field work.  The wipe establishes the mm_acc[3] = 0 invariant the
; accumulator shift relies on without depending on the loader zero-filling
; .bss (dylib), and clears stale data before use.
; Clobbers AF, BC, DE, HL.  Preserves IX, IY.
; ld a,i sets PV = IFF2 = IFF1 (outside an NMI); jp pe tests PV immediately.
p256_di:
    call    p256_wipe       ; zero scratch (establishes mm_acc[3] = 0)
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
    ; r, s, e as plain LE integers mod n: f0 = r, f1 = s (from the range
    ; checks above), f2 = e = hash mod n (hash < 2^256 < 2n).
    ld      hl, (ix + 9)
    ld      de, PF2
    call    p256_rev32
    ld      hl, PF2
    ld      de, __p256_N
    ld      c, 0
    call    p256_reduce_top
    ld      hl, PF1
    ld      bc, PF7
    call    p256_ord_inv_vt             ; f7 = w = s^-1 (public s: variable time)
    OMUL    PF8, PF7, __p256_N_R2       ; f8 = w R
    OMUL    __p256_k, PF2, PF8          ; u1 = e w   (plain)
    OMUL    __p256_x, PF0, PF8          ; u2 = r w   (plain)
    call    p256_verify_shamir          ; saved0 = u1 G + u2 Q
    ld      a, (vs_inf)
    or      a, a
    jp      nz, .Lvf_fail               ; R = O
    ; Fail closed independently of vs_inf: if Z(saved0) == 0 the projective
    ; check X == r' Z^2 below degenerates to X == 0 and is not a sound test
    ; of x(R).  Field elements are kept canonical (< p), so Z == 0 mod p iff
    ; all 32 bytes are zero (same test point_double/point_add use).  Public.
    ld      hl, PS0Z
    call    p256_ct_is_zero             ; A = 0xFF iff Z == 0
    or      a, a
    jp      nz, .Lvf_fail
    ; x(R) mod n == r  <=>  x(R) = r  or  x(R) = r + n (only if r + n < p),
    ; checked projectively as X == r' Z^2 (mod p): no inversion.
    ld      hl, (ix + 6)
    ld      de, PF8
    call    p256_rev32                  ; f8 = r (LE, < n < p)
    call    .Lvf_xchk
    or      a, a
    jp      nz, p256_exit               ; A = 1
    ld      hl, PF8
    ld      de, __p256_N
    ld      iy, PF8
    call    .Lcz_add32                  ; f8 = r + n
    or      a, a
    jr      nz, .Lvf_fail               ; >= 2^256
    ld      hl, PF8
    ld      de, __p256_P
    call    p256_raw_ge
    or      a, a
    jr      nz, .Lvf_fail               ; >= p
    call    .Lvf_xchk
    jp      p256_exit
; A = 1 iff X(saved0) == f8 * Z(saved0)^2 (mod p), f8 < p.  Uses f9, f10.
.Lvf_xchk:
    FMUL    PF9, PF8, __p256_P_R2       ; f8 into the Montgomery domain
    FSQ     PF10, PS0Z
    FMUL    PF9, PF9, PF10
    ld      hl, PF9
    ld      de, PS0X
    jp      p256_eq32
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
    extern  _tls_crypto_guard_enable
    extern  _tls_crypto_guard_disable

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
; p256_det_k_continue: entry point for r=0/s=0 retry (RFC 6979 §3.2 step h.3).
; K/V state in DK_K/DK_V must be valid before calling.
p256_det_k_continue:
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
;
; KEY-RESIDUE CONTRACT (callers MUST honour):
;  - The RFC 6979 HMAC-SHA-256 work (p256_det_k) is bracketed below by
;    tls_crypto_guard_enable/disable, so the SHA-256 stack frames (which
;    lay below this function's SP) are scrubbed before the ladder runs.
;    The guard is entered AFTER p256_di, so it records "interrupts off"
;    and its disable does not ei mid-sign; p256_exit restores IFF1.
;  - Frames of the later internal routines (ladder, ord_inv, ...) and
;    this function's own stack use are NOT scrubbed here.  Callers must
;    ensure the stack is scrubbed via tls_crypto_guard after return,
;    i.e. wrap the call: tls_crypto_guard_enable(); tls_p256_sign(...);
;    tls_crypto_guard_disable();
;  - _sprng_sha_mbuffer (the 256-byte SHA-256 message schedule in the
;    .saferam.rng overlay at 0xE30800) would otherwise keep the schedule of
;    the last compressed HMAC block (K/V-derived): tls_crypto_guard_disable
;    scrubs only the stack and p256_exit only __p256_scratch.  It is
;    therefore zeroed explicitly right after p256_det_k.  sha256.s keeps no
;    other state in saferam (its context is DK_CTX, wiped by p256_exit).
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
; RFC 6979 §3.2 step h.3: if r=0 or s=0 after scalar multiply, update K/V
; and retry.  The loop label sits here so the retry path re-enters after the
; initial p256_det_k seeding (which must run only once).
.Lsg_try:
    call    _tls_crypto_guard_enable    ; nests inside p256_di: records IFF=0
    call    p256_det_k                  ; k -> __p256_k  (first try: full init)
    call    _tls_crypto_guard_disable   ; scrub SHA-256 frames below SP; no ei
    ld      hl, _sprng_sha_mbuffer      ; wipe the SHA-256 message schedule
    ld      (hl), 0                     ; (W[0..63] of the last HMAC block,
    ld      de, _sprng_sha_mbuffer + 1  ;  K/V-derived) in saferam
    ld      bc, 64 * 4 - 1
    ldir
.Lsg_scalar:
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
    jp      z, .Lsg_retry               ; r == 0: RFC 6979 §3.2 step h.3
    ld      hl, PF6
    call    p256_ct_is_zero
    inc     a
    jp      z, .Lsg_retry               ; s == 0: RFC 6979 §3.2 step h.3
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
.Lsg_retry:
    ; r=0 or s=0: advance K/V per RFC 6979 §3.2 step h.3, then retry.
    ; DK_K/DK_V still hold valid state from the last p256_det_k run.
    call    _tls_crypto_guard_enable
    call    p256_det_k_continue         ; update K/V, generate new k
    call    _tls_crypto_guard_disable
    ld      hl, _sprng_sha_mbuffer
    ld      (hl), 0
    ld      de, _sprng_sha_mbuffer + 1
    ld      bc, 64 * 4 - 1
    ldir
    jp      .Lsg_scalar
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
    globl   _p256_test_fe_mul
    .type   _p256_test_fe_mul, @function
    globl   _p256_test_fe_sq
    .type   _p256_test_fe_sq, @function
    globl   _p256_test_fe_add
    .type   _p256_test_fe_add, @function
    globl   _p256_test_fe_sub
    .type   _p256_test_fe_sub, @function
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
    globl   _p256_test_madd_vt
    .type   _p256_test_madd_vt, @function
    globl   _p256_test_jadd_vt
    .type   _p256_test_jadd_vt, @function
    globl   _p256_test_ord_inv_vt
    .type   _p256_test_ord_inv_vt, @function

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

; void p256_test_fe_mul(uint8_t *out, const uint8_t *a, const uint8_t *b)
; void p256_test_fe_sq(uint8_t *out, const uint8_t *a)      (p-specific paths)
_p256_test_fe_mul:
    ld      iy, p256_mul_p
    jr      .Lt_fe
_p256_test_fe_add:
    ld      iy, p256_fe_add
    jr      .Lt_fe
_p256_test_fe_sub:
    ld      iy, p256_fe_sub
    jr      .Lt_fe
_p256_test_fe_sq:
    ld      iy, p256_sq_p
.Lt_fe:
    push    ix
    ld      ix, 0
    add     ix, sp
    ld      bc, (ix + 6)
    ld      hl, (ix + 9)
    ld      de, (ix + 12)       ; ignored by fe_sq
    call    .Lt_jp_iy
    pop     ix
    ret

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

; uint8_t p256_test_madd_vt(uint8_t out[96], const uint8_t acc[96],
;                           const uint8_t a[96], uint8_t acc_inf)
;   a: affine X||Y in the first 64 bytes (all 96 are copied).
; uint8_t p256_test_jadd_vt(uint8_t out[96], const uint8_t acc[96],
;                           const uint8_t t[96], uint8_t acc_inf)
; Return the resulting vs_inf (1 = result is O).
_p256_test_madd_vt:
    ld      iy, p256_point_add_affine
    jr      .Lt_vtadd
_p256_test_jadd_vt:
    ld      iy, p256_point_add_vt
.Lt_vtadd:
    push    ix
    ld      ix, 0
    add     ix, sp
    push    iy
    ld      hl, (ix + 9)
    ld      de, __p256_saved0
    ld      bc, 96
    ldir
    ld      hl, (ix + 12)
    ld      de, __p256_saved1
    ld      bc, 96
    ldir
    ld      a, (ix + 15)
    ld      (vs_inf), a
    pop     iy
    call    .Lt_jp_iy
    ld      hl, __p256_saved0
    ld      de, (ix + 6)
    ld      bc, 96
    ldir
    ld      a, (vs_inf)
    pop     ix
    ret

; void p256_test_ord_inv_vt(uint8_t out[32], const uint8_t a[32])
;   a: plain LE integer, 1 <= a < n.
_p256_test_ord_inv_vt:
    push    ix
    ld      ix, 0
    add     ix, sp
    ld      hl, (ix + 9)
    ld      bc, (ix + 6)
    call    p256_ord_inv_vt
    pop     ix
    ret
.endif

    .section .note.GNU-stack,"",@progbits

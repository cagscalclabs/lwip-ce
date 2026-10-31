; ---------------------------------------------------------------------------
; ecc_curve.inc -- curve-independent middle layer shared by p256.s / p384.s.
;
; Everything here is a macro; nothing is emitted by the .include itself.
; Each curve file invokes the macros at the place the routine is to live in
; its own .text section, so each curve keeps its own code layout (the
; routines were factored out of p256.s / p384.s without changing a single
; emitted byte).
;
; ---- Parameters the including file must provide ---------------------------
; Numeric (.equ, defined before any macro below is expanded):
;   FIELD_BYTES   field / scalar width in bytes            (32 | 48)
;   SCALAR_BITS   scalar width in bits                     (256 | 384)
;   COMB_D        fixed-base comb strip length in bits     (64 | 96)
;   COMB_W        fixed-base comb width (strips)           (4)
;   WS_DIGITS     signed fixed-window ECDH digit count     (64 | 96)
; Symbol prefix: the first argument `pfx` of every macro is CURVE_PFX, the
; curve's symbol prefix (p256 | p384).  GNU as cannot paste symbol names from
; an .equ, so it is passed textually; `nb` (where present) is FIELD_BYTES
; spelled as a literal, needed only to form the historical routine names
; pXXX_rev<nb>, pXXX_eq<nb> and pXXX_add<nb>.
;
; Curve-specific macros (expanded here, defined by the curve file):
;   FMUL o,a,b   o = a*b mod p (Montgomery)    FSQ o,a     o = a^2 mod p
;   FADD o,a,b   o = a+b mod p                 FSUB o,a,b  o = a-b mod p
; Curve-specific routines called from here:
;   pfx_fe_add/sub, pfx_mul_p/sq_p (via the macros), pfx_point_select
;   (out = C ? DE : HL over 3*FIELD_BYTES bytes), the reloc loader named in
;   ECC_DI_EXIT.
; Curve-specific scratch / constants referenced by name:
;   PF0..PF12, PS0[XYZ], PS1[XYZ], PRT[XYZ], PQ[XYZ], PZERO,
;   __pfx_{saved0,pq,r0,r1,add_result,double_result,k,N,P,P_R,P_R2,P_B_R,
;   INF,COMB,scratch_start,scratch_end}, pfx_di_save,
;   pd_out, pa_out, pa_pinf, pa_qinf, pa_h, pa_r, pa_lad,
;   sm_out, sm_k, sm_bit, sm_cnt, sm_e0, sm_e1, sm_em1, sm_kp, pi_src,
;   vs_inf, vs_i, VS_DIG, VS_WK, VS_T3, VS_T5, VS_T7.
;
; Calling conventions are the curve files' internal convention: arguments
; in registers as documented per routine, IX preserved, AF/BC/DE/HL/IY
; clobbered unless stated otherwise.
;
; Constant-time contract: every routine in this file except the
; ECC_VT_ADD / ECC_VS_TABLE_WNAF group (the documented variable-time
; ECDSA-verify engine, public inputs only) branches only on public values
; (loop counters, digit indices, the public per-call ladder flag) and reaches
; secret data only through adc/sbc/and/or/xor/mlt and masked selects.
; ---------------------------------------------------------------------------

; ===========================================================================
; ECC_UTILS pfx, nb -- byte-string helpers.
;   pfx_raw_ge:     A = (a >= m) ? 1 : 0.  In: HL=a, DE=m.  Clobbers AF, B,
;                   DE, HL.
;   pfx_ct_is_zero: A = 0xFF if the FIELD_BYTES bytes at HL are all zero,
;                   else 0x00.  Clobbers AF, B, HL.  Branch-free on the data.
;   pfx_eq<nb>:     A = 1 if the bytes at HL equal those at DE, else 0.
;                   Clobbers AF, BC, DE, HL.  Branch-free on the data.
;   pfx_rev<nb>:    dst[i] = src[FIELD_BYTES-1-i].  In: HL=src, DE=dst (must
;                   not overlap).  Clobbers AF, BC, DE, HL.
; ===========================================================================
.macro ECC_UTILS pfx, nb
\pfx\()_raw_ge:
    ld      b, FIELD_BYTES
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

\pfx\()_ct_is_zero:
    ld      b, FIELD_BYTES
    xor     a, a
.Lz_loop:
    or      a, (hl)
    inc     hl
    djnz    .Lz_loop
    neg                         ; CF = (A != 0)
    sbc     a, a                ; 0xFF iff nonzero
    cpl                         ; 0xFF iff zero
    ret

\pfx\()_eq\nb:
    ld      bc, FIELD_BYTES << 8
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

\pfx\()_rev\nb:
    ld      bc, FIELD_BYTES - 1
    add     hl, bc
    ld      b, FIELD_BYTES
.Lrv_loop:
    ld      a, (hl)
    ld      (de), a
    dec     hl
    inc     de
    djnz    .Lrv_loop
    ret
.endm

; ===========================================================================
; ECC_SELECT_B pfx -- pfx_select_b: out = mask ? b : a  (B bytes, 1..255).
;   In: HL=a, DE=b, IY=out, B=count, C=mask (0x00/0xFF).  out may alias a or
;   b.  Clobbers AF, B, DE, HL, IY.  Branch-free on the data.
; (pfx_point_select -- the 3*FIELD_BYTES-byte form -- is per curve: P-256
; falls through into this routine, P-384 jumps to it.)
; ===========================================================================
.macro ECC_SELECT_B pfx
\pfx\()_select_b:
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
.endm

; ===========================================================================
; ECC_ADDN pfx, nb -- pfx_add<nb>: (IY) = (HL) + (DE), FIELD_BYTES bytes;
;   A = carry ? 0xFF : 0.  Clobbers AF, B, DE, HL, IY.
; ===========================================================================
.macro ECC_ADDN pfx, nb
\pfx\()_add\nb:
    ld      b, FIELD_BYTES
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
.endm

; ===========================================================================
; ECC_POINT_DOUBLE_ADD pfx -- Jacobian point formulas (Montgomery domain,
; points are X||Y||Z, 3*FIELD_BYTES bytes, a = -3).
;
; pfx_point_double: out = 2 * saved0.  In: HL=out.
;   Uses f[0..6], rt.  out must not be saved0's rt or f[] (out = saved0 is
;   safe: saved0 is dead before the final select writes out).
;   Clobbers AF, BC, DE, HL, IY.
;
; pfx_point_add: out = saved0 + saved1 (complete wrapper, as the reference).
;   In: HL=out.  Uses f[0..12], rt, add_result, double_result.
;   out must not be saved1/rt/add_result/double_result/f[].
;   Clobbers AF, BC, DE, HL, IY.
;
; pfx_point_add_ladder: same, but omits the always-computed doubling and its
;   select.  Only valid where the doubling case (both finite, h = r = 0) is
;   unreachable or handled by the caller (pfx_point_add_vt).  The infinity
;   and P = -Q selects are kept.  The choice is a public, per-call constant.
;   On return pa_h / pa_r hold the H == 0 / r == 0 masks.
; ===========================================================================
.macro ECC_POINT_DOUBLE_ADD pfx
\pfx\()_point_double:
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
    call    \pfx\()_ct_is_zero
    ld      c, a
    ld      hl, PRT
    ld      de, __\pfx\()_INF
    ld      iy, (pd_out)
    jp      \pfx\()_point_select        ; out = (Z==0) ? inf : rt

\pfx\()_point_add_ladder:
    ld      a, 1
    jr      .Lpa_entry
\pfx\()_point_add:
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
    call    \pfx\()_ct_is_zero
    ld      (pa_pinf), a
    ld      hl, PS1Z
    call    \pfx\()_ct_is_zero
    ld      (pa_qinf), a
    ld      hl, PF6
    call    \pfx\()_ct_is_zero
    ld      (pa_h), a
    ld      hl, PF9
    call    \pfx\()_ct_is_zero
    ld      (pa_r), a
    ld      a, (pa_lad)
    or      a, a
    jr      nz, .Lpa_nodbl              ; public: ladder variant
    ld      hl, PRT
    ld      de, __\pfx\()_add_result
    ld      bc, 3*FIELD_BYTES
    ldir
    ld      hl, __\pfx\()_double_result
    call    \pfx\()_point_double        ; always computed (constant work)
    ld      a, (pa_h)
    ld      b, a
    ld      a, (pa_r)
    and     a, b
    ld      c, a                        ; h_zero & r_zero
    ld      hl, __\pfx\()_add_result
    ld      de, __\pfx\()_double_result
    ld      iy, PRT
    call    \pfx\()_point_select
.Lpa_nodbl:
    ld      a, (pa_r)
    cpl
    ld      b, a
    ld      a, (pa_h)
    and     a, b
    ld      c, a                        ; h_zero & ~r_zero
    ld      hl, PRT
    ld      de, __\pfx\()_INF
    ld      iy, PRT
    call    \pfx\()_point_select
    ld      a, (pa_pinf)
    ld      c, a
    ld      hl, PRT
    ld      de, PS1
    ld      iy, PRT
    call    \pfx\()_point_select        ; P = inf -> Q
    ld      a, (pa_qinf)
    ld      c, a
    ld      hl, PRT
    ld      de, PS0
    ld      iy, (pa_out)
    jp      \pfx\()_point_select        ; Q = inf -> P
.endm

; ===========================================================================
; ECC_WS_MUL pfx, nb, t5 -- constant-time variable-base k * Q for ECDH:
; width-4 fixed window with Joye-Tunstall signed regular recoding.
;
; pfx_ws_mul: pq = k * Q.
;   In: DE = k (FIELD_BYTES big-endian, 1 <= k < n; the caller validates the
;   range), pq = Q (validated affine point, Z = R).  Out: pq = k Q
;   (Jacobian).  Clobbers AF, BC, DE, HL, IY and every scratch buffer except
;   the mm_* field state.  Preserves IX.
;
; 1. k' = k odd ? k : n - k (constant-time select on bit 0), ws_kneg = mask.
;    k' Q = +-k Q; the sign is applied to Y at the end (also a select).
; 2. Recoding (right to left), for i = 0 .. WS_DIGITS-2:
;      v = k' mod 32 (odd), d_i = v - 16 in {+-1, +-3, .., +-15},
;      k' = (k' - d_i) / 16 = (k' >> 4) | 1   (stays odd; no carries),
;    and d_(WS_DIGITS-1) = k' (< 16, odd, positive).  Digit byte =
;    (d < 0 ? 0x80 : 0) | (|d| - 1) / 2, computed with masks only.
; 3. Table T[j] = (2j + 1) Q, j = 0..7, Jacobian, T[j] = T[j-1] + 2Q (never
;    exceptional for a point of prime order n).  Entries live in buffers that
;    are dead in ECDH: pq, r0, r1, add_result, double_result, `t5`, f7..f9,
;    f10..f12.  The lookup reads all eight entries every step (masks only).
; 4. acc = T(d_top); for i = top-1 .. 0: acc = 16 acc; acc += d_i Q.  For
;    i >= 1 the plain addition pfx_ws_add is exact (acc != +-d_i Q, acc != O);
;    for i = 0 the wrap 16 m = n + d_0 is reachable, so the last step uses the
;    complete pfx_point_add.  The result is never O.
;   (Full derivation: p256.s / p384.s header comments of the original
;   routines; validated by ws_model.py, agent scratchpad, not committed.)
;
; pfx_ws_lookup: saved1 = s T[j] for the digit byte A (j = A & 7, s = A bit 7
;   ? -1 : 1).  All eight entries are read with masks, Y is always negated
;   and the result selected.  Uses f0.
;
; pfx_ws_add: saved0 = saved0 + saved1 (Jacobian, add-2007-bl, 11M + 5S), in
;   place, NO exceptional-case handling (see step 4).  Uses only f0..f6
;   (f7..f12 hold table entries).
;
; Constant time: loops, table addresses and every branch depend only on the
; public digit index; the secret digits reach only masks.
; ===========================================================================
.macro ECC_WS_ENT j, t
    ld      a, (ws_idx)
    xor     a, \j
    neg                                 ; CF = (idx != j)
    sbc     a, a
    cpl
    ld      c, a                        ; C = 0xFF iff idx == j
    ld      de, \t
    call    .Lwl_or
.endm

.macro ECC_WS_MUL pfx, nb, t5
.equ ws_ptr,  sm_k                      ; 3 B digit pointer (public)
.equ ws_kneg, sm_e0                     ; 0xFF iff k was even (negate Y)
.equ ws_idx,  sm_e1                     ; current |d| index (secret) / counter
.equ ws_neg,  sm_em1                    ; current digit sign mask (secret)
.equ WS_K,    sm_kp                     ; FIELD_BYTES: k' (LE), recoded in place
.equ WS_DIG,  __\pfx\()_k               ; WS_DIGITS B: digit i at WS_DIG + i (k || x)
.equ WS_T6,   PF7                       ; 3*FIELD_BYTES: f7..f9
.equ WS_T7,   PF10                      ; 3*FIELD_BYTES: f10..f12

\pfx\()_ws_mul:
    ex      de, hl
    ld      de, WS_K
    call    \pfx\()_rev\nb              ; WS_K = k (LE)
    ld      hl, __\pfx\()_N
    ld      de, WS_K
    ld      iy, PF7
    ld      b, FIELD_BYTES
    or      a, a
.Lws_nk:
    ld      a, (hl)
    ex      de, hl
    sbc     a, (hl)
    ex      de, hl
    ld      (iy + 0), a
    inc     hl
    inc     de
    inc     iy
    djnz    .Lws_nk                     ; f7 = n - k  (1 <= k < n: no borrow)
    ld      a, (WS_K)
    and     a, 1
    dec     a                           ; A = k even ? 0xFF : 0
    ld      (ws_kneg), a
    ld      c, a
    ld      hl, WS_K
    ld      de, PF7
    ld      iy, WS_K
    ld      b, FIELD_BYTES
    call    \pfx\()_select_b            ; WS_K = k' (odd)
; ---- signed regular recoding, digits 0 .. WS_DIGITS-2 ----
    ld      hl, WS_DIG
    ld      (ws_ptr), hl
    ld      a, WS_DIGITS - 1
    ld      (ws_idx), a                 ; public counter
.Lws_rec:
    ld      a, (WS_K)
    and     a, 0x1F                     ; v (odd)
    sub     a, 16                       ; d = v - 16, CF = (d < 0)
    ld      b, a
    sbc     a, a
    ld      c, a                        ; C = sign mask
    ld      a, b
    xor     a, c
    sub     a, c                        ; |d|
    srl     a                           ; (|d| - 1) / 2
    ld      b, a
    ld      a, c
    and     a, 0x80
    or      a, b                        ; digit byte
    ld      hl, (ws_ptr)
    ld      (hl), a
    inc     hl
    ld      (ws_ptr), hl
    ld      hl, WS_K + FIELD_BYTES - 1
    ld      b, FIELD_BYTES
    xor     a, a
.Lws_shr:
    rrd                                 ; k' >>= 4, one byte per step
    dec     hl
    djnz    .Lws_shr
    ld      hl, WS_K
    set     0, (hl)                     ; k' = (k' >> 4) | 1 = (k' - d) / 16
    ld      hl, ws_idx
    dec     (hl)
    jr      nz, .Lws_rec
    ld      a, (WS_K)                   ; top digit = k' (1..15, odd, positive)
    srl     a
    ld      hl, (ws_ptr)
    ld      (hl), a
; ---- table T[j] = (2j + 1) Q ----
    ld      hl, __\pfx\()_pq
    ld      de, PS0
    ld      bc, 3*FIELD_BYTES
    ldir                                ; saved0 = Q
    ld      hl, PS1
    call    \pfx\()_point_double        ; saved1 = 2Q
.irp t, __\pfx\()_r0, __\pfx\()_r1, __\pfx\()_add_result, __\pfx\()_double_result, \t5, WS_T6, WS_T7
    call    \pfx\()_ws_add              ; saved0 += 2Q
    ld      hl, PS0
    ld      de, \t
    ld      bc, 3*FIELD_BYTES
    ldir
.endr
; ---- main loop ----
    ld      a, (WS_DIG + WS_DIGITS - 1)
    call    \pfx\()_ws_lookup
    ld      hl, PS1
    ld      de, PS0
    ld      bc, 3*FIELD_BYTES
    ldir                                ; acc = d_top Q
    ld      hl, WS_DIG + WS_DIGITS - 2
    ld      (ws_ptr), hl
.Lws_loop:
.rept 4
    ld      hl, PS0
    call    \pfx\()_point_double        ; acc = 2 acc (out = saved0 is safe)
.endr
    ld      hl, (ws_ptr)
    ld      a, (hl)
    call    \pfx\()_ws_lookup           ; saved1 = d_i Q
    ld      hl, (ws_ptr)
    ld      de, WS_DIG
    or      a, a
    sbc     hl, de
    jr      z, .Lws_last                ; public: i == 0
    call    \pfx\()_ws_add              ; acc += d_i Q  (never exceptional)
    ld      hl, (ws_ptr)
    dec     hl
    ld      (ws_ptr), hl
    jr      .Lws_loop
.Lws_last:
    ld      hl, __\pfx\()_pq            ; table dead: pq is free
    call    \pfx\()_point_add           ; complete (acc = d_0 Q is reachable)
    FSUB    PF0, PZERO, PQY
    ld      a, (ws_kneg)
    ld      c, a
    ld      hl, PQY
    ld      de, PF0
    ld      iy, PQY
    ld      b, FIELD_BYTES
    jp      \pfx\()_select_b            ; k even: k Q = -(k' Q)

\pfx\()_ws_lookup:
    ld      c, a
    and     a, 0x07
    ld      (ws_idx), a
    ld      a, c
    rlca
    sbc     a, a
    ld      (ws_neg), a
    ld      hl, PS1
    ld      (hl), 0
    ld      de, PS1 + 1
    ld      bc, 3*FIELD_BYTES - 1
    ldir
    ECC_WS_ENT 0, __\pfx\()_pq
    ECC_WS_ENT 1, __\pfx\()_r0
    ECC_WS_ENT 2, __\pfx\()_r1
    ECC_WS_ENT 3, __\pfx\()_add_result
    ECC_WS_ENT 4, __\pfx\()_double_result
    ECC_WS_ENT 5, \t5
    ECC_WS_ENT 6, WS_T6
    ECC_WS_ENT 7, WS_T7
    FSUB    PF0, PZERO, PS1Y
    ld      a, (ws_neg)
    ld      c, a
    ld      hl, PS1Y
    ld      de, PF0
    ld      iy, PS1Y
    ld      b, FIELD_BYTES
    jp      \pfx\()_select_b
; saved1 |= (DE) & C, 3*FIELD_BYTES bytes.
.Lwl_or:
    ld      hl, PS1
    ld      b, 3*FIELD_BYTES
.Lwl_byte:
    ld      a, (de)
    and     a, c
    or      a, (hl)
    ld      (hl), a
    inc     hl
    inc     de
    djnz    .Lwl_byte
    ret

\pfx\()_ws_add:
    FSQ     PF0, PS0Z                   ; Z1Z1
    FSQ     PF1, PS1Z                   ; Z2Z2
    FMUL    PF2, PS0X, PF1              ; U1
    FMUL    PF3, PS1X, PF0              ; U2
    FMUL    PF4, PS1Z, PF1
    FMUL    PF4, PS0Y, PF4              ; S1
    FMUL    PF5, PS0Z, PF0
    FMUL    PF5, PS1Y, PF5              ; S2
    FSUB    PF3, PF3, PF2               ; H
    FADD    PF6, PS0Z, PS1Z
    FSQ     PF6, PF6
    FSUB    PF6, PF6, PF0
    FSUB    PF6, PF6, PF1
    FMUL    PS0Z, PF6, PF3              ; Z3 = ((Z1+Z2)^2 - Z1Z1 - Z2Z2) H
    FSUB    PF5, PF5, PF4
    FADD    PF5, PF5, PF5               ; r = 2 (S2 - S1)
    FADD    PF0, PF3, PF3
    FSQ     PF0, PF0                    ; I = (2H)^2
    FMUL    PF1, PF3, PF0               ; J = H I
    FMUL    PF2, PF2, PF0               ; V = U1 I
    FSQ     PS0X, PF5
    FSUB    PS0X, PS0X, PF1
    FADD    PF6, PF2, PF2
    FSUB    PS0X, PS0X, PF6             ; X3 = r^2 - J - 2V
    FSUB    PF6, PF2, PS0X
    FMUL    PF6, PF5, PF6
    FMUL    PF4, PF4, PF1
    FADD    PF4, PF4, PF4
    FSUB    PS0Y, PF6, PF4              ; Y3 = r (V - X3) - 2 S1 J
    ret
.endm

; ===========================================================================
; ECC_COMB pfx -- constant-time fixed-base k * G (Lim-Lee comb), w = COMB_W,
; d = COMB_D, over the affine ROM table __pfx_COMB (entry j = 1..2^w-1 at
; __pfx_COMB + 2*FIELD_BYTES*(j-1) = sum over set bits s of j of 2^(d s) G,
; Montgomery form, x || y).
;
; pfx_comb_mul: out = k * G.
;   In: HL = out (3*FIELD_BYTES, may be saved0), DE = k (FIELD_BYTES
;   big-endian, < n; 0 allowed -> O).  k must not lie in f[], saved0, saved1
;   or rt.  Out: Jacobian k G (Montgomery domain; O as (0, R, 0)).
;   Uses f[0..8], saved0 (accumulator), saved1 (table point), rt.
;   Clobbers AF, BC, DE, HL, IY.  Preserves IX.
;   For i = d-1 .. 0: acc = 2 acc; acc += T[idx_i], idx_i = k3[i]<<3 |
;   k2[i]<<2 | k1[i]<<1 | k0[i] (strip s = bits s*d .. s*d+d-1 of k).
;
; pfx_comb_madd: saved0 = saved0 + saved1, constant time (comb step).
;   saved0 = acc (Jacobian; O iff cb_inf), saved1 = T (X, Y affine, Z = R).
;   madd-2007-bl (7M + 4S) into rt, always computed, then
;     rt = cb_inf ? saved1 : rt;  saved0 = cb_iz ? saved0 : rt;
;     cb_inf &= cb_iz.
;   Uses f0..f8, rt.  Clobbers AF, BC, DE, HL, IY.
;
; Constant time: the loop, the bit addresses and the table scan depend only
; on the public step index.  The secret index reaches only masks: the lookup
; reads all 15 entries every step, the mixed addition is always computed and
; its two exceptional cases are resolved by selects (acc = O -> T[idx];
; idx = 0 -> acc).  Completeness (acc != +-T[idx] when both are nonzero):
; see the proof in the p256.s comb comment history / comb_model.py.
;
; State (aliases of sm_* bytes shared with pfx_ws_mul; never concurrent):
;   cb_out = out, cb_ptr = byte of strip 0 holding bit i, cb_bit = mask of
;   bit i in that byte, cb_cnt = steps left (low byte), cb_inf / cb_iz = masks.
; ===========================================================================
.macro ECC_COMB pfx
.if COMB_W != 4
    .error "ECC_COMB: the strip-bit gather is unrolled for COMB_W = 4"
.endif
.if (COMB_D % 8) != 0 || COMB_D * COMB_W != SCALAR_BITS
    .error "ECC_COMB: COMB_D must be a multiple of 8 with COMB_D*COMB_W = SCALAR_BITS"
.endif
.equ cb_out, sm_out
.equ cb_ptr, sm_k
.equ cb_bit, sm_bit
.equ cb_cnt, sm_cnt
.equ cb_inf, sm_e0
.equ cb_iz,  sm_e1
\pfx\()_comb_mul:
    ld      (cb_out), hl
    ld      hl, FIELD_BYTES - COMB_D/8  ; bit d-1 of strip 0 (BE)
    add     hl, de
    ld      (cb_ptr), hl
    ld      a, 0x80
    ld      (cb_bit), a
    ld      a, COMB_D
    ld      (cb_cnt), a
    ld      a, 0xFF
    ld      (cb_inf), a                 ; acc = O
    ld      hl, __\pfx\()_INF
    ld      de, PS0
    ld      bc, 3*FIELD_BYTES
    ldir
    ld      hl, __\pfx\()_P_R
    ld      de, PS1Z
    ld      bc, FIELD_BYTES
    ldir                                ; table point Z = 1 (never rewritten)
    jr      .Lcb_first                  ; 2 O = O: skip the first doubling
.Lcb_loop:
    ld      hl, PS0
    call    \pfx\()_point_double        ; acc = 2 acc (out = saved0 is safe)
.Lcb_first:
; ---- idx = k3[i] k2[i] k1[i] k0[i]: strip s byte at cb_ptr - (d/8) s ----
    ld      hl, (cb_ptr)
    ld      de, -3*(COMB_D/8)
    add     hl, de                      ; strip 3
    ld      de, COMB_D/8
    ld      a, (cb_bit)
    ld      c, a
    ld      b, 0
    ld      a, (hl)
    and     a, c
    add     a, 0xFF                     ; CF = bit
    rl      b
    add     hl, de                      ; strip 2
    ld      a, (hl)
    and     a, c
    add     a, 0xFF
    rl      b
    add     hl, de                      ; strip 1
    ld      a, (hl)
    and     a, c
    add     a, 0xFF
    rl      b
    add     hl, de                      ; strip 0
    ld      a, (hl)
    and     a, c
    add     a, 0xFF
    rl      b                           ; B = idx (secret)
; ---- constant-time lookup: saved1 X||Y = idx ? T[idx] : 0 ----
    ld      a, b
    ld      iyh, a                      ; IYH = idx
    neg                                 ; CF = (idx != 0)
    sbc     a, a
    cpl
    ld      (cb_iz), a                  ; 0xFF iff idx == 0
    ld      hl, PS1
    ld      (hl), 0
    ld      de, PS1 + 1
    ld      bc, 2*FIELD_BYTES - 1
    ldir
    ld      de, __\pfx\()_COMB
    ld      iyl, 1                      ; j = 1 .. 15 (public)
.Lcb_ent:
    ld      a, iyl
    xor     a, iyh
    neg                                 ; CF = (j != idx)
    sbc     a, a
    cpl
    ld      c, a                        ; C = 0xFF iff j == idx
    ld      hl, PS1
    ld      b, 2*FIELD_BYTES
.Lcb_byte:
    ld      a, (de)
    and     a, c
    or      a, (hl)
    ld      (hl), a
    inc     hl
    inc     de
    djnz    .Lcb_byte
    inc     iyl
    ld      a, iyl
    cp      a, 1 << COMB_W
    jr      c, .Lcb_ent
    call    \pfx\()_comb_madd
; ---- next bit (public) ----
    ld      a, (cb_bit)
    rrca
    ld      (cb_bit), a
    jr      nc, .Lcb_same
    ld      hl, (cb_ptr)
    inc     hl
    ld      (cb_ptr), hl
.Lcb_same:
    ld      hl, cb_cnt
    dec     (hl)
    jp      nz, .Lcb_loop
    ld      hl, PS0
    ld      de, (cb_out)
    ld      bc, 3*FIELD_BYTES
    ldir                                ; (no-op copy when out = saved0)
    ret

\pfx\()_comb_madd:
    FSQ     PF0, PS0Z                   ; Z1Z1 = Z1^2
    FMUL    PF1, PS1X, PF0              ; U2 = x2 Z1Z1
    FMUL    PF2, PS0Z, PF0
    FMUL    PF2, PS1Y, PF2              ; S2 = y2 Z1 Z1Z1
    FSUB    PF1, PF1, PS0X              ; H = U2 - X1
    FSUB    PF2, PF2, PS0Y
    FADD    PF2, PF2, PF2               ; r = 2 (S2 - Y1)
    FSQ     PF3, PF1                    ; HH = H^2
    FADD    PF4, PF3, PF3
    FADD    PF4, PF4, PF4               ; I = 4 HH
    FMUL    PF5, PF1, PF4               ; J = H I
    FMUL    PF6, PS0X, PF4              ; V = X1 I
    FMUL    PF7, PS0Y, PF5              ; Y1 J
    FSQ     PRTX, PF2                   ; r^2
    FSUB    PRTX, PRTX, PF5
    FSUB    PRTX, PRTX, PF6
    FSUB    PRTX, PRTX, PF6             ; X3 = r^2 - J - 2V
    FSUB    PF6, PF6, PRTX
    FMUL    PF6, PF2, PF6
    FADD    PF7, PF7, PF7
    FSUB    PRTY, PF6, PF7              ; Y3 = r (V - X3) - 2 Y1 J
    FADD    PF8, PS0Z, PF1
    FSQ     PF8, PF8
    FSUB    PF8, PF8, PF0
    FSUB    PRTZ, PF8, PF3              ; Z3 = (Z1 + H)^2 - Z1Z1 - HH
    ld      a, (cb_inf)
    ld      c, a
    ld      hl, PRT
    ld      de, PS1
    ld      iy, PRT
    call    \pfx\()_point_select        ; acc = O -> T
    ld      a, (cb_iz)
    ld      c, a
    ld      hl, PRT
    ld      de, PS0
    ld      iy, PS0
    call    \pfx\()_point_select        ; idx = 0 -> keep acc
    ld      a, (cb_iz)
    ld      hl, cb_inf
    and     a, (hl)
    ld      (hl), a
    ret
.endm

; ===========================================================================
; ECC_VT_ADD pfx -- VARIABLE-TIME additions for the ECDSA-verify engine.
; PUBLIC DATA ONLY: these branch on the exceptional cases of the formulas.
;
; pfx_point_add_affine: acc += A (mixed Jacobian + affine).
;   acc = saved0 (Jacobian, Montgomery; O iff vs_inf != 0).
;   A   = saved1 X||Y (affine, Montgomery), a finite curve point.
;   madd-2007-bl, 7M + 4S.  Exceptional cases (public): acc = O -> acc = A;
;   H = 0 and S2 = Y1 (acc = A) -> doubling; H = 0 otherwise (acc = -A) -> O.
;   Uses f0..f8 (and f0..f6, rt via point_double).  Clobbers AF, BC, DE, HL,
;   IY.
;
; pfx_dbl_acc: saved0 = 2 saved0.  point_double reads saved0 only before its
;   final select (which reads rt/INF and writes out byte by byte), so
;   out = saved0 is safe.
;
; pfx_point_add_vt: acc += saved1 (Jacobian, finite).  Same acc conventions.
;   Uses the ladder variant of the Jacobian addition (11M + 5S, no
;   always-computed doubling) and handles its omitted case explicitly:
;   H = 0 and r = 0 (acc == saved1) -> doubling.  out = saved0 is safe for
;   point_add_ladder: saved0 is only read by the final select, at the same
;   byte index it writes.
; ===========================================================================
.macro ECC_VT_ADD pfx
\pfx\()_point_add_affine:
    ld      a, (vs_inf)
    or      a, a
    jr      z, .Lmd_go
    ld      hl, PS1
    ld      de, PS0
    ld      bc, 2*FIELD_BYTES
    ldir                                ; acc = (x, y, ...)
    ld      hl, __\pfx\()_P_R
    ld      c, FIELD_BYTES              ; BC = 0 after ldir
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
    call    \pfx\()_ct_is_zero
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
    call    \pfx\()_ct_is_zero
    inc     a
    jr      z, \pfx\()_dbl_acc          ; acc == A: 2 acc
.Lvt_inf:
    ld      a, 1                        ; acc == -A: O
    ld      (vs_inf), a
    ret

\pfx\()_dbl_acc:
    ld      hl, __\pfx\()_saved0
    jp      \pfx\()_point_double

\pfx\()_point_add_vt:
    ld      a, (vs_inf)
    or      a, a
    jr      z, .Lav_go
    ld      hl, PS1
    ld      de, PS0
    ld      bc, 3*FIELD_BYTES
    ldir                                ; O + T = T
    xor     a, a
    ld      (vs_inf), a
    ret
.Lav_go:
    ld      hl, __\pfx\()_saved0
    call    \pfx\()_point_add_ladder
    ld      a, (pa_h)
    or      a, a
    ret     z                           ; generic case
    ld      a, (pa_r)
    or      a, a
    jr      z, .Lvt_inf                 ; acc == -T (saved0 already O)
    ld      hl, PS1
    ld      de, PS0
    ld      bc, 3*FIELD_BYTES
    ldir                                ; acc == T: acc = 2 T
    jr      \pfx\()_dbl_acc
.endm

; ===========================================================================
; ECC_VS_TABLE_WNAF pfx -- VARIABLE-TIME verify-engine helpers (public data).
;
; pfx_vs_table: VS_T3 = 3Q, VS_T5 = 5Q, VS_T7 = 7Q (Jacobian), from pq = Q.
;   The ladder-variant addition is valid: its omitted case would need
;   Q + 2Q, 3Q + 2Q or 5Q + 2Q with equal operands, i.e. Q, 3Q or 5Q = O,
;   impossible for a validated Q (n is a large prime).
;
; pfx_vs_wnaf: width-4 NAF of u2 (__pfx_x, LE) into VS_DIG, positions
;   0..SCALAR_BITS (u2 < 2^SCALAR_BITS, so SCALAR_BITS+1 digits suffice and
;   the work value ends at 0).  Code for digit d: 0 if d = 0, else
;   |d| | (d < 0 ? 8 : 0); code i at nibble i of VS_DIG.  VS_WK is a
;   FIELD_BYTES+1 work copy of u2 (must follow VS_DIG's codes).
; ===========================================================================
.macro ECC_VS_TABLE_WNAF pfx
\pfx\()_vs_table:
    ld      hl, __\pfx\()_pq
    ld      de, PS0
    ld      bc, 3*FIELD_BYTES
    ldir
    ld      hl, PS1
    call    \pfx\()_point_double        ; saved1 = 2Q
    ld      hl, VS_T3
    call    \pfx\()_point_add_ladder    ; 3Q
    ld      hl, VS_T3
    ld      de, PS0
    ld      bc, 3*FIELD_BYTES
    ldir
    ld      hl, VS_T5
    call    \pfx\()_point_add_ladder    ; 5Q
    ld      hl, VS_T5
    ld      de, PS0
    ld      bc, 3*FIELD_BYTES
    ldir
    ld      hl, VS_T7
    jp      \pfx\()_point_add_ladder    ; 7Q

\pfx\()_vs_wnaf:
    ld      hl, VS_DIG
    ld      (hl), 0
    ld      de, VS_DIG + 1
    ld      bc, VS_WK + FIELD_BYTES - VS_DIG
    ldir                                ; codes = 0, work[FIELD_BYTES] = 0
    ld      hl, __\pfx\()_x
    ld      de, VS_WK
    ld      bc, FIELD_BYTES
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
    ld      b, FIELD_BYTES
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
    ld      hl, VS_WK + FIELD_BYTES
    ld      b, FIELD_BYTES + 1
    or      a, a
.Lwn_sh:
    rr      (hl)                        ; k >>= 1
    dec     hl
    djnz    .Lwn_sh
    ld      hl, (vs_i)
    inc     hl
    ld      (vs_i), hl
    ld      de, SCALAR_BITS + 1
    or      a, a
    sbc     hl, de
    jr      nz, .Lwn_loop
    ret
.endm

; ===========================================================================
; ECC_POINT_IMPORT pfx, nb -- pfx_point_import: validate and import an
; uncompressed SEC1 point (0x04 || x || y, 2*FIELD_BYTES+1 bytes, non-NULL)
; into pq (Montgomery-Jacobian, Z = R).
;   In: HL=pub.  Out: A = 1 ok / 0 reject.
;   Rejects: prefix != 0x04, x >= p, y >= p, point not on y^2 = x^3 - 3x + b.
;   Uses f[0..4], pi_src.  Clobbers AF, BC, DE, HL, IY.
; ===========================================================================
.macro ECC_POINT_IMPORT pfx, nb
\pfx\()_point_import:
    ld      a, (hl)
    cp      a, 0x04
    jp      nz, .Lpi_fail
    inc     hl
    ld      (pi_src), hl
    ex      de, hl
    ld      hl, PF0
    ld      iy, __\pfx\()_P
    ld      c, 0
    call    \pfx\()_import_be
    or      a, a
    jp      z, .Lpi_fail
    ld      hl, (pi_src)
    ld      de, FIELD_BYTES
    add     hl, de
    ex      de, hl
    ld      hl, PF1
    ld      iy, __\pfx\()_P
    ld      c, 0
    call    \pfx\()_import_be
    or      a, a
    jp      z, .Lpi_fail
    FMUL    PQX, PF0, __\pfx\()_P_R2
    FMUL    PQY, PF1, __\pfx\()_P_R2
    ld      hl, __\pfx\()_P_R
    ld      de, PQZ
    ld      bc, FIELD_BYTES
    ldir
    FSQ     PF2, PQY                    ; y^2
    FSQ     PF3, PQX
    FMUL    PF3, PF3, PQX               ; x^3
    FADD    PF4, PQX, PQX
    FADD    PF4, PF4, PQX               ; 3x
    FSUB    PF3, PF3, PF4
    FADD    PF3, PF3, __\pfx\()_P_B_R   ; x^3 - 3x + b
    ld      hl, PF2
    ld      de, PF3
    jp      \pfx\()_eq\nb
.Lpi_fail:
    xor     a, a
    ret
.endm

; ===========================================================================
; ECC_DI_EXIT pfx, reload -- public-entry prologue/epilogue helpers.
;
; pfx_di: zero the scratch block, save IFF1 into pfx_di_save (bit 0),
;   disable interrupts, then tail-call `reload` (the curve's fast-RAM MAC
;   block loader).  Must be called once per public entry, before any field
;   work.  The wipe establishes the mm_acc[3] = 0 invariant the accumulator
;   shift relies on and clears stale data.  ld a,i sets PV = IFF2 = IFF1
;   (outside an NMI); jp pe tests PV immediately.
;   Clobbers AF, BC, DE, HL (plus whatever `reload` clobbers).
; pfx_wipe: zero the whole scratch block.  Clobbers BC, DE, HL.
; pfx_exit: common public-API epilogue.  In: A = result.  Expects the stack
;   to hold only the caller's saved IX above the return address.  Wipes the
;   scratch, then re-enables interrupts iff they were enabled on entry.
; pfx_null: Z set iff HL == 0 (all 24 bits).  Clobbers F.  Preserves HL, DE.
; ===========================================================================
.macro ECC_DI_EXIT pfx, reload
\pfx\()_di:
    call    \pfx\()_wipe                ; zero scratch (establishes mm_acc[3] = 0)
    ld      a, i                        ; PV = IFF1
    jp      pe, .Lpd_on                 ; PV set = interrupts enabled
    xor     a, a
    ld      (\pfx\()_di_save), a        ; save 0: ei not needed on exit
    di
    jp      \reload                     ; MAC blocks -> fast RAM (interrupts off)
.Lpd_on:
    ld      a, 1
    ld      (\pfx\()_di_save), a        ; save 1: ei needed on exit
    di
    jp      \reload                     ; MAC blocks -> fast RAM (interrupts off)

\pfx\()_wipe:
    ld      hl, __\pfx\()_scratch_start
    ld      (hl), 0
    ld      de, __\pfx\()_scratch_start + 1
    ld      bc, __\pfx\()_scratch_end - __\pfx\()_scratch_start - 1
    ldir
    ret

\pfx\()_exit:
    push    af
    ld      a, (\pfx\()_di_save)        ; save before wipe zeroes it
    push    af                          ; stash di_save below result
    call    \pfx\()_wipe
    pop     af                          ; A = di_save
    bit     0, a
    jr      z, .Lpx_noei
    ei
.Lpx_noei:
    pop     af                          ; A = result
    pop     ix
    ret

\pfx\()_null:
    add     hl, de
    or      a, a
    sbc     hl, de
    ret
.endm

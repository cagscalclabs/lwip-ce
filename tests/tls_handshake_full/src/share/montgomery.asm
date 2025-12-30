;----------------------------------------------------------------------
; Montgomery multiplication (CIOS) over byte limbs, little-endian.
; void tls_mont_mul_le(uint8_t *t, const uint8_t *a, const uint8_t *b,
;                      const uint8_t *n, uint8_t n0inv, uint16_t len);
; All operands are len bytes little-endian. t is len+1 bytes workspace/result.
;----------------------------------------------------------------------

assume adl=1

section .text
public _tls_mont_mul_le
_tls_mont_mul_le:
    push ix
    ld   hl, -27                  ; locals
    call __frameset
    ; args:
    ; ix+3  t
    ; ix+6  a
    ; ix+9  b
    ; ix+12 n
    ; ix+15 n0inv
    ; ix+16 len (u16)
    ; locals:
    ; ix-3  tbase (3)
    ; ix-6  tptr  (3)
    ; ix-9  aptr  (3)
    ; ix-12 bptr  (3)
    ; ix-15 nptr  (3)
    ; ix-17 len   (2)
    ; ix-19 i     (2)
    ; ix-21 j     (2)
    ; ix-23 carry_lo (1)
    ; ix-24 carry_hi (1)
    ; ix-25 u     (1)
    ; ix-26 ai    (1)

    ; store pointers/len
    ld   hl,(ix+3)
    ld   (ix-3),hl
    ld   (ix-6),hl
    ld   hl,(ix+6)
    ld   (ix-9),hl
    ld   hl,(ix+9)
    ld   (ix-12),hl
    ld   hl,(ix+12)
    ld   (ix-15),hl
    ld   hl,(ix+16)
    ld   (ix-17),hl

    ; zero t[0..len]
    ld   bc,(ix+16)
    inc  bc
    ld   hl,(ix-6)
    xor  a,a
.zero_loop:
    ld   (hl),a
    inc  hl
    dec  bc
    ld   a,b
    or   a,c
    jr   nz,.zero_loop

    ; for i=0..len-1
    ld   bc,(ix-17)
    ld   (ix-19),bc      ; i counter
    ld   hl,(ix-9)       ; hl = aptr
.outer_loop:
    ld   a,(hl)          ; ai
    ld   (ix-26),a
    inc  hl
    ld   (ix-9),hl

    ; u = (t0 + ai*b0) * n0inv (low byte)
    ld   de,(ix-6)
    ld   a,(de)          ; t0
    ld   l,a             ; save t0 in L
    ld   de,(ix-12)
    ld   a,(de)          ; b0
    ld   h,a
    ld   e,(ix-26)       ; ai
    ld   d,h             ; d = b0, e = ai
    mlt  de              ; DE = ai*b0
    ld   a,l
    add  a,e             ; t0 + prod_low
    ld   e,a
    ld   d,(ix+15)       ; d = n0inv
    mlt  de              ; DE = u_pre * n0inv
    ld   a,e
    ld   (ix-25),a       ; u

    ; reset tptr, bptr, nptr for inner loop
    ld   hl,(ix-6)       ; tptr
    ld   de,(ix-12)      ; bptr
    ld   iy,(ix-15)      ; nptr
    xor  a,a
    ld   (ix-23),a
    ld   (ix-24),a
    ld   bc,(ix-17)
    ld   (ix-21),bc      ; j counter
.inner_loop:
    ; bj in d:e? use d for bj
    ld   a,(de)
    ld   d,a             ; d = bj
    ld   e,(ix-26)       ; e = ai
    mlt  de              ; DE = ai*bj
    ld   b,(iy)          ; b = nj
    ld   c,(ix-25)       ; c = u
    mlt  bc              ; BC = u*nj

    ld   a,(hl)          ; t[j]
    add  a,e             ; + ab_low
    adc  a,c             ; + un_low
    ld   l,(ix-23)       ; carry_lo
    adc  a,l
    ld   (hl),a

    ld   a,d             ; ab_hi
    adc  a,b             ; + un_hi + carry flag
    ld   l,(ix-24)       ; carry_hi
    adc  a,l
    ld   (ix-23),a       ; new carry_lo
    sbc  a,a
    ld   (ix-24),a       ; carry_hi

    inc  hl
    inc  de
    inc  iy
    ld   bc,(ix-21)
    dec  bc
    ld   (ix-21),bc
    ld   a,b
    or   a,c
    jr   nz,.inner_loop

    ; t[len] = carry_lo
    ld   a,(ix-23)
    ld   (hl),a

    ; advance tptr++
    ld   hl,(ix-6)
    inc  hl
    ld   (ix-6),hl

    ld   bc,(ix-19)
    dec  bc
    ld   (ix-19),bc
    ld   a,b
    or   a,c
    jp   nz,.outer_loop

    ; restore tptr to base
    ld   hl,(ix-3)
    ld   (ix-6),hl

    ; if t >= n then t -= n
    ld   bc,(ix-17)
    ld   hl,(ix-6)
    ld   de,(ix-15)
    add  hl,bc
    ex   de,hl
    add  hl,bc
    ex   de,hl
    dec  hl
    dec  de
    ld   (ix-21),bc
.cmp_loop:
    ld   a,(de)           ; n byte
    ld   b,a
    ld   a,(hl)           ; t byte
    cp   b
    jr   nz,.cmp_decide
    dec  hl
    dec  de
    ld   bc,(ix-21)
    dec  bc
    ld   (ix-21),bc
    ld   a,b
    or   a,c
    jr   nz,.cmp_loop
    jr   .do_sub           ; equal
.cmp_decide:
    jr   c,.done           ; t < n

.do_sub:
    ld   bc,(ix-17)
    ld   hl,(ix-6)
    ld   de,(ix-15)
    add  hl,bc
    ex   de,hl
    add  hl,bc
    ex   de,hl
    dec  hl
    dec  de
    ld   (ix-21),bc
    scf
.sub_loop:
    ld   a,(hl)          ; t byte
    ld   c,a
    ld   a,(de)          ; n byte
    ld   b,a
    ld   a,c
    sbc  a,b
    ld   (hl),a
    dec  hl
    dec  de
    ld   bc,(ix-21)
    dec  bc
    ld   (ix-21),bc
    ld   a,b
    or   a,c
    jr   nz,.sub_loop

.done:
    ld   sp,ix
    pop  ix
    ret

extern __frameset

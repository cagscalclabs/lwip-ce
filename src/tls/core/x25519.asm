INT_SIZE = 32
P_OFFSET = 19

; Code size: 544 bytes
; Relocation size: 1024 bytes
; Data size: 320 bytes (+ padding)
; Read only data size: 64 bytes

    assume adl=1

define ti? ti
namespace ti?
?cursorImage               := 0E30800h
end namespace

    section .text
    public _tls_x25519_secret
    public _tls_x25519_publickey

arg1 := 3
arg2 := 6
arg3 := 9
arg4 := 12
sparg1 := 6
sparg2 := 9
sparg3 := 12
sparg4 := 15
sparg5 := 18

_tls_x25519_publickey:
; Inputs:
;   arg1 = public_key
;   arg2 = private_key
;   arg3 = yield_fn
;   arg4 = yield_data
; Timing: _tls_x25519_secret + 313 cc
    ld      iy, 0
    add     iy, sp
    ld      hl, (iy + arg4)
    push    hl
    ld      hl, (iy + arg3)
    push    hl
    ld      hl, _9
    push    hl
    ld      hl, (iy + arg2)
    push    hl
    ld      hl, (iy + arg1)
    push    hl
    call    _tls_x25519_secret
    pop     hl, hl, hl, hl, hl
    ret

_tls_x25519_secret:
; Inputs:
;   arg1 = shared_secret (out)
;   arg2 = my_private (scalar)
;   arg3 = their_public (point)
;   arg4 = yield_fn
;   arg5 = yield_data
; Timing first attempt: 482,792,828 cc
; Timing current:       215,953,142 cc      ; Assuming yield_fn = NULL
tempVariables:
tempVariables.mainLoopIndex := 0                   ; Main loop index

tempVariables.size := 1

    push    ix
    ld      ix, -tempVariables.size
    add     ix, sp
    ld      sp, ix
; Relocate code to be more performant
    ld      hl, reloc.data
    ld      de, ti.cursorImage
    ld      bc, reloc.data.len
    ldir
; Copy point to actual point and edit byte 31
    ld      de, _point
    ld      hl, (ix + sparg3 + tempVariables.size)
    ld      c, INT_SIZE - 1
    ldir
    ld      a, (hl)
    and     a, 0x7F
    ld      (de), a
    inc     de
; Copy scalar to clamped, and edit byte 0 and byte 31
    ld      hl, (ix + sparg2 + tempVariables.size)
    ld      a, (hl)
    and     a, 0xF8
    ld      (de), a
    inc     hl
    inc     de
    ld      c, INT_SIZE - 2
    ldir
    ld      a, (hl)
    or      a, 0x40         ; and a, 0x7F is not necessary, as the last bit is not used at all
    add     a, a            ; Bit 7 is not used, so shift in advance
    ld      (de), a
    inc     de
; Fill _a to _d
    ld      a, 1            ; a[0] = 1
    ld      (de), a
    inc     de
    dec     a
    ld      (de), a
    inc     de              ; DE = _a + 2
    ld      c, INT_SIZE * 2 - 2 ; Clear _a and _c
    ld      hl, _a + 1
    ldir
    ld      hl, _point      ; Copy point to b
    ld      c, INT_SIZE
    ldir
    ld      hl, _a          ; _d = _a
    ld      c, INT_SIZE
    ldir
    ld      hl, _clamped + INT_SIZE - 1
    dec     b               ; b = loop index
    ld      c, 1 shl 6      ; c = bit mask
    call    mainCalculationLoop
    lea     hl, ix + tempVariables.size
    ld      sp, hl
    pop     ix
    ld      a, 1
    ret

mainCalculationLoop:
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    ;;;;;;;;;;;;;;; CHANGE THIS LOGIC TO FIT YOUR NEEDS ;;;;;;;;;;;;;;
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; A loops back from 255 to 1, so the current logic calls the yield_fn function after 128 loops (every ~2.25 seconds)
    push    bc
    sla     b
    jr      nz, .noYieldFn
    push    hl
    ld      hl, (ix + tempVariables.size + sparg4)
    add     hl, de
    or      a, a
    sbc     hl, de
    jr      z, .skipYieldFn
    ld      de, (ix + tempVariables.size + sparg5)
    push    de
    call    _jumpHL
    pop     de
.skipYieldFn:
    pop     hl
.noYieldFn:
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    ;;;;;;;;;;;;;; /CHANGE THIS LOGIC TO FIT YOUR NEEDS ;;;;;;;;;;;;;;
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

    ; Get bit
    rlc     (hl)         ; hl -> clamped pointer
    push    hl
    sbc     a, a
    ld      c, a
    push    bc
; swap _a, _b
    ld      de, _a
    ld      hl, _b
    ld      iyh, INT_SIZE / 4 * 2
    call    _swap
; fadd _e, _a, _c
    ex      de, hl              ; de -> _e
    ld      l, _a and 0xFF
    ld      bc, INT_SIZE
    ldir
    ld      e, _e and 0xFF      ; hl -> _c
    call    _faddInline
; fsub _a, _a, _c
    ld      e, _a and 0xFF
    ld      l, _c and 0xFF
    call    _fsubInline
; fadd _c, _b, _d
    ld      l, _b and 0xFF      ; de -> _c
    ld      c, INT_SIZE
    ldir
    ld      e, _c and 0xFF      ; hl -> _d
    call    _faddInline
; fsub _b, _b, _d
    ld      l, _d and 0xFF      ; de -> _b
    call    _fsubInline
; fsquare _d, _e
    ld      iy, _e              ; de -> _d
    call    _fmul.iy
; fsquare _f, _a
    ld      e, _f and 0xFF
    ld      iy, _a
    call    _fmul.iy
; fmul _a, _c, _a
    ld      iy, _c
    ld      e, _a and 0xFF
    ld      l, e
    call    _fmul.hl
; fmul _c, _b, _e
    ld      iy, _b
    ld      e, _c and 0xFF
    ld      l, _e and 0xFF
    call    _fmul.hl
; fadd _e, _a, _c
    ld      e, _e and 0xFF
    ld      l, _a and 0xFF
    ld      c, INT_SIZE
    ldir
    ld      e, _e and 0xFF      ; hl -> _c
    call    _faddInline
; fsub _a, _a, _c
    ld      e, _a and 0xFF
    ld      l, _c and 0xFF
    call    _fsubInline
; fsquare _b, _a
    ld      iy, _a
    ld      e, _b and 0xFF
    call    _fmul.iy
; copy _d, _c
    ld      e, _c and 0xFF
    inc     hl                  ; hl -> _d
    ld      c, INT_SIZE
    ldir
; fsub _c, _c, _f
    ld      e, _c and 0xFF
    ld      l, _f and 0xFF
    call    _fsubInline
; fmul _a, _c, _121665
    ld      iy, _c
    ld      e, _a and 0xFF
    ld      hl, _121665
    call    _fmul.hl
; fadd _a, _a, _d
    ld      e, _a and 0xFF
    ld      l, _d and 0xFF
    call    _faddInline
; fmul _c, _c, _a
    ld      iy, _c              ; de -> _c
    ld      l, _a and 0xFF
    call    _fmul.hl
; fmul _a, _d, _f
    ld      iy, _d
    ld      e, _a and 0xFF
    ld      l, _f and 0xFF
    call    _fmul.hl
; fmul _d, _b, _point
    ld      iy, _b
    ld      e, _d and 0xFF
    ld      hl, _point
    call    _fmul.hl
; fsquare _b, _e
    ld      iy, _e
    ld      e, _b and 0xFF
    call    _fmul.iy
; swap _a, _b
    pop     bc
    ld      e, _a and 0xFF
    ld      l, _b and 0xFF
    ld      iyh, INT_SIZE / 4 * 2
    call    _swap

; Get to the next bit
    pop     de              ; de -> clamped pointer
    pop     bc              ; b -> loop index, c -> mask
    rrc     c               ; loop through the bit mask
    sbc     hl, hl
    add     hl, de          ; hl -> clamped pointer, decremented if the carry flag was set
    dec     b
    jq      nz, mainCalculationLoop

; Copy _c to _b
    inc     d
    ld      e, _b and 0xFF
    inc     h
    ld      l, _c and 0xFF
    ld      c, INT_SIZE
    ldir

; Inverse _c
    ld      (ix + tempVariables.mainLoopIndex), 254
.inverseLoop:
; fsquare _c, _c
    ld      iy, _c
    ld      e, _c and 0xFF
    call    _fmul.iy
    ld      a, (ix + tempVariables.mainLoopIndex)
    cp      a, 3
    jr      z, .continue2
    cp      a, 5
    jr      z, .continue2
; fmul _c, _c, _b
    ld      iy, _c
    ld      e, _c and 0xFF
    ld      l, _b and 0xFF
    call    _fmul.hl
.continue2:
    dec     (ix + tempVariables.mainLoopIndex)
    jr      nz, .inverseLoop

; Final multiplication, putting the result in out
; fmul (ix + sparg1 + tempVariables.size), _a, _c
    ld      de, (ix + sparg1 + tempVariables.size)
    ld      iy, _a
    ld      l, _c and 0xFF
    call    _fmul.hl
; Out is now in the range [0, 2^256), which is slightly more than 2p. Subtract p and swap if necessary. Repeat this step
; to account for the possible output in the range of [2p, 2^256).
    call    .normalizeModP
.normalizeModP:
    ld      hl, (ix + sparg1 + tempVariables.size)
; Perform the pack to calculate mod p instead of mod 2p
    ld      de, _product
; Subtract p from out and store to _product
    ld      a, (hl)
    sub     a, -P_OFFSET
    ld      (de), a
    ld      b, INT_SIZE - 2
    ld      c, -1
.subtractLoop:
; TODO: you can decide to unroll this loop a few times to have a small speed increase. However, that will only save ~800cc, while you add 150 bytes.
    inc     de
    inc     hl
    ld      a, (hl)
    sbc     a, c
    ld      (de), a
    djnz    .subtractLoop
    inc     de              ; Same as within the loop, but now 7F to not subtract the last bit
    inc     hl
    ld      a, (hl)
    sbc     a, 0x7F
    ld      (de), a
    ccf                     ; If the carry flag WAS set, out < p, so no swap needed. Flip the carry flag and call the swap
    sbc     a, a
    ld      bc, -INT_SIZE + 1
    add     hl, bc
    ex      de, hl
    add     hl, bc
    ld      c, a
    ld      iyh, INT_SIZE / 4
    jp      _swap

_jumpHL:
    jp      (hl)

virtual at ti.cursorImage
_swap:
; Eventually swaps 2 big integers based on the carry flag. Performs the swap in constant time to prevent timing attacks
; Inputs:
;    C = swap ? 0xFF : 0
;   DE = a
;   HL = b
;  IYH = loop count / 4
; Outputs:
;  BCU = ?
;    B = ?
;    C = swap ? 0xFF : 0
;   DE = a + INT_SIZE (+ INT_SIZE)
;   HL = b + INT_SIZE (+ INT_SIZE)

.swapLoop:
repeat 4
    ld      a, (de)         ; t = c & (a[i] ^ b[i])
    xor     a, (hl)
    and     a, c
    ld      b, a
    xor     a, (hl)         ; b[i] ^= t
    ld      (hl), a
    ld      a, (de)         ; a[i] ^= t
    xor     a, b
    ld      (de), a
    inc     hl
    inc     de
end repeat
    dec     iyh
    jr      nz, .swapLoop
    ret

_fmul:
; Performs a multiplication between two big integers, and returns the result in mod 2p. The pseudocode for multiplying
; looks like this:
;  - Reset first 32 bytes of product outcome to zeroes
;  - For each byte in input a, multiply the value with the entirety of b, and add to the product output at the correct offset.
;  - Now product is a 64-byte value, i.e.:
;      product = t_0 * 2^0 + t_1 * 2^8 + ... + t_31 * 2^248 + t_32 * 2^256 + t_33 * 2^264 + ... + t_63 * 2^504
;              = t_0 * 2^0 + t_1 * 2^8 + ... + t_31 * 2^248 + t_32 * 2^0 * (2p + 38) + t_33 * 2^1 * (2p + 38) + ... + t_63 * 2^248 * (2p + 38)
;              = t_0 * 2^0 + t_1 * 2^8 + ... + t_31 * 2^248 + t_32 * 38 * 2^0 + t_33 * 38 * 2^1 + ... + t_63 * 38 * 2^248 (mod 2p)
;              = (t_0 + 38 * t_32) * 2^0 + ... + (t_30 + 38 * t_62) * 2^240 + (t_31 + 38 * t_63) * 2^248 (mod 2p)
;    That means that for each index in the lower 32 bytes, we can add 38*product[index + 32] and the result becomes mod 2p.
;  - Calculate 38 times each byte in the second half of the product, and add it to the first half of the product output.
;  - The last byte from the intermediate result (the carry) will be propagated back, namely 38 * (value of last byte) will
;    be added to the first byte again. This can again trigger an overflow, so propagate the carry even further.
;  - The first 32 bytes of product now contains the output mod 2p, and will be copied to the out variable.
; Inputs:
;    B = 0
;   DE = out
;   IY = a mod 2p
;   HL = b mod 2p
; Outputs:
;   BC = 0
;   DE = _product + INT_SIZE * 2 - 1
;   HL = out + INT_SIZE - 1
.iy:
    db      0xFD            ; ld hl, * -> ld iy, *
.hl:
; Copy the input variable to the temporary storage
    ld      (_fmul.mulArg2SMC), hl
    push    de
; Setup the product output
    ld      hl, _product
    ld      c, INT_SIZE - 1
    ld      (hl), b
    ld      de, _product + 1
    ldir
; Also setup the other variables
    lea     hl, iy
    ld      e, _product and 0xFF
; Within a loop, get a single byte from a, and multiply it with the entirety of b, adding it to the product immediately
.mainLoop:
    ld      b, (hl)         ; de -> output pointer, hl -> a + index, b -> a[index]
    inc     hl
    push    hl
    ld      iyh, b
.mulArg2SMC = $+1
    ld      hl, 0
; First iteration
    ld      c, (hl)
    mlt     bc
    ld      a, (de)         ; Add c to (de)
    add     a, c
    ld      (de), a
    ld      a, b
    inc     de
    inc     hl
; Other iterations
repeat INT_SIZE - 1
    ld      c, (hl)
    ld      b, iyh
    mlt     bc
    adc     a, c
    ld      c, a            ; Temporarily save a
    adc     a, b            ; b + cf -> b
    sub     a, c
    ld      b, a
    ld      a, (de)         ; Restore a and add to (de)
    add     a, c
    ld      (de), a
    ld      a, b
    inc     de
if % <> %%
    inc     hl
end if
end repeat
; Add the last carry byte to the product. Since we work from low to high indexes, this last carry byte is guaranteed to
; not overlap with the previous product result, thus storing it directly works properly.
    adc     a, 0
    ld      (de), a
; Continue with the main loop
    ld      a, -INT_SIZE + 1
    add     a, e
    ld      e, a
    pop     hl
    sub     a, (_product + INT_SIZE) and 0xFF
    jp      nz, .mainLoop

; For the lower 32 bytes of the product, calculate sum(38 * product[i + 32]) and add to product + 32 directly
    ex      de, hl          ; hl -> _product + INT_SIZE
    ld      de, _product
.addMul38Loop:
repeat 8
    ld      c, (hl)
    ld      b, 2 * P_OFFSET
    mlt     bc
    adc     a, c
    ld      c, a            ; Temporarily save a
    adc     a, b            ; b + cf -> b
    sub     a, c
    ld      b, a
    ld      a, (de)         ; Restore a and add (de) to (hl)
    add     a, c
    ld      (hl), a
    inc     de
    ld      a, b
if % <> %%
    inc     hl
end if
end repeat
    inc     l               ; l = 0 -> stop, since then it's _product + INT_SIZE * 2 = XXXX00
    jp      nz, .addMul38Loop

; Propagate the last carry byte back to the first value and store to out directly
    adc     a, l
    ld      c, a
    ld      b, 2 * P_OFFSET
    mlt     bc
    pop     hl              ; hl -> out, de -> _product + INT_SIZE
    ld      a, (de)
    add     a, c
    ld      (hl), a
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, b
    ld      (hl), a
    ld      c, 0
    ld      b, (INT_SIZE - 2) / 15
.addLoop:
repeat 15
    inc     hl
    inc     de
    ld      a, (de)
    adc     a, c
    ld      (hl), a
end repeat
    djnz    .addLoop
    ret

_faddInline:
; Performs an inline addition between two big integers mod 2p, and returns the result in the first num with mod 2p.
; Inputs:
;   cf = reset
;   DE = out, a mod 2p
;   HL = b mod 2p
; Outputs:
;  BCU = untouched
;    B = 0
;    C = 0
;   DE = out + INT_SIZE
;   HL = out + INT_SIZE - 1

    ld      b, INT_SIZE / 8
.addLoop1:
repeat 8
    ld      a, (de)         ; out[i] = a[i] + b[i] + carry
    adc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
end repeat
    djnz    .addLoop1
    sbc     a, a
    and     a, 2 * P_OFFSET ; a -> cf ? 38 : 0
    ld      hl, -INT_SIZE
    add     hl, de          ; hl -> out
    add     a, (hl)
    ld      (hl), a
    ld      c, b
    ld      b, (INT_SIZE - 2) / 10
.addLoop2:
repeat 10
    inc     hl
    ld      a, (hl)
    adc     a, c
    ld      (hl), a
end repeat
    djnz    .addLoop2
    inc     hl
    ld      a, (hl)
    adc     a, c
    ld      (hl), a
    ret

_fsubInline:
; Performs an inline subtraction between two big integers mod 2p, and returns the result in the first num in mod 2p again.
; Inputs:
;   cf = reset
;   DE = out, a mod 2p
;   HL = b mod 2p
; Outputs:
;  BCU = untouched
;    B = 0
;    C = 0
;   DE = out + INT_SIZE
;   HL = out + INT_SIZE - 1

    ld      b, INT_SIZE / 8
.subLoop1:
repeat 8
    ld      a, (de)         ; out[i] = a[i] - b[i] - carry
    sbc     a, (hl)
    ld      (de), a
    inc     hl
    inc     de
end repeat
    djnz    .subLoop1

; Now out is in the range (-2^255+19, 2^255-19). If the carry flag is set, the value is "negative", but we can easily
; calculate a mod 2p by subtracting 38 from the entire value, such that the output is always [0, 2p).
    sbc     a, a
    and     a, 2 * P_OFFSET ; a -> cf ? 38 : 0
    ld      hl, -INT_SIZE
    add     hl, de          ; hl -> out
    ld      c, a
    ld      a, (hl)
    sub     a, c
    ld      (hl), a
    ld      c, b
    ld      b, (INT_SIZE - 2) / 5
.subLoop2:
repeat 5
    inc     hl
    ld      a, (hl)
    sbc     a, c
    ld      (hl), a
end repeat
    djnz    .subLoop2
    inc     hl
    ld      a, (hl)
    sbc     a, c
    ld      (hl), a
    ret

    private	reloc_rodata
load reloc_rodata: $-$$ from $$
end virtual


repeat 1, x:$-_tls_x25519_publickey
    display 'Code size: ', `x, ' bytes', 10
end repeat

repeat 1, x:reloc.data.len
    display 'Relocation size: ', `x, ' bytes', 10
end repeat

    section	.data
    private	reloc.data
    private	reloc.data.len
reloc.data:
    db	reloc_rodata
.len := $-.
reloc.base := ti.cursorImage
reloc.offset := reloc.base - reloc.data

    section .data
    private _point
    private _clamped
    private _a
    private _b
    private _c
    private _d
    private _e
    private _f
    private _product

; Align _a to 0xXXXX00
    db      ((0xC0 - (($ and 0xFF))) and 0xFF) dup 0
; Duplicate of the input point, but with msb reset
_point:
    rb      INT_SIZE
; Used for scalar
_clamped:
    rb      INT_SIZE
_a:
    rb      INT_SIZE
_c:
    rb      INT_SIZE
_b:
    rb      INT_SIZE
_d:
    rb      INT_SIZE
_e:
    rb      INT_SIZE
_f:
    rb      INT_SIZE
; Used for multiplication
_product:
    rb      INT_SIZE * 2


repeat 1, x:$-_point
    display 'Data size: ', `x, ' bytes', 10
end repeat


    section .rodata
    private _9
    private _121665

_9:
    db      0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00

_121665:
    db      0x41, 0xDB, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00
    db      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00


repeat 1, x:$-_9
    display 'Read only data size: ', `x, ' bytes', 10
end repeat

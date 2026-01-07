
assume adl=1

section .text
public u64_addi
; add unsigned 24-bit BC to the 64-bit integer pointed to by IY
; destroys AF, DE, HL
u64_addi:
	xor a,a
	sbc hl,hl
	ex de,hl
	ld hl,(iy)
	add hl,bc
	ld (iy),hl
	ld hl,(iy+3)
	adc hl,de
	ld (iy+3),hl
	lea hl,iy+6
	adc a,(hl)
	ld (hl),a
	inc hl
	ld a,(hl)
	adc a,e
	ld (hl),a
	ret

section .text
public _gf128_mul
_gf128_mul:
; Galois-Field GF(2^128) multiplication routine
; little endian fields expected
	ld hl, -16
	call __frameset
	lea de, ix - 16		; stack mem?
	ld hl, (ix + 6)		; op1 (save a copy)
	ld bc, 16
	ldir				; ix - 32 = tmp = op1
 
	; zero out output
	ld de, (ix + 12)		; output
	xor a
	ld (de), a
	inc de
	ld hl, (ix + 12)
	ld bc, 15
	ldir
 
	ld hl, (ix + 9)		; op2 = for bit in bits
	ld b, 0
	ld c, 16
.loop_op2:
	ld a, (hl)
	push hl
		ld b, 8
.loop_bits_in_byte:
		rla
		push af
			sbc a,a
			push bc
				ld c,a
 
				; add out (res) + tmp
				ld hl, (ix + 12)		; hl = (dest)
				lea de, ix - 16		; de = tmp (src)
				ld b, 16
.loop_add:
				ld a, (de)
				and a, c
				xor a, (hl)
				ld (hl), a
				inc hl
				inc de
				djnz .loop_add
 
			; now double tmp
				lea hl, ix - 16		; tmp in hl	little endian
			 ld b, 16
			 or a                ; reset carry
.loop_mul2:
			 rr (hl)
			 inc hl		; little endian
			 djnz .loop_mul2
 
			 ; now xor with polynomial x^128 + x^7 + x^2 + x + 1
			 ; if bit 128 set, xor least-significant byte with 10000111b
 
			 sbc a, a
			 and a, 11100001b
			 xor a, (ix - 16)		; little endian
			 ld (ix - 16), a
 
.no_xor_poly:
			pop bc
		pop af
		djnz .loop_bits_in_byte
	pop hl
	inc hl		; little endian
	dec c
	jr nz, .loop_op2
	ld sp, ix
	pop ix
	ret

extern __frameset


section .text
public _powmod_exp_u24

;void powmod_exp_u24(uint8_t size, uint8_t *restrict base, uint24_t exp, const uint8_t *restrict mod);
_powmod_exp_u24:
   push   ix
   ld   ix, 0
   lea   bc, ix
   add   ix, sp
.ret  := ix    + long
.size := .ret  + long
.base := .size + long
.exp  := .base + long
.mod  := .exp  + long
.acc  := ix    - long
.tmp  := .acc  - long
.end  := .tmp  - byte
   ld   c, (.size)
   dec   c
   ld   hl, .end - ix
   add   hl, sp
   push   hl
;   scf
   sbc   hl, bc
   push   hl
;   or   a, a
   sbc   hl, bc
   ld   sp, hl
   ld   hl, (.mod)
   add   hl, bc
   ld   (.mod), hl
   ld   b, bsr 8
   ld   e, b
;   ld   e, 1
.nmi.loop:
   ld   a, e
   ld   d, (hl)
   mlt   de
   inc   de
   inc   de
   ld   d, a
   mlt   de
   djnz   .nmi.loop ; leaks size
   ld   a, e
   ld   (.nmi), a
   ld   hl, (.base)
   add   hl, bc
   ld   (.base), hl
   ld   c, 8
.mod.outer:
   ld   b, (.size)
.mod.inner:
   push   bc, hl
   ld   b, (.size)
;   or   a, a
.shift:
   rl   (hl)
   dec   hl
   djnz   .shift ; leaks size
   pop   hl
   push   hl
   call   .reduce
   pop   hl, bc
   djnz   .mod.inner ; leaks size
   dec   c
   jq   nz, .mod.outer ; leaks constant
   ld   c, (.size)
   dec   c
   inc   bc
   ld   de, (.acc)
   lddr ; leaks size
   ld   hl, (.exp)
   scf
.normalize:
   adc   hl, hl
   jq   nc, .normalize ; leaks exp
   xor   a, a
.loop:
   push   hl, af
   ld   hl, (.acc)
   call   nz, .mul ; leaks exp
   pop   af
   ld   hl, (.base)
   call   c, .mul ; leaks exp
   pop   hl
;   or   a, a
   adc   hl, hl
   jq   nz, .loop ; leaks exp
   ld   de, (.tmp)
   add   hl, de
   dec   de
;   ld   bc, 0
   ld   c, (.size)
   dec   c
   ld   (hl), b
   push   hl
   lddr ; leaks size
   pop   hl
   inc   (hl)
   ld   iy, (.base)
   call   .mul.alt
   ld   sp, ix
   pop   ix
   ret
   ; vi(acc) = vi(acc) * vi(hl) % vi(mod)
   ; assumes bc = 0
   ; destroys vi(tmp)
   ; returns bc = 0, cf = 0
.mul:
   ld   iy, (.tmp)
.mul.alt:
   push   hl
   lea   hl, iy - 0
   lea   de, iy - 1
   ld   c, (.size)
   dec   c
   ld   (hl), b
   lddr ; leaks size
   ld   de, (.acc)
   ld   (.acc), iy
   ld   (.tmp), de
   pop   hl
   ld   c, (.size)
   or   a, a
.mul.outer:
   ld   a, (de)
   ld   (.cur), a
   dec   de
   push   de, hl, ix, iy, af
   ld   e, (hl)
   ld   d, a
   mlt   de
   push   hl
   ld   l, (iy)
   ld   h, 0
   add   hl, de
   ld   e, l
   ld   d, 0
.nmi := $ - byte
   mlt   de
   ld   a, e
   ld   (.adj), a
   ld   b, (.size)
   dec   b
   ld   ix, (.mod)
   ld   d, (ix)
   mlt   de
   add.s   hl, de
   ld   e, h
   ld   d, l
;   ld   d, 0
   rl   d
   pop   hl
.mul.inner:
   dec   hl
   push   hl
   ld   l, (hl)
   ld   h, 0
.cur := $ - byte
   mlt   hl
   adc   hl, de
   dec   ix
   ld   e, (ix)
   ld   d, 0
.adj := $ - byte
   mlt   de
   add.s   hl, de
   ld   e, h
   ld   d, 0
   rl   d
   ld   a, l
   dec   iy
   add   a, (iy)
   ld   (iy + 1), a
   pop   hl
   djnz   .mul.inner ; leaks size
   ld   l, b
   rl   l
   ld   h, b
   pop   af
   adc   hl, de
   ld   (iy + 0), l
   sra   h
   pop   iy, ix, hl, de
   dec   c
   jq   nz, .mul.outer ; leaks size
   lea   hl, iy
   ; if (cf:vi(hl) >= vi(mod)) cf:vi(hl) -= vi(mod)
   ; assumes bcu = 0
   ; destroys vi(tmp)
   ; returns bc = 0, cf = 0
.reduce:
   ccf
   sbc   a, a
   ld   c, a
   ld   b, (.size)
   ld   de, (.tmp)
   ld   iy, (.mod)
   or   a, a
   push   hl, de
.reduce.sub:
   ld   a, (hl)
   dec   hl
   sbc   a, (iy)
   dec   iy
   ld   (de), a
   dec   de
   djnz   .reduce.sub ; leaks size
   sbc   a, a
   and   a, c
   and   a, long
   sbc   hl, hl
   ld   l, a
   add   hl, sp
   ld   hl, (hl)
   pop   de, de
   ld   c, (.size)
   dec   c
   inc   bc
   lddr ; leaks size, assuming that base and stack are in normal ram
   ret


;section .text
;public _powmod_exp_u4096

;void powmod(uint8_t size, uint8_t *restrict base, uint24_t exp, const uint8_t *restrict mod);
;_powmod_exp_u4096

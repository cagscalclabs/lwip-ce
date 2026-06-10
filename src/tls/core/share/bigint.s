
.assume adl=1

.section	.text,"ax",@progbits
globl u64_addi
.type	u64_addi,@function

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

.section	.text,"ax",@progbits
globl _gf128_mul
.type	_gf128_mul,@function

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
.Lloop_op2:
	ld a, (hl)
	push hl
		ld b, 8
.Lloop_bits_in_byte:
		rla
		push af
			sbc a,a
			push bc
				ld c,a
 
				; add out (res) + tmp
				ld hl, (ix + 12)		; hl = (dest)
				lea de, ix - 16		; de = tmp (src)
				ld b, 16
.Lloop_add:
				ld a, (de)
				and a, c
				xor a, (hl)
				ld (hl), a
				inc hl
				inc de
				djnz .Lloop_add
 
			; now double tmp
				lea hl, ix - 16		; tmp in hl	little endian
			 ld b, 16
			 or a                ; reset carry
.Lloop_mul2:
			 rr (hl)
			 inc hl		; little endian
			 djnz .Lloop_mul2
 
			 ; now xor with polynomial x^128 + x^7 + x^2 + x + 1
			 ; if bit 128 set, xor least-significant byte with 10000111b
 
			 sbc a, a
			 and a, 0b11100001
			 xor a, (ix - 16)		; little endian
			 ld (ix - 16), a
 
.Lno_xor_poly:
			pop bc
		pop af
		djnz .Lloop_bits_in_byte
	pop hl
	inc hl		; little endian
	dec c
	jr nz, .Lloop_op2
	ld sp, ix
	pop ix
	ret

extern __frameset


.section	.text,"ax",@progbits
globl _powmod_exp_u24
.type _powmod_exp_u24,@function

; ---------------------------------------------------------------------------
; powmod_exp_u24 must run from writable RAM: its inner loop self-modifies
; three instruction operands (.Lnmi/.Lcur/.Ladj below). In the resident lwIP
; flash app, .text is read-only flash, so running in place faults. Mirror the
; X25519 approach: the real routine lives in the .powmod.reloc section (placed
; by the linker at the 0xE30800 safe-RAM overlay VMA, with a load image in
; prgm); this public trampoline copies it to that RAM address and JUMPS to it.
;
; We `jp`, not `call`: the relocated body reads its args as (ix + offset) after
; `push ix / add ix,sp`, relative to THIS call's return address + pushed args.
; A `call` would push an extra return address and shift every arg offset by 3.
; The safe-RAM window is shared (sequentially, never co-resident) with X25519
; and the RNG scratch — see linker_script_lwip.ld.
;void powmod_exp_u24(uint8_t size, uint8_t *restrict base, uint24_t exp, const uint8_t *restrict mod);

; __tls_scratch / __tls_scratch_end are defined in share/memory.s (assembled
; as its own translation unit). Reference them as externals here — do NOT
; .include memory.s, or its .space reservations get defined twice (here and
; in memory.s.o) and the link fails with "multiple definition".

_powmod_exp_u24:
   ld   hl, _powmod_reloc_load_start
   ld   de, _powmod_reloc_run_start
   ld   bc, _powmod_reloc_len
   ldir
   jp   _powmod_reloc_run_start

.section	.powmod.reloc,"ax",@progbits

extern __tls_scratch
extern __tls_scratch_end

_powmod_reloc_run_start:
_powmod_exp_u24_impl:
   push   ix
   ld   ix, 0
   lea   bc, ix + 0
   add   ix, sp
   .equ   Lret,  3
   .equ   Lsize, Lret  + 3
   .equ   Lbase, Lsize + 3
   .equ   Lexp,  Lbase + 3
   .equ   Lmod,  Lexp  + 3
   .equ   Lacc,  -3
   .equ   Ltmp,  Lacc  - 3
   .equ   Lend,  Ltmp  - 1
   ld   c, (ix + Lsize)
   dec   c
   ld   hl, __tls_scratch_end - 1
   ld (ix + Lacc), hl
   or a, a
   sbc   hl, bc
   ld (ix + Ltmp), hl
   lea hl, ix + Lend
   ld sp, hl
   ld   hl, (ix + Lmod)
   add   hl, bc
   ld   (ix + Lmod), hl
   ld   b, 3
   ld   e, b
;   ld   e, 1
.Lnmi_loop:
   ld   a, e
   ld   d, (hl)
   mlt   de
   inc   de
   inc   de
   ld   d, a
   mlt   de
   djnz   .Lnmi_loop ; leaks size
   ld   a, e
   ld   (.Lnmi), a
   ld   hl, (ix + Lbase)
   add   hl, bc
   ld   (ix + Lbase), hl
   ld   c, 8
.Lmod_outer:
   ld   b, (ix + Lsize)
.Lmod_inner:
   push   bc
   push  hl
   ld   b, (ix + Lsize)
;   or   a, a
.Lshift:
   rl   (hl)
   dec   hl
   djnz   .Lshift ; leaks size
   pop   hl
   push   hl
   call   .Lreduce
   pop   hl
   pop   bc
   djnz   .Lmod_inner ; leaks size
   dec   c
   jp   nz, .Lmod_outer ; leaks constant
   ld   c, (ix + Lsize)
   dec   c
   inc   bc
   ld   de, (ix + Lacc)
   lddr ; leaks size
   ld   hl, (ix + Lexp)
   scf
.Lnormalize:
   adc   hl, hl
   jp   nc, .Lnormalize ; leaks exp
   xor   a, a
.Lloop:
   push   hl
   push  af
   ld   hl, (ix + Lacc)
   call   nz, .Lmul ; leaks exp
   pop   af
   ld   hl, (ix + Lbase)
   call   c, .Lmul ; leaks exp
   pop   hl
;   or   a, a
   adc   hl, hl
   jp   nz, .Lloop ; leaks exp
   ld   de, (ix + Ltmp)
   add   hl, de
   dec   de
;   ld   bc, 0
   ld   c, (ix + Lsize)
   dec   c
   ld   (hl), b
   push   hl
   lddr ; leaks size
   pop   hl
   inc   (hl)
   ld   iy, (ix + Lbase)
   call   .Lmul_alt
   ld   sp, ix
   pop   ix
   ret
   ; vi(acc) = vi(acc) * vi(hl) % vi(mod)
   ; assumes bc = 0
   ; destroys vi(tmp)
   ; returns bc = 0, cf = 0
.Lmul:
   ld   iy, (ix + Ltmp)
.Lmul_alt:
   push   hl
   lea   hl, iy - 0
   lea   de, iy - 1
   ld   c, (ix + Lsize)
   dec   c
   ld   (hl), b
   lddr ; leaks size
   ld   de, (ix + Lacc)
   ld   (ix + Lacc), iy
   ld   (ix + Ltmp), de
   pop   hl
   ld   c, (ix + Lsize)
   or   a, a
.Lmul_outer:
   ld   a, (de)
   ld   (.Lcur), a
   dec   de
   push   de
   push  hl
   push  ix
   push  iy
   push  af
   ld   e, (hl)
   ld   d, a
   mlt   de
   push   hl
   ld   l, (iy)
   ld   h, 0
   add   hl, de
   ld   e, l
   ld   d, 0
.Lnmi = . - 1
   mlt   de
   ld   a, e
   ld   (.Ladj), a
   ld   b, (ix + Lsize)
   dec   b
   ld   ix, (ix + Lmod)
   ld   d, (ix)
   mlt   de
   add.s   hl, de
   ld   e, h
   ld   d, l
;   ld   d, 0
   rl   d
   pop   hl
.Lmul_inner:
   dec   hl
   push   hl
   ld   l, (hl)
   ld   h, 0
.Lcur = . - 1
   mlt   hl
   adc   hl, de
   dec   ix
   ld   e, (ix)
   ld   d, 0
.Ladj = . - 1
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
   djnz   .Lmul_inner ; leaks size
   ld   l, b
   rl   l
   ld   h, b
   pop   af
   adc   hl, de
   ld   (iy + 0), l
   sra   h
   pop   iy
   pop   ix
   pop   hl
   pop   de
   dec   c
   jp   nz, .Lmul_outer ; leaks size
   lea   hl, iy + 0
   ; if (cf:vi(hl) >= vi(mod)) cf:vi(hl) -= vi(mod)
   ; assumes bcu = 0
   ; destroys vi(tmp)
   ; returns bc = 0, cf = 0
.Lreduce:
   ccf
   sbc   a, a
   ld   c, a
   ld   b, (ix + Lsize)
   ld   de, (ix + Ltmp)
   ld   iy, (ix + Lmod)
   or   a, a
   push   hl
   push  de
.Lreduce_sub:
   ld   a, (hl)
   dec   hl
   sbc   a, (iy)
   dec   iy
   ld   (de), a
   dec   de
   djnz   .Lreduce_sub ; leaks size
   sbc   a, a
   and   a, c
   and   a, 3
   sbc   hl, hl
   ld   l, a
   add   hl, sp
   ld   hl, (hl)
   pop   de
   pop   de
   ld   c, (ix + Lsize)
   dec   c
   inc   bc
   lddr ; leaks size, assuming that base and stack are in normal ram
   ret
_powmod_reloc_run_end:

.section	.text,"ax",@progbits

;section .text
;public _powmod_exp_u4096

;void powmod(uint8_t size, uint8_t *restrict base, uint24_t exp, const uint8_t *restrict mod);
;_powmod_exp_u4096


.section	.note.GNU-stack,"",@progbits

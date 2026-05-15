
.assume adl=1

.section	.text,"ax",@progbits
globl _indcallhl
.type _indcallhl,@function

;-------------------------
; call hl
_indcallhl:
; Calls HL
; Inputs:
;  HL : Address to call
	jp	(hl)

.section	.text,"ax",@progbits
globl _rmemcpy
.type _rmemcpy,@function
;-------------------------
; rmemcpy(void *dest, void *src, size_t len)
_rmemcpy:
; optimized by calc84maniac
	ld  iy, -3
	add iy, sp
	ld  bc, (iy + 12)
	sbc hl, hl
	add hl, bc
	ret nc
	ld  de, (iy + 9)
	add hl, de
	ld  de, (iy + 6)
.Lrmemcpy_loop:
	ldi
	ret po
	dec hl
	dec hl
	jr  .Lrmemcpy_loop
	
.section	.text,"ax",@progbits
globl _memrev
.type _memrev,@function
;-------------------------
; memrev(void *data, size_t len)
_memrev:
	pop hl
	pop de
	pop bc
	push bc
	push de
	push de
	ex (sp), hl
	add hl, bc
	set 0, c
	cpd
.Lmemrev_loop:
	ret po
	ld a, (de)
	dec bc
	ldi
	dec hl
	ld (hl), a
	dec hl
	jr .Lmemrev_loop

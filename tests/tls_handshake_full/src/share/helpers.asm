
assume adl=1


section .text
public _indcallhl
;-------------------------
; call hl
_indcallhl:
; Calls HL
; Inputs:
;  HL : Address to call
	jp	(hl)

section .text
public _rmemcpy
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
.loop:
	ldi
	ret po
	dec hl
	dec hl
	jr  .loop
	
section .text
public _memrev
;-------------------------
; memrev(void *data, size_t len)
_memrev:
	pop hl, de, bc
	push bc, de, de
	ex (sp), hl
	add hl, bc
	set 0, c
	cpd
.loop:
	ret po
	ld a, (de)
	dec bc
	ldi
	dec hl
	ld (hl), a
	dec hl
	jr .loop

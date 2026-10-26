; Constant-time byte primitives.
.assume adl=1

.section	.text,"ax",@progbits
globl _tls_bytes_compare
.type _tls_bytes_compare,@function

_tls_bytes_compare:
	pop	iy
	pop de
	pop hl
	pop bc
	push bc
	push hl
	push de
	push iy
	xor	a, a
.Lloop:
	ld	iyl, a
	ld	a, (de)
	inc	de
	xor	a, (hl)
	or	a, iyl
	cpi
	jp	pe, .Lloop
	add	a, -1
	sbc	a, a
	inc	a
	ret

.section	.text,"ax",@progbits
globl _tls_secure_memzero
.type _tls_secure_memzero,@function

_tls_secure_memzero:
	pop	hl
	pop	de
	pop	bc
	push	bc
	push	de
	push	hl
	scf
	sbc	hl, hl
	xor	a, a
	adc	hl, bc
	ret	nc
	ld	(de), a
	ret	z
	inc	de
	sbc	hl, hl
	add	hl, de
	dec	bc
	ldir
	ret

.section	.text,"ax",@progbits
globl _bytelen_to_bitlen
.type _bytelen_to_bitlen,@function

_bytelen_to_bitlen:
; hl = size
; iy = dst
; converts a size_t to a u8[8]
; outputs in big endian
	pop bc
	pop hl
	pop iy
	push iy
	push hl
	push bc
	xor a, a
	add hl, hl
	adc a, a
	add hl, hl
	adc a, a
	add hl, hl
	adc a, a
	; a = bits 24..26, hl = bits 0..23 of (size * 8)
	ld (iy + 4), a
	ld (iy + 5), hl		; little-endian: +5=L +6=H +7=U
	ld a, (iy + 5)
	ld c, (iy + 7)
	ld (iy + 7), a		; byte 7 = bits 0..7
	ld (iy + 5), c		; byte 5 = bits 16..23 (byte 6 = bits 8..15)
	ld hl, 0
	ld (iy + 0), hl		; bytes 0..2
	ld (iy + 3), l		; byte 3
	ret

.section	.note.GNU-stack,"",@progbits

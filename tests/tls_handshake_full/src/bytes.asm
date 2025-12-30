assume adl=1


section .text
public _tls_bytes_compare

_tls_bytes_compare:
	pop	iy, de, hl, bc
	push	bc, hl, de, iy
	xor	a, a
.loop:
	ld	iyl, a
	ld	a, (de)
	inc	de
	xor	a, (hl)
	or	a, iyl
	cpi
	jq	pe, .loop
	add	a, -1
	sbc	a, a
	inc	a
	ret


section .text
public _bytelen_to_bitlen

_bytelen_to_bitlen:
; hl = size
; iy = dst
; converts a size_t to a u8[8]
; outputs in big endian
	pop bc, hl, iy
	push iy, hl, bc
	xor a, a
	add hl, hl
	adc a, a
	add hl, hl
	adc a, a
	add hl, hl
	adc a, a
	ld (iy + 5), a
	ld (iy + 6), h
	ld (iy + 7), l
	sbc hl, hl
	ld (iy + 0), hl
	ld (iy + 2), hl
	ret

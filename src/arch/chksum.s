.assume adl=1

.section	.text,"ax",@progbits
globl _lwip_ce_chksum_pairs
.type _lwip_ce_chksum_pairs,@function

_lwip_ce_chksum_pairs:
	push	ix
	ld	iy, 0
	add	iy, sp
	ld	ix, (iy + 6)
	ld	bc, (iy + 9)
	ld	hl, (iy + 12)
	push	hl
	or	a, a
	sbc	hl, hl
	ld	iy, 0
	ld	de, 0
	ld	a, b
	or	a, c
	jr	z, .Lckdone
.Lckloop:
	ld	e, (ix + 0)
	add	hl, de
	ld	e, (ix + 1)
	add	iy, de
	ld	e, (ix + 2)
	add	hl, de
	ld	e, (ix + 3)
	add	iy, de
	ld	e, (ix + 4)
	add	hl, de
	ld	e, (ix + 5)
	add	iy, de
	ld	e, (ix + 6)
	add	hl, de
	ld	e, (ix + 7)
	add	iy, de
	ld	e, (ix + 8)
	add	hl, de
	ld	e, (ix + 9)
	add	iy, de
	ld	e, (ix + 10)
	add	hl, de
	ld	e, (ix + 11)
	add	iy, de
	ld	e, (ix + 12)
	add	hl, de
	ld	e, (ix + 13)
	add	iy, de
	ld	e, (ix + 14)
	add	hl, de
	ld	e, (ix + 15)
	add	iy, de
	lea	ix, ix + 16
	dec	bc
	ld	a, b
	or	a, c
	jr	nz, .Lckloop
.Lckdone:
	pop	de
	ex	de, hl
	ld	(hl), de
	inc	hl
	inc	hl
	inc	hl
	lea	de, iy + 0
	ld	(hl), de
	pop	ix
	ret

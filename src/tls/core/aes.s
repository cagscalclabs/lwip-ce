;--------------------------------------------
; AES EZ80 implementation
; Author: calc84maniac
;--------------------------------------------

	.assume adl=1

	.equ AES_BLOCK_SIZE, 16
	; must be consistent with struct tls_aes_context in aes.h
	.equ CTX_KEYSIZE_OFFSET, 1
	.equ CTX_ROUNDKEYS_OFFSET, 4

	.equ ti.frameset0, 000130h
	.extern __frameset0

	.section .text,"ax",@progbits
	.global _aes_xor_buf
	.type _aes_xor_buf,@function
_aes_xor_buf:
	pop	iy
	pop	hl
	pop	de
	pop	bc
	push	bc
	push	de
	push	hl

	ld	b, c
	inc	b
	srl	b
	jr	nc, .Lxor_buf_start
	ret	z
.Lxor_buf_loop:
	ld	a, (de)
	xor	a, (hl)
	ld	(de), a
	inc	hl
	inc	de
.Lxor_buf_start:
	ld	a, (de)
	xor	a, (hl)
	ld	(de), a
	inc	hl
	inc	de
	djnz	.Lxor_buf_loop
	jp	(iy)

	.section .text,"ax",@progbits
	.global _aes_prepare_encrypt
	.type _aes_prepare_encrypt,@function
_aes_prepare_encrypt:
	ld	hl, _aes_encrypt_reloc_load_start
	ld	de, _aes_encrypt_reloc_run_start
	ld	bc, _gf128_mul - _aes_encrypt_reloc_run_start
	ldir
	ret

	.section .text,"ax",@progbits
	.global _aes_prepare_ghash
	.type _aes_prepare_ghash,@function
_aes_prepare_ghash:
	ld	hl, _aes_encrypt_reloc_load_start + (_gf128_mul - _aes_encrypt_reloc_run_start)
	ld	de, _gf128_mul
	ld	bc, _aes_encrypt_reloc_len - (_gf128_mul - _aes_encrypt_reloc_run_start)
	ldir
	ret

	.section .text,"ax",@progbits
	.global _aes_prepare_decrypt
	.type _aes_prepare_decrypt,@function
_aes_prepare_decrypt:
	ld	hl, _aes_decrypt_reloc_load_start
	ld	de, _aes_decrypt_reloc_run_start
	ld	bc, _aes_decrypt_reloc_len
	ldir
	ret

	.section .text,"ax",@progbits
	.global _aes_key_schedule
	.type _aes_key_schedule,@function
_aes_key_schedule:
	call	__frameset0
	ld	de, (ix + 6)	; DE = round_keys
	ld	hl, (ix + 9)	; HL = key
	ld	bc, (ix + 12)	; BC = key_len
	ld	a, c
	push	de
	; copy key to round_keys
	ldir

	rrca
	ld	c, a	; C = key_len / 2
	rrca		; A = key_len / 4
	ld	l, a
	inc	l	; L = key_len / 4 + 1
	ld	h, $8D	; H = 1 / x in galois field
	ex	(sp), hl	; HL = start of round keys

	add	a, c
	add	a, 28
	ld	ixl, a	; IXL = key_len * 3 / 4 + 28

	push	de
	pop	iy	; IY = round_keys + key_len
	; load previous word into BC:DE
	ld	de, (iy - 4)
	ld	bc, (iy - 2)

	; first word is always at the mod point
.Lkey_schedule_next_mod:
	ex	(sp), iy
	; IYH = previous round constant
	; IYL = key_len / 4 + 1, plus $80 if 256-bit and current word
	;       index is not a multiple of 8
	push	hl
	; SBox Word
	ld	hl, _aes_sbox + (8 + 1)
	ld	a, iyl
	cp	a, l	; check if key is 256-bit (IYL == $09 or IYL == $89)
	; replace each byte of the previous word using the SBox
	ld	l, e
	ld	e, (hl)
	ld	l, d
	ld	d, (hl)
	ld	l, c
	ld	c, (hl)
	ld	l, b
	ld	b, (hl)
	jr	c, .Lkey_schedule_not_256
	; 256-bit key case
	sub	a, $80	; check and track whether word index is is a multiple of 8
	ld	iyl, a
	ld	a, 4 + 1	; next word mod is always in 4 words
.Lkey_schedule_not_256:
	ld	ixh, a	; IXH = number of words until next mod, plus 1
	; if 256-bit and not a multiple of 8, skip rotation and round constant
	jr	nc, .Lkey_schedule_no_con
	; multiply previous round constant by x in galois field
	ld	a, iyh
	add	a, a
	ld	l, a
	sbc	a, a
	and	a, $1B
	xor	a, l
	ld	iyh, a
	; rotate left, and XOR round constant
	xor	a, d
	ld	d, c
	ld	c, b
	ld	b, e
	ld	e, a
.Lkey_schedule_no_con:
	pop	hl
	ex	(sp), iy

.Lkey_schedule_loop:
	; check if next mod has arrived
	dec	ixh
	jr	z, .Lkey_schedule_next_mod

	; XOR word from (key_len / 4) words ago
	ld	a, (hl)
	xor	a, e
	ld	e, a
	inc	hl
	ld	a, (hl)
	xor	a, d
	ld	d, a
	inc	hl
	ld	a, (hl)
	xor	a, c
	ld	c, a
	inc	hl
	ld	a, (hl)
	xor	a, b
	ld	b, a
	inc	hl

	; write to next word
	ld	(iy + 0), de
	ld	(iy + 2), c
	ld	(iy + 3), b
	lea	iy, iy + 4

	; check if all words have been processed
	dec	ixl
	jr	nz, .Lkey_schedule_loop
	pop	hl
	pop	ix
	ret

	.section .aes.encrypt.reloc, "ax", @progbits

_aes_encrypt_reloc_run_start:

	; must be first in the section, assumes 256-byte alignment
_aes_sbox:
	.db 0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76
	.db 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0
	.db 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15
	.db 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75
	.db 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84
	.db 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF
	.db 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8
	.db 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2
	.db 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73
	.db 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB
	.db 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79
	.db 0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08
	.db 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A
	.db 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E
	.db 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF
	.db 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16

	.global _aes_encrypt_block
	.type _aes_encrypt_block,@function
_aes_encrypt_block:
	call	ti.frameset0	; app __frameset0 does not currently relocate properly

	; copy in block to out block (works for in-place encrypt)
	ld	hl, (ix + 6)	; HL = in
	ld	iy, (ix + 9)	; IY = out
	lea	de, iy + 0
	ld	bc, AES_BLOCK_SIZE
	ldir

	ld	ix, (ix + 12)	; IX = context
	ld	hl, (ix + CTX_KEYSIZE_OFFSET)	; HL = keysize
	add	hl, hl
	add	hl, hl
	add	hl, hl
	ld	a, h	; A = keysize / 32 (4, 6, or 8)
	add	a, 6	; A = number of rounds (10, 12, or 14)
	push	af
	jr	.Lencrypt_start

.Lencrypt_loop:
	push	af

	; MixColumns
	ld	b, AES_BLOCK_SIZE / 4
.Lmix_columns:
	ld	hl, (iy + 0)	; L = a, H = b
	ld	de, (iy + 2)	; E = c, D = d

	ld	a, d
	xor	a, e
	ld	d, a	; D = (c+d)
	xor	a, h
	xor	a, l
	ld	c, a	; C = (a+b+c+d)
	xor	a, d	; A = (a+b)

	add	a, a
	ld	h, a
	sbc	a, a
	and	a, $1B
	xor	a, h	; A = (a+b)*x
	xor	a, c
	xor	a, l
	ld	h, l	; H = a
	ld	l, a	; L = (a+b)*x + (b+c+d)

	ld	a, h
	xor	a, e	; A = (a+c)
	add	a, a
	ld	h, a
	sbc	a, a
	and	a, $1B
	xor	a, h	; A = (a+c)*x
	xor	a, l	; A = (b+c)*x + (b+c+d)
	xor	a, c	; A = (b+c)*x + (a)
	xor	a, d
	ld	h, a	; H = (b+c)*x + (a+c+d)

	sla	d
	sbc	a, a
	and	a, $1B
	xor	a, d	; A = (c+d)*x
	xor	a, c
	xor	a, e	; A = (c+d)*x + (a+b+d)

	ld	(iy + 0), hl
	ld	(iy + 2), a
	xor	a, h	; A = (b+d)*x + (b+c)
	xor	a, l	; A = (a+d)*x + (d)
	xor	a, c	; A = (a+d)*x + (a+b+c)
	ld	(iy + 3), a
	
	lea	iy, iy + 4
	djnz	.Lmix_columns
	lea	iy, iy - 16

.Lencrypt_start:
	; AddRoundKey
	lea	hl, iy + 0
	lea	de, ix + CTX_ROUNDKEYS_OFFSET
	ld	b, AES_BLOCK_SIZE / 4
.Lencrypt_add_round_key:
	.rept	4
	ld	a, (de)
	xor	a, (hl)
	ld	(hl), a
	inc	hl
	inc	de
	.endr
	djnz	.Lencrypt_add_round_key

	; SubBytes
	ld	de, _aes_sbox + (AES_BLOCK_SIZE / 4)
	ld	b, e
.Lencrypt_subbytes:
	.rept	4
	dec	hl
	ld	e, (hl)
	ld	a, (de)
	ld	(hl), a
	.endr
	djnz	.Lencrypt_subbytes

	; ShiftRows
	pea	ix + AES_BLOCK_SIZE	; advance IX to next round key

	; load rows 1-3 of all 4 columns into HL, DE, BC, IX
	; registers will be stored back rotated left by 3 columns,
	; so the rows in each register will be rotated relative to that
	ld	hl, (iy + 0*4 + 1)
	ld	de, (iy + 1*4 + 1)
	ld	bc, (iy + 2*4 + 1)
	ld	ix, (iy + 3*4 + 1)

	; rotate row 1 right by 2 columns (will be stored rotated left by 1)
	ld	a, ixl
	ld	ixl, e
	ld	e, a
	ld	a, c
	ld	c, l
	ld	l, a

	; rotate row 2 right by 1 column (will be stored rotated left by 2)
	ld	a, ixh
	ld	ixh, b
	ld	b, d
	ld	d, h
	ld	h, a

	; store all 3 rows rotated left by 3 columns
	ld	(iy + 0*4 + 1), ix
	ld	(iy + 1*4 + 1), hl
	ld	(iy + 2*4 + 1), de
	ld	(iy + 3*4 + 1), bc
	pop	ix

	pop	af
	dec	a
	jp	nz, .Lencrypt_loop

	; AddRoundKey
	lea	hl, iy + 0
	lea	de, ix + CTX_ROUNDKEYS_OFFSET
	ld	b, AES_BLOCK_SIZE / 4
.Lencrypt_add_last_round_key:
	.rept	4
	ld	a, (de)
	xor	a, (hl)
	ld	(hl), a
	inc	hl
	inc	de
	.endr
	djnz	.Lencrypt_add_last_round_key

	pop	ix
	ret

	.global _gf128_mul
	.type _gf128_mul,@function
_gf128_mul:
; Galois-Field GF(2^128) multiplication routine
; fields are in a big endian bitstream, but coefficients treated
; as little endian (i.e. x^0 to x^127 from left to right)
	call	ti.frameset0	; app __frameset0 does not currently relocate properly

	; initialize a zeroed 16-byte buffer for the result,
	; then the outer loop counter, then one padding byte
	ld	bc, 16 << 8	; outer loop counter
	push	bc
	ld	b, c
	.rept	5
	push	bc
	.endr

	lea	hl, ix - 18	; HL = result
	ld	de, (ix + 12)	; DE = output
	ld	iy, (ix + 9)	; IY = op2
	ld	ix, (ix + 6)	; IX = op1
	push	de
.Lgf_mul_loop:
	; outer loop, iterate over op1 bytes from top to bottom
	ld	c, (ix + 15)	; C = op1 byte
	dec	ix
	ld	de, (iy - 2)	; DEU = first op2 byte
	ld	e, b	; E = 0 (low byte of result * x^8)
	ld	b, 16	; B = inner loop counter
	; result = (result * x^8) + (op1_byte * op2 * x)
.Lgf_byte_loop:
	; inner loop, iterate over op2 bytes from bottom to top
	inc	iy
	ld	d, (iy + 0)	; D = next op2 byte
	; DE = (DEU * C * x) + E + (result_byte * x^8), DEU = D
	ex	de, hl
	.rept	7
	add	hl, hl
	sbc	a, a
	and	a, c
	xor	a, l
	ld	l, a
	.endr
	add	hl, hl
	sbc	a, a
	and	a, c
	xor	a, l
	ex	de, hl
	xor	a, (hl)	; add previous result byte * x^8
	ld	e, a
	ld	(hl), d	; update result with bottom byte
	inc	hl
	djnz	.Lgf_byte_loop

	; modulo the galois field, using E = A = x^128 overflow byte
	lea	iy, iy - 16	; IY = op2
	ld	c, 15
	dec	(hl)	; decrement outer loop counter
	jr	nz, .Lgf_no_div
	; on final loop, divide out the extra factor of x before modulo
	add	a, a
	ld	e, a
	inc	c	; C == 16 indicates loop termination
	ld	b, c
.Lgf_div_loop:
	dec	hl
	rl	(hl)
	djnz	.Lgf_div_loop
	add	hl, bc
	inc	hl	; HL = loop counter
.Lgf_no_div:
	sbc	hl, bc	; HL = second byte of result

	; D = upper byte of E * (1 + x + x^2 + x^7)
	add	a, a
	ld	d, a
	xor	a, e
	rrca
	rrca
	and	a, $C0
	xor	a, d
	ld	d, a
	; add to second byte of result
	xor	a, (hl)
	ld	(hl), a
	dec	hl

	; A = lower byte of E * (1 + x + x^2 + x^7)
	ld	a, e
	rlca
	xor	a, e
	ld	e, a
	rrca
	rrca
	xor	a, e
	xor	a, d
	; add to first byte of result
	xor	a, (hl)
	ld	(hl), a

	; check loop termination condition
	bit	4, c
	jr	z, .Lgf_mul_loop

	; copy result to output pointer
	pop	de
	ldir
	; deallocate stack frame
	inc	hl
	inc	hl
	ld	sp, hl
	; secure-zero result buffer on stack and deallocate again
	.rept	6
	push	bc
	.endr
	ld	sp, hl
	pop	ix
	ret

	.section .aes.decrypt.reloc, "ax", @progbits

_aes_decrypt_reloc_run_start:

	; must be first in the section, assumes 256-byte alignment
_aes_invsbox:
	.db 0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB
	.db 0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB
	.db 0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E
	.db 0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25
	.db 0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92
	.db 0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84
	.db 0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06
	.db 0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B
	.db 0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73
	.db 0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E
	.db 0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B
	.db 0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4
	.db 0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F
	.db 0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF
	.db 0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61
	.db 0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D

	.global _aes_decrypt_block
	.type _aes_decrypt_block,@function
_aes_decrypt_block:
	call	ti.frameset0	; app __frameset0 does not currently relocate properly

	; copy in block to out block (works for in-place decrypt)
	ld	hl, (ix + 6)	; HL = in
	ld	iy, (ix + 9)	; IY = out
	lea	de, iy + 0
	ld	bc, AES_BLOCK_SIZE
	ldir

	ld	ix, (ix + 12)	; IX = context
	ld	hl, (ix + CTX_KEYSIZE_OFFSET)	; HL = keysize
	add	hl, hl
	add	hl, hl
	add	hl, hl
	ld	a, h	; A = keysize / 32 (4, 6, or 8)
	add	a, 6	; A = number of rounds (10, 12, or 14)
	push	af
	ld	b, a
	ld	c, AES_BLOCK_SIZE
	mlt	bc
	add	ix, bc	; IX = pointer to last round key (minus 4)

	; AddRoundKey
	lea	hl, ix + 16 + CTX_ROUNDKEYS_OFFSET	; HL = pointer past end of last round key
	ld	b, AES_BLOCK_SIZE / 4
.Ldecrypt_add_last_round_key:
	.rept	4
	dec	hl
	dec	de
	ld	a, (de)
	xor	a, (hl)
	ld	(de), a
	.endr
	djnz	.Ldecrypt_add_last_round_key

	jr	.Ldecrypt_start

.Ldecrypt_loop:
	push	af

	; InvMixColumns
	ld	b, AES_BLOCK_SIZE / 4
.Linv_mix_columns:
	ld	hl, (iy + 0)	; L = a, H = b
	ld	de, (iy + 2)	; E = c, D = d

	ld	a, l
	xor	a, h
	xor	a, e
	xor	a, d
	ld	d, a	; D = (a+b+c+d)
	add	a, a
	ld	c, a
	sbc	a, a
	and	a, $1B
	xor	a, c	; A = (a+b+c+d)*x
	xor	a, l
	xor	a, e
	ld	e, a	; E = (a+b+c+d)*x + (a+c)
	add	a, a
	ld	c, a
	sbc	a, a
	and	a, $1B
	xor	a, c	; A = (a+b+c+d)*x^2 + (a+c)*x
	xor	a, l
	xor	a, h
	ld	c, a	; C = (a+b+c+d)*x^2 + (a+c)*x + (a+b)
	add	a, a
	ld	h, a
	sbc	a, a
	and	a, $1B
	xor	a, h	; A = (a+b+c+d)*x^3 + (a+c)*x^2 + (a+b)*x
	xor	a, d	; A = (a+b+c+d)*x^3 + (a+c)*x^2 + (a+b)*x + (a+b+c+d)
	xor	a, l
	ld	l, a	; L = (a+b+c+d)*x^3 + (a+c)*x^2 + (a+b)*x + (b+c+d)

	xor	a, c
	ld	h, a	; H = (a+b+c+d)*x^3 + (b+d)*x^2 + (b+c)*x + (a+c+d)

	ld	a, l	; A = (a+b+c+d)*x^3 + (a+c)*x^2 + (a+b)*x + (b+c+d)
	xor	a, e	; A = (a+b+c+d)*x^3 + (a+c)*x^2 + (c+d)*x + (a+b+d)

	ld	(iy + 0), hl
	ld	(iy + 2), a
	xor	a, c	; A = (a+b+c+d)*x^3 + (b+d)*x^2 + (a+d)*x + (d)
	xor	a, d	; A = (a+b+c+d)*x^3 + (b+d)*x^2 + (a+d)*x + (a+b+c)
	ld	(iy + 3), a

	lea	iy, iy + 4
	djnz	.Linv_mix_columns
	lea	iy, iy - 16

.Ldecrypt_start:
	; InvSubBytes
	lea	hl, iy + 0
	ld	de, _aes_invsbox + (AES_BLOCK_SIZE / 4)
	ld	b, e
.Ldecrypt_subbytes:
	.rept	4
	ld	e, (hl)
	ld	a, (de)
	ld	(hl), a
	inc	hl
	.endr
	djnz	.Ldecrypt_subbytes

	; InvShiftRows
	pea	ix - AES_BLOCK_SIZE	; advance IX to previous round key

	; load rows 1-3 of all 4 columns into HL, DE, BC, IX
	; registers will be stored back rotated right by 3 columns,
	; so the rows in each register will be rotated relative to that
	ld	hl, (iy + 0*4 + 1)
	ld	de, (iy + 1*4 + 1)
	ld	bc, (iy + 2*4 + 1)
	ld	ix, (iy + 3*4 + 1)

	; rotate row 1 left by 2 columns (will be stored rotated right by 1)
	ld	a, ixl
	ld	ixl, e
	ld	e, a
	ld	a, c
	ld	c, l
	ld	l, a

	; rotate row 1 left by 1 column (will be stored rotated right by 2)
	ld	a, h
	ld	h, d
	ld	d, b
	ld	b, ixh
	ld	ixh, a

	; store all 3 rows rotated right by 3 columns
	ld	(iy + 0*4 + 1), de
	ld	(iy + 1*4 + 1), bc
	ld	(iy + 2*4 + 1), ix
	ld	(iy + 3*4 + 1), hl
	pop	ix

	; AddRoundKey
	lea	hl, iy + 0
	lea	de, ix + CTX_ROUNDKEYS_OFFSET
	ld	b, AES_BLOCK_SIZE / 4
.Ldecrypt_add_round_key:
	.rept	4
	ld	a, (de)
	xor	a, (hl)
	ld	(hl), a
	inc	hl
	inc	de
	.endr
	djnz	.Ldecrypt_add_round_key

	pop	af
	dec	a
	jp	nz, .Ldecrypt_loop

	pop	ix
	ret

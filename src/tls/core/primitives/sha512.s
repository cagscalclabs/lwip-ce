;--------------------------------------------
; SHA-512 / SHA-384 compression for eZ80
;
; void tls_sha512_compress(uint64_t state[8], const uint8_t block[128]);
;
; The function performs the 80-round FIPS 180-4 SHA-512 compression.  It does
; not implement padding: the caller supplies exactly one 128-byte block and
; the eight-word state is transformed in place.
;
; Representation:
;   * The state words are native little-endian uint64_t values, i.e. the least
;     significant byte is at offset 0.
;   * The message schedule W[0..79] is kept little-endian in BSS.
;   * All 64-bit additions are byte-serial carry chains.
;   * Rotations are done with a byte-permute plus a 16-bit right shift built
;     from SRL A / RR C.  This avoids a 64-bit shift instruction, which the
;     eZ80 does not have.
;
; Scratch:
;   _sha512_w    640 bytes  message schedule
;   _sha512_work  64 bytes  a..h
;   _sha512_t1     8 bytes
;   _sha512_t2     8 bytes
;   _sha512_tmp    8 bytes  Ch/Maj/sigma temporary
; All of it is wiped before returning because the same block path is used by
; HMAC with key-derived blocks.  The buffer is plain .bss, deliberately not
; the RNG fastMem overlay.
;--------------------------------------------

.assume adl=1
.section	.text,"ax",@progbits

globl _tls_sha512_compress
.type _tls_sha512_compress,@function

; ---------------------------------------------------------------------------
; Scratch storage
; ---------------------------------------------------------------------------
.section .bss._sha512_scratch,"aw",@nobits
.balign 8
_sha512_w:
	.space 640
_sha512_work:
	.space 64
_sha512_t1:
	.space 8
_sha512_t2:
	.space 8
_sha512_tmp:
	.space 8
_sha512_scratch_end:

.section .rodata._sha512_k,"a",@progbits
_sha512_k:
	.quad 0x428a2f98d728ae22
	.quad 0x7137449123ef65cd
	.quad 0xb5c0fbcfec4d3b2f
	.quad 0xe9b5dba58189dbbc
	.quad 0x3956c25bf348b538
	.quad 0x59f111f1b605d019
	.quad 0x923f82a4af194f9b
	.quad 0xab1c5ed5da6d8118
	.quad 0xd807aa98a3030242
	.quad 0x12835b0145706fbe
	.quad 0x243185be4ee4b28c
	.quad 0x550c7dc3d5ffb4e2
	.quad 0x72be5d74f27b896f
	.quad 0x80deb1fe3b1696b1
	.quad 0x9bdc06a725c71235
	.quad 0xc19bf174cf692694
	.quad 0xe49b69c19ef14ad2
	.quad 0xefbe4786384f25e3
	.quad 0x0fc19dc68b8cd5b5
	.quad 0x240ca1cc77ac9c65
	.quad 0x2de92c6f592b0275
	.quad 0x4a7484aa6ea6e483
	.quad 0x5cb0a9dcbd41fbd4
	.quad 0x76f988da831153b5
	.quad 0x983e5152ee66dfab
	.quad 0xa831c66d2db43210
	.quad 0xb00327c898fb213f
	.quad 0xbf597fc7beef0ee4
	.quad 0xc6e00bf33da88fc2
	.quad 0xd5a79147930aa725
	.quad 0x06ca6351e003826f
	.quad 0x142929670a0e6e70
	.quad 0x27b70a8546d22ffc
	.quad 0x2e1b21385c26c926
	.quad 0x4d2c6dfc5ac42aed
	.quad 0x53380d139d95b3df
	.quad 0x650a73548baf63de
	.quad 0x766a0abb3c77b2a8
	.quad 0x81c2c92e47edaee6
	.quad 0x92722c851482353b
	.quad 0xa2bfe8a14cf10364
	.quad 0xa81a664bbc423001
	.quad 0xc24b8b70d0f89791
	.quad 0xc76c51a30654be30
	.quad 0xd192e819d6ef5218
	.quad 0xd69906245565a910
	.quad 0xf40e35855771202a
	.quad 0x106aa07032bbd1b8
	.quad 0x19a4c116b8d2d0c8
	.quad 0x1e376c085141ab53
	.quad 0x2748774cdf8eeb99
	.quad 0x34b0bcb5e19b48a8
	.quad 0x391c0cb3c5c95a63
	.quad 0x4ed8aa4ae3418acb
	.quad 0x5b9cca4f7763e373
	.quad 0x682e6ff3d6b2b8a3
	.quad 0x748f82ee5defb2fc
	.quad 0x78a5636f43172f60
	.quad 0x84c87814a1f0ab72
	.quad 0x8cc702081a6439ec
	.quad 0x90befffa23631e28
	.quad 0xa4506cebde82bde9
	.quad 0xbef9a3f7b2c67915
	.quad 0xc67178f2e372532b
	.quad 0xca273eceea26619c
	.quad 0xd186b8c721c0c207
	.quad 0xeada7dd6cde0eb1e
	.quad 0xf57d4f7fee6ed178
	.quad 0x06f067aa72176fba
	.quad 0x0a637dc5a2c898a6
	.quad 0x113f9804bef90dae
	.quad 0x1b710b35131c471b
	.quad 0x28db77f523047d84
	.quad 0x32caab7b40c72493
	.quad 0x3c9ebe0a15c9bebc
	.quad 0x431d67c49c100d4c
	.quad 0x4cc5d4becb3e42b6
	.quad 0x597f299cfc657e2a
	.quad 0x5fcb6fab3ad6faec
	.quad 0x6c44198c4a475817

.section .text,"ax",@progbits

; ---------------------------------------------------------------------------
; Helpers.  All of them preserve IX (the caller's frame) and never touch the
; caller's block or state memory except through explicitly passed pointers.
; ---------------------------------------------------------------------------

; HL = destination, DE = source.  dst += src (64-bit, little-endian).
; Clobbers AF, BC, HL, DE (HL/DE advance by 8).  Preserves B?  No: B is not
; used by this routine; it uses C as the inner counter, so B survives.
_sha512_add64:
	ld	a,(de)
	add	a,(hl)
	ld	(hl),a
	inc	hl
	inc	de
	ld	c,7
.Ladd64_loop:
	ld	a,(de)
	adc	a,(hl)
	ld	(hl),a
	inc	hl
	inc	de
	dec	c
	jp	nz,.Ladd64_loop
	ret

; HL = destination, DE = source.  Copy exactly 8 bytes.
; Clobbers AF, B, DE, HL.
_sha512_copy64:
	ld	b,8
.Lcopy64_loop:
	ld	a,(de)
	ld	(hl),a
	inc	de
	inc	hl
	djnz	.Lcopy64_loop
	ret

; DE = destination.  Zero exactly 8 bytes, preserve DE.
; Clobbers AF, B, HL.
_sha512_zero64:
	push	de
	ex	de,hl
	xor	a
	ld	b,8
.Lzero64_loop:
	ld	(hl),a
	inc	hl
	djnz	.Lzero64_loop
	pop	de
	ret

; HL = block (big-endian, 128 bytes), DE = W (little-endian, 128 bytes).
; Clobbers A, C, HL, DE, IY.
_sha512_load_block:
	push	hl
	ex	de,hl
	pop	iy
	ld	c,16
.Lload_block_loop:
	ld	a,(iy + 7)
	ld	(hl),a
	inc	hl
	ld	a,(iy + 6)
	ld	(hl),a
	inc	hl
	ld	a,(iy + 5)
	ld	(hl),a
	inc	hl
	ld	a,(iy + 4)
	ld	(hl),a
	inc	hl
	ld	a,(iy + 3)
	ld	(hl),a
	inc	hl
	ld	a,(iy + 2)
	ld	(hl),a
	inc	hl
	ld	a,(iy + 1)
	ld	(hl),a
	inc	hl
	ld	a,(iy + 0)
	ld	(hl),a
	inc	hl
	lea	iy,iy + 8
	dec	c
	jp	nz,.Lload_block_loop
	ret

; A = word index.  Returns HL = _sha512_w + index * 8.
; Clobbers A, DE, HL.
_sha512_get_wptr:
	ld	hl,0
	ld	l,a
	add	hl,hl
	add	hl,hl
	add	hl,hl
	ld	de,_sha512_w
	add	hl,de
	ret

; A = round index.  Returns HL = _sha512_k + index * 8.
; Clobbers A, DE, HL.
_sha512_get_kptr:
	ld	hl,0
	ld	l,a
	add	hl,hl
	add	hl,hl
	add	hl,hl
	ld	de,_sha512_k
	add	hl,de
	ret

; ---------------------------------------------------------------------------
; ROTR(x, N) XOR into the destination.
;
; Input:  IY = x (8-byte little-endian), DE = destination (XORed into, not
;         overwritten).  N = n*8 + r.
; The routine keeps DE and IY fixed and uses HL as the destination cursor.
; Clobbers A, C, HL.
; ---------------------------------------------------------------------------
.macro _rotr_xor n, r
	push	de
	pop	hl
	.irp i,0,1,2,3,4,5,6,7
	.if \r == 0
	ld	a,(iy + (((\i + \n) & 7)))
	xor	a,(hl)
	ld	(hl),a
	inc	hl
	.else
	ld	c,(iy + (((\i + \n) & 7)))
	ld	a,(iy + (((\i + \n + 1) & 7)))
	.rept \r
	srl	a
	rr	c
	.endr
	ld	a,c
	xor	a,(hl)
	ld	(hl),a
	inc	hl
	.endif
	.endr
.endm

; ---------------------------------------------------------------------------
; SHR(x, r) XOR into the destination.  Unlike ROTR, the byte above the top
; byte is treated as zero, so this is a logical shift, not a rotation.
; Input: IY = x, DE = destination, r = 1..7.
; Clobbers A, C, HL.
; ---------------------------------------------------------------------------
.macro _shr_xor r
	push	de
	pop	hl
	.irp i,0,1,2,3,4,5,6,7
	ld	c,(iy + \i)
	.if \i == 7
	.rept \r
	srl	c
	.endr
	ld	a,c
	.else
	ld	a,(iy + \i + 1)
	.rept \r
	srl	a
	rr	c
	.endr
	ld	a,c
	.endif
	xor	a,(hl)
	ld	(hl),a
	inc	hl
	.endr
.endm

_sha512_shr7:
	_shr_xor 7
	ret
_sha512_shr6:
	_shr_xor 6
	ret

_sha512_rotr28:
	_rotr_xor 3,4
	ret
_sha512_rotr34:
	_rotr_xor 4,2
	ret
_sha512_rotr39:
	_rotr_xor 4,7
	ret
_sha512_rotr14:
	_rotr_xor 1,6
	ret
_sha512_rotr18:
	_rotr_xor 2,2
	ret
_sha512_rotr41:
	_rotr_xor 5,1
	ret
_sha512_rotr1:
	_rotr_xor 0,1
	ret
_sha512_rotr8:
	_rotr_xor 1,0
	ret
_sha512_rotr19:
	_rotr_xor 2,3
	ret
_sha512_rotr61:
	_rotr_xor 7,5
	ret

; Sigma0(x) = ROTR28 ^ ROTR34 ^ ROTR39.
; Input HL = x, DE = destination (zeroed first by this routine).
; Output is written to DE.  Preserves DE; clobbers A, C, HL, IY.
_sha512_big_sigma0:
	push	hl
	pop	iy
	call	_sha512_zero64
	call	_sha512_rotr28
	call	_sha512_rotr34
	call	_sha512_rotr39
	ret

; Sigma1(x) = ROTR14 ^ ROTR18 ^ ROTR41.
_sha512_big_sigma1:
	push	hl
	pop	iy
	call	_sha512_zero64
	call	_sha512_rotr14
	call	_sha512_rotr18
	call	_sha512_rotr41
	ret

; sigma0(x) = ROTR1 ^ ROTR8 ^ (x >> 7).
_sha512_small_sigma0:
	push	hl
	pop	iy
	call	_sha512_zero64
	call	_sha512_rotr1
	call	_sha512_rotr8
	call	_sha512_shr7
	ret

; sigma1(x) = ROTR19 ^ ROTR61 ^ (x >> 6).
_sha512_small_sigma1:
	push	hl
	pop	iy
	call	_sha512_zero64
	call	_sha512_rotr19
	call	_sha512_rotr61
	call	_sha512_shr6
	ret

; Ch(e,f,g) -> _sha512_tmp.
; Input: HL = e, DE = f, IY = g.
; Clobbers A, HL, DE.
_sha512_ch64:
	.irp i,0,1,2,3,4,5,6,7
	ld	a,(de)
	xor	a,(iy + \i)
	and	a,(hl)
	xor	a,(iy + \i)
	ld	(_sha512_tmp + \i),a
	inc	hl
	inc	de
	.endr
	ret

; Maj(a,b,c) -> _sha512_tmp.
; Input: HL = a, DE = b, IY = c.
; Clobbers A, B, C, HL, DE.
_sha512_maj64:
	.irp i,0,1,2,3,4,5,6,7
	ld	a,(de)
	ld	b,a
	ld	a,(hl)
	and	a,b
	ld	c,a
	ld	a,(hl)
	or	a,b
	and	a,(iy + \i)
	or	a,c
	ld	(_sha512_tmp + \i),a
	inc	hl
	inc	de
	.endr
	ret

; ---------------------------------------------------------------------------
; void tls_sha512_compress(uint64_t state[8], const uint8_t block[128]);
;
; Frame:
;   ix + 6  state
;   ix + 9  block
;   ix - 3  loop index
; ---------------------------------------------------------------------------
_tls_sha512_compress:
	ld	hl,-3
	call	__frameset

	; W[0..15] = big-endian block words, stored little-endian.
	ld	hl,(ix + 9)
	ld	de,_sha512_w
	call	_sha512_load_block

	; W[i] = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16]
	ld	a,16
	ld	(ix - 3),a
.Lw_loop:
	; t1 = W[i-16]
	ld	a,(ix - 3)
	sub	a,16
	call	_sha512_get_wptr
	push	hl
	pop	de
	ld	hl,_sha512_t1
	call	_sha512_copy64

	; t1 += W[i-7]
	ld	a,(ix - 3)
	sub	a,7
	call	_sha512_get_wptr
	push	hl
	pop	de
	ld	hl,_sha512_t1
	call	_sha512_add64

	; t1 += sigma0(W[i-15])
	ld	a,(ix - 3)
	sub	a,15
	call	_sha512_get_wptr
	ld	de,_sha512_tmp
	call	_sha512_small_sigma0
	ld	hl,_sha512_t1
	ld	de,_sha512_tmp
	call	_sha512_add64

	; t1 += sigma1(W[i-2])
	ld	a,(ix - 3)
	sub	a,2
	call	_sha512_get_wptr
	ld	de,_sha512_tmp
	call	_sha512_small_sigma1
	ld	hl,_sha512_t1
	ld	de,_sha512_tmp
	call	_sha512_add64

	; W[i] = t1
	ld	a,(ix - 3)
	call	_sha512_get_wptr
	ld	de,_sha512_t1
	call	_sha512_copy64

	ld	a,(ix - 3)
	inc	a
	ld	(ix - 3),a
	cp	a,80
	jp	nz,.Lw_loop

	; a..h = state[0..7]
	ld	hl,(ix + 6)
	ld	de,_sha512_work
	ld	bc,64
	ldir

	ld	a,0
	ld	(ix - 3),a
.Lround_loop:
	; t1 = h
	ld	hl,_sha512_t1
	ld	de,_sha512_work + 56
	call	_sha512_copy64

	; t1 += Sigma1(e)
	ld	hl,_sha512_work + 32
	ld	de,_sha512_tmp
	call	_sha512_big_sigma1
	ld	hl,_sha512_t1
	ld	de,_sha512_tmp
	call	_sha512_add64

	; t1 += Ch(e,f,g)
	ld	hl,_sha512_work + 32
	ld	de,_sha512_work + 40
	push	hl
	ld	hl,_sha512_work + 48
	push	hl
	pop	iy
	pop	hl
	call	_sha512_ch64
	ld	hl,_sha512_t1
	ld	de,_sha512_tmp
	call	_sha512_add64

	; t1 += K[i]
	ld	a,(ix - 3)
	call	_sha512_get_kptr
	push	hl
	pop	de
	ld	hl,_sha512_t1
	call	_sha512_add64

	; t1 += W[i]
	ld	a,(ix - 3)
	call	_sha512_get_wptr
	push	hl
	pop	de
	ld	hl,_sha512_t1
	call	_sha512_add64

	; t2 = Sigma0(a)
	ld	de,_sha512_t2
	call	_sha512_zero64
	ld	hl,_sha512_work + 0
	ld	de,_sha512_t2
	call	_sha512_big_sigma0

	; t2 += Maj(a,b,c)
	ld	hl,_sha512_work + 0
	ld	de,_sha512_work + 8
	push	hl
	ld	hl,_sha512_work + 16
	push	hl
	pop	iy
	pop	hl
	call	_sha512_maj64
	ld	hl,_sha512_t2
	ld	de,_sha512_tmp
	call	_sha512_add64

	; h = g; g = f; f = e
	ld	hl,_sha512_work + 56
	ld	de,_sha512_work + 48
	call	_sha512_copy64
	ld	hl,_sha512_work + 48
	ld	de,_sha512_work + 40
	call	_sha512_copy64
	ld	hl,_sha512_work + 40
	ld	de,_sha512_work + 32
	call	_sha512_copy64

	; e = d + t1
	ld	hl,_sha512_work + 32
	ld	de,_sha512_work + 24
	call	_sha512_copy64
	ld	hl,_sha512_work + 32
	ld	de,_sha512_t1
	call	_sha512_add64

	; d = c; c = b; b = a
	ld	hl,_sha512_work + 24
	ld	de,_sha512_work + 16
	call	_sha512_copy64
	ld	hl,_sha512_work + 16
	ld	de,_sha512_work + 8
	call	_sha512_copy64
	ld	hl,_sha512_work + 8
	ld	de,_sha512_work + 0
	call	_sha512_copy64

	; a = t1 + t2
	ld	hl,_sha512_work + 0
	ld	de,_sha512_t1
	call	_sha512_copy64
	ld	hl,_sha512_work + 0
	ld	de,_sha512_t2
	call	_sha512_add64

	ld	a,(ix - 3)
	inc	a
	ld	(ix - 3),a
	cp	a,80
	jp	nz,.Lround_loop

	; state[i] += work[i] for all eight words.
	ld	hl,(ix + 6)
	ld	de,_sha512_work
	ld	b,8
.Lfeed_loop:
	call	_sha512_add64
	djnz	.Lfeed_loop

	; Wipe all derived state and schedule (HMAC keys live here).
	ld	hl,$FF0000
	ld	de,_sha512_w
	ld	bc,_sha512_scratch_end - _sha512_w
	ldir

	ld	sp,ix
	pop	ix
	ret

extern __frameset

.section	.note.GNU-stack,"",@progbits

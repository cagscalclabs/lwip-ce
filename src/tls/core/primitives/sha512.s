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
;   * State words and the message schedule are native little-endian uint64_t
;     values (least significant byte at offset 0).
;   * A 64-bit add is three overlapping 24-bit chunks.  In ADL mode the eZ80
;     add/adc on HL+DE are 24-bit operations, so this is 8 cycles of work per
;     chunk instead of a byte-serial carry chain.
;   * Rotations use the fact that RR(x,...) can be built from an 8-bit
;     shift-through-carry chain.  For a 16-bit source pair (high:low) the
;     result low byte of (pair >> r) is obtained with min(r, 8-r) shift
;     pairs: right-shift r times, or shift left 8-r times and keep the high
;     byte.  This halves the work for the large rotations and makes SHR(7)
;     and SHR(6) cheap.
;   * The two big Sigma functions are copied into the 0xE30800 fast-RAM
;     overlay once per compression (the schedule and the rest of the round
;     stay in flash).  The copy happens before the first round and is
;     wiped/clobbered by the next overlay user, like the existing SHA-256,
;     AES, X25519 and RSA overlays.  Callers must ensure no other overlay
;     user is live concurrently; this function is not reentrant.
;
; Loop structure (optimized):
;   5 outer passes × 16 inner = 80 rounds.
;   B is the inner counter; dec b; jp nz replaces the old _sha512_inner BSS
;   byte (3 BSS ops/round → 2 register ops/round, ~240 cycles saved).
;   _maj uses A, C, E, HL only — B survives the macro.
;   Feed-forward: compact 8-iteration djnz loop (IY=state, IX=work).
;
; Scratch (all wiped before return; HMAC key-derived blocks pass through
; this path):
;   BSS (_sha512_scratch):
;   _sha512_w      256 bytes  16-word rolling schedule plus a mirrored copy
;                             used to make the (mod 16) reads branch-free.
;                             The mirror is seeded once by a 128-byte ldir
;                             then kept current per-iteration in rounds 16+.
;   Fast-RAM overlay tail (0xE30800 + 792, via linker-defined _sha512_*_vma):
;   _sha512_work    64 bytes  a..h  (IY=_sha512_work during compression;
;                             offsets to all scratch fit in signed byte (iy+d))
;   _sha512_t1/t2/tmp 9 bytes each  (iy+64/73/82)
;   _sha512_outer   1 byte    outer loop counter (iy+91)
;   _sha512_sched   1 byte    schedule-expansion enable flag (iy+92)
;--------------------------------------------

.assume adl=1
.section	.text,"ax",@progbits

globl _tls_sha512_compress
.type _tls_sha512_compress,@function

; ---------------------------------------------------------------------------
; Scratch storage
; ---------------------------------------------------------------------------
; BSS: message schedule only.
.section .bss._sha512_scratch,"aw",@nobits
.balign 8
_sha512_scratch:
_sha512_w:
	.space 256
_sha512_scratch_end:

; Fast-RAM scratch — placed in the 0xE30800 overlay tail by the linker.
; IY = _sha512_work during compression; all offsets fit in (iy+d).
extern _sha512_work_vma
extern _sha512_t1_vma
extern _sha512_t2_vma
extern _sha512_tmp_vma
extern _sha512_outer_vma
extern _sha512_sched_vma
.equ _sha512_work,  _sha512_work_vma
.equ _sha512_t1,    _sha512_t1_vma
.equ _sha512_t2,    _sha512_t2_vma
.equ _sha512_tmp,   _sha512_tmp_vma
.equ _sha512_outer, _sha512_outer_vma
.equ _sha512_sched, _sha512_sched_vma

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
; Macros.  The round macros use only AF, BC, DE and HL; IX holds the current
; schedule word.  During the round body IY = _sha512_work (constant), so the
; a..h reads in _ch, _maj and the relocated big Sigmas use (iy+d) operands.
; The K pointer lives in the stack slot just above the return address and is
; swapped into IY with "ex (sp),iy" only around the K[i] add.  B is the inner
; counter; the outer counter and schedule flag live in BSS.
; ---------------------------------------------------------------------------

; DE = src + off.  src is either an absolute symbol or an IX-relative
; expression; idx selects which form to emit.
.macro _set_de src, off, idx
	.if \idx
		lea	de, \src + \off
	.else
		ld	de, \src + \off
	.endif
.endm

; 64-bit addition: (\dst) += (\base+\off).  base is ix or iy; off is a
; compile-time displacement.  The last chunk is only 2 bytes wide, so the
; 3-byte load may read one byte beyond the word (into padding or the next
; word) and only the low two bytes are stored.
.macro _add64_idx dst, base, off
	ld	hl, (\dst)
	ld	de, (\base+\off)
	add	hl, de
	ld	(\dst), hl

	ld	hl, (\dst+3)
	ld	de, (\base+\off+3)
	adc	hl, de
	ld	(\dst+3), hl

	ld	hl, (\dst+6)
	ld	de, (\base+\off+6)
	adc	hl, de
	ld	a, l
	ld	(\dst+6), a
	ld	a, h
	ld	(\dst+7), a
.endm

; 64-bit addition: (\dst) += (\src), both absolute symbols.
.macro _add64_sym dst, src
	ld	hl, (\dst)
	ld	de, (\src)
	add	hl, de
	ld	(\dst), hl

	ld	hl, (\dst+3)
	ld	de, (\src+3)
	adc	hl, de
	ld	(\dst+3), hl

	ld	hl, (\dst+6)
	ld	de, (\src+6)
	adc	hl, de
	ld	a, l
	ld	(\dst+6), a
	ld	a, h
	ld	(\dst+7), a
.endm

; 8-byte copy, absolute to absolute.
.macro _copy64 dst, src
	ld	hl, (\src)
	ld	(\dst), hl
	ld	hl, (\src+3)
	ld	(\dst+3), hl
	ld	hl, (\src+5)
	ld	(\dst+5), hl
.endm

; One output byte of a byte-aligned rotation (r == 0).
.macro _rot_byte q, srcbase, first
	.irp j,0,1,2,3,4,5,6,7
		ld	a, (\srcbase + ((\j + \q) & 7))
		.if \first
			ld	(hl), a
		.else
			xor	a, (hl)
			ld	(hl), a
		.endif
		inc	hl
	.endr
.endm

; One 64-bit rotation with a non-zero bit shift, XORed into (HL).
; srcbase is the unshifted source address; q is the whole-byte part of the
; rotation.  wrap == 0 turns the rotation into a logical shift (the byte
; above the top of the word is zero).
;
; Carry-over optimisation: for j>0 the high byte of iteration j-1 equals the
; low byte of iteration j, so we keep it in E and reload with "ld c,e" instead
; of a second BSS read.  For the wrap case we save src[q] in D before the loop
; so the j=7 wrap-around can use it without a re-load.
.macro _rot_bits r, q, srcbase, first, wrap
	; SHR (wrap=0) with q>0 not supported: stale E would give wrong output.
	.if (\wrap == 0) && (\q != 0)
		.error "_rot_bits: SHR with q>0 is unsupported"
	.endif
	; Load first low byte and prime carry register E with first high byte.
	ld	a, (\srcbase + (\q & 7))
	.if \wrap
		ld	d, a            ; save src[q] for j=7 wrap
	.endif
	ld	c, a
	.if \wrap
		ld	a, (\srcbase + ((\q + 1) & 7))
		ld	e, a            ; E = high byte for j=0
	.else
		.if ((\q + 1) < 8)
			ld	a, (\srcbase + (\q + 1))
			ld	e, a
		.else
			xor	a, a        ; high byte is zero (shift, not rotate)
			ld	e, a
		.endif
	.endif
	.irp j,0,1,2,3,4,5,6,7
		.if \j
			; Reuse previous high byte as this iteration's low byte.
			ld	c, e
			; Load next high byte into E (or A directly for final shift step).
			.if \wrap
				.if \j == 7
					ld	a, d    ; wrap: high byte is src[q] saved above
				.else
					ld	a, (\srcbase + ((\j + \q + 1) & 7))
					ld	e, a
				.endif
			.else
				.if ((\j + \q + 1) < 8)
					ld	a, (\srcbase + (\j + \q + 1))
					ld	e, a
				.else
					xor	a, a
				.endif
			.endif
		.else
			; j=0: A already holds the high byte (loaded above).
		.endif
		.if \r <= 4
			.rept \r
				srl	a
				rr	c
			.endr
			ld	a, c
		.else
			.rept (8 - \r)
				sla	c
				adc	a, a
			.endr
		.endif
		.if \first
			ld	(hl), a
		.else
			xor	a, (hl)
			ld	(hl), a
		.endif
		inc	hl
	.endr
.endm

.macro _rot n, srcbase, first, wrap
	.if ((\n & 7) == 0)
		_rot_byte (\n >> 3), \srcbase, \first
	.else
		_rot_bits (\n & 7), (\n >> 3), \srcbase, \first, \wrap
	.endif
.endm

; Sigma into \out.  src is an absolute symbol or an IX-relative expression.
.macro _sigma_big src, n1, n2, n3, out
	ld	hl, \out
	_rot \n1, \src, 1, 1
	ld	hl, \out
	_rot \n2, \src, 0, 1
	ld	hl, \out
	_rot \n3, \src, 0, 1
.endm

.macro _sigma_small src, n1, n2, sh, out
	ld	hl, \out
	_rot \n1, \src, 1, 1
	ld	hl, \out
	_rot \n2, \src, 0, 1
	ld	hl, \out
	_rot \sh, \src, 0, 0
.endm

; Ch(e,f,g) = g ^ (e & (f ^ g))
; Requires IY = _sha512_work (e = iy+32, f = iy+40, g = iy+48).
; Uses A, C, HL only; B, D, E, IX, IY preserved.  13 bytes per output byte.
.macro _ch out
	ld	hl, \out
	.irp j,0,1,2,3,4,5,6,7
		ld	c, (iy + 48 + \j)	; g
		ld	a, (iy + 40 + \j)	; f
		xor	a, c			; f ^ g
		and	a, (iy + 32 + \j)	; e & (f ^ g)
		xor	a, c			; g ^ (e & (f ^ g))
		ld	(hl), a
		inc	hl
	.endr
.endm

; Maj(a,b,c) = b ^ ((a ^ b) & (b ^ c))
; Per bit: a == b gives b (= a); a != b gives (b ^ c) ^ b = c, which is the
; majority because a and b disagree.  Equal to (a&b)|(c&(a|b)) on all 8
; input combinations.
; Requires IY = _sha512_work (a = iy+0, b = iy+8, c = iy+16).
; Uses A, C, E, HL only; B, D, IX, IY preserved.  16 bytes per output byte.
.macro _maj out
	ld	hl, \out
	.irp j,0,1,2,3,4,5,6,7
		ld	c, (iy + 8 + \j)	; b
		ld	a, (iy + 0 + \j)	; a
		xor	a, c			; a ^ b
		ld	e, a
		ld	a, (iy + 16 + \j)	; c
		xor	a, c			; b ^ c
		and	a, e			; (a ^ b) & (b ^ c)
		xor	a, c			; ^ b
		ld	(hl), a
		inc	hl
	.endr
.endm

; ---------------------------------------------------------------------------
; Helpers.
; ---------------------------------------------------------------------------

; HL = block (big-endian, 128 bytes), DE = W (little-endian, 128 bytes).
; Clobbers A, C, HL, DE, IY.  Called once per block.
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

; ---------------------------------------------------------------------------
; void tls_sha512_compress(uint64_t state[8], const uint8_t block[128]);
; ---------------------------------------------------------------------------
_tls_sha512_compress:
	ld	hl,-3
	call	__frameset

	; W[0..15] = big-endian block words, stored little-endian.
	ld	hl,(ix + 9)
	ld	de,_sha512_w
	call	_sha512_load_block

	; Mirror the 16-word schedule so mod-16 reads never cross a branch.
	; (Required: rounds 16+ read mirror slots seeded here.)
	ld	hl,_sha512_w
	ld	de,_sha512_w + 128
	ld	bc,128
	ldir

	; a..h = state[0..7]
	ld	hl,(ix + 6)
	ld	de,_sha512_work
	ld	bc,64
	ldir

	; Copy the Sigma hot blocks into fast RAM once per compression.
	ld	hl,_sha384_reloc_load_start
	ld	de,_sha384_reloc_run_start
	ld	bc,_sha384_reloc_len
	ldir

	; Everything below uses IX as the schedule pointer; keep the frame
	; pointer on the stack for the epilogue.
	push	ix
	ld	ix,_sha512_w
	; K pointer lives on the stack (swapped into IY only for the K add);
	; IY = _sha512_work for the rest of the round body.
	ld	hl,_sha512_k
	push	hl
	ld	iy,_sha512_work

	; B is the inner counter (16 per outer pass), advanced with dec b; jp nz.
	; _maj uses A, C, E, HL only (not B), so this is safe.
	; _sha512_sched and _sha512_outer stay in BSS (5 and 4 outer iterations
	; respectively — negligible cost vs the 240 inner-counter BSS ops saved).
	xor	a,a
	ld	(_sha512_sched),a
	ld	a,5
	ld	(_sha512_outer),a

.Louter:
	ld	b,16

.Linner:
	; ---------------------------------------------------------------
	; W[i] = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16]
	; (rounds 16..79 only)
	; ---------------------------------------------------------------
	ld	a,(_sha512_sched)
	or	a,a
	jp	z,.Lno_sched

	_sigma_small ix + 112, 19, 61, 6, _sha512_t2
	_add64_idx _sha512_t2, ix, 72
	_sigma_small ix + 8, 1, 8, 7, _sha512_tmp
	_add64_sym _sha512_t2, _sha512_tmp
	_add64_idx _sha512_t2, ix, 0

	; W[i] = t2; keep the 128-byte mirror in sync.
	ld	hl,(_sha512_t2)
	ld	(ix),hl
	ld	hl,(_sha512_t2 + 3)
	ld	(ix + 3),hl
	ld	hl,(_sha512_t2 + 5)
	ld	(ix + 5),hl
	ld	de,(_sha512_t2)
	lea	hl,ix + 127
	inc	hl
	ld	(hl),de
	inc	hl
	inc	hl
	inc	hl
	ld	de,(_sha512_t2 + 3)
	ld	(hl),de
	inc	hl
	inc	hl
	ld	de,(_sha512_t2 + 5)
	ld	(hl),de

.Lno_sched:
	; T1 = h + Sigma1(e) + Ch(e,f,g) + K[i] + W[i]
	; T2 = Sigma0(a) + Maj(a,b,c)
	_copy64 _sha512_t1, _sha512_work + 56

	call	_sha384_sigma1
	_add64_sym _sha512_t1, _sha512_t2

	_ch _sha512_tmp
	_add64_sym _sha512_t1, _sha512_tmp

	ex	(sp),iy			; IY = &K[i], (SP) = _sha512_work
	_add64_idx _sha512_t1, iy, 0
	lea	iy,iy + 8
	ex	(sp),iy			; IY = _sha512_work, (SP) = &K[i+1]
	_add64_idx _sha512_t1, ix, 0

	call	_sha384_sigma0
	_maj _sha512_tmp
	_add64_sym _sha512_t2, _sha512_tmp

	; a_new = T1 + T2, e_new = d + T1 (old d)
	_add64_sym _sha512_t2, _sha512_t1
	_add64_sym _sha512_t1, _sha512_work + 24

	; h=g; g=f; f=e  (high to low, so no overlap problem)
	_copy64 _sha512_work + 56, _sha512_work + 48
	_copy64 _sha512_work + 48, _sha512_work + 40
	_copy64 _sha512_work + 40, _sha512_work + 32
	; d=c; c=b; b=a
	_copy64 _sha512_work + 24, _sha512_work + 16
	_copy64 _sha512_work + 16, _sha512_work + 8
	_copy64 _sha512_work + 8, _sha512_work + 0
	_copy64 _sha512_work + 0, _sha512_t2
	_copy64 _sha512_work + 32, _sha512_t1

	lea	ix,ix + 8
	dec	b
	jp	nz,.Linner

	; End of a 16-word group: wrap the schedule ring back to slot 0.
	lea	ix,ix - 128
	ld	a,1
	ld	(_sha512_sched),a

	ld	a,(_sha512_outer)
	dec	a
	ld	(_sha512_outer),a
	jp	nz,.Louter

	; Restore the frame pointer and fold the work state back in.
	; Feed-forward: state[i] += work[i] for i=0..7, as a djnz loop.
	; IY = state word, IX = work word (both advance by 8).  The frame
	; pointer is parked on the stack for the duration of the loop.  The
	; top chunk is a 24-bit add whose third byte is discarded (mod 2^64);
	; only bytes 6-7 are stored so the next state word is never touched.
	; The (ix+6) read on the last word reads 1 byte past _sha512_work,
	; into _sha512_t1 (same BSS block), whose value is discarded.
	pop	hl			; discard K pointer
	pop	ix
	ld	iy,(ix + 6)
	push	ix
	ld	ix,_sha512_work
	ld	b,8
.Lfeed:
	ld	hl,(iy + 0)
	ld	de,(ix + 0)
	add	hl,de
	ld	(iy + 0),hl
	ld	hl,(iy + 3)
	ld	de,(ix + 3)
	adc	hl,de
	ld	(iy + 3),hl
	ld	hl,(iy + 6)
	ld	de,(ix + 6)
	adc	hl,de
	ld	(iy + 6),l
	ld	(iy + 7),h
	lea	iy,iy + 8
	lea	ix,ix + 8
	djnz	.Lfeed
	pop	ix

	; Wipe BSS schedule (HMAC key-derived material lives here).
	ld	hl,$FF0000
	ld	de,_sha512_scratch
	ld	bc,_sha512_scratch_end - _sha512_scratch
	ldir
	; Wipe fast-RAM scratch (working state + t1/t2/tmp + counters).
	ld	hl,$FF0000
	ld	de,_sha512_work
	ld	bc,93
	ldir

	ld	sp,ix
	pop	ix
	ret

extern __frameset

.section	.note.GNU-stack,"",@progbits
; ---------------------------------------------------------------------------
; Big-signature hot blocks.  These run on every one of the 80 rounds and are
; copied to the fast-RAM overlay (0xE30800) by the trampoline above.  Both
; blocks are straight-line code with a single ret, so the copied image is
; position-independent apart from its absolute BSS data references.
; Callers must have IY = _sha512_work: the source words are read as (iy+d).
; ---------------------------------------------------------------------------
.section .sha384.reloc,"ax",@progbits
_sha384_sigma1:
	_sigma_big iy + 32, 14, 18, 41, _sha512_t2
	ret

_sha384_sigma0:
	_sigma_big iy + 0, 28, 34, 39, _sha512_t2
	ret


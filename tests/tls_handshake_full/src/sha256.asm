;--------------------------------------------
; SHA-256 EZ80 implementation
; Author: beckadamtheinventor
;--------------------------------------------

assume adl=1
section .text

include "share/virtuals.inc"
include "share/nointerrupts.inc"

public _tls_sha256_init
public _tls_sha256_update
public _tls_sha256_digest

_sha256_m_buffer := _sprng_sha_mbuffer

; reverse b longs endianness from iy to hl
_sha256_reverse_endianness:
	ld de, (iy + 0)
	ld c, (iy + 2)
	ld a, (iy + 3)
	ld (hl), a
	inc hl
	ld (hl), c
	inc hl
	ld (hl), d
	inc hl
	ld (hl), e
	inc hl
	lea iy, iy + 4
	djnz _sha256_reverse_endianness
	ret
 
; helper macro to xor [B,C] with [R1,R2] storing into [R1,R2]
; destroys: af
macro _xorbc? R1,R2
	ld a,b
	xor a,R1
	ld R1,a
	ld a,c
	xor a,R2
	ld R2,a
end macro

; helper macro to xor [(HL),(HL+1)] with [R1,R2] storing into [R1,R2], advancing HL
; destroys: af
macro _xorihl? R1,R2
	ld a,R1
	xor a,(hl)
	ld R1,a
	inc hl
	ld a,R2
	xor a,(hl)
	ld R2,a
	inc hl
end macro

; helper macro to xor [(R3), (R3+1)] with [R1,R2] storing into [R1,R2]
; destroys: af
macro _xoriix? R1,R2, R3
	ld a,R1
	xor a,(R3)
	ld R1,a
	ld a,R2
	xor a,(R3+1)
	ld R2,a
end macro

; helper macro to and [(R3), (R3+1)] with [R1,R2] storing into [R1,R2]
; destroys: af
macro _andiix? R1,R2, R3
	ld a,R1
	and a,(R3)
	ld R1,a
	ld a,R2
	and a,(R3+1)
	ld R2,a
end macro

; helper macro to or [(R3), (R3+1)] with [R1,R2] storing into [R1,R2]
; destroys: af
macro _oriix? R1,R2, R3
	ld a,R1
	or a,(R3)
	ld R1,a
	ld a,R2
	or a,(R3+1)
	ld R2,a
end macro

; helper macro to add [(R3), (R3+1)] with [R1,R2] storing into [R1,R2]
; destroys: af
macro _addiix? R1,R2, R3
	ld a,R1
	add a,(R3)
	ld R1,a
	ld a,R2
	adc a,(R3+1)
	ld R2,a
end macro

; helper macro to adc [(R3), (R3+1)] with [R1,R2] storing into [R1,R2]
; destroys: af
macro _adciix? R1,R2, R3
	ld a,R1
	adc a,(R3)
	ld R1,a
	ld a,R2
	adc a,(R3+1)
	ld R2,a
end macro

; helper macro to add [(R3), (R3+1)] with [R1,R2] storing into [(R3), (R3+1)]
; destroys: af
macro _addiix_store? R1,R2, R3
	ld a,R1
	add a,(R3)
	ld R1,a
	ld a,R2
	adc a,(R3+1)
	ld R2,a
end macro

; helper macro to adc [(R3), (R3+1)] with [R1,R2] storing into [(R3), (R3+1)]
; destroys: af
macro _adciix_store? R1,R2, R3
	ld a,R1
	adc a,(R3)
	ld (R3),a
	ld a,R2
	adc a,(R3+1)
	ld (R3+1),a
end macro

; helper macro to xor [R1,R2] with [R3,R4] storing into [R1,R2]
; destroys: af
macro _xor? R1,R2,R3,R4
	ld a,R1
	xor a,R3
	ld R1,a
	ld a,R2
	xor a,R4
	ld R2,a
end macro

; helper macro to or [R1,R2] with [R3,R4] storing into [R1,R2]
; destroys: af
macro _or? R1,R2,R3,R4
	ld a,R1
	or a,R3
	ld R1,a
	ld a,R2
	or a,R4
	ld R2,a
end macro

; helper macro to and [R1,R2] with [R3,R4] storing into [R1,R2]
; destroys: af
macro _and? R1,R2,R3,R4
	ld a,R1
	and a,R3
	ld R1,a
	ld a,R2
	and a,R4
	ld R2,a
end macro

; helper macro to add [R1,R2] with [R3,R4] storing into [R1,R2]
; destroys: af
macro _add? R1,R2,R3,R4
	ld a,R1
	add a,R3
	ld R1,a
	ld a,R2
	adc a,R4
	ld R2,a
end macro

; helper macro to adc [R1,R2] with [R3,R4] storing into [R1,R2]
; destroys: af
macro _adc? R1,R2,R3,R4
	ld a,R1
	adc a,R3
	ld R1,a
	ld a,R2
	adc a,R4
	ld R2,a
end macro

; helper macro to rotate [a,uhl] left by the given amount
; input: c=0
; destroys: f
macro _rotleft32? AMOUNT
repeat AMOUNT
	add a,a
	adc hl,hl
	adc a,c
end repeat
end macro


; initialize sha256 hash state
_tls_sha256_init:
	pop iy,de
	push de
	ld hl,$FF0000
	ld bc,sha256_offset_state
	ldir
	ld c,8*4
	ld hl,_sha256_state_init
	ldir
	ld a, 1
	jp (iy)

; update sha256 hash state
_tls_sha256_update:
	save_interrupts
	call __frameset0
	; (ix + 0) RV
	; (ix + 3) old IX
	; (ix + 6) arg1: ctx
	; (ix + 9) arg2: data
	; (ix + 12) arg3: len
	ld iy, (ix + 6)			   ; iy = context
	; get pointers to the things
	ld bc, 0
	ld c, (iy + sha256_offset_datalen) ; bc = data block offset
	lea hl, iy       ; hl = data ptr
	add hl,bc        ; adjust data pointer by the current offset
	ex de,hl         ; de = adjusted data ptr
	ld a,64
	sub a,c
	ld c,a           ; bc = remaining bytes in block (always non-zero)
	ld hl, (ix + 9)  ; hl = source data
	push hl          ; push source data
	ld hl, (ix + 12) ; hl = len
	jq .loop_entry
.loop:
	ex (sp),hl  ; pop source data, push len
	ldir        ; fill rest of block
	push hl     ; push source data
	push iy     ; context ptr
	call _sha256_transform ; transform block
	pop iy
	ld bc, 512  ; add 1 blocksize of bitlen to the bitlen field
	lea iy, iy + sha256_offset_bitlen
	call u64_addi  ; preserves iy, bc
	lea iy, iy - sha256_offset_bitlen
	lea de, iy  ; de = data ptr
	ld b,c      ; bc = 0
	ld c, 64    ; remaining bytes in block is 64
	pop hl      ; pop source data
	ex (sp),hl  ; pop len, push source data
.loop_entry:
	; subtract remaining bytes in block and check whether the block gets filled
	xor a,a
	sbc hl,bc
	jq nc,.loop

	add hl,bc   ; restore len
	ld c,l      ; bc = len
	pop hl      ; pop source data
	or a,c      ; check len == 0
	jq z,.no_copy
	ldir
.no_copy:
	ld a,e
	sub a,iyl
	ld (iy + sha256_offset_datalen), a   ;save current datalen
	pop ix
	restore_interrupts _tls_sha256_update
	ret
 
; return sha256 digest
_tls_sha256_digest:
	save_interrupts
	ld hl,-_sha256ctx_size
	call __frameset
	; ix-_sha256ctx_size to ix-1
	; (ix + 0) Return address
	; (ix + 3) saved IX
	; (ix + 6) arg1: ctx
	; (ix + 9) arg2: outbuf
	ld hl, (ix + 6)             ; hl = original ctx
	lea de, ix-_sha256ctx_size  ; de = local ctx
	push de ; ctx
	ld bc, _sha256ctx_size
	ldir
	pop hl
	push hl ; ctx
	ld c, (ix-_sha256ctx_size + sha256_offset_datalen) ; data length
	add hl,bc ; hl + bc (context_block_cache_addr + bytes cached)
	ld (hl),$80
	inc hl
	ex de,hl
	ld a,55
	sub a,c ; c is set to datalen earlier
	ld c,a
	inc c   ; zeroing data + 56 is okay
	jq nc, .pad2
.pad1:
	add a,63-55
	jq z, .done_pad1   ; zeroing data + 64 is not okay
	ld c,a
	ld hl,$FF0000
	ldir
.done_pad1:
	call _sha256_transform
	pop de
	push de ; ctx
	ld bc,56
.pad2:
	ld hl,$FF0000
	ldir
.done_pad2:
	ld c, (ix-_sha256ctx_size + sha256_offset_datalen)
	ld b,8
	mlt bc ;multiply 8-bit datalen by 8-bit value 8
	lea iy, ix-_sha256ctx_size + sha256_offset_bitlen
	call u64_addi ; preserves iy
	; fast 64-bit endian swap
	ld hl, (iy + 0)
	ld e,h
	ld d,l
	ld (ix-_sha256ctx_size + sha256_offset_data + 62), de ; trashes sha256_offset_datalen, but it's no longer needed
	ld de, (iy + 3)
	ld l,d
	ld h,e
	ld (ix-_sha256ctx_size + sha256_offset_data + 59), hl
	ld hl, (iy + 6)
	ld e,h
	ld d,l
	ld (ix-_sha256ctx_size + sha256_offset_data + 56), de
	call _sha256_transform
	pop hl
	ld hl, (ix + 9)
	lea iy, ix-_sha256ctx_size + sha256_offset_state
	ld b, 8
	call _sha256_reverse_endianness
	ld sp,ix
	pop ix
	restore_interrupts _tls_sha256_digest
	ret


; void _sha256_transform(SHA256_CTX *ctx);
_sha256_transform:
._h := -4
._g := -8
._f := -12
._e := -16
._d := -20
._c := -24
._b := -28
._a := -32
._state_vars := -32
._i := -35
._frame_offset := -35
	ld hl,._state_vars              ; exclude the _i variable for now
	call __frameset

	ld iy, (ix + 6)
	lea hl, iy + sha256_offset_state
	lea de, ix + ._state_vars
	ld bc, 8*4
	ldir				; copy the ctx state to scratch stack memory (uint32_t a,b,c,d,e,f,g,h)

	ld c, 64-16
	push bc                         ; set the _i variable and finish stack frame setup

	ld hl,_sha256_m_buffer
	ld b,16
	call _sha256_reverse_endianness ;first loop is essentially just reversing the endian-ness of the data into m (both represented as 32-bit integers)
	push hl
	pop iy

._loop2:
; m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

; SIG0(m[i - 15])
; #define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
	ld hl,(iy + -15*4 + 0)
	ld a, (iy + -15*4 + 3)
	ld c,0     ; input to _rotleft32 macro
	_rotleft32 1           ; x << 1
	push hl    ; push (x << 1)[0:2]
	ld b,a     ; (x << 1)[3]
	ld e,h     ; (x << 1)[1]
	_rotleft32 4           ; x << 5
	push hl    ; push (x << 5)[0:2]
	ld d,a     ; (x << 5)[3]
	_rotleft32 1           ; x << 6
	ld c,a     ; (x << 6)[3]
	; SIG0[2] == (x >> 7)[2] ^ (x >> 18)[2] ^ (x >> 3)[2] == (x << 1)[3] ^ (x << 6)[1] ^ (x << 5)[3]
	ld a,h     ; (x << 6)[1]
	xor a,d    ; (x << 5)[3]
	xor a,b    ; (x << 1)[3]
	ld b,a     ; SIG0[2]
	; SIG0[1] == (x >> 7)[1] ^ (x >> 18)[1] ^ (x >> 3)[1] == (x << 1)[2] ^ (x << 6)[0] ^ (x << 5)[2]
	ld a,l     ; (x << 6)[0]
	xor a, (ix + ._frame_offset - 3 + 2) ; (x << 1)[2]
	xor a, (ix + ._frame_offset - 6 + 2) ; (x << 5)[2]
	ld h,a     ; SIG0[1]
	; SIG0[0] == (x >> 7)[0] ^ (x >> 18)[0] ^ (x >> 3)[0] == (x << 1)[1] ^ (x << 6)[3] ^ (x << 5)[1]
	ld a,e     ; (x << 1)[1]
	pop de     ; pop (x << 5)[0:1]
	xor a,c    ; (x << 6)[3]
	xor a,d    ; (x << 5)[1]
	ld l,a     ; SIG0[0]
	ex (sp),hl ; pop (x << 1)[0:1], push SIG0[0:1] and (x << 6)[2]
	; SIG0[3] == (x >> 7)[3] ^ (x >> 18)[3] ^ (x >> 3)[3] == (x << 1)[0] ^ (x << 6)[2] ^ (x << 5)[0]
	ld a,e     ; (x << 5)[0]
	and a,$1F  ; cut off the upper 3 bits from (x >> 3)
	xor a,l    ; (x << 1)[0]
	lea hl, ix + ._frame_offset - 3 + 2
	xor a,(hl) ; (x << 6)[2]
	ld (hl),b  ; SIG0[2]
	push af    ; push SIG0[3]

; SIG1(m[i - 2])
; #define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))
	ld hl,(iy + -2*4 + 0)
	ld a, (iy + -2*4 + 3)
	ld c,0     ; input to _rotleft32 macro
	_rotleft32 5           ; x << 5
	push hl    ; push (x << 5)[0:2]
	ld e,a     ; (x << 5)[3]
	ld b,l     ; (x << 5)[0]
	_rotleft32 1           ; x << 6
	push hl    ; push (x << 6)[0:2]
	ld d,a     ; (x << 6)[3]
	_rotleft32 1           ; x << 7
	ld c,l     ; (x << 7)[0]
	; SIG1[0] == (x >> 17)[0] ^ (x >> 19)[0] ^ (x >> 10)[0] == (x << 7)[3] ^ (x << 5)[3] ^ (x << 6)[2]
	xor a,e    ; (x << 5)[3]
	xor a, (ix + ._frame_offset - 12 + 2) ; (x << 6)[2]
	ld l,a     ; SIG1[0]
	; SIG1[1] == (x >> 17)[1] ^ (x >> 19)[1] ^ (x >> 10)[1] == (x << 7)[0] ^ (x << 5)[0] ^ (x << 6)[3]
	ld a,d     ; (x << 6)[3]
	xor a,b    ; (x << 5)[0]
	xor a,c    ; (x << 7)[0]
	ld c,h     ; (x << 7)[1]
	ld h,a     ; SIG1[1]
	; SIG1[3] == (x >> 17)[3] ^ (x >> 19)[3] ^ (x >> 10)[3] == (x << 7)[2] ^ (x << 5)[2] ^ 0
	pop de     ; pop (x << 6)[0:1]
	inc sp     ; safe to trash the flags from the prior push af
	ex (sp),hl ; pop (x << 5)[1:2], push SIG1[0:1] and (x << 7)[2]
	ld a, (ix + ._frame_offset - 8 + 2) ; (x << 7)[2]
	xor a,h    ; (x << 5)[2]
	ld b,a     ; SIG1[3]
	; SIG1[2] == (x >> 17)[2] ^ (x >> 19)[2] ^ (x >> 10)[2] == (x << 7)[1] ^ (x << 5)[1] ^ (x << 6)[0]
	ld a,e     ; (x << 6)[0]
	and a,$3F  ; cut off the upper 10 bits of (x >> 10)
	xor a,c    ; (x << 7)[1]
	xor a,l    ; (x << 5)[1]
	ld (ix + ._frame_offset - 8 + 2), a ; SIG1[2]
	pop hl     ; pop SIG1[0:2]
	dec sp     ; restore stack pointer for pop af

; + SIG0(m[i - 15])
	pop af, de
	add hl,de
	adc a,b

; + m[i - 16]
	ld de, (iy + -16*4 + 0)
	add hl,de
	adc a, (iy + -16*4 + 3)

; + m[i - 7]
	ld de, (iy + -7*4)
	add hl,de
	adc a, (iy + -7*4 + 3)

; --> m[i]
	ld (iy + 0), hl
	ld (iy + 3), a

	lea iy, iy + 4
	dec (ix + ._i)
	jq nz, ._loop2

._loop3:
; tmp1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];

; CH(e,f,g)
; #define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
	ld hl, (ix + ._e + 0)
	ld de, (ix + ._f + 0)
	ld bc, (ix + ._g + 0)
	ld a,e
	xor a,c
	and a,l
	xor a,c
	ld c,a
	ld a,d
	xor a,b
	and a,h
	xor a,b
	ld b,a
	push bc

	ld de, (ix + ._e + 2)
	ld bc, (ix + ._g + 2)
	ld a, (ix + ._f + 2)
	xor a,c
	and a,e
	xor a,c
	ld (ix + ._frame_offset - 3 + 2), a
	ld a, (ix + ._f + 3)
	xor a,b
	and a,d
	xor a,b
	ld iyl,a

; EP1(e)
; #define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
	ld a,d
	ld c,0     ; input to _rotleft32 macro
	_rotleft32 2         ; x << 2
	push hl    ; push (x << 2)[0:2]
	ld b,a     ; (x << 2)[3]
	ld e,h     ; (x << 2)[1]
	_rotleft32 3         ; x << 5
	push hl    ; push (x << 5)[0:2]
	ld d,a     ; (x << 5)[3]
	_rotleft32 2         ; x << 7 == x >> 25
	ld c,a     ; (x >> 25)[3]
	; EP1[0] == (x >> 6)[0] ^ (x >> 11)[0] ^ (x >> 25)[0] == (x << 2)[1] ^ (x << 5)[2] ^ (x >> 25)[0]
	ld a,l     ; (x >> 25)[0]
	xor a, (ix + ._frame_offset - 9 + 2) ; (x << 5)[2]
	xor a,e    ; (x << 2)[1]
	ld l,a     ; EP1[0]
	; EP1[1] == (x >> 6)[1] ^ (x >> 11)[1] ^ (x >> 25)[1] == (x << 2)[2] ^ (x << 5)[3] ^ (x >> 25)[1]
	ld a,h     ; (x >> 25)[1]
	xor a, (ix + ._frame_offset - 6 + 2) ; (x << 2)[2]
	xor a,d    ; (x << 5)[3]
	ld h,a     ; EP1[1]
	; EP1[2] == (x >> 6)[2] ^ (x >> 11)[2] ^ (x >> 25)[2] == (x << 2)[3] ^ (x << 5)[0] ^ (x >> 25)[2]
	ex (sp),hl ; pop (x << 5)[0:1], push EP1[0:1] and (x >> 25)[2]
	lea de, ix + ._frame_offset - 9 + 2
	ld a, (de) ; (x >> 25)[2]
	xor a,b    ; (x << 2)[3]
	xor a,l    ; (x << 5)[0]
	ld (de), a ; EP1[2]
	; EP1[3] == (x >> 6)[3] ^ (x >> 11)[3] ^ (x >> 25)[3] == (x << 2)[0] ^ (x << 5)[1] ^ (x >> 25)[3]
	ld a,h     ; (x << 5)[1]
	pop hl     ; pop EP1[0:2]
	pop de     ; pop (x << 2)[0:1]
	xor a,e    ; (x << 2)[0]
	xor a,c    ; (x >> 25)[3]

; + h
	ld de, (ix + ._h + 0)
	add hl,de
	adc a, (ix + ._h + 3)

; + CH(e,f,g)
	pop de
	add hl,de
	adc a,iyl

; + m[i]
	ld bc,(ix + ._i)
	ld iy,_sha256_m_buffer
	add iy,bc
	ld de,(iy + 0)
	add hl,de
	adc a,(iy + 3)

; + k[i]
	ld iy,_sha256_k
	add iy,bc
	ld de,(iy + 0)
	add hl,de
	adc a,(iy + 3)

; --> tmp1
	push hl
	ld iyl,a
; d = d + tmp1
	ld de, (ix + ._d + 0)
	add hl,de
	ld (ix + ._d + 0), hl
	lea hl, ix + ._d + 3
	adc a, (hl)
	ld (hl), a

; tmp2 = EP0(a) + MAJ(a,b,c);

; MAJ(a,b,c)
; #define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
	ld hl, (ix + ._a + 0)
	ld de, (ix + ._b + 0)
	ld a,l
	and a,e
	ld c,a
	ld a,l
	xor a,e
	and a, (ix + ._c + 0)
	or a,c
	ld l,a
	ld a,h
	and a,d
	ld c,a
	ld a,h
	xor a,d
	and a, (ix + ._c + 1)
	or a,c
	ld h,a
	push hl

	ld hl, (ix + ._a + 2)
	ld de, (ix + ._b + 2)
	ld a,l
	and a,e
	ld c,a
	ld a,l
	xor a,e
	and a, (ix + ._c + 2)
	or a,c
	ld (ix + ._frame_offset - 6 + 2),a
	ld a,h
	and a,d
	ld c,a
	ld a,h
	xor a,d
	and a, (ix + ._c + 3)
	or a,c
	ld iyh,a

; h = g;
; g = f;
; f = e;
; e = d;
; d = c;
; c = b;
; b = a;
	lea hl, ix + ._g + 3
	lea de, ix + ._h + 3
	ld c, ._h - ._a - 1
	lddr
	ld a, (hl)
	ld (de), a

; EP0(a)
; #define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
	ld hl, (ix + ._a + 1) ; x >> 8
	_rotleft32 2          ; x >> 6
	push hl    ; push (x >> 6)[0:2]
	ld e,a     ; (x >> 6)[3]
	_rotleft32 1          ; x >> 5
	push hl    ; push (x >> 5)[0:2]
	ld d,a     ; (x >> 5)[3]
	ld b,h     ; (x >> 5)[1]
	_rotleft32 3          ; x >> 2
	ld c,a     ; (x >> 2)[3]
	; EP0[0] == (x >> 2)[0] ^ (x >> 13)[0] ^ (x >> 22)[0] == (x >> 2)[0] ^ (x >> 5)[1] ^ (x >> 6)[2]
	ld a,l     ; (x >> 2)[0]
	xor a, (ix + ._frame_offset - 9 + 2) ; (x >> 6)[2]
	xor a,b    ; (x >> 5)[1]
	ld l,a     ; EP0[0]
	; EP0[1] == (x >> 2)[1] ^ (x >> 13)[1] ^ (x >> 22)[1] == (x >> 2)[1] ^ (x >> 5)[2] ^ (x >> 6)[3]
	ld a,h     ; (x >> 2)[1]
	xor a, (ix + ._frame_offset - 12 + 2) ; (x >> 5)[2]
	xor a,e    ; (x >> 6)[3]
	ld h,a     ; EP0[1]
	; EP0[2] == (x >> 2)[2] ^ (x >> 13)[2] ^ (x >> 22)[2] == (x >> 2)[2] ^ (x >> 5)[3] ^ (x >> 6)[0]
	ld a,d     ; (x >> 5)[3]
	pop de     ; pop (x >> 5)[0:1]
	ex (sp),hl ; pop (x >> 6)[0:1], push EP0[0:1] and (x >> 2)[2]
	xor a,l    ; (x >> 6)[0]
	xor a, (ix + ._frame_offset - 9 + 2) ; (x >> 2)[2]
	ld (ix + ._frame_offset - 9 + 2), a ; EP0[2]
	; EP0[3] == (x >> 2)[3] ^ (x >> 13)[3] ^ (x >> 22)[3] == (x >> 2)[3] ^ (x >> 5)[0] ^ (x >> 6)[1]
	ld a,c     ; (x >> 2)[3]
	xor a,h    ; (x >> 6)[1]
	xor a,e    ; (x >> 5)[0]
	pop hl     ; pop EP0[0:2]

; + MAJ(a,b,c)
	pop de
	add hl,de
	adc a,iyh

; + tmp1
	pop de
	add hl,de
	adc a,iyl

; --> a
	ld (ix + ._a + 0), hl
	ld (ix + ._a + 3), a

	lea hl, ix + ._i
	ld a, (hl)
	add a,4
	ld (hl), a
	jq nc,._loop3

	ld iy, (ix + 6)
	lea hl, iy + sha256_offset_state
	ld b,8
._loop4:
	ld de, (ix + ._state_vars)
	ld a,  (ix + ._state_vars + 3)
	lea ix, ix + 4

	ld iy, (hl)
	add iy, de
	ld (hl), iy
	inc hl
	inc hl
	inc hl
	adc a, (hl)
	ld (hl), a
	inc hl

	djnz ._loop4
	lea ix, ix + -8*4

	ld sp,ix
	pop ix
	ret

_sha256_state_init:
	dl 648807
	db 106
	dl 6794885
	db -69
	dl 7271282
	db 60
	dl 5240122
	db -91
	dl 938623
	db 81
	dl 354444
	db -101
	dl -8136277
	db 31
	dl -2044647
	db 91
 
 _sha256_k:
	dd	1116352408
	dd	1899447441
	dd	3049323471
	dd	3921009573
	dd	961987163
	dd	1508970993
	dd	2453635748
	dd	2870763221
	dd	3624381080
	dd	310598401
	dd	607225278
	dd	1426881987
	dd	1925078388
	dd	2162078206
	dd	2614888103
	dd	3248222580
	dd	3835390401
	dd	4022224774
	dd	264347078
	dd	604807628
	dd	770255983
	dd	1249150122
	dd	1555081692
	dd	1996064986
	dd	2554220882
	dd	2821834349
	dd	2952996808
	dd	3210313671
	dd	3336571891
	dd	3584528711
	dd	113926993
	dd	338241895
	dd	666307205
	dd	773529912
	dd	1294757372
	dd	1396182291
	dd	1695183700
	dd	1986661051
	dd	2177026350
	dd	2456956037
	dd	2730485921
	dd	2820302411
	dd	3259730800
	dd	3345764771
	dd	3516065817
	dd	3600352804
	dd	4094571909
	dd	275423344
	dd	430227734
	dd	506948616
	dd	659060556
	dd	883997877
	dd	958139571
	dd	1322822218
	dd	1537002063
	dd	1747873779
	dd	1955562222
	dd	2024104815
	dd	2227730452
	dd	2361852424
	dd	2428436474
	dd	2756734187
	dd	3204031479
	dd	3329325298

extern u64_addi
extern __frameset0
extern __frameset

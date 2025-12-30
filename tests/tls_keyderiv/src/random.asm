;--------------------------------------------
; TRNG
; Author: nefariousarcher, beckadamtheinventor
;--------------------------------------------
; include to supported algorithms


assume adl=1
section .text

include "share/virtuals.inc"
include "share/nointerrupts.inc"

public _tls_random_init_entropy
public _tls_random
public _tls_random_bytes

;-------------------------------------
; bool tls_random_init_entropy(void);
_tls_random_init_entropy:
    ld hl, $D65800
    ld iy, 0
    lea de,iy
    ld c, l
.loop1: ; loops 256 times
    call .test_byte
    dec c
    jr nz,.loop1
.loop2: ; loops 256 times
    call .test_byte
    dec c
    jr nz,.loop2
    call .test_byte ; run a total of 513 times

    ex hl,de
    ld bc,256*8/3 ; change the 31 if the number of tests changes
    xor a,a
    sbc hl,bc
    ret nc
    add hl,bc

    lea hl, iy+0
    ld (_sprng_read_addr), hl

    add hl, bc
    xor a, a
    sbc hl, bc  ; set the z flag if HL is 0
    ret z
    inc a
    ret


; test byte at hl, set iy=hl if entropy is better
.test_byte:
    push de
    ld de,0
    ld b,0 ; probably enough tests
.test_byte_outer_loop:
; sample byte twice and bitwise-xor
    ld a,(hl) ; sample 1
    xor a,(hl) ; sample 2
; test the entropy for each of the 8 bits
.test_byte_loop:
    jr z,.done_test_byte_loop
    add a,a ; test next bit (starting with the high bit)
    jr nc,.test_byte_loop ; jump if bit unset
    inc de ; increment score
    jr .test_byte_loop
.done_test_byte_loop:
    djnz .test_byte_outer_loop

    ex (sp),hl ; save pointer to byte, restore current entropy score
    ; check if the new entropy score is higher than the current entropy score
    or a,a
    sbc hl,de ; current - new
    jr nc,.test_byte_is_worse
    pop iy ; return iy = pointer to byte
    lea hl,iy+1 ; advance pointer to byte for next test
    ret
.test_byte_is_worse:
    ex hl,de ; de = current score
    pop hl ; restore pointer to byte
    inc hl ; advance pointer
    ret


;--------------------------------------
; uint64_t tls_random(void);
_tls_random:
    save_interrupts
; set rand to 0
    or a,a
    sbc hl,hl
    ld (_sprng_rand), hl
    ld (_sprng_rand+3), hl
    ld (_sprng_rand+5), hl

; populate entropy pool with entropy
;   119 bytes at 0.811 bits of entropy per byte in pool = 96.51 bits
;   xor from entropy source 17 times per byte => reduce correlation
    ld hl,(_sprng_read_addr)
    ld de, _sprng_entropy_pool
    ld b, 119
.byte_read_loop:
    ld a, (hl)
    xor a, (hl)
    xor a, (hl)
    xor a, (hl)
    xor a, (hl)
    xor a, (hl)
    xor a, (hl)
    xor a, (hl)
    xor a, (hl)
    xor a, (hl)
    xor a, (hl)
    xor a, (hl)
    xor a, (hl)
    xor a, (hl)
    xor a, (hl)
    xor a, (hl)
    xor a, (hl)
    ld (de), a
    inc de
    djnz .byte_read_loop

; hash the entropy pool sha256
    ld hl, _sprng_hash_ctx
    push hl
    call _tls_sha256_init
    pop bc
    ld hl, 119
    push hl
    ld hl, _sprng_entropy_pool
    push hl
    push bc
    call _tls_sha256_update
    pop bc, hl, hl
    ld hl, _sprng_sha_digest
    push hl
    push bc
    call _tls_sha256_digest
    pop bc, hl

; xor hash cyclically into uint64_t
; each 4 64-bit blocks xor together
    ld hl,_sprng_sha_digest
    ld de,_sprng_rand
    ld c,8
.outer:
    xor a,a
    ld b,4
.inner:
    xor a,(hl)
    inc hl
    djnz .inner
    ld (de),a
    inc de
    dec c
    jq nz,.outer
; destroy sprng state
    ld hl, _sprng_entropy_pool
    ld (hl), 0
    ld de, _sprng_entropy_pool + 1
    ld bc, _sprng_rand - _sprng_entropy_pool - 1
    ldir
.return:
    restore_interrupts_noret _tls_random
; load 64 bits from _sprng_rand into BC:UDE:UHL
    ld hl,_sprng_rand
    ld c,(hl)
    inc hl
    ld b,(hl)
    inc hl
    ld de,(hl)
    inc hl
    inc hl
    inc hl
    ld hl,(hl)
    ret


; -----------------------------------------------
; void* tls_random_bytes(void* buf, size_t len);
_tls_random_bytes:
    save_interrupts
    ld hl,-3
    call __frameset
    ld hl,(ix+6)
    ld (ix-3),hl ; temp pointer
.loop:
    ld hl,(ix+9)
    add hl,bc
    or a,a
    sbc hl,bc
    jr z,.done ; handle end of loop and when len is zero
    call _tls_random
    ld hl,(ix+9)
    ld bc,8
    or a,a
    sbc hl,bc
    ld (ix+9),hl
    jr nc,.not_last
    ld c,l ; both uh and ub are zero here, we only need the low byte
.not_last:
    ld hl,(ix-3)
    add hl,bc
    ld de,(ix-3)
    ld (ix-3),hl ; advance dest pointer
    ld hl,_sprng_rand
    ldir ; copy to dest
    jr .loop
.done:
    restore_interrupts_noret _tls_random_bytes
    ld hl,(ix+6) ; return pointer to dest
    ld sp,ix
    pop ix
    ret


extern _tls_sha256_init
extern _tls_sha256_update
extern _tls_sha256_digest
extern __frameset

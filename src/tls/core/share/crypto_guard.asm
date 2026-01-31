include "virtuals.inc"

; -----------------------------------
; C-callable crypto guards (ez80)
; -----------------------------------
; tls_crypto_guard_start() -> save interrupt state + frame pointer, disable interrupts
; tls_crypto_guard_stop()  -> clear stack, restore interrupts/frame pointer

assume adl=1
section .text

public _tls_crypto_guard_enable
public _tls_crypto_guard_disable

?stackBot		:= 0D1987Eh

; void tls_crypto_guard_enable(void)
_tls_crypto_guard_enable:
	ld hl, (_crypto_guard_state_ptr)
	ld a, h
	or l
	jr nz, .has_ptr
; .no_has_ptr
	ld hl, _crypto_guard_state_start
	jr .save_state
.has_ptr:
	ld bc, _crypto_guard_state_end
	or a
	sbc hl, bc
	ld hl, (_crypto_guard_state_ptr)
	ret z
.save_state:
	ld a, i
	ld (hl), a
	inc hl
	ld (_crypto_guard_state_ptr), hl
	di
	ret

; void tls_crypto_guard_disable(void)
_tls_crypto_guard_disable:
; load sp into hl, store 0 to data at hl, decrement hl, store hl to de, subtract stack bottom to store into bc, lddr
; set hl to SP - 1: scf \ sbc hl, hl \ add hl, sp
; _erase_stack:
	; set from stackBot + 4 to ix - 1 to 0
	lea de, ix - 2
	ld hl, -(stackBot + 3)
	add hl, de
	push hl
	pop bc
	lea hl, ix - 1
	ld (hl), 0
	lddr

	; restore interrupts
	; do we have the pointer
	ld hl, (_crypto_guard_state_ptr)
	ld a, h
	or l
	ret z
	; is the pointer at the start
	ld bc, _crypto_guard_state_start
	or a
	sbc hl, bc
	ret z
	ld hl, (_crypto_guard_state_ptr)
	dec hl
	ld (_crypto_guard_state_ptr), hl
	ld a, (hl)
	or a
	ret z
	ei
	ret


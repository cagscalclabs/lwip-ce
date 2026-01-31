include "virtuals.inc"

; -----------------------------------
; C-callable crypto guards (ez80)
; -----------------------------------
; tls_crypto_guard_enable() -> save interrupt state, disable interrupts
; tls_crypto_guard_disable()  -> clear stack, restore interrupt state

assume adl=1
section .text

public _tls_crypto_guard_enable
public _tls_crypto_guard_disable

?stackBot		:= 0D1987Eh

; void tls_crypto_guard_enable(void)
_tls_crypto_guard_enable:
	; if pointer is zero check
	ld hl, (_crypto_guard_state_ptr)
	ld a, h
	or l
	jr nz, .has_ptr
; .no_has_ptr
	ld hl, _crypto_guard_state_start	; init pointer to start of state stack
	jr .save_state
.has_ptr:
	; if pointer is at end of state stack
	ld bc, _crypto_guard_state_end
	or a
	sbc hl, bc
	ld hl, (_crypto_guard_state_ptr)
	ret z	; do nothing
.save_state:
	ld a, i								; interrupt state into a
	ld (hl), a
	inc hl
	ld (_crypto_guard_state_ptr), hl	; advance state ptr
	di
	ret

; void tls_crypto_guard_disable(void)
_tls_crypto_guard_disable:
; _erase_stack:
	; set from stackBot + 4 to ix - 1 to 0
	scf
	sbc hl, hl
	add hl, sp
	dec hl
	ex de, hl
	ld hl, -(stackBot + 3)
	add hl, de
	push hl
	pop bc
	scf
	sbc hl, hl
	add hl, sp
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


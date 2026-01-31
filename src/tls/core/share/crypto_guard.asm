; -----------------------------------
; C-callable crypto guards (ez80)
; -----------------------------------
; tls_crypto_guard_start() -> save interrupt state + frame pointer, disable interrupts
; tls_crypto_guard_stop()  -> clear stack, restore interrupts/frame pointer

assume adl=1
section .text

public _tls_crypto_guard_start
public _tls_crypto_guard_stop

; void tls_crypto_guard_start(void)
_tls_crypto_guard_start:
	ld a, (_cg_enabled)
	or a
	ret nz
	ld a, i
	ld (_cg_interrupt_state), a
	ld (_cg_saved_ix), ix
	di
	ld a, 1
	ld (_cg_enabled), a
	ret

; void tls_crypto_guard_stop(void)
?stackBot		:= 0D1987Eh
_tls_crypto_guard_stop:
	xor a
	ld (_cg_enabled), a
	ld ix, (_cg_saved_ix)
	; save a, hl, e
	ld (_erase_saved_a), a
	ld (_erase_saved_hl), hl
	ld a, e
	ld (_erase_saved_e), a

	; set from stackBot + 4 to ix - 1 to 0
	lea de, ix - 2
	ld hl, -(stackBot + 3)
	add hl, de
	push hl
	pop bc
	lea hl, ix - 1
	ld (hl), 0
	lddr

	ld a, (_cg_interrupt_state)
	or a
	jr z, .done
	ei
.done:
	ld a, (_erase_saved_e)
	ld e, a
	ld a, (_erase_saved_a)
	ld hl, (_erase_saved_hl)
	ret

_erase_saved_a: db 0
_erase_saved_e: db 0
_erase_saved_hl: db 0, 0, 0
_cg_enabled: db 0
_cg_interrupt_state: db 0
_cg_saved_ix: db 0, 0, 0

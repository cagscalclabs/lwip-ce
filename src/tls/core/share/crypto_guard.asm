include "virtuals.inc"

; -----------------------------------
; C-callable crypto guards (ez80)
; -----------------------------------
; tls_crypto_guard_start() -> save interrupt state + frame pointer, disable interrupts
; tls_crypto_guard_stop()  -> clear stack, restore interrupts/frame pointer

assume adl=1
section .text

public _tls_crypto_guard_start
public _tls_crypto_guard_stop

; bool tls_crypto_guard_start(void)
_tls_crypto_guard_start:
	ld a, i
	ld hl, 0
	add hl, sp
	call _cg_push_state
	ret

; bool tls_crypto_guard_stop(void)
_tls_crypto_guard_stop:

	call _cg_pop_state
	or a
	ret z		; return if failed

	; wipe from current return address (sp + 3) up to saved SP - 1
	ld hl, 3
	add hl, sp
	ex de, hl
	ld hl, (_cg_saved_sp)
	dec hl
	or a
	sbc hl, de
	jr c, .no_wipe
	push hl
	pop bc
	ld hl, (_cg_saved_sp)
	dec hl
	ld (hl), 0
	jr z, .no_wipe
	dec bc
	push hl
	pop de
	dec de
	lddr
.no_wipe:
.done:
	ret

_erase_saved_a: db 0
_erase_saved_e: db 0
_erase_saved_hl: db 0, 0, 0

_cg_push_state:
; push state, A = interrupt state, HL = SP
; returns A = success/fail
	di
	push hl
		push af
			; test if we have a stack pointer
			ld hl, (_crypto_guard_stack_ptr)
			ld de, 0
			add hl, de
			or a
			sbc hl, de
			jr nz, .not_zero
			ld hl, _crypto_guard_stack_start
			ld (_crypto_guard_stack_ptr), hl	; set the starting pointer
			jr .skip_stack_end_test
		.not_zero:
			; test if we're at the stack end
			ld bc, (_crypto_guard_stack_ptr)
			ld hl, _crypto_guard_stack_end
			or a
			sbc hl, bc
			jr z, .exit_no_push
		.skip_stack_end_test:
		pop af
		; save interrupt state
		ld hl, (_crypto_guard_stack_ptr)
		ld (hl), a
	pop de
	inc hl
	; save stack pointer
	ld (hl), de
	inc hl
	inc hl
	inc hl
	ld (_crypto_guard_stack_ptr), hl
	ld a, 1
	ret
.exit_no_push
		pop af
	pop hl
	ld a, 0
	ret


_cg_pop_state:
; pops last state off the stack
; returns A = success/fail, HL = previous SP
	; test if we have a stack pointer
	ld hl, (_crypto_guard_stack_ptr)
	ld de, 0
	add hl, de
	or a
	sbc hl, de
	jr z, .not_zero
	ld hl, (_crypto_guard_stack_ptr)
	ld bc, _crypto_guard_stack_start
	or a
	sbc hl, bc
	jr z, .no_state
	ld hl, (_crypto_guard_stack_ptr)
	dec hl
	dec hl
	dec hl
	push hl
		dec hl
		ld (_crypto_guard_stack_ptr), hl
		ld a, (hl)
	pop hl
	ld hl, (hl)
	or a
	jr z, .no_interrupt_enable
	ei
.no_interrupt_enable:
	ld a, 1
	ret
.no_state:
	ld a, 0
	ret



_cg_stack_inc		:= 4

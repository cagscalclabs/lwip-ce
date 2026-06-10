.include "virtuals.inc"

; -----------------------------------
; C-callable crypto guards (ez80)
; -----------------------------------
; tls_crypto_guard_enable() -> save interrupt state, disable interrupts
; tls_crypto_guard_disable()  -> clear stack, restore interrupt state

.assume adl=1
.section	.text,"ax",@progbits


.globl _tls_crypto_guard_enable
.globl _tls_crypto_guard_disable
.type	_tls_crypto_guard_enable,@function
.type	_tls_crypto_guard_disable,@function

.equ stackBot, 0x0D1987E

.section .bss._crypto_guard_state,"aw",@nobits
_crypto_guard_state_ptr:
	.zero	3
_crypto_guard_state_start:
	.zero	16
_crypto_guard_state_end:


.section	.text,"ax",@progbits

; void tls_crypto_guard_enable(void)
_tls_crypto_guard_enable:
	; if pointer is zero check
	ld hl, (_crypto_guard_state_ptr)
	ld a, h
	or l
	jr nz, .Lhas_ptr
; .no_has_ptr
	ld hl, _crypto_guard_state_start	; init pointer to start of state stack
	jr .Lsave_state
.Lhas_ptr:
	; if pointer is at end of state stack
	ld bc, _crypto_guard_state_end
	or a
	sbc hl, bc
	ld hl, (_crypto_guard_state_ptr)
	ret z	; do nothing
.Lsave_state:
	ld a, i								; interrupt state into a
	ld (hl), a
	inc hl
	ld (_crypto_guard_state_ptr), hl	; advance state ptr
	di
	ret

; void tls_crypto_guard_disable(void)
_tls_crypto_guard_disable:
; _erase_stack:
	; Only scrub if the current SP is above the scrub floor. The resident
	; app's TLS callback path can be much deeper than standalone crypto tests;
	; if SP has already moved below stackBot, the old length calculation wraps
	; and lddr wipes unrelated memory.
	or a, a
	sbc hl, hl
	add hl, sp
	dec hl
	ld de, stackBot + 4
	or a, a
	sbc hl, de
	jr z, .Lrestore_interrupts
	jr c, .Lrestore_interrupts

		; Seed the byte below the guard's own return address, then lddr that
		; zero downward. Do not write to (sp): in ADL mode that is the low byte
		; of tls_crypto_guard_disable's return address.
		push hl
		pop bc
		scf
		sbc hl, hl
		add hl, sp
		dec hl
		ld (hl), 0
		push hl
		pop de
		dec de
		lddr

	; restore interrupts
.Lrestore_interrupts:
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


.section	.note.GNU-stack,"",@progbits

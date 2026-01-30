; -----------------------------
; == Side-Channel Resistance ==
; ------- erases stack --------
; guarantees stack erasure before returning to caller if
; called at the end of a function that encrypts/decrypts.

assume adl=1

section .text
public erase_stack

?stackBot		:= 0D1987Eh
erase_stack:
	
	; save a, hl, e
	ld (saved_a), a
	ld (saved_hl), hl
	ld a, e
	ld (saved_e), a
	
	; set from stackBot + 4 to ix - 1 to 0
	lea de, ix - 2
	ld hl, -(stackBot + 3)
	add hl, de
	push hl
	pop bc
	lea hl, ix - 1
	ld (hl), 0
	lddr
	
	; restore a, hl, e
	ld a, (saved_e)
	ld e, a
	ld a, (saved_a)
	ld hl, (saved_hl)
	ld sp, ix
	pop ix
	ret

section .bss
saved_a: db 0
saved_e: db 0
saved_hl: db 0, 0, 0

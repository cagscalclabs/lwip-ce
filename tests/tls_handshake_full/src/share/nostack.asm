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
	ld (.smc_a), a
	ld (.smc_hl), hl
	ld a, e
	ld (.smc_e), a
	
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
	ld e, 0
.smc_e:=$-1
	ld a, 0
.smc_a:=$-1
	ld hl, 0
.smc_hl:=$-3
	ld sp, ix
	pop ix
	ret

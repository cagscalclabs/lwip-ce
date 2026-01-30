; -----------------------------------
; ===== Side-Channel Resistance =====
; -- saves and disables interrupts --
; macros to disable system interrupts in code
; prevents the possible use of USB sideloading
; to view memory during encryption/decryption

;------------------------------------------
; helper macro for saving the interrupt state, then disabling interrupts
macro save_interrupts?
	ld a,i
	push af
	pop bc
	ld (__interrupt_state),bc
	di
end macro

;------------------------------------------
; helper macro for restoring the interrupt state
macro restore_interrupts? parent
	ld bc,(__interrupt_state)
	push bc
	pop af
	ret po
	ei
end macro

;------------------------------------------
; helper macro for restoring the interrupt state without prematurely returning
macro restore_interrupts_noret? parent
	ld bc,(__interrupt_state)
	push bc
	pop af
	jp po,parent.__dont_reenable_interrupts
	ei
parent.__dont_reenable_interrupts = $
end macro

;------------------------------------------
; helper macro for restoring the interrupt state, preserving a
macro restore_interrupts_preserve_a? parent
	ld bc,(__interrupt_state)
	push bc
	ld c,a
	pop af
	ld a,c
	ret po
	ei
end macro

;------------------------------------------
; helper macro for restoring the interrupt state without prematurely returning, preserving a
macro restore_interrupts_preserve_a? parent
	ld bc,(__interrupt_state)
	push bc
	ld c,a
	pop af
	ld a,c
	jp po,parent.__dont_reenable_interrupts
	ei
parent.__dont_reenable_interrupts = $
end macro

section .bss
__interrupt_state: dw 0
section .text

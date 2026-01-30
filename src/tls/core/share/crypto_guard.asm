; -----------------------------------
; C-callable crypto guards (ez80)
; -----------------------------------
; tls_crypto_enter() -> returns interrupt state (0/1)
; tls_crypto_exit(state) -> restores interrupt state
; tls_crypto_erase_stack() -> calls erase_stack

assume adl=1
section .text

public _tls_crypto_enter
public _tls_crypto_exit
public _tls_crypto_erase_stack
extern erase_stack

; uint8_t tls_crypto_enter(void)
_tls_crypto_enter:
	ld a, i
	jp po, .disabled
	ld a, 1
	di
	ret
.disabled:
	xor a
	di
	ret

; void tls_crypto_exit(uint8_t state)
_tls_crypto_exit:
	ld iy, -3
	add iy, sp
	ld a, (iy + 6)
	or a
	jr z, .done
	ei
.done:
	ret

; void tls_crypto_erase_stack(void)
_tls_crypto_erase_stack:
	jp erase_stack

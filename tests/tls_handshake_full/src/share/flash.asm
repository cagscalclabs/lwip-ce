
assume adl=1
section .text

public _flash_unlock
public _flash_lock
public _get_flash_lock_status
public _flash_sequence
public _set_priv
public _reset_priv
public _priv_upper
public _boot_Sha256Init
public _boot_Sha256Part
public _boot_Sha256Hash


_flash_unlock:
	ld	bc,$24
	ld	a,$8c
	call	write_port
	ld	bc,$06
	call	read_port
	or	a,4
	call	write_port
	ld	bc,$28
	ld	a,$4
	jp	write_port

_flash_lock:
	ld	bc,$28
	xor	a,a
	call	write_port
	ld	bc,$06
	call	read_port
	res	2,a
	call	write_port
	ld	bc,$24
	ld	a,$88
	jp	write_port

_get_flash_lock_status:
    ld  bc,$28
    jp  read_port

_flash_sequence:
    pop de
    pop hl
    push    hl
    push    de
    jp  (hl)

; this is hella inefficient, but who actually cares?
read_port:
	ld	a,mb
	push	af
	ld	a,.z80 shr 16
	ld	mb,a
	jp.sis	.z80 and $FFFF
assume adl = 0
.z80:
	in	e,(bc)
	jp.lil	.continue
assume adl = 1
.continue:
	pop	af
	ld	mb,a
	ld	a,e
	ret

write_port:
	ld	e,a
	ld	a,mb
	push	af
	ld	a,.z80 shr 16
	ld	mb,a
	jp.sis	.z80 and $FFFF
assume adl = 0
.z80:
	out	(bc),e
	jp.lil	.continue
assume adl = 1
.continue:
	pop	af
	ld	mb,a
	ret

_set_priv:
	ld	bc,$1d
	call	read_port
	ld	(priv_bkp),a
	ld	a,$FF
	call	write_port
	ld	bc,$1e
	call	read_port
	ld	(priv_bkp+1),a
	ld	a,$FF
	call	write_port
	ld	bc,$1f
	call	read_port
	ld	(priv_bkp+2),a
	ld	a,$FF
	jp	write_port

_reset_priv:
	ld	bc,$1d
	ld	a,(priv_bkp)
	call	write_port
	ld	bc,$1e
	ld	a,(priv_bkp+1)
	call	write_port
	ld	bc,$1f
	ld	a,(priv_bkp+2)
	jp	write_port

_priv_upper:
	ld	bc,$1d
	call	read_port
	ret

priv_bkp:
rl	1

_boot_Sha256Init           := 000035Ch
_boot_Sha256Part           := 0000360h
_boot_Sha256Hash           := 0000364h

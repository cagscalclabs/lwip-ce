.assume adl=1

.section .text,"ax",@progbits

.equ ti.flags, 0xD00080
.equ ti.Mov9ToOP1, 0x020320
.equ ti.ChkFindSym, 0x02050C
.equ ti.DelVarArc, 0x021434
.equ ti.Arc_Unarc, 0x021448
.equ ti.OP1, 0xD005F8

globl _lwip_app_config_delete_var
.type _lwip_app_config_delete_var,@function

; void lwip_app_config_delete_var(const char *name, uint8_t type)
; Mirrors the installer helper: build OP1 from type/name, find it, and let
; DelVarArc delete it whether it lives in RAM or archive.
_lwip_app_config_delete_var:
	ld	iy, ti.flags
	pop	de
	pop	hl
	pop	bc
	push	bc
	push	hl
	push	de
	ld	a, c
	dec	hl
	push	af
	call	ti.Mov9ToOP1
	pop	af
	ld	(ti.OP1), a
	call	ti.ChkFindSym
	ret	c
	jp	ti.DelVarArc

globl _lwip_app_config_arc_unarc_var
.type _lwip_app_config_arc_unarc_var,@function

; void lwip_app_config_arc_unarc_var(const char *name, uint8_t type)
; Build OP1 from type/name, find it, then call Arc_Unarc to swap it between
; RAM and archive.
_lwip_app_config_arc_unarc_var:
	ld	iy, ti.flags
	pop	de
	pop	hl
	pop	bc
	push	bc
	push	hl
	push	de
	ld	a, c
	dec	hl
	push	af
	call	ti.Mov9ToOP1
	pop	af
	ld	(ti.OP1), a
	call	ti.ChkFindSym
	ret	c
	jp	ti.Arc_Unarc

.section .note.GNU-stack,"",@progbits

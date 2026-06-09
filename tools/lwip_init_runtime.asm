; lwip_init_runtime_opaque(malloc, free, realloc)
;   Stores the three CRTs in _fn_imports_table, locates the lwIP app via
;   FindAppStart, verifies the export-table magic, and patches each in-lib
;   trampoline (jp 0) to point at its real in-app function address.
;
; __lwip_fn_table_off is the byte offset from app base to _fn_exports_table.
; The phase-2 build greps it from bin/lwIP.map and substitutes the literal
; below before fasmg runs.

; ti.* OS entry points (ti.FindAppStart, ti._frameset0, ...) are provided
; by ti84pceg.inc, which library.inc includes for the libload lib build —
; so they must NOT be redefined here or fasmg reports a symbol conflict.
__lwip_fn_table_off  := 0x000000

	export lwip_init_runtime_opaque

__lwip_app_name:
	db "lwIP", 0

lwip_init_runtime_opaque:
	call ti._frameset0

	ld hl, (ix + 6)
	ld (_fn_imports_table + 0), hl		; malloc
	ld hl, (ix + 9)
	ld (_fn_imports_table + 3), hl		; free
	ld hl, (ix + 12)
	ld (_fn_imports_table + 6), hl		; realloc

	ld hl, __lwip_app_name
	call ti.FindAppStart			; HL <- app base, carry on not-found
	jr c, .table_fail

	push hl
	pop de					; DE = app base, held through the loop

	push de
	ld de, __lwip_fn_table_off
	add hl, de				; HL -> _fn_exports_table
	pop de

	; Magic: 'L','W','I','P','T','B'
	ld a, (hl)
	cp a, 'L'
	jr nz, .table_fail
	inc hl
	ld a, (hl)
	cp a, 'W'
	jr nz, .table_fail
	inc hl
	ld a, (hl)
	cp a, 'I'
	jr nz, .table_fail
	inc hl
	ld a, (hl)
	cp a, 'P'
	jr nz, .table_fail
	inc hl
	ld a, (hl)
	cp a, 'T'
	jr nz, .table_fail
	inc hl
	ld a, (hl)
	cp a, 'B'
	jr nz, .table_fail
	inc hl

	ld bc, (hl)				; count
	inc hl					; HL -> first entry
	inc hl
	inc hl

	push ix
	ld ix, _lwip_jp_table_start + 1		; first trampoline operand
.patch_loop:
	ld a, b
	or a, c
	jr z, .patch_done

	push hl
	ld hl, (hl)				; entry: offset from app base
	add hl, de				; -> real in-app address
	ld (ix + 0), hl				; patch trampoline operand
	pop hl

	inc hl					; entry stride 3
	inc hl
	inc hl
	lea ix, ix + 4				; jp stride 4
	dec bc
	jr .patch_loop
.patch_done:
	pop ix

	; Trampolines are live — call into the app to do BSS/.data init and
	; copy our imports table into its reserved fn_imports_table.
	;   void lwip_init_runtime_internal(const void *src, size_t len);
	ld hl, _fn_imports_table_end - _fn_imports_table
	push hl					; arg2: len
	ld hl, _fn_imports_table
	push hl					; arg1: src
	call lwip_init_runtime_internal
	pop hl
	pop hl

	pop ix
	ld a, 1
	ret

.table_fail:
	; TODO: decide failure surface (return status vs abort with message).
	pop ix
	ld a, 0
	ret

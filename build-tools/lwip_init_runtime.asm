; lwip_init_runtime_opaque(malloc, free, realloc)
;   Stores the three CRTs in _fn_imports_table, locates the lwIP app via
;   FindAppStart, verifies the export-table magic, and patches each in-lib
;   trampoline (jp 0) to point at its real in-app function address.
;
; FindAppStart returns the CE app container base, not the linked image base.
; The linked image base is computed from the installed app metadata, matching
; the installer relocation logic. __lwip_fn_table_off is a fixed ABI offset
; from that linked image base to _fn_exports_table.

__lwip_fn_table_off := 0x000040
__lwip_expected_export_count := 0x000000

	export lwip_init_runtime_opaque

__lwip_app_name:
	db "lwIP", 0

; uint8_t lwip_init_runtime_opaque(malloc, free, realloc)
;   Returns the status code directly in A:
;     0 = success
;     1 = app not found
;     2 = export-table error (bad magic or count mismatch)
lwip_init_runtime_opaque:
	call ti._frameset0

	ld hl, (ix + 6)
	ld (_fn_imports_table + 0), hl		; malloc
	ld hl, (ix + 9)
	ld (_fn_imports_table + 3), hl		; free
	ld hl, (ix + 12)
	ld (_fn_imports_table + 6), hl		; realloc

	ld hl, __lwip_app_name
	call ti.FindAppStart	; HL <- app base, carry on not-found
	jp c, .app_missing

	; CE app metadata at app_base + 0x112 stores the offset to the linked
	; image after the relocation table. The linked image starts 0x100 bytes
	; after the CE app header, so:
	;   linked_base = app_base + 0x100 + d24(app_base + 0x112)
	push hl
	ld de, $112
	add hl, de
	ld hl, (hl)
	ld de, $100
	add hl, de
	pop de
	add hl, de
	push hl
	pop de					; DE = linked image base

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
	push hl
	ld hl, __lwip_expected_export_count
	or a, a
	sbc hl, bc
	pop hl
	jr nz, .table_fail

	push ix
	ld ix, _lwip_jp_table_start + 1		; first trampoline operand
.patch_loop:
	ld a, b
	or a, c
	jr z, .patch_done

	push hl
	ld hl, (hl)				; entry: installer-relocated app address
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
	ld a, 0
	ret

.app_missing:
	ld a, 1
	jr .fail
.table_fail:
	ld a, 2
	jr .fail
.fail:
	pop ix
	ret

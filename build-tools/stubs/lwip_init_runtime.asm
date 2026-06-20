; lwip_init_runtime_opaque(malloc, free, realloc)
;   Stores the three CRTs in _fn_imports_table, locates the lwIP app, verifies
;   the export-table magic, and patches the shared prefix of the in-lib
;   trampolines (jp 0) to point at their real in-app function addresses.
;
; App presence is checked first with the self-contained _find_lwip_app flash
; app-table walk below because the OS FindAppStart is not safe to call when
; the app is absent. Only once present do we call FindAppStart for the CE app
; container base. The linked image base is then computed from the installed app
; metadata, matching the installer relocation logic. __lwip_fn_table_off is a
; fixed ABI offset from that linked image base to _fn_exports_table.

__lwip_fn_table_off := 0x000040
__lwip_expected_export_count := 0x000000

	export lwip_start_with_crt
	export lwip_get_start_errstring
	export lwip_is_newer

__lwip_app_name:
	db "lwIP", 0
__lwip_error_lut:
	dl __err_library_not_found_str
	dl __err_library_invalid_str
	dl __err_library_too_old_str
	dl __err_lwip_init_failed_str
__err_library_not_found_str:
	db "library missing",0
__err_library_invalid_str:
	db "library format",0
__err_library_too_old_str:
	db "install newer library",0
__err_lwip_init_failed_str:
	db "runtime-int failed",0

	__lwip_errno		db		0
	__lwip_is_newer		db		0
	__lwip_max_errno	equ		4

lwip_is_newer:
	ld a, (__lwip_is_newer)
	ret

; char *lwip_get_start_errstring(void);
;   Reports the reason for the last lwip_start_with_crt() failure 
lwip_get_start_errstring:
	ld a, (__lwip_errno)
	or a
	jr z, .invalid_errno		; exit if a == 0
	dec a						; 0 == ERR_OK, so get dec 1
	cp a, __lwip_max_errno
	jr nc, .invalid_errno		; exit if a > __lwip_error_ct
	ld l, a						; index into l
	ld h, 3						; 3 into h
	mlt hl						; hl = h * l (index * 3, LUT entry stride)
	ld de, __lwip_error_lut
	add hl, de					; hl = lut base + (index * 3)
	ld hl, (hl)					; address at hl into hl
	ret							; return hl pointing to err string
.invalid_errno:
	ld	hl, 0
	ret							; return hl = NULL


; uint8_t lwip_start_with_crt(malloc, free, realloc)
;	returns true or false, errno internal
;	call lwip_get_start_errno and/or lwip_is_newer if you care
lwip_start_with_crt:
	call ti._frameset0
	xor a
	ld (__lwip_is_newer), a
	ld hl, (ix + 6)
	ld (_fn_imports_table + 0), hl		; malloc
	ld hl, (ix + 9)
	ld (_fn_imports_table + 3), hl		; free
	ld hl, (ix + 12)
	ld (_fn_imports_table + 6), hl		; realloc

	push iy
	ld iy, ti.flags
	ld hl, __lwip_app_name
	call ti.FindAppStart
	pop iy
	jp c, .app_missing

.app_found:
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

	; Append-mode slot ABI guarantees existing entries never move or get
	; renumbered across builds — only new ones are added at the end. Patch
	; the shared prefix, i.e. min(app_count, stub_count). Missing trailing
	; exports remain unavailable to this pairing instead of aborting startup.
	push hl
	ld hl, __lwip_expected_export_count
	or a, a
	sbc hl, bc				; expected - actual
	pop hl
	jr z, .count_ready			; equal: copy all
	jr nc, .count_ready			; expected > actual: bc already actual
	ld bc, __lwip_expected_export_count	; expected < actual: clamp to expected
	ld a, 1
	ld (__lwip_is_newer), a

.count_ready:
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

	; Trampolines are live — call into the app to do BSS/.data init, copy
	; our imports table into its reserved fn_imports_table, and bring up
	; the no-network stack (memory/timers/RNG).
	;   bool lwip_init_runtime_internal(const void *src, size_t len);
	ld hl, _fn_imports_table_end - _fn_imports_table
	push hl					; arg2: len
	ld hl, _fn_imports_table
	push hl					; arg1: src
	call lwip_init_runtime_internal
	pop hl
	pop hl

	pop ix
	or a
	jr z, .stack_init_failed
	ld a, 1
	ret

.stack_init_failed:
	ld a, 4
	jr .exit_fail
.lib_too_old:
	ld a, 3
	jr .exit_fail
.table_fail:
	ld a, 2
	jr .exit_fail
.app_missing:
	ld a, 1
.exit_fail:
	ld (__lwip_errno), a
	pop ix				; undo ti._frameset0's push ix
	xor a
	ret

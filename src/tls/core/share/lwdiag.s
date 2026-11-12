; TEMPORARY DIAGNOSTIC (nettls NMI hunt). Remove with diag_trap.h.
; uintptr_t lwdiag_ix(void) -> caller's frame pointer, for the saved-IX walk.
.assume adl=1

.section	.text,"ax",@progbits
.globl _lwdiag_ix
.type _lwdiag_ix,@function
_lwdiag_ix:
	lea	hl, ix + 0
	ret

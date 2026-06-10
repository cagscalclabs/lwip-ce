.assume adl=1

; ---------------------------------------------------------------------------
; Static TLS crypto scratch regions (.bss / RAM).
;
; These replace deep stack allocations in the crypto call chain
; (truststore_init -> rsa_decrypt_signature -> powmod) that pushed the eZ80
; stack ~900 B down a single leaf and risked overflow in the resident dylib.
; Both regions are pure scratch: nothing here persists across calls, and the
; two are used by routines that are never live at the same instant.
;
;   __tls_scratch    520 B  -- powmod_exp_u24 inner working buffers
;                              (Lacc + Ltmp for an RSA-2048 modulus, formerly
;                              carved off the stack via `ld sp`).
;   __rsa_transient  256 B  -- RSA OAEP/PSS encoded-message buffer (e.g. the
;                              decrypted-signature output `d_sig`), formerly a
;                              256-byte stack local in the C callers.
;
; __rsa_transient is exported for use from C. The eZ80 C ABI prepends one
; underscore to C identifiers, so the C name `__rsa_transient` resolves to the
; asm symbol `___rsa_transient`. Declare it in C as:
;     extern uint8_t __rsa_transient[256];
; ---------------------------------------------------------------------------

.equ	__tls_scratch.size,    520
.equ	__rsa_transient.size,  256

; powmod inner scratch -- asm-only consumer. Both the base and the end label
; are exported: bigint.s anchors its working buffers at __tls_scratch_end-1
; and walks downward.
globl	__tls_scratch
globl	__tls_scratch_end
.section	.bss.__tls_scratch,"aw",@nobits
__tls_scratch:
	.space	__tls_scratch.size
__tls_scratch_end:

; RSA OAEP/PSS encoded-message scratch -- shared between asm and C.
; `___rsa_transient` is the C-visible symbol for `__rsa_transient` in C.
globl	___rsa_transient
.section	.bss.__rsa_transient,"aw",@nobits
___rsa_transient:
	.space	__rsa_transient.size
___rsa_transient_end:

.section	.note.GNU-stack,"",@progbits

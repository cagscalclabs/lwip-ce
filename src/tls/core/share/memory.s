.assume adl=1

; ---------------------------------------------------------------------------
; Shared crypto scratch layout note.
;
; The single authoritative scratch buffer is .bss.__p256_scratch (p256.s).
; The linker script (build-tools/meta/linker_script_lwip.ld) provides the
; following aliases so that powmod, HKDF, and the RSA transient callers can
; use canonical names without knowing P-256 internals:
;
;   __tls_scratch_start  = __p256_scratch_start  (also: __tls_scratch)
;   __tls_scratch_end    = __p256_scratch_end
;
; All consumers (P-256, powmod, X25519 via x25519.s, HKDF) are mutually
; exclusive at runtime; one 1647-byte buffer covers all.
;
; scratch.inc (same directory) externs __tls_scratch_start/_end for asm
; consumers; rsa.h declares __tls_scratch_start for C consumers.
; ---------------------------------------------------------------------------

.section .note.GNU-stack,"",@progbits

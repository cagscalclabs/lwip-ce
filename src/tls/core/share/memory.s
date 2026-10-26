.assume adl=1

; ---------------------------------------------------------------------------
; Shared crypto scratch layout note.
;
; RSA/powmod/HKDF have their own reserved member in the linker-enforced crypto
; scratch overlay. The linker defines its bounds and the canonical aliases so
; consumers do not need to know this member's private name:
;
;   __tls_scratch_start  = __rsa_scratch_start  (also: __tls_scratch)
;   __tls_scratch_end    = __rsa_scratch_end
;
; P-256, RSA/HKDF, and X25519 are mutually exclusive at runtime. Their
; independently sized sections occupy one BSS address through OVERLAY.
;
; scratch.inc (same directory) externs __tls_scratch_start/_end for asm
; consumers; rsa.h declares __tls_scratch_start for C consumers.
; ---------------------------------------------------------------------------

.section .note.GNU-stack,"",@progbits

; scratch.inc -- shared crypto scratch aliases
;
; The RSA/HKDF member of the linker-enforced scratch overlay is defined in
; share/memory.s and exported as __tls_scratch_start / __tls_scratch_end.
;
; P-256, RSA/HKDF, and X25519 are mutually exclusive at runtime, so their
; separate input sections share one output address.

extern __tls_scratch_start
extern __tls_scratch_end

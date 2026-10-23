; scratch.inc -- shared crypto scratch aliases
;
; The consolidated scratch buffer is defined in share/memory.s and exported as
; __tls_scratch_start / __tls_scratch_end.  Each consumer .include "scratch.inc"
; and then uses the canonical names directly, or defines its own aliases below.
;
; Consumers are mutually exclusive at runtime (P-256, powmod, X25519 never
; overlap), so all share one 1647-byte .bss block.

extern __tls_scratch_start
extern __tls_scratch_end

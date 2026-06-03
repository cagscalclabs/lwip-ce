
;--------------------------------
; SHA256_CTX
.equ	sha256_offset_data,    0
.equ	sha256_offset_datalen, sha256_offset_data + 64
.equ	sha256_offset_bitlen,  sha256_offset_datalen + 1
.equ	sha256_offset_state,   sha256_offset_bitlen + 8
.equ	_sha256ctx_size,       sha256_offset_state + 4 * 8

; ------------------------------
; snrg / common sha state
;
; _sprng_entropy_pool is the base of the .saferam.rng overlay member,
; provided by the linker (linker_script_lwip.ld) at 0xE30800. It shares
; that address window with the relocated X25519 hot loop — the two are
; never live simultaneously (used as quick scratch). The offsets below
; remain assemble-time constants relative to that base; only the base is
; now a relocatable symbol rather than a literal address.
extern	_sprng_entropy_pool
.equ	_sprng_entropy_pool.size, 119
.equ	_sprng_sha_digest,   _sprng_entropy_pool + _sprng_entropy_pool.size
.equ	_sprng_sha_mbuffer,  _sprng_sha_digest + 32
.equ	_sprng_rand,         _sprng_sha_mbuffer + 64 * 4
.equ	_sprng_hash_ctx,     _sprng_rand + 8
; Offset (in bytes) of _sprng_rand from the entropy pool base — i.e.
; (_sprng_sha_digest 32) + (_sprng_sha_mbuffer 64*4) on top of the pool.
; Defined via literal arithmetic so it stays an assemble-time constant now
; that _sprng_entropy_pool is an external (overlay) symbol — a direct
; "_sprng_rand - _sprng_entropy_pool" can no longer be folded.
.equ	_sprng_rand.offset,  _sprng_entropy_pool.size + 32 + 64 * 4

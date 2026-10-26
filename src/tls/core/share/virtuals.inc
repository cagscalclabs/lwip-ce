
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
; _sprng_entropy_pool is the scratch base within the .saferam.rng overlay
; member. The linker reserves the first 384 bytes of fastMem for the SHA-256
; compression loop, then places this 520-byte region above it. Other overlay
; consumers replace the whole window and are never live at the same time.
extern	_sprng_entropy_pool
.equ	_sprng_entropy_pool.size, 119
.equ	_sprng_sha_digest.size, 32
.equ	_sprng_sha_digest,   _sprng_entropy_pool + _sprng_entropy_pool.size
.equ	_sprng_sha_mbuffer,  _sprng_sha_digest + _sprng_sha_digest.size
.equ	_sprng_rand,         _sprng_sha_mbuffer + 64 * 4
.equ	_sprng_hash_ctx,     _sprng_rand + 8
.equ	_sprng_overlay.size, _sprng_entropy_pool.size + _sprng_sha_digest.size + 64 * 4 + 8 + _sha256ctx_size
; Offset (in bytes) of _sprng_rand from the entropy pool base — i.e.
; (_sprng_sha_digest 32) + (_sprng_sha_mbuffer 64*4) on top of the pool.
; Defined via literal arithmetic so it stays an assemble-time constant now
; that _sprng_entropy_pool is an external (overlay) symbol — a direct
; "_sprng_rand - _sprng_entropy_pool" can no longer be folded.
.equ	_sprng_rand.offset,  _sprng_entropy_pool.size + _sprng_sha_digest.size + 64 * 4

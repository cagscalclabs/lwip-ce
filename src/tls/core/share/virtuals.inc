
;--------------------------------
; SHA256_CTX
.equ	sha256_offset_data,    0
.equ	sha256_offset_datalen, sha256_offset_data + 64
.equ	sha256_offset_bitlen,  sha256_offset_datalen + 1
.equ	sha256_offset_state,   sha256_offset_bitlen + 8
.equ	_sha256ctx_size,       sha256_offset_state + 4 * 8

; ------------------------------
; snrg / common sha state
.equ	_sprng_entropy_pool.size, 119
.equ	_sprng_entropy_pool, 0xE30800
.equ	_sprng_sha_digest,   _sprng_entropy_pool + _sprng_entropy_pool.size
.equ	_sprng_sha_mbuffer,  _sprng_sha_digest + 32
.equ	_sprng_rand,         _sprng_sha_mbuffer + 64 * 4
.equ	_sprng_hash_ctx,     _sprng_rand + 8

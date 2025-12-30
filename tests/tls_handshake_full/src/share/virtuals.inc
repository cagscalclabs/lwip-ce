
;--------------------------------
; SHA256_CTX
virtual at 0
	sha256_offset_data     rb 64
	sha256_offset_datalen  rb 1
	sha256_offset_bitlen   rb 8
	sha256_offset_state    rb 4*8
	_sha256ctx_size:
end virtual

; ------------------------------
; snrg / common sha state
_sprng_entropy_pool.size = 119
virtual at $E30800
    _sprng_entropy_pool     rb _sprng_entropy_pool.size
    _sprng_sha_digest       rb 32
    _sprng_sha_mbuffer      rb (64*4)
    _sprng_rand             rb 8
    _sprng_hash_ctx         rb _sha256ctx_size
    _sprng_read_addr        rb 3

end virtual

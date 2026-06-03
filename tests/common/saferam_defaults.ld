/* Default placement for the RNG safe-RAM scratch base, for standalone
 * unit/profiling test programs.
 *
 * In the real lwIP app, _sprng_entropy_pool is defined by the .saferam.rng
 * member of the safe-RAM OVERLAY in linker_script_lwip.ld (shared with the
 * X25519 hot loop at 0xE30800). The standalone tests don't build that
 * overlay, so virtuals.inc's `extern _sprng_entropy_pool` would be
 * undefined at link time. PROVIDE supplies the same fixed hardware address
 * (ti.cursorImage) as a default — it yields to any real definition, so this
 * is harmless if a test ever does define the symbol itself. */
PROVIDE(_sprng_entropy_pool = 0xE30800);

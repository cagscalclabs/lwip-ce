;--------------------------------------------
; TRNG
; Author: nefariousarcher, beckadamtheinventor
;--------------------------------------------
; include to supported algorithms



.assume adl=1
.section	.text,"ax",@progbits

.include "virtuals.inc"

globl _tls_random_init_entropy
globl _tls_entropy_collect
globl _tls_random_debug_source_ptr
globl _tls_random_debug_source_mask
globl _tls_random_health_epoch
; Exported for the C layer to read and log after tls_entropy_collect()
; returns -- see tls_rng_log_asm_health() in random.c. Read-only from C.
globl _sprng_consec_health_fails
globl _sprng_recovery_rescanned
.type _tls_random_init_entropy,@function
.type _tls_entropy_gather256,@function
.type _tls_entropy_collect,@function
.type _tls_random_debug_source_ptr,@function
.type _tls_random_debug_source_mask,@function
.type _tls_random_health_epoch,@function


;-------------------------------------
; bool tls_random_init_entropy(void);
;
; Scan 513 byte addresses beginning at $D65800. Each address is evaluated
; per bit from 256 adjacent read pairs (512 raw reads):
;
;   - marginal ones must be within [128, 384] (observed 25/75 bound), and
;   - pair disagreements must be within [64, 192].
;
; Among qualifying bits, prefer the disagreement count closest to 128. The
; selected address/bit pair is then validated (.Linit_validate_candidate):
; first by an SP 800-90B §4.3 start-up test -- 1024 samples drawn through
; .Lsample_bits, the exact code path and sample spacing used by generation,
; all of which must pass the continuous RCT/APT (.Lsample_health_check) --
; and then by 512 fresh adjacent pairs (1024 raw reads) against the scaled
; marginal/disagreement bounds. Start-up samples are wiped and never conditioned or credited. Only the
; byte address is needed by tls_entropy_collect(); the bit mask is retained so raw
; source diagnostics can target the exact bit to which entropy is credited.
;
; Counter records use the RNG overlay because initialization and generation
; are never live at the same time:
;
;   byte +0: 24-bit marginal-one count
;   byte +3: 24-bit pair-disagreement count
;
; Eight records therefore consume 48 of the 119 entropy-pool bytes.
;
; While reads are being accumulated, the counts are kept bit-sliced instead
; (one byte per count bit, bit b of every plane belonging to source bit b),
; so one pair updates all eight source bits with a few byte-wide XOR/AND
; ripple steps. Two counters per bit are kept:
;
;   D = disagreeing pairs   (sum of s0 ^ s1)
;   A = pairs read as 1 1   (sum of s0 & s1)
;
; and ones = s0 + s1 summed = D + 2*A. Each counter is at most 512 (two
; 256-pair passes), so ten planes (values < 1024) hold it and a ripple carry
; can never leave plane 9. .Linit_decode_counters expands the planes into
; the records above; the selection and validation logic reads only the
; records.
.equ _sprng_init_plane_count,   10
.equ _sprng_init_records,       _sprng_entropy_pool
.equ _sprng_init_sample0,       _sprng_init_records + 48
.equ _sprng_init_sample1,       _sprng_init_sample0 + 1
.equ _sprng_init_best_addr,     _sprng_init_sample1 + 1
.equ _sprng_init_best_mask,     _sprng_init_best_addr + 3
.equ _sprng_init_best_score,    _sprng_init_best_mask + 1
.equ _sprng_init_eval_mask,     _sprng_init_best_score + 1
.equ _sprng_init_insert_addr,   _sprng_init_eval_mask + 1
.equ _sprng_init_insert_mask,   _sprng_init_insert_addr + 3
.equ _sprng_init_dplanes,       _sprng_entropy_pool + 64
.equ _sprng_init_aplanes,       _sprng_init_dplanes + _sprng_init_plane_count

; SP 800-90B continuous health-test parameters. The engineering Hmin floor is
; TLS_ENTROPY_HMIN_Q16 = 22282/65536 ≈ 0.34 bits per selected-bit sample.
; h_in = 952 * 0.34 = 323.68 bits >= n_out+64 = 320 (SP 800-90C full-entropy margin).
; With H=0.34 and alpha=2^-20:
;
;   RCT: C = 1 + ceil(20 / 0.34) = 60
;   APT: binary W=1024, C=870 (SP 800-90B §4.4.2, H=0.34, alpha=2^-20)
;
; The binary APT extension checks both the reference bit and its complement.
.equ _sprng_rct_cutoff,         60
.equ _sprng_apt_window,         1024
.equ _sprng_apt_cutoff,         870

; SP 800-90B §4.3 start-up test: 128 pool-format bytes = 1024 samples, i.e.
; exactly one complete APT window. The samples are written into the (idle)
; SHA message-buffer region of the overlay -- never into the entropy pool,
; whose low bytes hold the live _sprng_init_* selection scratch -- and are
; wiped before validation returns.
.equ _sprng_startup_bytes,           128
.equ _sprng_init_startup_samples,    _sprng_sha_mbuffer

; §4.5 post-collection tests: lag-k match counts (k=1..8) and first-order Markov.
; Null hypothesis: p(match at lag k) = p_s = 2^-H = 2^-0.34 ≈ 0.790 (H=0.34 claim).
; Family-wise alpha = 2^-20 per gather, split by Bonferroni over 18 tails (16 lag +
; 2 Markov), giving per-tail alpha ≈ 2^-24.17. Cutoffs from exact binomial quantiles.
; Markov: fail if n_sx*256 > n_s*243 for either state s. Worst-case FP = 2^-25.8
; (n_s in [150,475]). At n_s < 150 (unreachable under H=0.34) FP rises to ~2^-17.
;
; Raw pool: 119 bytes, n = 952 samples, tested after collection and before SHA-256.
; Lag-k match test: matches_k = #{ i < n-k : s[i] == s[i+k] }, n_k = n-k pairs.
; Fail if matches_k < LOW_k or matches_k > HIGH_k. (The routine counts
; mismatches; mismatches = (n-k) - matches, so the bounds table below holds
; [(n-k)-HIGH_k, (n-k)-LOW_k].)
.equ _sprng_post_n,             952
.equ _sprng_lag1_low,           136
.equ _sprng_lag1_high,          815
.equ _sprng_lag2_low,           136
.equ _sprng_lag2_high,          814
.equ _sprng_lag3_low,           135
.equ _sprng_lag3_high,          814
.equ _sprng_lag4_low,           135
.equ _sprng_lag4_high,          813
.equ _sprng_lag5_low,           135
.equ _sprng_lag5_high,          812
.equ _sprng_lag6_low,           135
.equ _sprng_lag6_high,          811
.equ _sprng_lag7_low,           135
.equ _sprng_lag7_high,          810
.equ _sprng_lag8_low,           135
.equ _sprng_lag8_high,          809

; First-order Markov test. For each state s in {0,1} with n_s transitions out
; of s, fail if n_s0 > MAX*n_s or n_s1 > MAX*n_s, evaluated exactly in
; integers as n_sx*256 > n_s*_sprng_markov_max_q8.
;   Fixed Q = 243 (MAX = 243/256 = 0.9492). Exact binomial at p = 2^-0.34:
;   worst-case per-tail FP = 2^-25.8 over n_s in [150,475], within the
;   2^-24.17 per-tail budget. Residual: for n_s < 150 (unreachable for a
;   healthy H=0.34 source) FP rises, reaching ~2^-17 at n_s = 100.
.equ _sprng_markov_max_q8,      243

; Tap abandonment: the third consecutive §4.5 failure on one tap forces
; .Lhealth_recover; earlier failures discard the pool and resample the tap.
.equ _sprng_post_max_consec,    3

; §4.5 scratch, in the overlay region that is idle until SHA-256 starts and
; is covered by every 520-byte overlay wipe:
;   _sprng_post_shifted: 119-byte copy of the pool, shifted left k bits
;   _sprng_post_*:       24-bit Markov intermediates
.equ _sprng_post_shifted,       _sprng_sha_digest
.equ _sprng_post_mis1,          _sprng_post_shifted + _sprng_entropy_pool.size
.equ _sprng_post_n1,            _sprng_post_mis1 + 3
.equ _sprng_post_ob,            _sprng_post_n1 + 3
.equ _sprng_post_n11,           _sprng_post_ob + 3
.equ _sprng_post_n0,            _sprng_post_n11 + 3
.equ _sprng_post_n01,           _sprng_post_n0 + 3

; .Lpost_tests unrolls its shift chain by 7 and its lag loop by 2.
.if (_sprng_entropy_pool.size % 7) <> 0
.error "pool size must be a multiple of 7 (.Lpost_tests shift chain)"
.endif
.if ((_sprng_entropy_pool.size - 1) % 2) <> 0
.error "pool size - 1 must be even (.Lpost_tests lag loop)"
.endif
; .Lsample_bits treats B = 0 as 256 bytes, which would corrupt the pool.
.if (_sprng_entropy_pool.size < 1) || (_sprng_entropy_pool.size > 255)
.error "pool size must be in 1..255 (.Lsample_bits byte counter)"
.endif
.if (_sprng_startup_bytes < 1) || (_sprng_startup_bytes > 255)
.error "startup bytes must be in 1..255 (.Lsample_bits byte counter)"
.endif

_tls_random_init_entropy:
    push ix
    push iy

    xor a,a
    ld (_sprng_init_best_score),a
    ld (_sprng_init_best_mask),a
    ld (_sprng_read_mask),a
    ld hl,0
    ld (_sprng_read_addr),hl

    ; The top three non-selected candidates survive initialization so a
    ; failed active source can be replaced without immediately rescanning all
    ; 513 addresses. Each record is {address[3], mask[1]}.
    ld hl,_sprng_backup_candidates
    ld (hl),0
    ld de,_sprng_backup_candidates+1
    ld bc,11
    ldir

    ld ix,$D65800
    ld bc,513
.Linit_scan_address:
    push bc
    call .Linit_clear_counters
    call .Linit_measure_256_pairs
    call .Linit_decode_counters
    call .Linit_consider_candidate
    pop bc

    inc ix
    dec bc
    ld a,b
    or a,c
    jr nz,.Linit_scan_address

    ; No bit met both discovery bounds.
    ld a,(_sprng_init_best_mask)
    or a,a
    jr z,.Linit_fail

    ; Revalidate the selected address/bit with 1024 fresh reads.
    ld ix,(_sprng_init_best_addr)
    ld a,(_sprng_init_best_mask)
    call .Linit_validate_candidate
    jr c,.Linit_fail

    ld hl,(_sprng_init_best_addr)
    ld (_sprng_read_addr),hl
    ld a,(_sprng_init_best_mask)
    ld (_sprng_read_mask),a
    call .Lhealth_reset
    ld a,(_sprng_health_epoch_value)
    inc a
    ld (_sprng_health_epoch_value),a
    ld a,1
    jr .Linit_return

.Linit_fail:
    ; Never expose a stale or partially selected source after failure.
    ld hl,0
    ld (_sprng_read_addr),hl
    xor a,a
    ld (_sprng_read_mask),a
.Linit_return:
    pop iy
    pop ix
    ret

; Revalidate IX/A as an address/mask candidate. Returns carry clear on
; success and carry set on failure. IX, _sprng_init_eval_mask (= A), the
; _sprng_init_* selection scratch, and _sprng_read_addr/_sprng_read_mask are
; preserved. RCT/APT/consecutive-failure state is reset on both exits.
.Linit_validate_candidate:
    ld (_sprng_init_eval_mask),a

    ; SP 800-90B §4.3 start-up test. .Lsample_bits samples, and
    ; .Lsample_health_check tests, the bit selected by _sprng_read_mask, so
    ; point it at the candidate for the duration of both and restore the
    ; caller's value afterwards.
    ld a,(_sprng_read_mask)
    ld c,a
    push bc
    ld a,(_sprng_init_eval_mask)
    ld (_sprng_read_mask),a
    call .Lhealth_reset
    lea hl,ix+0
    ld de,_sprng_init_startup_samples
    ld b,_sprng_startup_bytes
    call .Lsample_bits
    ld hl,_sprng_init_startup_samples
    ld b,_sprng_startup_bytes
    call .Lsample_health_check      ; CF set: a sample failed RCT or APT
    pop bc                          ; POP/LD/LDIR below leave CF intact
    ld a,c
    ld (_sprng_read_mask),a
    ; Start-up samples are test-only: destroy them, never condition them.
    ld hl,_sprng_init_startup_samples
    ld (hl),0
    ld de,_sprng_init_startup_samples+1
    ld bc,_sprng_startup_bytes-1
    ldir
    jr c,.Linit_validate_fail

    ; Additional fixed marginal/disagreement gates on 1024 fresh reads.
    call .Linit_clear_counters
    call .Linit_measure_256_pairs
    call .Linit_measure_256_pairs
    call .Linit_decode_counters

    ; Locate the selected bit's six-byte counter record.
    ld iy,_sprng_init_records
    ld a,(_sprng_init_eval_mask)
.Linit_find_validation_record:
    rrca
    jr c,.Linit_validate_record
    lea iy,iy+6
    jr .Linit_find_validation_record

.Linit_validate_record:
    ; 1024 marginal samples: require 256 <= ones <= 768.
    ld bc,(iy+0)
    push bc
    pop hl
    ld de,256
    or a,a
    sbc hl,de
    jr c,.Linit_validate_fail
    push bc
    pop hl
    ld de,769
    or a,a
    sbc hl,de
    jr nc,.Linit_validate_fail

    ; 512 adjacent pairs: require 128 <= disagreements <= 384.
    ld bc,(iy+3)
    push bc
    pop hl
    ld de,128
    or a,a
    sbc hl,de
    jr c,.Linit_validate_fail
    push bc
    pop hl
    ld de,385
    or a,a
    sbc hl,de
    jr nc,.Linit_validate_fail
    call .Lhealth_reset             ; start-up state never leaks into use
    or a,a
    ret
.Linit_validate_fail:
    call .Lhealth_reset
    scf
    ret

; Clear the bit-sliced D and A counters (both plane sets are contiguous).
.Linit_clear_counters:
    ld hl,_sprng_init_dplanes
    ld (hl),0
    ld de,_sprng_init_dplanes+1
    ld bc,2*_sprng_init_plane_count-1
    ldir
    ret

; Accumulate 256 adjacent read pairs from the byte at IX into the
; bit-sliced counters. Counters are not cleared here so the routine can be
; called twice for validation. Clobbers AF, BC, DE, HL.
.Linit_measure_256_pairs:
    ld b,0
.Linit_measure_pair:
    ; Keep the physical reads adjacent. All data-dependent counter work is
    ; performed only after both samples have been acquired.
    ld a,(ix)
    ld d,a
    ld a,(ix)
    ld e,a
    xor a,d
    ld c,a                          ; bits whose two reads disagree
    ld hl,_sprng_init_dplanes
    ; Add the one-bit-per-lane vector C to the counter whose plane 0 is at
    ; HL: ripple carry, stopping as soon as no lane carries.
.Linit_add_d:
    ld a,(hl)
    xor a,c
    ld (hl),a                       ; plane ^= carry-in
    xor a,c                         ; old plane
    and a,c                         ; carry-out = old plane & carry-in
    jr z,.Linit_add_d_done
    ld c,a
    inc hl
    jr .Linit_add_d
.Linit_add_d_done:
    ld a,d
    and a,e
    ld c,a                          ; bits read as 1 both times
    ld hl,_sprng_init_aplanes
.Linit_add_a:                       ; same ripple add as above
    ld a,(hl)
    xor a,c
    ld (hl),a
    xor a,c
    and a,c
    jr z,.Linit_add_a_done
    ld c,a
    inc hl
    jr .Linit_add_a
.Linit_add_a_done:
    djnz .Linit_measure_pair
    ret

; Expand the bit-sliced counters into the eight {ones, disagreements}
; records (record b <- source bit b). Consumes (right-shifts) the planes.
; Clobbers AF, BC, DE, HL, IY.
.Linit_decode_counters:
    ld iy,_sprng_init_records
    ld c,8
.Linit_decode_lane:
    ld hl,_sprng_init_aplanes+_sprng_init_plane_count-1
    call .Linit_decode_count
    push de                         ; A = pairs read as 1 1
    ld hl,_sprng_init_dplanes+_sprng_init_plane_count-1
    call .Linit_decode_count        ; DE = D = disagreeing pairs
    ld (iy+3),de
    pop hl
    add hl,hl
    add hl,de                       ; ones = D + 2*A
    ld (iy+0),hl
    lea iy,iy+6
    dec c
    jr nz,.Linit_decode_lane
    ret

; DE = the count whose top plane is at HL, built from bit 0 of each plane
; (top plane first); every plane is shifted right by one lane.
; Clobbers AF, B, DE, HL.
.Linit_decode_count:
    ld de,0
    ld b,_sprng_init_plane_count
.Linit_decode_plane:
    srl (hl)
    rl e
    rl d
    dec hl
    djnz .Linit_decode_plane
    ret

; Evaluate all eight bits from one discovery sample. Marginal balance is a
; hard gate. Among passing bits, maximize min(flips, 256-flips), which
; prefers active but non-alternating sources.
.Linit_consider_candidate:
    ld iy,_sprng_init_records
    ld a,1
    ld (_sprng_init_eval_mask),a
.Linit_consider_bit:
    ; 512 marginal samples: require 128 <= ones <= 384.
    ld hl,(iy+0)
    ld de,128
    or a,a
    sbc hl,de
    jr c,.Linit_consider_next
    add hl,de
    ld de,385
    or a,a
    sbc hl,de
    jr nc,.Linit_consider_next

    ; 256 adjacent pairs: require 64 <= disagreements <= 192.
    ld hl,(iy+3)
    ld de,64
    or a,a
    sbc hl,de
    jr c,.Linit_consider_next
    add hl,de
    ld de,193
    or a,a
    sbc hl,de
    jr nc,.Linit_consider_next
    add hl,de

    ; Score is min(flips, 256-flips), in the range [64, 128].
    ld a,l
    cp a,129
    jr c,.Linit_score_ready
    xor a,a
    sub a,l
.Linit_score_ready:
    ld e,a
    ld a,(_sprng_init_best_score)
    cp a,e
    jr c,.Linit_replace_best
    jr z,.Linit_cache_equal
    jr .Linit_consider_next

.Linit_replace_best:
    ; Preserve the displaced winner as the first backup candidate.
    ld a,(_sprng_init_best_mask)
    or a,a
    jr z,.Linit_store_best
    ld hl,(_sprng_init_best_addr)
    push de
    call .Linit_cache_backup
    pop de
.Linit_store_best:
    ld a,e
    ld (_sprng_init_best_score),a
    lea hl,ix+0
    ld (_sprng_init_best_addr),hl
    ld a,(_sprng_init_eval_mask)
    ld (_sprng_init_best_mask),a
    jr .Linit_consider_next

.Linit_cache_equal:
    ; Equal-scoring taps are excellent fallbacks even though the first one
    ; remains the deterministic primary selection.
    lea hl,ix+0
    ld a,(_sprng_init_eval_mask)
    call .Linit_cache_backup

.Linit_consider_next:
    lea iy,iy+6
    ld a,(_sprng_init_eval_mask)
    add a,a
    ld (_sprng_init_eval_mask),a
    jp nz,.Linit_consider_bit
    ret

; Insert HL/A at the front of the three-record backup cache, dropping the
; oldest record. This cache is deliberately outside the RNG scratch overlay
; because it must survive after initialization returns.
.Linit_cache_backup:
    ld (_sprng_init_insert_addr),hl
    ld (_sprng_init_insert_mask),a
    ld hl,_sprng_backup_candidates+7
    ld de,_sprng_backup_candidates+11
    ld bc,8
    lddr
    ld hl,(_sprng_init_insert_addr)
    ld (_sprng_backup_candidates),hl
    ld a,(_sprng_init_insert_mask)
    ld (_sprng_backup_candidates+3),a
    ret

;--------------------------------------
; Internal 256-bit conditioned-source gather used by tls_entropy_collect().
; All sensitive state here (_sprng_entropy_pool, _sprng_sha_digest,
; _sprng_sha_mbuffer, _sprng_hash_ctx) lives in a BSS overlay, never on
; this function's own stack frame -- tls_crypto_guard_disable() (a
; stack scrub) was never capable of reaching it regardless of where it
; was called from. The entropy pool/SHA scratch is explicitly zeroed
; by tls_entropy_collect() after the digest has been copied to the caller.
_tls_entropy_gather256:
    xor a,a
    ld (_sprng_random_last_ok),a
    ld (_sprng_recovery_rescanned),a
.Lrandom_retry:

; Populate the 119-byte entropy pool with 952 consecutive observations of the
; selected source bit. Each pool byte preserves eight observations in arrival
; order (first observation becomes bit 7); SHA-256 conditions the complete raw
; bitstream below. Do not XOR observations together here: doing so collapses
; several source observations into one bit before the conditioner sees them.
    ld hl,(_sprng_read_addr)
    ld de,_sprng_entropy_pool
    ld b,_sprng_entropy_pool.size
    call .Lsample_bits
; SP 800-90B §4.4 continuous tests (RCT/APT) over the collected samples, in
; arrival order, before anything else reads the pool.
    ld hl,_sprng_entropy_pool
    ld b,_sprng_entropy_pool.size
    call .Lsample_health_check
    jr c,.Lrandom_health_fail

; SP 800-90B §4.5 post-collection tests on the raw pool, before conditioning.
    call .Lpost_tests
    jr c,.Lrandom_post_fail
    xor a,a
    ld (_sprng_consec_health_fails),a

; hash the entropy pool sha256
    ld hl, _sprng_hash_ctx
    push hl
    call _tls_sha256_init
    pop bc
    ld hl, 119
    push hl
    ld hl, _sprng_entropy_pool
    push hl
    push bc
    call _tls_sha256_update
    pop bc
    pop hl
    pop hl
    ld hl, _sprng_sha_digest
    push hl
    push bc
    call _tls_sha256_digest
    pop bc
    pop hl

; tls_entropy_collect() copies the full 256-bit digest directly. Avoid
; the former custom XOR-folding step and leave the digest live only until that
; copy completes.
    ld a,1
    ld (_sprng_random_last_ok),a
.Lrandom_return:
    ret

.Lrandom_post_fail:
    ; The pool failed a §4.5 test. It is never conditioned. Count the failure
    ; against this tap; on the third consecutive failure abandon the tap via
    ; the continuous-test failure path below.
    ld hl,_sprng_consec_health_fails
    inc (hl)
    ld a,(hl)
    cp a,_sprng_post_max_consec
    jr nc,.Lrandom_health_fail
    ; Below the abandonment threshold: destroy the pool and the §4.5 scratch,
    ; advance the epoch so the C layer discards this step, and resample the
    ; same tap (its RCT/APT state continues uninterrupted).
    ld hl,_sprng_entropy_pool
    ld (hl),0
    ld de,_sprng_entropy_pool+1
    ld bc,519
    ldir
    ld a,(_sprng_health_epoch_value)
    inc a
    ld (_sprng_health_epoch_value),a
    jp .Lrandom_retry

.Lrandom_health_fail:
    ; The current pool contains observations from a source that has failed a
    ; continuous health test. Destroy it before attempting any replacement.
    ld hl,_sprng_entropy_pool
    ld (hl),0
    ld de,_sprng_entropy_pool+1
    ld bc,519
    ldir
    ld a,(_sprng_health_epoch_value)
    inc a
    ld (_sprng_health_epoch_value),a
    call .Lhealth_recover
    jp nc,.Lrandom_retry

    ; No source survived cached-candidate validation or one complete rescan.
    xor a,a
    ld (_sprng_random_last_ok),a
    jr .Lrandom_return

; Collect B pool-format bytes (8*B samples) of the selected bit at (HL) into
; (DE). Each byte holds eight observations in arrival order (first becomes
; bit 7). This is the single sampling path used by both generation (B = 119)
; and the start-up test (B = 128), so both measure the same process at the
; same sample spacing. No health test runs here: the caller must pass the
; collected bytes through .Lsample_health_check before using them.
;
; Every read is the same four-instruction slot (read, mask, bit -> CF, shift)
; and the loop has no data-dependent branches, so the read schedule is fixed:
; seven identical intervals inside each byte, then one longer interval (the
; store and loop overhead) between bytes, for every byte of every call.
; Interrupts, if enabled, still add their own gaps as they always have.
;
; In:  HL = source byte address, DE = destination, B = byte count (1..255)
; Out: CF clear; DE advanced by B.
; Preserves HL, IX, IY. Clobbers AF, BC, DE.
;
; Internal: C = selected-bit mask, B = byte being assembled, IYL = bytes left.
.Lsample_bits:
    push iy
    ld iyl,b                        ; IYL = bytes left
    ld a,(_sprng_read_mask)
    ld c,a                          ; C = selected-bit mask
.Lsample_byte:
    ; A is 0 or the mask; adding $FF carries iff it is nonzero, and RL B
    ; shifts that sample in, so the first read ends up in bit 7.
    ld a,(hl)
    and a,c
    add a,$FF
    rl b
    ld a,(hl)
    and a,c
    add a,$FF
    rl b
    ld a,(hl)
    and a,c
    add a,$FF
    rl b
    ld a,(hl)
    and a,c
    add a,$FF
    rl b
    ld a,(hl)
    and a,c
    add a,$FF
    rl b
    ld a,(hl)
    and a,c
    add a,$FF
    rl b
    ld a,(hl)
    and a,c
    add a,$FF
    rl b
    ld a,(hl)
    and a,c
    add a,$FF
    rl b
    ld a,b
    ld (de),a
    inc de
    dec iyl
    jr nz,.Lsample_byte
    pop iy
    or a,a                          ; CF clear: health not yet checked
    ret

; SP 800-90B continuous health tests (RCT and APT) over B pool-format bytes
; at HL, i.e. 8*B samples in arrival order (bit 7 of each byte first). The
; tests use the selected bit given by _sprng_read_mask, so the caller must
; leave that mask exactly as it was when the bytes were collected.
;
; The result, and on success the final _sprng_rct_* / _sprng_apt_* /
; _sprng_health_current state, are identical to feeding every sample, in
; order, through .Lhc_sample (the per-sample state machine, formerly
; .Lhealth_observe, unchanged). A failure is reported iff some sample would
; fail there; the state is then left partially updated, and every failure
; path in this file resets it (.Lhealth_reset) before reuse.
;
; In:  HL = buffer, B = byte count (1..255)
; Out: CF clear: every sample passed. CF set: a sample failed RCT or APT.
; Preserves IX, IY. Clobbers AF, BC, DE, HL. _sprng_sample_byte is scratch.
;
; Method. Callers always hand over whole bytes, so the APT position is a
; multiple of 8 on entry and every window boundary falls between bytes.
; (Any other position is handled exactly, sample by sample, by
; .Lhc_reference.) The bytes are then split into segments, each lying
; inside one APT window, and scanned once:
;
;   APT: a segment's samples are tallied by popcount and folded in when the
;        segment ends: matches += samples equal to the reference, other +=
;        the rest, position += 8n (1024 -> 0). A segment starting at
;        position 0 first opens the window: reference = its first sample,
;        counts zeroed (that sample then counts as its own match). Counts
;        only grow inside a window and both start below the cutoff, so a
;        sample of the segment reaches the cutoff iff a count does after it.
;   RCT: a run inside non-uniform bytes is at most 7 + 7 samples long, so
;        only runs touching a uniform ($00/$FF) byte, or the run carried in
;        from the previous call, can reach the cutoff. The run state
;        (_sprng_rct_previous, _sprng_rct_count) always describes the run
;        ending just before the address P kept on the stack (initially the
;        buffer). Each uniform byte extends or restarts that run exactly;
;        when a run is followed by a non-uniform byte, its leading samples
;        that continue the run are checked by .Lhc_cross. At the end the
;        state is the run ending at the last sample.
;
; Scan registers: DE = next byte, HL = popcount table, BCU = B = 0 with the
; table index in C, IY = ones in this segment, IXL = bytes left in the
; segment, IXH = segment length. _sprng_sample_byte = bytes not yet in a
; segment.
.Lsample_health_check:
    push ix
    push iy
    ex de,hl                        ; DE = buffer
    ld a,(_sprng_apt_position)
    and a,7
    jp nz,.Lhc_reference            ; a window boundary inside a byte
    ld a,(_sprng_rct_valid)
    or a,a
    jr nz,.Lhc_primed
    ; First sample since a reset: .Lhc_sample would set valid, previous =
    ; that sample, count = 1. Starting from previous = that sample and
    ; count = 0, the sample itself extends the run to exactly that state.
    inc a
    ld (_sprng_rct_valid),a
    ld a,(de)
    rlca
    sbc a,a                         ; first sample replicated
    ld hl,_sprng_read_mask
    and a,(hl)
    ld (_sprng_rct_previous),a
    xor a,a
    ld (_sprng_rct_count),a
.Lhc_primed:
    push de                         ; P = buffer
    ld a,b
    ld (_sprng_sample_byte),a       ; bytes not yet in a segment
    ld bc,0

.Lhc_segment:
    ld hl,(_sprng_apt_position)     ; multiple of 8, 0..1016
    ld a,h
    or a,l
    jr nz,.Lhc_window_open
    ; Position 0: this byte's first sample opens a new window.
    ld a,(de)
    rlca
    sbc a,a
    ld hl,_sprng_read_mask
    and a,(hl)
    ld (_sprng_apt_reference),a     ; first sample as 0 / mask
    sbc hl,hl                       ; HL = 0 (CF = 0 after AND)
    ld (_sprng_apt_matches),hl
    ld (_sprng_apt_other),hl
.Lhc_window_open:
    ; Bytes to the end of the window: 128 - position/8 (1..128).
    ld a,l
    srl h
    rra
    srl h
    rra
    srl h
    rra                             ; A = position/8 (0..127)
    neg
    add a,128
    ld c,a
    ld a,(_sprng_sample_byte)
    sub a,c
    jr nc,.Lhc_segment_len          ; segment = rest of the window
    add a,c
    ld c,a                          ; segment = all remaining bytes
    xor a,a
.Lhc_segment_len:
    ld (_sprng_sample_byte),a
    ld ixl,c
    ld ixh,c
    ld iy,0
    ld hl,.Lpost_popcount8
.Lhc_scan:
    ld a,(de)
    inc de
    ld c,a
    add hl,bc                       ; no carry out of 24 bits: CF = 0
    ld a,(hl)
    sbc hl,bc                       ; restore the table base
    ld c,a
    add iy,bc                       ; ones += popcount
    and a,7
    jr z,.Lhc_uniform               ; popcount 0 or 8: $00 or $FF
.Lhc_scan_next:
    dec ixl
    jr nz,.Lhc_scan
    jr .Lhc_segment_end

.Lhc_uniform:
    ; Byte b at DE-1 is $00 or $FF.
    dec de                          ; DE = &b
    pop hl
    push hl                         ; HL = P
    or a,a
    sbc hl,de
    jr z,.Lhc_uniform_run           ; the stored run ends just before b
    ; The stored run was followed by the non-uniform byte at P: finish it.
    ; The byte before b is non-uniform (else P would be &b), so the run
    ; ending just before b is that byte's trailing run.
    add hl,de
    call .Lhc_cross
    jr c,.Lhc_fail1
    dec de
    ld a,(de)
    inc de
    call .Lhc_set_trailing
.Lhc_uniform_run:
    ld a,(_sprng_rct_previous)
    add a,$FF
    sbc a,a                         ; run value replicated
    ex de,hl
    xor a,(hl)                      ; zero iff b continues the run
    ex de,hl
    sub a,1
    sbc a,a                         ; $FF iff b continues the run
    ld hl,_sprng_rct_count
    and a,(hl)
    add a,8
    ld (hl),a                       ; run length through b
    cp a,_sprng_rct_cutoff
    jr nc,.Lhc_fail1
    ld a,(de)
    ld hl,_sprng_read_mask
    and a,(hl)
    ld (_sprng_rct_previous),a      ; b's value as 0 / mask
    inc de
    pop hl
    push de                         ; P = the byte after b
    ld hl,.Lpost_popcount8
    ld bc,0
    jr .Lhc_scan_next

.Lhc_fail3:
    pop hl
    pop hl
.Lhc_fail1:
    pop hl
.Lhc_fail0:
    pop iy
    pop ix
    scf
    ret

.Lhc_segment_end:
    ; APT: fold the segment (n = IXH bytes, IY ones) into the window.
    push de
    ld a,ixh
    or a,a
    sbc hl,hl
    ld l,a
    add hl,hl
    add hl,hl
    add hl,hl                       ; HL = 8n samples
    lea de,iy+0                     ; DE = ones
    push hl
    ld a,(_sprng_apt_reference)
    or a,a
    jr nz,.Lhc_ref_one
    sbc hl,de                       ; CF = 0 from OR
    ex de,hl                        ; DE = zeros
.Lhc_ref_one:                       ; DE = samples equal to the reference
    ld bc,_sprng_apt_cutoff
    ld hl,(_sprng_apt_matches)
    add hl,de
    ld (_sprng_apt_matches),hl
    or a,a
    sbc hl,bc
    jr nc,.Lhc_fail3                ; matches >= cutoff
    pop hl
    push hl
    or a,a
    sbc hl,de
    ex de,hl                        ; DE = samples differing from it
    ld hl,(_sprng_apt_other)
    add hl,de
    ld (_sprng_apt_other),hl
    or a,a
    sbc hl,bc
    jr nc,.Lhc_fail3                ; other >= cutoff
    pop de                          ; DE = 8n
    ld hl,(_sprng_apt_position)
    add hl,de                       ; <= window (1024 = $000400)
    ld a,h
    and a,3                         ; 1024 -> 0; anything below unchanged
    ld h,a
    ld (_sprng_apt_position),hl
    pop de                          ; DE = next byte
    ld bc,0
    ld a,(_sprng_sample_byte)
    or a,a
    jp nz,.Lhc_segment

    ; RCT: finish the run ending at the last sample.
    pop hl                          ; P
    or a,a
    sbc hl,de
    jr z,.Lhc_pass                  ; the last byte was uniform: state final
    add hl,de
    call .Lhc_cross                 ; the stored run, into the byte at P
    jr c,.Lhc_fail0
    dec de
    ld a,(de)                       ; last byte (non-uniform)
    call .Lhc_set_trailing
.Lhc_pass:
    ; .Lhc_sample leaves the last sample in _sprng_health_current, which
    ; then always equals _sprng_rct_previous.
    ld a,(_sprng_rct_previous)
    ld (_sprng_health_current),a
    pop iy
    pop ix
    or a,a
    ret

; The stored run is followed by the non-uniform byte at HL. CF set iff
; the run, extended by that byte's leading samples equal to it, reaches the
; RCT cutoff. Clobbers AF, B.
.Lhc_cross:
    ld a,(_sprng_rct_count)
    cp a,_sprng_rct_cutoff-7
    jr c,.Lhc_cross_ok              ; even 7 more samples cannot reach it
    sub a,_sprng_rct_cutoff
    neg
    ld b,a                          ; samples still needed: 1..7
    ld a,(_sprng_rct_previous)
    add a,$FF
    sbc a,a                         ; run value replicated
    xor a,(hl)                      ; leading 0 bits continue the run
.Lhc_cross_bit:
    add a,a                         ; CF = next sample differs
    jr c,.Lhc_cross_ok
    djnz .Lhc_cross_bit
    scf                             ; the run reached the cutoff
    ret
.Lhc_cross_ok:
    or a,a
    ret

; Set the stored run to the trailing run of byte A: value = its last
; sample, length = T, the number of trailing samples equal to it (1..8).
; Clobbers AF, BC, HL (leaves BCU = B = 0).
.Lhc_set_trailing:
    ld c,a
    rrca                            ; CF = last sample
    sbc a,a                         ; last sample replicated
    ld b,a
    ld hl,_sprng_read_mask
    and a,(hl)
    ld (_sprng_rct_previous),a      ; last sample as 0 / mask
    ld a,b
    xor a,c                         ; X: bit i = sample i differs from the
    rrca                            ; last one; bit 0 = 0. A = X >> 1.
    ld c,a
    dec a
    xor a,c                         ; popcount((X>>1) ^ ((X>>1)-1)) = T
    ld c,a                          ; (X = 0 gives $FF: T = 8)
    ld b,0
    ld hl,.Lpost_popcount8
    add hl,bc
    ld a,(hl)
    ld (_sprng_rct_count),a
    ret

; APT position not a multiple of 8 (unreachable from this file's callers,
; which always hand over whole bytes): feed every sample through the
; per-sample reference.
.Lhc_reference:
    ld a,(de)
    ld c,a
    ld l,8
.Lhc_reference_bit:
    sla c                           ; CF = next sample (bit 7 first)
    sbc a,a                         ; sample replicated: AND mask selects it
    call .Lhc_sample                ; preserves BC, DE, HL
    jp c,.Lhc_fail0
    dec l
    jr nz,.Lhc_reference_bit
    inc de
    djnz .Lhc_reference
    pop iy
    pop ix
    or a,a
    ret

; Per-sample reference: apply the SP 800-90B repetition-count and
; adaptive-proportion tests to one raw byte in A, considering only the
; selected source bit. BC, DE, and HL are preserved. Carry is set on either
; health-test failure. (Formerly .Lhealth_observe; logic unchanged.)
.Lhc_sample:
    push bc
    push de
    push hl

    ld b,a
    ld a,(_sprng_read_mask)
    and a,b
    ld (_sprng_health_current),a

    ; Repetition Count Test.
    ld a,(_sprng_rct_valid)
    or a,a
    jr nz,.Lhealth_rct_compare
    ld a,1
    ld (_sprng_rct_valid),a
    ld (_sprng_rct_count),a
    ld a,(_sprng_health_current)
    ld (_sprng_rct_previous),a
    jr .Lhealth_apt
.Lhealth_rct_compare:
    ld a,(_sprng_health_current)
    ld b,a
    ld a,(_sprng_rct_previous)
    cp a,b
    jr nz,.Lhealth_rct_new_value
    ld a,(_sprng_rct_count)
    inc a
    ld (_sprng_rct_count),a
    cp a,_sprng_rct_cutoff
    jp nc,.Lhealth_observe_fail
    jr .Lhealth_apt
.Lhealth_rct_new_value:
    ld a,b
    ld (_sprng_rct_previous),a
    ld a,1
    ld (_sprng_rct_count),a

.Lhealth_apt:
    ld hl,(_sprng_apt_position)
    ld de,0
    or a,a
    sbc hl,de
    jr nz,.Lhealth_apt_count

    ld a,(_sprng_health_current)
    ld (_sprng_apt_reference),a
    ld hl,1
    ld (_sprng_apt_matches),hl
    ld hl,0
    ld (_sprng_apt_other),hl
    ld hl,1
    ld (_sprng_apt_position),hl
    jr .Lhealth_observe_ok

.Lhealth_apt_count:
    ld a,(_sprng_health_current)
    ld b,a
    ld a,(_sprng_apt_reference)
    cp a,b
    jr nz,.Lhealth_apt_count_other
    ld hl,(_sprng_apt_matches)
    inc hl
    ld (_sprng_apt_matches),hl
    jr .Lhealth_apt_check_count
.Lhealth_apt_count_other:
    ld hl,(_sprng_apt_other)
    inc hl
    ld (_sprng_apt_other),hl
.Lhealth_apt_check_count:
    ld de,_sprng_apt_cutoff
    or a,a
    sbc hl,de
    jr nc,.Lhealth_observe_fail

    ld hl,(_sprng_apt_position)
    inc hl
    ld (_sprng_apt_position),hl
    ld de,_sprng_apt_window
    or a,a
    sbc hl,de
    jr nz,.Lhealth_observe_ok
    ld hl,0
    ld (_sprng_apt_position),hl

.Lhealth_observe_ok:
    pop hl
    pop de
    pop bc
    or a,a
    ret
.Lhealth_observe_fail:
    pop hl
    pop de
    pop bc
    scf
    ret

; SP 800-90B §4.5 post-collection tests over the 952-sample raw pool
; (_sprng_entropy_pool, MSB-first). Lag-k match counts for k = 1..8, then a
; first-order Markov transition check. All per-sample work is branch-free:
; popcounts use a table (eZ80 has no data cache, so lookups take constant
; time); the only data-dependent branches are the final pass/fail decisions.
;
; Out: CF clear = pass, CF set = fail. Preserves IX, IY. Clobbers AF,BC,DE,HL.
.Lpost_tests:
    push ix
    push iy
    ; _sprng_post_shifted starts as a copy of the pool; each lag pass shifts
    ; it one more bit left (zero fill), so pass k holds s << k.
    ld hl,_sprng_entropy_pool
    ld de,_sprng_post_shifted
    ld bc,_sprng_entropy_pool.size
    ldir
    ld hl,.Lpost_lag_bounds
    ld d,1                          ; D = k
.Lpost_lag_pass:
    push hl                         ; bounds entry for this k
    ld hl,_sprng_post_shifted+_sprng_entropy_pool.size-1
    ld b,_sprng_entropy_pool.size/7 ; 119 = 17 * 7
    or a,a                          ; zero fill into the last byte
.Lpost_shift_chain:
    rl (hl)
    dec hl                          ; 24-bit DEC and DJNZ preserve CF
    rl (hl)
    dec hl
    rl (hl)
    dec hl
    rl (hl)
    dec hl
    rl (hl)
    dec hl
    rl (hl)
    dec hl
    rl (hl)
    dec hl
    djnz .Lpost_shift_chain

    ; mismatches_k = popcount(pool[j] ^ shifted[j]) for j = 0..117, two
    ; bytes per iteration. HL stays at the table base: ADD HL,BC cannot
    ; carry out of 24 bits, so SBC HL,BC (CF = 0) restores it.
    ld ix,_sprng_entropy_pool
    ld iy,0
    ld bc,0                         ; BCU = B = 0 for table indexing
    ld hl,.Lpost_popcount8
    ld e,(_sprng_entropy_pool.size-1)/2
.Lpost_lag_byte:
    ld a,(ix+0)
    xor a,(ix+_sprng_entropy_pool.size)
    ld c,a
    add hl,bc
    ld a,(hl)
    sbc hl,bc
    ld c,a
    add iy,bc
    ld a,(ix+1)
    xor a,(ix+_sprng_entropy_pool.size+1)
    ld c,a
    add hl,bc
    ld a,(hl)
    sbc hl,bc
    ld c,a
    add iy,bc
    lea ix,ix+2
    dec e
    jr nz,.Lpost_lag_byte
    ; Last byte: only its first 8-k samples have a partner k later, i.e.
    ; the top 8-k bits. Mask = $FF << k (zero for k = 8).
    ld a,$FF
    ld b,d
.Lpost_tail_mask:
    add a,a
    djnz .Lpost_tail_mask           ; leaves B = 0
    ld c,a
    ld a,(ix+0)
    xor a,(ix+_sprng_entropy_pool.size)
    and a,c
    ld hl,.Lpost_popcount8
    ld c,a
    add hl,bc
    ld c,(hl)
    add iy,bc                       ; IY = mismatches_k

    pop hl                          ; HL = bounds entry
    ld a,d
    dec a
    jr nz,.Lpost_lag_compare
    lea bc,iy+0
    ld (_sprng_post_mis1),bc        ; lag-1 mismatches = n01 + n10
.Lpost_lag_compare:
    push de                         ; save k
    ld de,(hl)                      ; DE = min mismatches
    inc hl
    inc hl
    inc hl
    lea bc,iy+0                     ; BC = mismatches_k
    push hl
    lea hl,iy+0
    or a,a
    sbc hl,de                       ; CF: mismatches < min (matches > HIGH)
    pop hl
    jp c,.Lpost_fail_pop_k
    ld de,(hl)                      ; DE = max mismatches
    inc hl
    inc hl
    inc hl
    ex de,hl                        ; HL = max, DE = next entry
    or a,a
    sbc hl,bc                       ; CF: mismatches > max (matches < LOW)
    ex de,hl                        ; HL = next entry
    pop de                          ; D = k
    jp c,.Lpost_fail
    inc d
    ld a,d
    cp a,9
    jp c,.Lpost_lag_pass

    ; Markov: derive transition counts from the ones count O, the first and
    ; last samples, and lag-1 mismatches M1 (exact for any bit string):
    ;   n_1 = O - s[951]       (transitions out of 1 = ones in s[0..950])
    ;   O_b = O - s[0]         (ones in s[1..951] = n01 + n11)
    ;   n11 = (n_1 + O_b - M1) / 2
    ;   n10 = n_1 - n11,  n_0 = 951 - n_1,  n01 = O_b - n11,  n00 = n_0 - n01
    ld de,_sprng_entropy_pool
    ld iy,0
    ld bc,0
    ld hl,.Lpost_popcount8          ; table base, restored as above
    ld ixl,_sprng_entropy_pool.size
.Lpost_ones:
    ld a,(de)
    inc de
    ld c,a
    add hl,bc
    ld a,(hl)
    sbc hl,bc
    ld c,a
    add iy,bc
    dec ixl
    jr nz,.Lpost_ones               ; IY = O

    ld a,(_sprng_entropy_pool+_sprng_entropy_pool.size-1)
    and a,1
    ld c,a                          ; BC = s[951]
    lea hl,iy+0
    or a,a
    sbc hl,bc
    ld (_sprng_post_n1),hl          ; n_1
    ld a,(_sprng_entropy_pool)
    rlca
    and a,1
    ld c,a                          ; BC = s[0]
    lea hl,iy+0
    or a,a
    sbc hl,bc
    ld (_sprng_post_ob),hl          ; O_b
    ld de,(_sprng_post_n1)
    add hl,de
    ld de,(_sprng_post_mis1)
    or a,a
    sbc hl,de                       ; 2*n11, in [0, 1902]: HLU = 0
    srl h
    rr l
    ld (_sprng_post_n11),hl         ; n11

    ld de,(_sprng_post_n1)
    call .Lpost_markov_check        ; n11 vs n_1
    jr c,.Lpost_fail
    ld hl,(_sprng_post_n1)
    ld de,(_sprng_post_n11)
    or a,a
    sbc hl,de                       ; n10
    ld de,(_sprng_post_n1)
    call .Lpost_markov_check        ; n10 vs n_1
    jr c,.Lpost_fail
    ld hl,_sprng_post_n-1
    ld de,(_sprng_post_n1)
    or a,a
    sbc hl,de
    ld (_sprng_post_n0),hl          ; n_0
    ld hl,(_sprng_post_ob)
    ld de,(_sprng_post_n11)
    or a,a
    sbc hl,de
    ld (_sprng_post_n01),hl         ; n01
    ld de,(_sprng_post_n0)
    call .Lpost_markov_check        ; n01 vs n_0
    jr c,.Lpost_fail
    ld hl,(_sprng_post_n0)
    ld de,(_sprng_post_n01)
    or a,a
    sbc hl,de                       ; n00
    ld de,(_sprng_post_n0)
    call .Lpost_markov_check        ; n00 vs n_0
    jr c,.Lpost_fail

    pop iy
    pop ix
    or a,a
    ret

.Lpost_fail_pop_k:
    pop de
.Lpost_fail:
    pop iy
    pop ix
    scf
    ret

; In: HL = n_sx (transition count), DE = n_s (transitions out of s), both
; <= 951. Out: CF set iff n_sx*256 > n_s*_sprng_markov_max_q8.
; Clobbers AF, B, DE, HL.
.Lpost_markov_check:
    push hl                         ; n_sx
    ; HL = n_s * constant (<= 255): MSB-first shift/add with DE = n_s.
    ; Branches depend only on the constant's bits. Max 951*255 < 2^24.
    or a,a
    sbc hl,hl
    ld a,_sprng_markov_max_q8
    ld b,8
.Lpost_mul_loop:
    add hl,hl
    rla                             ; constant bit 7 -> CF (bit 0 gets junk,
    jr nc,.Lpost_mul_skip           ; never examined within 8 iterations)
    add hl,de
.Lpost_mul_skip:
    djnz .Lpost_mul_loop
    pop de                          ; DE = n_sx
    ex de,hl                        ; HL = n_sx, DE = n_s*MAX_Q8
    add hl,hl
    add hl,hl
    add hl,hl
    add hl,hl
    add hl,hl
    add hl,hl
    add hl,hl
    add hl,hl                       ; HL = n_sx*256 (<= 243456)
    ex de,hl
    or a,a
    sbc hl,de                       ; CF iff n_s*MAX_Q8 < n_sx*256
    ret

; {min, max} mismatches per lag, mismatches = (n-k) - matches.
.Lpost_lag_bounds:
    .d24 (_sprng_post_n-1)-_sprng_lag1_high, (_sprng_post_n-1)-_sprng_lag1_low
    .d24 (_sprng_post_n-2)-_sprng_lag2_high, (_sprng_post_n-2)-_sprng_lag2_low
    .d24 (_sprng_post_n-3)-_sprng_lag3_high, (_sprng_post_n-3)-_sprng_lag3_low
    .d24 (_sprng_post_n-4)-_sprng_lag4_high, (_sprng_post_n-4)-_sprng_lag4_low
    .d24 (_sprng_post_n-5)-_sprng_lag5_high, (_sprng_post_n-5)-_sprng_lag5_low
    .d24 (_sprng_post_n-6)-_sprng_lag6_high, (_sprng_post_n-6)-_sprng_lag6_low
    .d24 (_sprng_post_n-7)-_sprng_lag7_high, (_sprng_post_n-7)-_sprng_lag7_low
    .d24 (_sprng_post_n-8)-_sprng_lag8_high, (_sprng_post_n-8)-_sprng_lag8_low

; popcount(i), i = 0..255
.Lpost_popcount8:
    .db 0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4
    .db 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5
    .db 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5
    .db 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6
    .db 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5
    .db 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6
    .db 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6
    .db 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7
    .db 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5
    .db 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6
    .db 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6
    .db 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7
    .db 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6
    .db 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7
    .db 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7
    .db 4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8

; Reset continuous-test state whenever a freshly validated tap becomes active.
.Lhealth_reset:
    xor a,a
    ld (_sprng_rct_valid),a
    ld (_sprng_rct_previous),a
    ld (_sprng_rct_count),a
    ld (_sprng_apt_reference),a
    ld (_sprng_consec_health_fails),a
    ld hl,0
    ld (_sprng_apt_matches),hl
    ld (_sprng_apt_other),hl
    ld (_sprng_apt_position),hl
    ret

; Try the three cached runner-up taps, validating each with fresh samples.
; If none passes, perform at most one complete source-selection scan for this
; entropy-collection call. Carry clear means recovery succeeded.
.Lhealth_recover:
    push ix
    push iy
    ld iy,_sprng_backup_candidates
    ld b,3
.Lhealth_try_backup:
    ld a,(iy+3)
    or a,a
    jr z,.Lhealth_next_backup
    ld ix,(iy+0)
    ld (iy+3),0
    push bc
    push iy
    call .Linit_validate_candidate
    pop iy
    pop bc
    jr nc,.Lhealth_backup_ok
.Lhealth_next_backup:
    lea iy,iy+4
    djnz .Lhealth_try_backup

    ld a,(_sprng_recovery_rescanned)
    or a,a
    jr nz,.Lhealth_recover_fail
    inc a
    ld (_sprng_recovery_rescanned),a
    call _tls_random_init_entropy
    or a,a
    jr z,.Lhealth_recover_fail
    pop iy
    pop ix
    or a,a
    ret

.Lhealth_backup_ok:
    lea hl,ix+0
    ld (_sprng_read_addr),hl
    ld a,(_sprng_init_eval_mask)
    ld (_sprng_read_mask),a
    call .Lhealth_reset
    pop iy
    pop ix
    or a,a
    ret
.Lhealth_recover_fail:
    ; No usable tap survived. Clear the active source so tls_rng_healthcheck()
    ; does not treat the failed pointer as healthy, and reset health state so
    ; the next tap does not inherit counts from a failed source (SP 800-90B §4.3).
    ld hl,0
    ld (_sprng_read_addr),hl
    xor a,a
    ld (_sprng_read_mask),a
    call .Lhealth_reset
    pop iy
    pop ix
    scf
    ret


; -----------------------------------------------
; void* tls_entropy_collect(void* buf, size_t len);
; Internal entropy-source interface. Public callers must use
; tls_random_bytes(), which generates through Hash_DRBG.
_tls_entropy_collect:
    ld hl,-6
    call __frameset
    ld hl,(ix+6)
    ld (ix-3),hl ; temp pointer
    ld hl,(ix+9)
    ld (ix-6),hl ; original length for failure zeroization
.Lbytes_loop:
    ld hl,(ix+9)
    add hl,bc
    or a,a
    sbc hl,bc
    jr z,.Lbytes_done ; handle end of loop and when len is zero
    call _tls_entropy_gather256
    ld a,(_sprng_random_last_ok)
    or a,a
    jr z,.Lbytes_failed
    ld hl,(ix+9)
    ld bc,32
    or a,a
    sbc hl,bc
    jr nc,.Lbytes_full
    ; Short tail: HL is len-32 modulo 2^24. Restore len for the copy,
    ; and consume the entire remainder instead of storing the underflow.
    add hl,bc
    ld c,l ; remaining length is 1..31; upper BC bytes are already zero
    or a,a
    sbc hl,hl
.Lbytes_full:
    ld (ix+9),hl
.Lbytes_not_last:
    ld hl,(ix-3)
    add hl,bc
    ld de,(ix-3)
    ld (ix-3),hl ; advance dest pointer
    ld hl,_sprng_sha_digest
    ldir ; copy to dest
    ; Destroy all 520 bytes of entropy/SHA overlay scratch immediately after
    ; the conditioned digest fragment has left the overlay.
    ld hl,_sprng_entropy_pool
    ld (hl),0
    ld de,_sprng_entropy_pool+1
    ld bc,519
    ldir
    jr .Lbytes_loop
.Lbytes_done:
    ld hl,(ix+6) ; return pointer to dest
    ld sp,ix
    pop ix
    ret

.Lbytes_failed:
    ld hl,(ix-6)
    push hl
    ld hl,(ix+6)
    push hl
    call _tls_secure_memzero
    pop hl
    pop hl
    ld hl,0
    ld sp,ix
    pop ix
    ret


; ---------------------------------------------------------
; void* tls_random_debug_source_ptr(void);
; Debug/test accessor for current sampler source address.
_tls_random_debug_source_ptr:
    ld hl,(_sprng_read_addr)
    ret

; uint8_t tls_random_debug_source_mask(void);
; Debug/test accessor for the selected bit within the sampled byte.
_tls_random_debug_source_mask:
    ld a,(_sprng_read_mask)
    ret

; uint8_t tls_random_health_epoch(void);
; Increments whenever a continuous raw-source health test fails.
_tls_random_health_epoch:
    ld a,(_sprng_health_epoch_value)
    ret


extern _tls_sha256_init
extern _tls_sha256_update
extern _tls_sha256_digest
extern _tls_secure_memzero
extern __frameset

.section .bss._sprng_read_addr,"aw",@nobits
_sprng_read_addr:
    .zero 3
_sprng_read_mask:
    .zero 1
_sprng_backup_candidates:
    .zero 12
_sprng_rct_valid:
    .zero 1
_sprng_rct_previous:
    .zero 1
_sprng_rct_count:
    .zero 1
_sprng_apt_reference:
    .zero 1
_sprng_apt_matches:
    .zero 3
_sprng_apt_other:
    .zero 3
_sprng_apt_position:
    .zero 3
_sprng_health_current:
    .zero 1
_sprng_health_epoch_value:
    .zero 1
_sprng_random_last_ok:
    .zero 1
_sprng_recovery_rescanned:
    .zero 1
_sprng_sample_byte:
    .zero 1
_sprng_consec_health_fails:
    .zero 1


.section	.note.GNU-stack,"",@progbits

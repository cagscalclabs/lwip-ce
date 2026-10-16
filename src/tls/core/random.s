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
; selected address/bit pair is then checked again using 512 fresh pairs
; (1024 raw reads), with the correspondingly scaled fixed bounds. Only the
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
.equ _sprng_init_records,       _sprng_entropy_pool
.equ _sprng_init_sample0,       _sprng_init_records + 48
.equ _sprng_init_sample1,       _sprng_init_sample0 + 1
.equ _sprng_init_best_addr,     _sprng_init_sample1 + 1
.equ _sprng_init_best_mask,     _sprng_init_best_addr + 3
.equ _sprng_init_best_score,    _sprng_init_best_mask + 1
.equ _sprng_init_eval_mask,     _sprng_init_best_score + 1
.equ _sprng_init_insert_addr,   _sprng_init_eval_mask + 1
.equ _sprng_init_insert_mask,   _sprng_init_insert_addr + 3

; SP 800-90B continuous health-test parameters. Source selection permits a
; worst-case 25/75 marginal split, corresponding to slightly more than 0.4
; bits of min-entropy per selected-bit sample. With H=0.4 and alpha=2^-20:
;
;   RCT: C = 1 + ceil(20 / 0.4) = 51
;   APT: binary W=1024, C=840 (SP 800-90B Table 2)
;
; The binary APT extension checks both the reference bit and its complement.
.equ _sprng_rct_cutoff,         51
.equ _sprng_apt_window,         1024
.equ _sprng_apt_cutoff,         840

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
    xor a,a
.Linit_return:
    pop iy
    pop ix
    ret

; Revalidate IX/A as an address/mask candidate using 1024 fresh reads.
; Returns carry clear on success and carry set on failure.
.Linit_validate_candidate:
    ld (_sprng_init_eval_mask),a
    call .Linit_clear_counters
    call .Linit_measure_256_pairs
    call .Linit_measure_256_pairs

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
    or a,a
    ret
.Linit_validate_fail:
    scf
    ret

; Clear the eight {ones, disagreements} counter records.
.Linit_clear_counters:
    ld hl,_sprng_init_records
    ld (hl),0
    ld de,_sprng_init_records+1
    ld bc,47
    ldir
    ret

; Accumulate 256 adjacent read pairs from the byte at IX. Counter records
; are not cleared here so the routine can be called twice for validation.
.Linit_measure_256_pairs:
    ld b,0
.Linit_measure_pair:
    ; Keep the physical reads adjacent. All data-dependent counter work is
    ; performed only after both samples have been acquired.
    ld a,(ix)
    ld d,a
    ld a,(ix)
    ld e,a
    ld a,d
    ld (_sprng_init_sample0),a
    ld a,e
    ld (_sprng_init_sample1),a

    ld a,(_sprng_init_sample0)
    ld hl,_sprng_init_records
    call .Linit_increment_vector
    ld a,(_sprng_init_sample1)
    ld hl,_sprng_init_records
    call .Linit_increment_vector

    ld a,(_sprng_init_sample0)
    ld c,a
    ld a,(_sprng_init_sample1)
    xor a,c
    ld hl,_sprng_init_records+3
    call .Linit_increment_vector

    djnz .Linit_measure_pair
    ret

; Increment eight 24-bit counters selected by the bits in A. HL points to
; the first counter and each successive lane is six bytes away.
.Linit_increment_vector:
    push bc
    ld c,a
    ld b,8
.Linit_increment_lane:
    srl c
    jr nc,.Linit_increment_next
    ld de,(hl)
    inc de
    ld (hl),de
.Linit_increment_next:
    ld de,6
    add hl,de
    djnz .Linit_increment_lane
    pop bc
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
    ld de, _sprng_entropy_pool
    ld b, 119
.Lrandom_byte_read_loop:
    xor a,a
    ld (_sprng_sample_byte),a
    ld c,8
.Lrandom_raw_read_loop:
    ld a,(hl)
    ld (_sprng_raw_sample),a
    call .Lhealth_observe
    jr c,.Lrandom_health_fail

    ; Shift the next selected bit into the low end of the pool byte. The
    ; health observer has already normalized the selected bit to zero or the
    ; one-hot source mask in _sprng_health_current.
    ld a,(_sprng_sample_byte)
    add a,a
    ld (_sprng_sample_byte),a
    ld a,(_sprng_health_current)
    or a,a
    jr z,.Lrandom_raw_bit_stored
    ld a,(_sprng_sample_byte)
    inc a
    ld (_sprng_sample_byte),a
.Lrandom_raw_bit_stored:
    dec c
    jr nz,.Lrandom_raw_read_loop
    ld a,(_sprng_sample_byte)
    ld (de), a
    inc de
    djnz .Lrandom_byte_read_loop

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

; Apply the SP 800-90B repetition-count and adaptive-proportion tests to one
; raw byte in A, considering only the selected source bit. BC, DE, and HL are
; preserved. Carry is set on either health-test failure.
.Lhealth_observe:
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

; Reset continuous-test state whenever a freshly validated tap becomes active.
.Lhealth_reset:
    xor a,a
    ld (_sprng_rct_valid),a
    ld (_sprng_rct_previous),a
    ld (_sprng_rct_count),a
    ld (_sprng_apt_reference),a
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
_sprng_raw_sample:
    .zero 1
_sprng_sample_byte:
    .zero 1

.section	.note.GNU-stack,"",@progbits

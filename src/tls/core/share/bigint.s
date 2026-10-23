
.assume adl=1

.section	.text,"ax",@progbits
globl u64_addi
.type	u64_addi,@function

; add unsigned 24-bit BC to the 64-bit integer pointed to by IY
; destroys AF, DE, HL
u64_addi:
	xor a,a
	sbc hl,hl
	ex de,hl
	ld hl,(iy)
	add hl,bc
	ld (iy),hl
	ld hl,(iy+3)
	adc hl,de
	ld (iy+3),hl
	lea hl,iy+6
	adc a,(hl)
	ld (hl),a
	inc hl
	ld a,(hl)
	adc a,e
	ld (hl),a
	ret

.section	.text,"ax",@progbits
globl _powmod_exp_u24
.type _powmod_exp_u24,@function

; ---------------------------------------------------------------------------
; The hot loops of powmod_exp_u24 must run from writable RAM: they
; self-modify instruction operands (.Lq/.Lm8 quotient digits, .Ld2_jp Duff
; entry, .Ld2n/.Ld2tr/.Ld2fin chunk state, .Lnmi/.Ln0/.Ln1) and keep their
; state in data slots inside the block. In the resident lwIP flash app,
; .text is read-only flash, so running in place faults. Mirror the X25519
; approach: the hot routines live in the .powmod.reloc section (placed by
; the linker at the 0xE30800 safe-RAM overlay VMA = LCD cursor RAM, with a
; load image in prgm); this public trampoline copies them to that RAM
; address, fills in the public (size/mod/exp-only) parameters, and JUMPS to
; _powmod_exp_u24_impl. The cold orchestration (.Lorch_text and friends)
; stays in .text: the block calls it through a call operand the trampoline
; patches at runtime, because relocations inside the load image are not
; patched by the installer (see the __frameset0 note in aes.s).
;
; We `jp`, not `call`: the relocated body reads its args as (ix + offset) after
; `push ix / add ix,sp`, relative to THIS call's return address + pushed args.
; A `call` would push an extra return address and shift every arg offset by 3.
; The safe-RAM window is shared (sequentially, never co-resident) with X25519
; and the RNG scratch — see linker_script_lwip.ld.
;void powmod_exp_u24(uint16_t size, uint8_t *restrict base, uint24_t exp, const uint8_t *restrict mod);

; __tls_scratch / __tls_scratch_end are defined in share/memory.s (assembled
; as its own translation unit). Reference them as externals here — do NOT
; .include memory.s, or its .space reservations get defined twice (here and
; in memory.s.o) and the link fails with "multiple definition".

   .equ   Lret,  6                 ; frame of _powmod_exp_u24_impl
   .equ   Lsize, Lret  + 3
   .equ   Lbase, Lsize + 3
   .equ   Lexp,  Lbase + 3
   .equ   Lmod,  Lexp  + 3
   .equ   Lacc,  -3
   .equ   Ltmp,  Lacc  - 3
   .equ   Lcnt0, Ltmp  - 3         ; {hi_adj(size), lo(size), 0}

_powmod_exp_u24:
   ld   hl, _powmod_reloc_load_start
   ld   de, _powmod_reloc_run_start
   ld   bc, _powmod_reloc_len
   ldir
   ; Cold, public-only precomputation (depends on size, mod and exp only),
   ; done here in .text to keep the relocated block inside its 0x400 window.
   ; It only WRITES into the freshly copied block (absolute VMA addresses);
   ; nothing in the block calls back into .text (relocations inside the load
   ; image are not patched). Interrupts may still be on here: no iy, no
   ; alternate registers. ix is saved/restored so the jp below sees the
   ; caller's exact stack and registers layout.
   push   ix
   ld   ix, 0
   add   ix, sp                    ; ix+6 size, +9 base, +12 exp, +15 mod
   ld   bc, 0
   ld   c, (ix + 6)
   ld   b, (ix + 7)                ; bc = size (clean 24-bit)
   ld   (.LS), bc
   ld   hl, 255
   add   hl, bc
   ld   l, h                       ; c' = hi_adj(size)
   ld   h, c                       ; b' = lo(size)
   ld   (.Lsubc), hl
   dec   bc
   ld   hl, (ix + 15)              ; -> mod msb
   push   hl
   add   hl, bc                    ; -> mod lsb
   ld   a, (hl)
   ld   (.Ln0), a
   dec   hl
   ld   a, (hl)
   ld   (.Ln1), a                  ; size >= 2
   inc   hl
   ld   b, 3
   ld   e, b
.Lnmi_loop:                        ; e <- -mod^-1 mod 256 (Newton, 3 steps)
   ld   a, e
   ld   d, (hl)
   mlt   de
   inc   de
   inc   de
   ld   d, a
   mlt   de
   djnz   .Lnmi_loop ; leaks constant
   ld   a, e
   ld   (.Lnmi), a
   ; idx = index of the most significant nonzero byte of mod, l = its bit
   ; length, L = 8*idx + l = bitlen(mod). .Lwin extracts the window
   ; floor(v / 2^(L-23)) (= floor(256 v / 2^(L-15))) with bytes below index
   ; 0 read as 0, so N = .Lwin(mod) >> 8 = floor(mod / 2^(L-15)) is in
   ; [2^14, 2^15) and D = N + 1 <= 2^15.
   pop   hl                        ; -> mod msb
   ld   bc, 0
   ld   c, (ix + 6)
   ld   b, (ix + 7)
.Lidx_scan:
   dec   bc
   ld   a, (hl)
   or   a, a
   jr   nz, .Lidx_found ; leaks mod (public); stops at n_0 (odd) at worst
   inc   hl
   jr   .Lidx_scan ; leaks mod
.Lidx_found:
   ld   (.Lidx), bc                ; bc = idx (bcu = 0)
   ld   d, 1
.Lbitlen:
   inc   d
   srl   a
   jr   nz, .Lbitlen ; leaks mod
   ld   a, d
   ld   (.Lsh), a                  ; l + 1, in [2, 9]
   ld   a, b
   or   a, a
   ld   a, 4                       ; window bytes NV = min(idx, 3) + 1
   jr   nz, .Lnv_set ; leaks mod
   ld   a, c
   cp   a, 3
   ld   a, 4
   jr   nc, .Lnv_set ; leaks mod
   ld   a, c
   inc   a
.Lnv_set:
   ld   (.Lnv), a
   neg
   add   a, 5
   ld   (.Lnz), a                  ; 1 + number of zero pad bytes
   xor   a, a                      ; mod[idx+1] = 0
   call   .Lwin                    ; d:e = N
   ld   hl, 0
   ld   h, d
   ld   l, e
   inc   hl
   ld   (.LdivD), hl               ; D = N + 1 <= 2^15
   ; exp = 2^k + 1  <=>  odd and popcount 2: base stays in plain form
   ld   hl, (ix + 12)
   xor   a, a
   ld   b, 24
.Lpopcnt:
   add   hl, hl
   adc   a, 0
   djnz   .Lpopcnt ; leaks constant
   sub   a, 2                      ; z iff popcount == 2
   ld   a, (ix + 12)
   jr   z, .Lpc2 ; leaks exp
   xor   a, a
.Lpc2:
   and   a, 1
   ld   (.Lfast), a
   ld   hl, .Lorch_text
   ld   (.Lorch), hl               ; the block calls back through this
   pop   ix
   jp   _powmod_reloc_run_start

   ; -----------------------------------------------------------------------
   ; Cold orchestration, run from .text with interrupts already disabled by
   ; _powmod_exp_u24_impl (called through .Lorch). ix = frame (offsets are the
   ; .equ's in the block), the three frame slots are reserved, bc = 0.
   ; Calls into the block are absolute (VMA 0xE30800 window, no relocation).
   ; No self-modifying code here: .text may be flash.
   ; -----------------------------------------------------------------------
.Lorch_text:
   ld   bc, (.LS)                  ; size (clean 24-bit, from the trampoline)
   ld   (ix + Lsize), bc
   ld   hl, __tls_scratch_end - 1
   ld   (ix + Lacc), hl            ; acc lsb = end - 1
   or   a, a
   sbc   hl, bc
   ld   (ix + Ltmp), hl            ; tmp lsb = end - size - 1
   ld   hl, 255
   add   hl, bc                    ; h = hi_adj(size), hlu = 0
   ld   l, h
   ld   h, c                       ; h = lo(size)
   ld   (ix + Lcnt0), hl
   dec   bc                        ; bc = size - 1
   ld   hl, (ix + Lbase)
   add   hl, bc
   ld   (ix + Lbase), hl           ; base -> last (least significant) byte
   ld   hl, (ix + Lmod)
   add   hl, bc
   ld   (ix + Lmod), hl            ; mod -> last (least significant) byte
   ; acc <- base, then acc <- acc * R mod mod
   ld   hl, (ix + Lbase)
   ld   de, (ix + Lacc)
   ld   bc, (ix + Lsize)
   lddr ; leaks size
   call   .Lconv_text
   ld   a, (.Lfast)
   or   a, a
   jr   nz, .Lexp_go ; leaks exp
   ld   hl, (ix + Lacc)            ; general exponent: base <- base * R
   ld   de, (ix + Lbase)
   ld   bc, (ix + Lsize)
   lddr ; leaks size
.Lexp_go:
   ld   hl, (ix + Lexp)
   scf
.Lnormalize:
   adc   hl, hl
   jp   nc, .Lnormalize ; leaks exp
   xor   a, a
.Lloop:
   push   hl
   push  af
   call   nz, .Lsqr_text ; leaks exp
   pop   af
   call   c, .Lmul_text ; leaks exp
   pop   hl
   adc   hl, hl
   jp   nz, .Lloop ; leaks exp
   ld   a, (.Lfast)
   or   a, a
   jr   nz, .Lexp_done ; leaks exp
   ld   hl, (ix + Lbase)           ; base <- 1, acc <- acc * 1 * R^-1
   ld   (hl), 0
   push   hl
   pop   de
   dec   de
   ld   bc, (ix + Lsize)
   dec   bc
   lddr ; leaks size
   ld   hl, (ix + Lbase)
   inc   (hl)
   call   .Lmul_text
.Lexp_done:
   ld   hl, (ix + Lacc)
   ld   de, (ix + Lbase)
   ld   bc, (ix + Lsize)
   lddr ; leaks size
   ; scrub secret-derived state left in the relocated block (quotient
   ; digits, the conversion window, the column accumulator, the last y
   ; byte) and in the alternate registers; vi(acc)/vi(tmp) are the caller's
   ; (rsa.c zeroes the top 2*size bytes of the scratch after the call)
   xor   a, a
   ld   (.Lq), a
   ld   (.Lm8), a
   ld   hl, .Lacc40
   ld   (hl), a
   ld   de, .Lacc40 + 1
   ld   bc, .Ldata_end - .Lacc40 - 1
   ldir
   exx
   ld   bc, 0
   ld   de, 0
   ld   hl, 0
   exx
   ex   af, af'
   xor   a, a
   ex   af, af'
   ret

   ; .Lconv_text: vi(acc) <- vi(acc) * 256^size mod vi(mod).
   ; size steps of x <- 256*x - q*mod with lazy reduction: x stays in
   ; [0, 2n) (top bit in .Lxs). Y = floor(256x / 2^(L-15)) (.Lwin) is
   ; < 512*D and N >= 2^14, so q = floor(Y / D) (9 bits, two .Ldiv passes)
   ; is q_true or q_true - 1 and 256x - q*mod stays in [0, 2n).
   ; Each step builds r in vi(tmp), then acc/tmp swap roles (ping-pong).
   ; One .Lreduce at the end gives x < n. Requires base < 2*mod.
.Lconv_text:
   xor   a, a
   ld   (.Lxs), a
   ld   hl, (ix + Lsize)
   dec   hl
   ld   de, (.Lidx)
   or   a, a
   sbc   hl, de                    ; size - 1 - idx (< 2^16)
   ld   a, h
   or   a, l
   ld   (.Lxtop), a                ; 0 iff idx = size - 1
   ld   hl, (ix + Lsize)
.Lconv_loop:
   push   hl                       ; steps left
   ld   hl, (ix + Lacc)
   ld   de, (.Lidx)
   or   a, a
   sbc   hl, de                    ; -> x[idx]
   ld   a, (.Lxtop)
   or   a, a
   ld   a, (.Lxs)                  ; x[size] (top bit) ...
   jr   z, .Lconv_top ; leaks mod
   dec   hl
   ld   a, (hl)                    ; ... or x[idx+1]
   inc   hl
.Lconv_top:
   call   .Lwin                    ; d:e:c = Y
   push   bc
   ld   hl, 0
   ld   l, d                       ; R = Y >> 16 (< D)
   ld   c, e
   call   .Ldiv                    ; c = q8 in {0, 1}, hl = R
   xor   a, a
   sub   a, c
   ld   (.Lm8), a                  ; -q8
   pop   bc                        ; c = Y & 255
   call   .Ldiv                    ; c = q0
   ld   a, c
   ld   (.Lq), a
   call   .Lsubmul                 ; vi(tmp) = 256 x - q n, .Lxs = its top bit
   ld   hl, (ix + Lacc)
   ld   de, (ix + Ltmp)
   ld   (ix + Lacc), de
   ld   (ix + Ltmp), hl
   pop   hl
   dec   hl
   ld   a, h
   or   a, l
   jr   nz, .Lconv_loop ; leaks size
   ld   a, (.Lxs)
   rra                             ; cf = top bit
   ld   bc, 0
   ld   hl, (ix + Lacc)
   jp   .Lreduce

   ; .Lwin: a = v[idx+1], hl -> v[idx]. W = v[idx+1..idx-3] (40 bits,
   ; big-endian, bytes below index 0 read as 0) >> (l+1) < 2^24.
   ; Returns d:e:c = W. Destroys af, b, hl. (cold: once per .Lconv step)
.Lwin:
   ld   de, .Lwbuf
   ld   (de), a
   inc   de
   ld   bc, 0
   ld   a, (.Lnv)                  ; min(idx, 3) + 1 bytes from memory
   ld   c, a
   ldir
   ld   a, (.Lnz)                  ; 1 + zero bytes below index 0
   ld   b, a
   xor   a, a
   jr   .Lwin_zt
.Lwin_z:
   ld   (de), a
   inc   de
.Lwin_zt:
   djnz   .Lwin_z ; leaks mod
   ld   a, (.Lsh)                  ; l + 1
   ld   b, a
.Lwin_sh:
   ld   hl, .Lwbuf
   srl   (hl)
   inc   hl
   rr   (hl)
   inc   hl
   rr   (hl)
   inc   hl
   rr   (hl)
   inc   hl
   rr   (hl)
   djnz   .Lwin_sh ; leaks mod
   ld   a, (.Lwbuf + 2)
   ld   d, a
   ld   a, (.Lwbuf + 3)
   ld   e, a
   ld   a, (.Lwbuf + 4)
   ld   c, a
   ret

   ; .Ldiv: hl = R (< D, hlu = 0), c = next 8 dividend bits.
   ; Returns c = floor((R*256 + c) / D). Branch-free restoring division.
   ; Destroys a, b, de, hl, iyl.
.Ldiv:
   ld   b, 8
.Ldiv_loop:
   rl   c                          ; c <<= 1 | previous quotient bit
   adc   hl, hl                    ; R = 2R + next dividend bit (< 2^16)
   ld   de, (.LdivD)
   sbc   hl, de                    ; cf = (R < D)
   sbc   a, a
   ld   iyl, a                     ; mask = R < D ? 0xFF : 0
   and   a, e
   ld   e, a
   ld   a, iyl
   and   a, d
   ld   d, a
   add   hl, de                    ; restore R if R < D
   ld   a, iyl
   cp   a, 1                       ; cf = quotient bit = (mask == 0)
   djnz   .Ldiv_loop ; leaks constant
   rl   c
   ret

   ; .Lsqr_text / .Lmul_text: vi(acc) <- vi(acc) * vi(Y) * R^-1 mod vi(mod),
   ; Y = acc / base. Arms the column state of .Lcols, then runs it.
.Lsqr_text:
   ld   a, 1
   ld   hl, (ix + Lacc)
   jr   .Lmont_text
.Lmul_text:
   xor   a, a
   ld   hl, (ix + Lbase)
.Lmont_text:
   ld   (.Lsqf), a
   ld   (.LYl), hl
   ld   hl, (ix + Lmod)
   ld   (.LNl), hl
   ld   hl, (ix + Ltmp)
   ld   (.LTl), hl
   ld   hl, (ix + Lacc)
   ld   (.LAl), hl
   ld   de, (ix + Lsize)
   ld   (.Lkc), de                 ; size column pairs
   add   hl, de
   ld   (.LPOb), hl                ; acc lsb + size: acc[c - size] = (.LPOb) - c
   ld   hl, 0
   ld   (.Lacc40), hl
   ld   (.Lacc40 + 3), hl
   ld   (.Lacc40 + 4), hl
   call   .Lcols                   ; cf = top bit of the < 2n result
   ld   hl, (ix + Lacc)
   ld   bc, 0
   ;  fall through

   ; .Lreduce: if (cf:vi(hl) >= vi(mod)) cf:vi(hl) -= vi(mod), constant time
   ; (the difference is always computed into vi(tmp), then one of the two
   ; buffers is copied into vi(hl) via a stack-indexed pointer select).
   ; assumes bcu = 0; ix = frame; interrupts off (alternate b' = wrap count)
   ; destroys vi(tmp); returns bc = 0, cf = 0
.Lreduce:
   ccf
   sbc   a, a
   ld   c, a
   ld   a, (ix + Lcnt0)
   exx
   ld   b, a                       ; b' = hi_adj(size)
   exx
   ld   b, (ix + Lsize)            ; low count = lo(size)
   ld   de, (ix + Ltmp)
   ld   iy, (ix + Lmod)
   or   a, a
   push   hl
   push  de
.Lreduce_sub:
   ld   a, (hl)
   dec   hl
   sbc   a, (iy)
   dec   iy
   ld   (de), a
   dec   de
   djnz   .Lreduce_sub ; leaks size
   exx
   dec   b                         ; dec preserves cf
   exx
   jr   nz, .Lreduce_sub ; leaks size
   sbc   a, a
   and   a, c
   and   a, 3
   sbc   hl, hl
   ld   l, a
   add   hl, sp
   ld   hl, (hl)
   pop   de
   pop   de
   ld   bc, (ix + Lsize)
   lddr ; leaks size, assuming that base and stack are in normal ram
   ret


.section	.powmod.reloc,"ax",@progbits

.include "scratch.inc"

_powmod_reloc_run_start:
_powmod_exp_u24_impl:
   ; size is a uint16_t (callers pass 128..512; 2..1023 works).
   ; Preconditions: mod odd, base < 2*mod (callers guarantee base < mod;
   ; the old bit-serial conversion had the same practical requirement).
   ; Result: base <- base^exp mod mod (exp = 0 yields base mod mod, as
   ; before).
   ;
   ; Algorithm (all multiprecision loops are data-independent: every branch,
   ; loop count and address depends only on size, exp or the public mod):
   ;   1. acc <- base * R mod n, R = 256^size (.Lconv_text: size steps of
   ;      x <- 256x - q*n with an estimated quotient digit and lazy
   ;      reduction, instead of 8*size bit steps with a full reduce each)
   ;   2. left-to-right square-and-multiply with Montgomery products in
   ;      paired-column product-scanning (Comba / FIPS) form (.Lcols)
   ;   3. exp = 2^k + 1 (65537, 3, ...): base stays in plain form and the
   ;      last multiply by it yields the plain result directly (no R^-1
   ;      pass); otherwise base <- base*R and a final multiply by 1 leaves
   ;      Montgomery form.
   ;
   ; Interrupts are disabled for the whole body: .Ldot2, .Lsubmul and
   ; .Lreduce keep pointers / sums / counters in the alternate register set
   ; (exx, af'), and the TI-OS interrupt handler uses the alternate set. The entry IFF state is saved
   ; on the stack (PV of `ld a, i` = IFF2 = IFF1 outside an NMI) and restored
   ; at the single exit below: interrupts come back on only if they were on
   ; at entry, so callers already inside tls_crypto_guard_enable() (which
   ; itself executed `di`) stay disabled. There are no early exits.
   ld   a, i                       ; PV = IFF2
   push   af                       ; entry interrupt state, popped at exit
   di
   push   ix
   ld   ix, 0
   lea   bc, ix + 0               ; bc = 0 including BCU
   add   ix, sp
   ; frame offsets: see the .equ block above _powmod_exp_u24
   push   bc                       ; Lacc  (filled by .Lorch_text)
   push   bc                       ; Ltmp
   push   bc                       ; Lcnt0
   call   0                        ; -> .Lorch_text (.text; address written
.Lorch = . - 3                     ;    by the trampoline after the copy)
   ld   sp, ix
   pop   ix
   pop   af                        ; PV = IFF2 at entry
   ret   po                        ; interrupts were off at entry: keep off
   ei                              ; takes effect after the next instruction
   ret

   ; .Lsubmul: one .Lconv_text step (lazy reduction, x in [0, 2n)).
   ; x = vi(acc) + 2^(8*size) * (.Lxs), q = 256*q8 + q0 with q0 in .Lq and
   ; .Lm8 = -q8. vi(tmp) + 2^(8*size) * (.Lxs) <- 256*x - q*mod.
   ; Per byte: t = q0*n[i] + carry (<= 0xFFFF), r[i] = y[i] - t_lo - borrow,
   ; carry' = t_hi + (n[i] & m8) (<= 510: the q8*256*n part rides in the
   ; carry). y[i] = x[i-1] and the borrow live in a'/f'; the n / x / r
   ; pointers live in the alternate hl / de / bc. ix = frame.
   ; Destroys af, af', bc, de, hl and the alternate bc, de, hl.
.Lsubmul:
   ld   hl, (ix + Lmod)            ; -> n[0]
   ld   de, (ix + Lacc)            ; -> x[0]
   ld   bc, (ix + Ltmp)            ; -> r[0]
   exx                             ; pointers live in the alternate set
   ld   de, 0                      ; carry = 0
   ld   bc, (.Lsubc)               ; b = lo(size), c = hi_adj(size)
   xor   a, a                      ; y[0] = 0, borrow = 0
   ex   af, af'
.Lsub_top:
   exx
   ld   a, (hl)                    ; n[i]
   dec   hl
   exx
   ld   h, a
   ld   l, 0
.Lq = . - 1
   mlt   hl
   add   hl, de                    ; t = q0*n[i] + carry <= 0xFFFF
   and   a, 0
.Lm8 = . - 1
   add   a, h
   ld   e, a
   ld   a, 0
   adc   a, a
   ld   d, a                       ; carry' = t_hi + (n[i] & m8) <= 510
   ex   af, af'                    ; a = y[i], f = borrow
   sbc   a, l                      ; r[i] = y[i] - t_lo - borrow
   exx
   ld   (bc), a
   dec   bc
   ld   a, (de)                    ; y[i+1] = x[i]
   dec   de
   exx
   ex   af, af'
   djnz   .Lsub_top ; leaks size
   dec   c
   jr   nz, .Lsub_top ; leaks size
   ex   af, af'                    ; a = x[size-1], f = borrow
   ld   hl, 0
   ld   l, a
   ld   a, (.Lxs)
   ld   h, a
   sbc   hl, de                    ; r[size] in {0, 1}
   ld   a, l
   ld   (.Lxs), a
   ret

   ; -----------------------------------------------------------------------
   ; .Lcols: vi(acc) <- vi(acc) * vi(Y) * R^-1 mod vi(mod), Y = acc (sqr) or
   ; base (mul); state armed by .Lmont_text. ix = frame on entry and exit.
   ; Product-scanning Montgomery (FIPS), two columns (k, k+1) per pass:
   ;   ACC += F * sum a[i]*Y[k-i] + 256 * F * sum a[i]*Y[k+1-i]
   ;        + sum m[i]*n[k-i]     + 256 * sum m[i]*n[k+1-i]       (.Ldot2)
   ;   squaring: i < k-i half only, F = 2, plus a[k/2]^2 at column k
   ;   then column k, column k+1 are finished in turn (.Lfin):
   ;     c <  size: m[c] = ACC0 * n' -> vi(tmp), ACC += m[c]*n[0]
   ;                (column k also gets its m[k]*n[1] term at column k+1)
   ;     c >= size: acc[c-size] = ACC0 (in place: acc[c-size] is dead)
   ;     ACC >>= 8
   ; ACC (.Lacc40) is a 40-bit accumulator in the block; result < 2n, its
   ; top bit is ACC0 after the last column and goes to .Lreduce as cf.
   ; Returns cf = top bit of the (< 2n) result; the caller runs .Lreduce.
   ; -----------------------------------------------------------------------
.Lcols:
   push   ix
   ld   hl, 0
   ld   (.Lk), hl
.Lpair:
   ld   hl, (.Lkc)                 ; pairs left (this one included)
   dec   hl
   ld   a, h
   or   a, l
   ld   (.Lnl), a                  ; nonzero unless this is the last pair
   ld   hl, (.Lk)
   inc   hl
   ld   de, (.LS)
   or   a, a
   sbc   hl, de                    ; k + 1 - size, cf = (k + 1 < size)
   sbc   a, a
   ld   (.Lph1), a                 ; 0xFF iff column k+1 < size
   jr   nc, .Lp_lo ; leaks size
   ld   hl, 0
.Lp_lo:
   ld   (.Llo), hl                 ; lo = max(0, k + 1 - size)
   ex   de, hl
   ld   hl, (.Lk)
   or   a, a
   sbc   hl, de
   ld   (.Lj), hl                  ; j = k - lo  (= min(k, size - 1))
   sbc   hl, de
   ld   (.Ljml), hl                ; j - lo
   ; ---- a x Y ----
   ld   a, (.Lsqf)
   or   a, a
   jr   nz, .Lp_sq ; leaks exp
   inc   hl                        ; mul: j - lo + 1 terms in column k
   ld   a, (.Lph1)                 ; column k+1 has one more (i = k+1)
   jr   .Lp_d1
.Lp_sq:
   ld   hl, (.Lk)
   srl   h
   rr   l                          ; k/2, cf = 0
   sbc   hl, de                    ; sqr: k/2 - lo terms in column k
   ld   a, (.Lnl)                  ; column k+1 has one more (i = k/2)
.Lp_d1:
   ld   (.Ld2tr), a
   push   hl
   pop   bc                        ; bc = count (bcu = 0)
   ld   a, (.Lsqf)
   inc   a
   ld   (.LdotF), a
   ld   (.Ld2fin), a               ; fold F times at the end
   ld   hl, (.LYl)
   ld   de, (.Lj)
   or   a, a
   sbc   hl, de
   push   hl
   pop   iy                        ; -> Y[j]
   ld   hl, (.LAl)
   ld   de, (.Llo)
   sbc   hl, de
   ex   de, hl                     ; de -> acc[lo]
   ld   hl, 0
   ld   ix, 0
   call   .Lpre_dot2               ; seeds hl = ix = 0
   ; ---- m x n, seeded with the squaring diagonal a[k/2]^2 ----
   xor   a, a
   ld   (.Ld2tr), a
   ld   (.Ld2fin), a               ; return hl/ix unfolded
   ld   hl, 0
   ld   a, (.Lsqf)
   or   a, a
   jr   z, .Lp_d2 ; leaks exp
   ld   hl, (.Lk)
   srl   h
   rr   l
   ex   de, hl
   ld   hl, (.LAl)
   sbc   hl, de                    ; -> acc[k/2]  (cf = 0 from rr)
   ld   d, (hl)
   ld   e, d
   mlt   de
   ex   de, hl                     ; hl = a[k/2]^2
.Lp_d2:
   ld   a, 1
   ld   (.LdotF), a                ; intermediate chunk folds: x1
   ld   bc, (.Ljml)
   ld   de, (.Llo)
   ld   a, d
   or   a, e
   jr   z, .Lp_c2 ; leaks size
   inc   bc                        ; k >= size: j - lo + 1 terms
.Lp_c2:
   push   hl                       ; seed
   ld   hl, (.LTl)
   or   a, a
   sbc   hl, de
   push   hl                       ; -> m[lo]
   ld   hl, (.LNl)
   ld   de, (.Lj)
   sbc   hl, de
   push   hl
   pop   iy                        ; -> n[j]
   pop   de
   pop   hl
   ld   ix, 0
   call   .Lpre_dot2
   ; ---- finish columns k and k+1 (hl/ix = unfolded m x n sums) ----
   ld   bc, (.Llo)
   ld   a, b
   or   a, c
   push   af                       ; z iff column k < size
   jr   nz, .Lf_k ; leaks size
   ld   a, (.Lacc40)
   add   a, l                      ; byte 0 of ACC + hl
   ld   e, a
   ld   d, 0
.Lnmi = . - 1
   mlt   de                        ; e = m[k] = byte0 * n' mod 256
   push   hl
   ld   hl, (.LTl)
   ld   bc, (.Lk)
   or   a, a
   sbc   hl, bc
   ld   (hl), e                    ; m[k]
   pop   hl
   ld   c, e
   ld   d, 0
.Ln0 = . - 1
   mlt   de
   add   hl, de                    ; column k   += m[k]*n[0]  (<= 258 terms)
   ld   e, c
   ld   d, 0
.Ln1 = . - 1
   mlt   de
   add   ix, de                    ; column k+1 += m[k]*n[1]
.Lf_k:
   call   .Lfold                   ; ACC += hl + 256*ix
   pop   af
   jr   z, .Lf_k1 ; leaks size
   ld   hl, (.LPOb)
   ld   de, (.Lk)
   sbc   hl, de                    ; -> acc[k - size]  (cf = 0 from or)
   ld   a, (.Lacc40)
   ld   (hl), a
.Lf_k1:
   ld   a, (.Lph1)
   or   a, a
   ld   a, (.Lacc40 + 1)           ; byte 1 = column k+1
   ld   de, (.Lk)
   jr   z, .Lf_k1o ; leaks size
   ld   hl, (.LTl)
   scf
   sbc   hl, de                    ; -> m[k+1]
   ld   e, a
   ld   a, (.Lnmi)
   ld   d, a
   mlt   de                        ; e = m[k+1]
   ld   (hl), e
   ld   a, (.Ln0)
   ld   d, a
   mlt   de
   ld   hl, (.Lacc40 + 1)
   add   hl, de
   ld   (.Lacc40 + 1), hl          ; byte 1 -> 0
   ld   hl, .Lacc40 + 4
   ld   a, 0
   adc   a, (hl)
   ld   (hl), a
   jr   .Lf_sh
.Lf_k1o:
   ld   hl, (.LPOb)
   scf
   sbc   hl, de                    ; -> acc[k+1 - size]
   ld   (hl), a
.Lf_sh:
   ld   hl, .Lacc40 + 2            ; ACC >>= 16 (bytes 5, 6 are always 0)
   ld   de, .Lacc40
   ld   bc, 5
   ldir
   ld   hl, (.Lk)
   inc   hl
   inc   hl
   ld   (.Lk), hl
   ld   hl, (.Lkc)
   dec   hl
   ld   (.Lkc), hl
   ld   a, h
   or   a, l
   jp   nz, .Lpair ; leaks size
   pop   ix
   ld   a, (.Lacc40)
   rra                             ; cf = top bit of the < 2n result
   ret

   ; .Lpre_dot2: a <- Y[j+1] if column k+1 < size else 0 (iy -> Y[j]),
   ; then .Ldot2.
.Lpre_dot2:
   ld   a, (.Lph1)
   or   a, a
   jr   z, .Ldot2 ; leaks size
   ld   a, (iy - 1)
   ;  fall through

   ; .Ldot2: paired dot product of columns (k, k+1) along x (down) / y (up):
   ;   ACC += F * (hl + sum_t x[t]*y[t]
   ;               + 256 * (ix + sum_t x[t]*y[t-1] [+ x[cnt]*y[cnt-1]]))
   ; y[-1] = a on entry; the bracketed trailing term iff .Ld2tr != 0.
   ; in: de -> x[0], iy -> y[0], bc = cnt (bcu = 0), hl/ix = seeds.
   ; If .Ld2fin = 0 the final fold is skipped and the sums are returned
   ; (column k in hl, column k+1 in ix).
   ; Inner step (17 bytes, 2 mlts, 2 loads): alternate set: de' -> x,
   ; hl' = column k+1 sum; main set: hl -> y, ix = column k sum, b = count.
   ; The x byte crosses to the main set and the y byte to the next step in
   ; a. At most 256 steps (+ one seed / m term / trailing term) between
   ; folds keeps both sums < 2^24 (258 * 255^2 < 2^24). Entered Duff-style
   ; at step (7*ceil(chunk/7) - chunk) of a 7-step block.
   ; Uses the alternate registers (interrupts are off). Destroys everything.
.Ldot2:
   ld   (.Ld2pre), a
   push   hl                       ; seed, column k
   push   ix                       ; seed, column k+1
   push   de
   exx
   pop   de                        ; de' -> x
   pop   hl                        ; hl' = column k+1 sum
   exx
   pop   ix                        ; ix = column k sum
   lea   hl, iy + 0                ; hl -> y
   ld   a, c
   cp   a, 1                       ; cf = (lo byte == 0)
   ld   a, b
   sbc   a, -1                     ; a = number of chunks
   ld   b, c                       ; first chunk = cnt & 255 (0 = 256)
   jp   z, .Ld2_last ; leaks size
.Ld2_chunk:
   ld   (.Ld2n), a
   push   hl
   ld   a, b
   dec   a
   ld   c, a                       ; x = chunk - 1 (0..255)
   ld   d, a
   ld   e, 73
   mlt   de
   ld   hl, 36
   add   hl, de
   ld   a, h
   srl   a                         ; q = floor(x / 7) = (73x + 36) >> 9
   ld   b, a
   inc   b                         ; blocks = q + 1
   ld   e, a
   add   a, a
   add   a, a
   add   a, a
   sub   a, e
   add   a, 6
   sub   a, c                      ; skip = 7*blocks - chunk (0..6)
   ld   d, a
   ld   e, 17
   mlt   de
   ld   hl, .Ld2_blk
   add   hl, de
   ld   (.Ld2_jp), hl
   pop   hl
   ld   a, (.Ld2pre)
   jp   0                          ; enter the block at step `skip`
.Ld2_jp = . - 3
.Ld2_blk:
   exx
   ld   c, a
   ld   a, (de)
   dec   de
   ld   b, a
   mlt   bc
   add   hl, bc
   exx
   ld   d, a
   ld   e, (hl)
   inc   hl
   ld   a, e
   mlt   de
   add   ix, de
   exx
   ld   c, a
   ld   a, (de)
   dec   de
   ld   b, a
   mlt   bc
   add   hl, bc
   exx
   ld   d, a
   ld   e, (hl)
   inc   hl
   ld   a, e
   mlt   de
   add   ix, de
   exx
   ld   c, a
   ld   a, (de)
   dec   de
   ld   b, a
   mlt   bc
   add   hl, bc
   exx
   ld   d, a
   ld   e, (hl)
   inc   hl
   ld   a, e
   mlt   de
   add   ix, de
   exx
   ld   c, a
   ld   a, (de)
   dec   de
   ld   b, a
   mlt   bc
   add   hl, bc
   exx
   ld   d, a
   ld   e, (hl)
   inc   hl
   ld   a, e
   mlt   de
   add   ix, de
   exx
   ld   c, a
   ld   a, (de)
   dec   de
   ld   b, a
   mlt   bc
   add   hl, bc
   exx
   ld   d, a
   ld   e, (hl)
   inc   hl
   ld   a, e
   mlt   de
   add   ix, de
   exx
   ld   c, a
   ld   a, (de)
   dec   de
   ld   b, a
   mlt   bc
   add   hl, bc
   exx
   ld   d, a
   ld   e, (hl)
   inc   hl
   ld   a, e
   mlt   de
   add   ix, de
   exx
   ld   c, a
   ld   a, (de)
   dec   de
   ld   b, a
   mlt   bc
   add   hl, bc
   exx
   ld   d, a
   ld   e, (hl)
   inc   hl
   ld   a, e
   mlt   de
   add   ix, de
   djnz   .Ld2_blk ; leaks size
   ld   (.Ld2pre), a               ; y[t-1] for the next chunk / trailing
   ld   a, 0
.Ld2n = . - 1
   dec   a
   jr   z, .Ld2_last ; leaks size
   ld   (.Ld2n), a
   push   hl                       ; -> y
   call   .Ld2_acc
   call   .LfoldF                  ; intermediate fold, F times
   ld   ix, 0
   exx
   ld   hl, 0
   exx
   pop   hl
   ld   b, 0                       ; later chunks: 256 steps
   ld   a, (.Ld2n)
   jp   .Ld2_chunk
.Ld2_last:
   ld   a, 0
.Ld2tr = . - 1
   or   a, a
   jr   z, .Ld2_nt ; leaks size
   exx
   ld   a, (de)                    ; x[cnt]
   ld   b, a
   ld   a, (.Ld2pre)               ; y[cnt-1]
   ld   c, a
   mlt   bc
   add   hl, bc
   exx
.Ld2_nt:
   call   .Ld2_acc
   ld   a, 0
.Ld2fin = . - 1
   or   a, a
   ret   z ; leaks size             ; caller folds hl/ix itself
.LfoldF:                           ; ACC += F * (hl + 256 * ix)
   ld   a, (.LdotF)
   ld   b, a
.LfoldF_loop:
   call   .Lfold
   djnz   .LfoldF_loop ; leaks size
   ret

   ; .Ld2_acc: hl <- ix (column k sum), ix <- hl' (column k+1 sum).
.Ld2_acc:
   push   ix
   exx
   push   hl
   exx
   pop   ix
   pop   hl
   ret

   ; .Lfold: ACC += hl + 256 * ix (24-bit each). Preserves a, bc, hl, ix.
.Lfold:
   push   hl
   ex   de, hl
   ld   hl, (.Lacc40)
   add   hl, de
   ld   (.Lacc40), hl
   ld   hl, (.Lacc40 + 3)
   ld   de, 0
   adc   hl, de
   ld   (.Lacc40 + 3), hl
   lea   de, ix + 0
   ld   hl, (.Lacc40 + 1)
   add   hl, de
   ld   (.Lacc40 + 1), hl
   ld   hl, (.Lacc40 + 4)
   ld   de, 0
   adc   hl, de
   ld   (.Lacc40 + 4), hl
   pop   hl
   ret

   ; data (lives in the relocated block; re-armed on every call)
.Lacc40:
   .byte 0, 0, 0, 0, 0, 0, 0
.Lk:
   .byte 0, 0, 0
.Lkc:
   .byte 0, 0, 0
.Llo:
   .byte 0, 0, 0
.Lj:
   .byte 0, 0, 0
.Ljml:
   .byte 0, 0, 0
.LS:
   .byte 0, 0, 0
.LAl:
   .byte 0, 0, 0
.LTl:
   .byte 0, 0, 0
.LYl:
   .byte 0, 0, 0
.LNl:
   .byte 0, 0, 0
.LPOb:
   .byte 0, 0, 0
.Lsqf:
   .byte 0
.LdotF:
   .byte 0
.Ld2pre:
   .byte 0
.Lph1:
   .byte 0
.Lnl:
   .byte 0
.Lfast:
   .byte 0
.Lidx:
   .byte 0, 0, 0
.Lxs:
   .byte 0
.Lsubc:
   .byte 0, 0, 0
.Lxtop:
   .byte 0
.Lwbuf:
   .byte 0, 0, 0, 0, 0
.LdivD:
   .byte 0, 0, 0
.Lnv:
   .byte 0
.Lnz:
   .byte 0
.Lsh:
   .byte 0
.Ldata_end:
_powmod_reloc_run_end:

.section	.text,"ax",@progbits

.section	.note.GNU-stack,"",@progbits

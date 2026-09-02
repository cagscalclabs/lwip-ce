.include "virtuals.inc"
 
; -----------------------------------
; C-callable crypto guards (ez80)
; -----------------------------------
; tls_crypto_guard_enable() -> save interrupt state, disable interrupts
; tls_crypto_guard_disable()  -> clear stack, restore interrupt state
 
.assume adl=1
.section    .text,"ax",@progbits
 
 
.globl _tls_crypto_guard_enable
.globl _tls_crypto_guard_disable
.type   _tls_crypto_guard_enable,@function
.type   _tls_crypto_guard_disable,@function
 
.equ stackBot, 0x0D1987E
 
.section .bss._crypto_guard_state,"aw",@nobits
_crypto_guard_state:
    .zero   2
 
.section    .text,"ax",@progbits
 
; void tls_crypto_guard_enable(void)
_tls_crypto_guard_enable:
    ; put the interrupt state in the carry flag
    ld a, i
    scf
    jp pe, .Lenabled
    or a, a
.Lenabled:
    ; shift into state
    ld hl, _crypto_guard_state
    rl (hl)
    inc hl
    rl (hl)
	di
    ret nc
    ; if a bit overflowed, set the MSB to make sure interrupts are
    ; eventually re-enabled again after enough pops
    set 7, (hl)
    ret
 
; void tls_crypto_guard_disable(void)
_tls_crypto_guard_disable:
; _erase_stack:
    ; Scrub the stack below our return address down to the floor (stackBot+4),
    ; one byte above the hardware stack-limit guard at stackBot+3 (0xD19881).
    ;
    ; Two correctness points (calc84maniac):
    ;  - The seed byte (ld (hl),a) must be written AFTER the push hl/pop de,
    ;    otherwise that push would clobber the seed we just placed at (SP-1).
    ;  - This routine's OWN push reaches down to SP-3, so we must not even push
    ;    unless SP-3 stays above the guard. We require scrub length >= 3
    ;    (i.e. SP-1 >= stackBot+7): then the push touches down to SP-3 >=
    ;    stackBot+4 (0xD19882) and the lddr's lowest byte is stackBot+4 too —
    ;    both strictly above the guard at stackBot+3 (0xD19881). When length
    ;    is positive here it is also >= 3, so the old `jr z` is unnecessary.
    ;
    ; hl = SP-1 (top byte to scrub; SP itself is the low byte of our retaddr).
    scf
    sbc hl, hl
    add hl, sp
    ld de, stackBot + 4
    xor a, a
    sbc hl, de              ; hl = (SP-1) - (stackBot+4) = scrub length
    jr c,  .Lrestore_interrupts   ; SP below floor: skip before any push
    ; Require length >= 3 so this routine's own push (down to SP-3) and the
    ; lddr never write at/below the guard. cf is clear from the jr c above.
    ld de, 3
    sbc hl, de              ; hl = length - 3
    jr c,  .Lrestore_interrupts   ; length < 3: not enough room, skip
    add hl, de             ; hl = length (restored; cf clear after)

        ; length>=3 (room for the push): bc = length, then set up the lddr
        ; pointers (hl=SP-1 src, de=SP-2 dst) and seed (SP-1)=0 AFTER the
        ; push/pop so the push can't clobber the seed.
        push hl
        pop bc                   ; bc = length
        ld de, stackBot + 4
        add hl, de               ; hl = SP-1
        push hl
        pop de
        dec de                   ; de = SP-2
        ld (hl), a               ; seed (SP-1) = 0  (after the push/pop)
        lddr

    ; restore interrupts
.Lrestore_interrupts:
    ; pop the most recently pushed state and apply it
    ; if no state has been pushed, this does nothing
    ld hl, _crypto_guard_state + 1
    srl (hl)
    dec hl
    rr (hl)
    ret nc
    ei
    ret

.section    .note.GNU-stack,"",@progbits

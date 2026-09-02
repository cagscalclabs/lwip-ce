

.assume adl=1
.equ ti.InsertMem, 0020514h
.equ ti.EnoughMem, 002051Ch

.section .text,"ax",@progbits
.global _pcap_insert_mem
.global _pcap_enough_mem

.type _pcap_insert_mem,@function
; pcap_insert_mem(void *addr, size_t nbytes)
; stack on entry: [SP+0]=retaddr [SP+3]=addr [SP+6]=nbytes
_pcap_insert_mem:
    pop iy          ; save return address
    pop hl          ; addr
    pop de          ; nbytes
    call ti.InsertMem
    jp (iy)         ; return


.type _pcap_enough_mem,@function
; pcap_enough_mem(void *addr, size_t nbytes)
; stack on entry: [SP+0]=retaddr [SP+3]=addr [SP+6]=nbytes
; returns bool: EnoughMem sets carry if enough; sbc hl,hl -> HL=0 (false) or -1 (true)
_pcap_enough_mem:
    pop iy          ; save return address
    pop hl          ; addr
    pop de          ; nbytes
    call ti.EnoughMem
    sbc hl, hl
    jp (iy)         ; return

.section    .note.GNU-stack,"",@progbits

/* TEMPORARY DIAGNOSTIC (nettls NMI hunt). Remove with TLS_NMI_TRAP_DIAG.
 *
 * LWDIAG(k) prints "[lwdiag] kk sp=XXXXXX" to CEmu's debug-error console
 * (0xFC0000), which the CI autotester forwards to stderr. Written byte by
 * byte instead of through printf: the original crash PC was in the
 * formatter. On hardware 0xFC0000 is unmapped MMIO, so the writes are inert;
 * host builds compile it out. */
#ifndef TLS_DIAG_TRAP_H
#define TLS_DIAG_TRAP_H

#include <stdint.h>

#if defined(__ez80__)
static inline void lwdiag_mark(uint8_t k)
{
    static const char hex[] = "0123456789ABCDEF";
    static const char prefix[] = "[lwdiag] ";
    volatile uint8_t probe;
    uintptr_t sp = (uintptr_t)&probe;
    volatile char *port = (volatile char *)0xFC0000;

    for (const char *s = prefix; *s; s++)
        *port = *s;
    *port = hex[k >> 4];
    *port = hex[k & 15];
    *port = ' ';
    *port = 's';
    *port = 'p';
    *port = '=';
    for (int shift = 20; shift >= 0; shift -= 4)
        *port = hex[(sp >> shift) & 15];
    *port = '\n';
    *port = 0;
}
#define LWDIAG(k) lwdiag_mark((uint8_t)(k))
#else
#define LWDIAG(k) ((void)0)
#endif

#endif

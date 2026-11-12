/* TEMPORARY DIAGNOSTIC (nettls NMI hunt). Remove with TLS_NMI_TRAP_DIAG.
 *
 * LWDIAG(k) prints to CEmu's debug-error console (0xFC0000), which the CI
 * autotester forwards to stderr:
 *   [lwdiag] kk sp=XXXXXX ix=XXXXXX ch=NN:TTTTTT [BAD]
 * ch walks the saved-IX frame chain: NN frames, TTTTTT the value that ended
 * the walk. BAD = a saved IX pointing down the stack or to zero, or a return
 * address outside flash/user RAM -- i.e. a smashed frame, caught before the
 * function owning it returns. The first breadcrumb in each file also prints
 * lwip_now_ms's runtime address so stack dumps can be mapped to symbols.
 * Written byte by byte, not via printf (the original crash PC was in the
 * formatter). On hardware 0xFC0000 is unmapped MMIO; host builds compile it
 * out. */
#ifndef TLS_DIAG_TRAP_H
#define TLS_DIAG_TRAP_H

#include <stdbool.h>
#include <stdint.h>

#if defined(__ez80__)
uintptr_t lwdiag_ix(void);
uint32_t lwip_now_ms(void);

#define LWDIAG_STK_LO 0xD19882u
#define LWDIAG_STK_HI 0xD1A87Eu

static void lwdiag_puts(const char *s)
{
    volatile char *port = (volatile char *)0xFC0000;
    while (*s)
        *port = *s++;
}

static void lwdiag_hex(uintptr_t v, uint8_t digits)
{
    static const char hex[] = "0123456789ABCDEF";
    volatile char *port = (volatile char *)0xFC0000;
    while (digits--)
        *port = hex[(v >> (digits * 4u)) & 15u];
}

static uintptr_t lwdiag_u24(uintptr_t addr)
{
    const volatile uint8_t *p = (const volatile uint8_t *)addr;
    return (uintptr_t)p[0] | ((uintptr_t)p[1] << 8) | ((uintptr_t)p[2] << 16);
}

static bool lwdiag_code_addr(uintptr_t ret)
{
    return (ret >= 0x020000u && ret < 0x400000u) ||   /* flash: OS, dylib */
           (ret >= 0xD1A881u && ret < 0xD65800u);     /* userMem: program */
}

static __attribute__((noinline, unused)) void lwdiag_mark(uint8_t k)
{
    static bool base_printed;
    volatile uint8_t probe;
    uintptr_t ix = lwdiag_ix();
    uintptr_t cur = ix;
    uintptr_t term = ix;
    uint8_t frames = 0;
    bool bad = false;

    if (!base_printed)
    {
        base_printed = true;
        lwdiag_puts("[lwdiag] base now_ms=");
        lwdiag_hex((uintptr_t)&lwip_now_ms, 6);
        lwdiag_puts("\n");
        *(volatile char *)0xFC0000 = 0;
    }

    while (frames < 64 && cur >= LWDIAG_STK_LO && cur <= LWDIAG_STK_HI - 6u)
    {
        uintptr_t saved = lwdiag_u24(cur);
        uintptr_t ret = lwdiag_u24(cur + 3u);
        frames++;
        term = saved;
        if (!lwdiag_code_addr(ret))
        {
            bad = true;
            term = ret;
            break;
        }
        if (saved == 0 || (saved >= LWDIAG_STK_LO && saved <= cur))
        {
            bad = true;
            break;
        }
        if (saved > LWDIAG_STK_HI || saved < LWDIAG_STK_LO)
            break;                                      /* left the stack: end */
        cur = saved;
    }

    lwdiag_puts("[lwdiag] ");
    lwdiag_hex(k, 2);
    lwdiag_puts(" sp=");
    lwdiag_hex((uintptr_t)&probe, 6);
    lwdiag_puts(" ix=");
    lwdiag_hex(ix, 6);
    lwdiag_puts(" ch=");
    lwdiag_hex(frames, 2);
    lwdiag_puts(":");
    lwdiag_hex(term, 6);
    lwdiag_puts(bad ? " BAD\n" : "\n");
    *(volatile char *)0xFC0000 = 0;
}
#define LWDIAG(k) lwdiag_mark((uint8_t)(k))
#else
#define LWDIAG(k) ((void)0)
#endif

#endif

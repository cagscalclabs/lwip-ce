#include "lwip/opt.h"
#include "lwip/arch.h"

void lwip_ce_chksum_pairs(const u8_t *p, size_t blocks, size_t out[2]);

u16_t lwip_ce_chksum(const void *dataptr, int len)
{
    const u8_t *p = (const u8_t *)dataptr;
    size_t s[2];
    size_t blocks = (size_t)len >> 4;
    u32_t acc;

    lwip_ce_chksum_pairs(p, blocks, s);
    p += blocks << 4;
    len &= 15;
    while (len > 1)
    {
        s[0] += p[0];
        s[1] += p[1];
        p += 2;
        len -= 2;
    }
    if (len > 0)
    {
        s[0] += p[0];
    }
    acc = (u32_t)s[0] + ((u32_t)s[1] << 8);
    acc = (acc >> 16) + (acc & 0xffffUL);
    acc = (acc >> 16) + (acc & 0xffffUL);
    return (u16_t)acc;
}

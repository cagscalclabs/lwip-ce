#include "lwip/arch.h"
#include <sys/timers.h>
#include <sys/util.h>
#include <sys/rtc.h>
#include <stdlib.h>
#include <time.h>
#include <usbdrvce.h>

u32_t sys_jiffies(void)
{
    return clock();
}

/* clock() * 1000 overflows 32 bits after 131 s, which made the ms count wrap at
 * 131072 instead of 2^32 and broke every lwIP timer. Accumulate elapsed ticks
 * instead, so the result wraps at 2^32 like lwIP expects. */
u32_t sys_now(void)
{
    static u32_t last_ticks;
    static u32_t ms;
    static u32_t remainder;
    u32_t ticks = sys_jiffies();
    u32_t elapsed = ticks - last_ticks;

    last_ticks = ticks;
    ms += elapsed / CLOCKS_PER_SEC * 1000;
    remainder += elapsed % CLOCKS_PER_SEC * 1000;
    ms += remainder / CLOCKS_PER_SEC;
    remainder %= CLOCKS_PER_SEC;
    return ms;
}

void sys_init(void)
{
    srandom(rtc_Time() ^ (unsigned long)clock());
    timer_Enable(1, TIMER_32K, TIMER_NOINT, TIMER_UP);
}

u32_t lwip_ce_rand(void)
{
    return (u32_t)random();
}

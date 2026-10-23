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

u32_t sys_now(void)
{
    u32_t t = sys_jiffies();
    /* t * 1000 overflows 32 bits after ~131 s at 32768 Hz; split seconds out. */
    return (t >> 15) * 1000u + (((t & 0x7FFFu) * 1000u) >> 15);
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

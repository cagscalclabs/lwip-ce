#include "lwip/arch.h"
#include <sys/timers.h>
#include <sys/util.h>
#include <sys/rtc.h>
#include <time.h>
#include <usbdrvce.h>

u32_t sys_jiffies(void)
{
    return clock();
}

u32_t sys_now(void)
{
    return sys_jiffies() * 1000 / CLOCKS_PER_SEC;
}

void sys_init(void)
{
    srandom(rtc_Time());
    timer_Enable(1, TIMER_32K, TIMER_NOINT, TIMER_UP);
}

u32_t lwip_ce_rand(void)
{
    static u32_t state;
    state ^= (u32_t)clock() ^ rtc_Time();
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    return state;
}

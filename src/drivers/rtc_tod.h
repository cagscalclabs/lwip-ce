#ifndef RTC_TOD_H
#define RTC_TOD_H

/*
 * Wall-clock time of day from the RTC registers: the clock the user sets in
 * TI-OS, that boot_GetTime() reads, and that SNTP writes. Used for log-file
 * line stamps and capture record timestamps so both match the user's clock.
 *
 * Not rtc_Time(): that is a free-running seconds counter (fine for intervals,
 * e.g. TLS ticket age) whose value has no fixed relation to the time of day.
 */

#include <stdint.h>
#include <sys/rtc.h>

/** Seconds since local midnight, 0..86399. */
static inline uint32_t rtc_tod_seconds(void)
{
    uint8_t s, m, h;
    /* Re-read if the seconds register ticked mid-read (see sys/rtc.h). */
    do {
        s = rtc_Seconds;
        m = rtc_Minutes;
        h = rtc_Hours;
    } while (s != rtc_Seconds);
    return (uint32_t)h * 3600u + (uint32_t)m * 60u + s;
}

/** Format a time of day as "HH:MM:SS" into out[9]. */
static inline void rtc_tod_format(uint32_t tod, char out[9])
{
    uint8_t h = (uint8_t)(tod / 3600u), m = (uint8_t)(tod / 60u % 60u), s = (uint8_t)(tod % 60u);
    out[0] = (char)('0' + h / 10); out[1] = (char)('0' + h % 10); out[2] = ':';
    out[3] = (char)('0' + m / 10); out[4] = (char)('0' + m % 10); out[5] = ':';
    out[6] = (char)('0' + s / 10); out[7] = (char)('0' + s % 10); out[8] = '\0';
}

#endif

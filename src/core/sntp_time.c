#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <sys/rtc.h>
#include <graphx.h>
#include <tice.h>

#include "lwip/app_config.h"

volatile bool g_sntp_time_set = false;

static bool is_leap_year(uint16_t year)
{
    return ((year % 4u) == 0u) && (((year % 100u) != 0u) || ((year % 400u) == 0u));
}

void lwip_sntp_reset_flag(void)
{
    g_sntp_time_set = false;
}

bool lwip_sntp_time_was_set(void)
{
    return g_sntp_time_set;
}

/* boot_SetDate()'s year parameter is a real, full-width year (e.g. 2026),
 * NOT a 2-digit 0-99-offset-from-2000 value — confirmed against a real
 * device's post-RAM-clear reading (raw year=2014, not 14). */
static void unix_seconds_to_rtc_fields(uint32_t seconds,
                                       uint8_t *secs, uint8_t *minutes, uint8_t *hours,
                                       uint8_t *day, uint8_t *month, uint16_t *year)
{
    static const uint8_t days_in_month[] = {
        31u, 28u, 31u, 30u, 31u, 30u, 31u, 31u, 30u, 31u, 30u, 31u
    };

    uint32_t days = seconds / 86400u;
    uint32_t rem  = seconds % 86400u;

    *hours = (uint8_t)(rem / 3600u);
    rem %= 3600u;
    *minutes = (uint8_t)(rem / 60u);
    *secs    = (uint8_t)(rem % 60u);

    *year = 1970u;
    while (1)
    {
        uint16_t year_days = is_leap_year(*year) ? 366u : 365u;
        if (days < year_days)
            break;
        days -= year_days;
        (*year)++;
    }

    *month = 1u;
    *day   = 1u;
    for (uint8_t i = 0; i < 12u; i++)
    {
        uint8_t dim = days_in_month[i];
        if ((i == 1u) && is_leap_year(*year))
            dim = 29u;
        if (days < dim)
        {
            *month = (uint8_t)(i + 1u);
            *day   = (uint8_t)(days + 1u);
            break;
        }
        days -= dim;
    }
}

static uint32_t rtc_fields_to_unix_seconds(uint8_t sec, uint8_t min, uint8_t hr,
                                           uint8_t day, uint8_t month, uint16_t year)
{
    static const uint16_t days_before_month[] = {
        0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334
    };
    uint32_t days = 0;

    for (uint16_t y = 1970u; y < year; y++)
        days += is_leap_year(y) ? 366u : 365u;

    if (month >= 1u && month <= 12u)
    {
        days += days_before_month[month - 1u];
        if (month > 2u && is_leap_year(year))
            days += 1u;
    }

    days += (day - 1u);

    return days * 86400u + (uint32_t)hr * 3600u + (uint32_t)min * 60u + sec;
}

static int32_t locale_offset_seconds(void)
{
    const lwip_app_config_t *cfg = lwip_app_config_get();
    int32_t off = cfg ? (int32_t)cfg->tz_offset_minutes * 60 : 0;
    if (cfg && cfg->dst_enabled)
        off += 3600;
    return off;
}

/* Write a UTC Unix timestamp to the RTC as local time. */
static void rtc_write_with_locale(uint32_t utc_seconds)
{
    int64_t local = (int64_t)utc_seconds + (int64_t)locale_offset_seconds();
    if (local < 0)
        local = 0;

    uint8_t secs, minutes, hours, day, month;
    uint16_t year;
    unix_seconds_to_rtc_fields((uint32_t)local, &secs, &minutes, &hours, &day, &month, &year);

    while (rtc_IsBusy()) {}
    boot_SetTime(secs, minutes, hours);
    while (rtc_IsBusy()) {}
    boot_SetDate(day, month, year);
}

/* Read the RTC and reverse the locale offset to recover UTC. */
static uint32_t rtc_read_with_locale(void)
{
    uint8_t sec, min, hr, day, month;
    uint16_t year;

    while (rtc_IsBusy()) {}
    boot_GetTime(&sec, &min, &hr);
    boot_GetDate(&day, &month, &year);

    uint32_t local = rtc_fields_to_unix_seconds(sec, min, hr, day, month, year);

    int64_t utc = (int64_t)local - (int64_t)locale_offset_seconds();
    if (utc < 0)
        utc = 0;
    return (uint32_t)utc;
}

void lwip_sntp_set_time(uint32_t seconds)
{
    rtc_write_with_locale(seconds);
    g_sntp_time_set = true;
}

uint32_t lwip_sntp_get_unix_time(void)
{
    if (!g_sntp_time_set)
        return 0;
    return rtc_read_with_locale();
}

uint32_t lwip_sntp_read_rtc_raw(void)
{
    return rtc_read_with_locale();
}

void lwip_sntp_clamp_rtc_floor(uint32_t floor_unix_seconds)
{
    if (rtc_read_with_locale() >= floor_unix_seconds)
    {
        /* Clock already reads at or after the floor -- leave it alone.
         * Deliberately does not touch g_sntp_time_set: this is a plausibility
         * clamp, not an SNTP sync. */
        return;
    }
    rtc_write_with_locale(floor_unix_seconds);
}

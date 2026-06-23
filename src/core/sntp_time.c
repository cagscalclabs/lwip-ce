#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <sys/rtc.h>
#include <graphx.h>
#include <tice.h>

static int32_t g_tz_offset_seconds = 0;
static bool g_dst_enabled = false;
volatile bool g_sntp_time_set = false;

static bool is_leap_year(uint16_t year)
{
    return ((year % 4u) == 0u) && (((year % 100u) != 0u) || ((year % 400u) == 0u));
}

void lwip_sntp_set_timezone_offset(int32_t seconds)
{
    g_tz_offset_seconds = seconds;
}

void lwip_sntp_set_dst_enabled(bool enabled)
{
    g_dst_enabled = enabled;
}

void lwip_sntp_reset_flag(void)
{
    g_sntp_time_set = false;
}

bool lwip_sntp_time_was_set(void)
{
    return g_sntp_time_set;
}

/* Shared Unix-seconds -> RTC component conversion. tz_adjusted controls
 * whether g_tz_offset_seconds/DST are applied first (lwip_sntp_set_time()
 * wants the RTC to read local time; the raw floor-clamp path wants the RTC
 * written directly in UTC since lwip_sntp_read_rtc_raw() reads it back
 * un-adjusted). */
static void unix_seconds_to_rtc_fields(uint32_t adj_seconds,
                                       uint8_t *secs, uint8_t *minutes, uint8_t *hours,
                                       uint8_t *day, uint8_t *month, uint16_t *year_2digit)
{
    static const uint8_t days_in_month[] = {
        31u, 28u, 31u, 30u, 31u, 30u, 31u, 31u, 30u, 31u, 30u, 31u
    };

    uint32_t days = adj_seconds / 86400u;
    uint32_t rem = adj_seconds % 86400u;
    uint16_t year;

    *hours = (uint8_t)(rem / 3600u);
    rem %= 3600u;
    *minutes = (uint8_t)(rem / 60u);
    *secs = (uint8_t)(rem % 60u);

    year = 1970u;
    while (1)
    {
        uint16_t year_days = is_leap_year(year) ? 366u : 365u;
        if (days < year_days)
        {
            break;
        }
        days -= year_days;
        year++;
    }

    *month = 1u;
    *day = 1u;
    for (uint8_t i = 0; i < 12u; i++)
    {
        uint8_t dim = days_in_month[i];
        if ((i == 1u) && is_leap_year(year))
        {
            dim = 29u;
        }
        if (days < dim)
        {
            *month = (uint8_t)(i + 1u);
            *day = (uint8_t)(days + 1u);
            break;
        }
        days -= dim;
    }

    /* TI-84 CE RTC uses 2-digit years (0-99 representing 2000-2099) */
    *year_2digit = (year >= 2000u) ? (year - 2000u) : year;
    if (*year_2digit > 99u)
    {
        *year_2digit = 99u; /* cap at 2099 */
    }
}

void lwip_sntp_set_time(uint32_t seconds)
{
    int64_t adjusted = (int64_t)seconds + (int64_t)g_tz_offset_seconds;
    uint8_t secs, minutes, hours, day, month;
    uint16_t year_2digit;

    if (g_dst_enabled)
    {
        adjusted += 3600;
    }
    if (adjusted < 0)
    {
        adjusted = 0;
    }

    unix_seconds_to_rtc_fields((uint32_t)adjusted, &secs, &minutes, &hours, &day, &month, &year_2digit);

    while (rtc_IsBusy()) {}
    boot_SetTime(secs, minutes, hours);
    while (rtc_IsBusy()) {}
    boot_SetDate(day, month, year_2digit);

    // Signal that time has been set (after all RTC operations complete)
    g_sntp_time_set = true;
}

/* Inverse of unix_seconds_to_rtc_fields(): RTC component reading -> Unix
 * seconds (no timezone/DST adjustment applied here -- caller's choice). */
static uint32_t rtc_fields_to_unix_seconds(uint8_t sec, uint8_t min, uint8_t hr,
                                           uint8_t day, uint8_t month, uint8_t year_2digit)
{
    static const uint16_t days_before_month[] = {
        0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334
    };
    uint16_t year = (uint16_t)year_2digit + 2000u;
    uint32_t days = 0;

    for (uint16_t y = 1970u; y < year; y++)
    {
        days += is_leap_year(y) ? 366u : 365u;
    }

    if (month >= 1u && month <= 12u)
    {
        days += days_before_month[month - 1u];
        if (month > 2u && is_leap_year(year))
        {
            days += 1u;
        }
    }

    days += (day - 1u);

    return days * 86400u + (uint32_t)hr * 3600u + (uint32_t)min * 60u + sec;
}

uint32_t lwip_sntp_get_unix_time(void)
{
    uint8_t sec, min, hr;
    uint8_t day, month, year_2digit;
    uint32_t timestamp;
    int64_t utc;

    /* If time was never set via SNTP, return 0 */
    if (!g_sntp_time_set)
    {
        return 0;
    }

    while (rtc_IsBusy()) {}
    boot_GetTime(&sec, &min, &hr);
    boot_GetDate(&day, &month, &year_2digit);

    timestamp = rtc_fields_to_unix_seconds(sec, min, hr, day, month, year_2digit);

    /* Subtract timezone and DST adjustments to get UTC */
    utc = (int64_t)timestamp - (int64_t)g_tz_offset_seconds;
    if (g_dst_enabled)
    {
        utc -= 3600;
    }
    if (utc < 0)
    {
        utc = 0;
    }

    return (uint32_t)utc;
}

uint32_t lwip_sntp_read_rtc_raw(void)
{
    uint8_t sec, min, hr;
    uint8_t day, month, year_2digit;

    while (rtc_IsBusy()) {}
    boot_GetTime(&sec, &min, &hr);
    boot_GetDate(&day, &month, &year_2digit);

    return rtc_fields_to_unix_seconds(sec, min, hr, day, month, year_2digit);
}

void lwip_sntp_clamp_rtc_floor(uint32_t floor_unix_seconds)
{
    uint8_t secs, minutes, hours, day, month;
    uint16_t year_2digit;

    if (lwip_sntp_read_rtc_raw() >= floor_unix_seconds)
    {
        /* Clock already reads at or after the floor -- leave it alone.
         * Deliberately does not touch g_sntp_time_set either way: this is
         * a plausibility clamp, not an SNTP sync. */
        return;
    }

    unix_seconds_to_rtc_fields(floor_unix_seconds, &secs, &minutes, &hours, &day, &month, &year_2digit);

    while (rtc_IsBusy()) {}
    boot_SetTime(secs, minutes, hours);
    while (rtc_IsBusy()) {}
    boot_SetDate(day, month, year_2digit);
}

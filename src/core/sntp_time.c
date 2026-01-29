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

void lwip_sntp_set_time(uint32_t seconds)
{
    static const uint8_t days_in_month[] = {
        31u, 28u, 31u, 30u, 31u, 30u, 31u, 31u, 30u, 31u, 30u, 31u
    };

    int64_t adjusted = (int64_t)seconds + (int64_t)g_tz_offset_seconds;
    if (g_dst_enabled)
    {
        adjusted += 3600;
    }
    if (adjusted < 0)
    {
        adjusted = 0;
    }

    uint32_t adj_seconds = (uint32_t)adjusted;
    uint32_t days = adj_seconds / 86400u;
    uint32_t rem = adj_seconds % 86400u;
    uint8_t hours = (uint8_t)(rem / 3600u);
    rem %= 3600u;
    uint8_t minutes = (uint8_t)(rem / 60u);
    uint8_t secs = (uint8_t)(rem % 60u);

    uint16_t year = 1970u;
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

    uint8_t month = 1u;
    uint8_t day = 1u;
    for (uint8_t i = 0; i < 12u; i++)
    {
        uint8_t dim = days_in_month[i];
        if ((i == 1u) && is_leap_year(year))
        {
            dim = 29u;
        }
        if (days < dim)
        {
            month = (uint8_t)(i + 1u);
            day = (uint8_t)(days + 1u);
            break;
        }
        days -= dim;
    }

    while (rtc_IsBusy()) {}
    boot_SetTime(secs, minutes, hours);
    while (rtc_IsBusy()) {}

    // TI-84 CE RTC uses 2-digit years (0-99 representing 2000-2099)

    uint16_t year_2digit = (year >= 2000u) ? (year - 2000u) : year;
    if (year_2digit > 99u)
    {
        year_2digit = 99u; // Cap at 2099
    }

    boot_SetDate(day, month, year_2digit);

    // Signal that time has been set (after all RTC operations complete)
    g_sntp_time_set = true;
}

uint32_t lwip_sntp_get_unix_time(void)
{
    static const uint16_t days_before_month[] = {
        0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334
    };

    /* If time was never set via SNTP, return 0 */
    if (!g_sntp_time_set)
    {
        return 0;
    }

    uint8_t sec, min, hr;
    uint8_t day, month, year_2digit;

    while (rtc_IsBusy()) {}
    boot_GetTime(&sec, &min, &hr);
    boot_GetDate(&day, &month, &year_2digit);

    /* TI-84 CE RTC uses 2-digit years (0-99 representing 2000-2099) */
    uint16_t year = (uint16_t)year_2digit + 2000u;

    /* Calculate days since Jan 1, 1970 */
    uint32_t days = 0;

    /* Add days for complete years */
    for (uint16_t y = 1970u; y < year; y++)
    {
        days += is_leap_year(y) ? 366u : 365u;
    }

    /* Add days for complete months in current year */
    if (month >= 1u && month <= 12u)
    {
        days += days_before_month[month - 1u];
        /* Add leap day if past February in a leap year */
        if (month > 2u && is_leap_year(year))
        {
            days += 1u;
        }
    }

    /* Add days in current month (day is 1-based) */
    days += (day - 1u);

    /* Convert to seconds and add time */
    uint32_t timestamp = days * 86400u;
    timestamp += (uint32_t)hr * 3600u;
    timestamp += (uint32_t)min * 60u;
    timestamp += sec;

    /* Subtract timezone and DST adjustments to get UTC */
    int64_t utc = (int64_t)timestamp - (int64_t)g_tz_offset_seconds;
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

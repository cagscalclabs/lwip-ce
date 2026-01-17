#include <stdbool.h>
#include <stdint.h>

#include <sys/rtc.h>

static int32_t g_tz_offset_seconds = 0;
static bool g_dst_enabled = false;

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
    boot_SetDate(day, month, year);
}

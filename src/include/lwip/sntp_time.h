#ifndef LWIP_SNTP_TIME_H
#define LWIP_SNTP_TIME_H

#include <stdbool.h>
#include <stdint.h>

void lwip_sntp_set_timezone_offset(int32_t seconds);
void lwip_sntp_set_dst_enabled(bool enabled);
void lwip_sntp_set_time(uint32_t seconds);
void lwip_sntp_reset_flag(void);
bool lwip_sntp_time_was_set(void);

/**
 * @brief Get current Unix timestamp from RTC
 * @return Current time as Unix timestamp (seconds since Jan 1, 1970)
 *         Returns 0 if time has not been set via SNTP
 */
uint32_t lwip_sntp_get_unix_time(void);

/**
 * @brief Read the RTC's current value as a Unix timestamp, regardless of
 * whether it was ever set via SNTP. Unlike lwip_sntp_get_unix_time(), this
 * does not gate on lwip_sntp_time_was_set() -- it reports whatever the
 * hardware clock currently holds (e.g. a user-set OS clock, a value left
 * over from a prior session, or the post-RAM-clear default), is not
 * timezone/DST-adjusted (raw local RTC reading), and is used to decide
 * whether the clock looks plausible at all.
 * @return Current RTC reading as Unix-seconds-shaped value.
 */
uint32_t lwip_sntp_read_rtc_raw(void);

/**
 * @brief Write seconds/minutes/hours/day/month/year (RTC component form,
 * same conversion lwip_sntp_set_time() uses) directly to the RTC, without
 * touching the SNTP-set flag. Used to clamp a clearly-wrong RTC forward to
 * a known-sane floor (e.g. the library's release date) so timestamp-based
 * checks elsewhere -- certificate expiry, ticket aging -- aren't silently
 * defeated by a post-RAM-clear clock reading 1970/0.
 * @param seconds Unix timestamp (UTC) to write into the RTC.
 */
void lwip_sntp_clamp_rtc_floor(uint32_t floor_unix_seconds);

#endif

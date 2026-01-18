#ifndef LWIP_SNTP_TIME_H
#define LWIP_SNTP_TIME_H

#include <stdbool.h>
#include <stdint.h>

void lwip_sntp_set_timezone_offset(int32_t seconds);
void lwip_sntp_set_dst_enabled(bool enabled);
void lwip_sntp_set_time(uint32_t seconds);
void lwip_sntp_reset_flag(void);
bool lwip_sntp_time_was_set(void);

#endif

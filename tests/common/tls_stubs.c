#include <stdbool.h>
#include <stdint.h>
#include "lwip/app_config.h"
#include "lwip/logging.h"
#include "lwip/sntp_time.h"

void lwip_log_set_enabled(uint8_t type_mask)
{
    (void)type_mask;
}

void lwip_log_set_min_level(uint8_t min_level)
{
    (void)min_level;
}

void lwip_log_set_fatal_handler(lwip_log_fatal_handler_t handler)
{
    (void)handler;
}

void lwip_log_event(uint8_t type, uint8_t reason)
{
    (void)type;
    (void)reason;
}

void lwip_log_event_at(uint8_t type, uint8_t reason, uint16_t line)
{
    (void)type;
    (void)reason;
    (void)line;
}

void lwip_log_fatal(uint8_t type, uint8_t reason)
{
    (void)type;
    (void)reason;
    while (1)
    {
    }
}

void lwip_log_fatal_at(uint8_t type, uint8_t reason, uint16_t line)
{
    (void)type;
    (void)reason;
    (void)line;
    while (1)
    {
    }
}

void lwip_log_set_max_bytes(uint16_t max_bytes)
{
    (void)max_bytes;
}

bool lwip_log_read_header(struct lwip_log_header *out_header)
{
    (void)out_header;
    return false;
}

const struct lwip_log_descriptor *lwip_log_describe(uint8_t type, uint8_t reason)
{
    (void)type;
    (void)reason;
    return NULL;
}

bool lwip_log_read_entry_at(const struct lwip_log_header *header, uint16_t offset,
                            struct lwip_log_entry *out_entry)
{
    (void)header;
    (void)offset;
    (void)out_entry;
    return false;
}

const lwip_app_config_t *lwip_app_config_get(void)
{
    return NULL;
}

uint32_t lwip_sntp_get_unix_time(void)
{
    return 0;
}

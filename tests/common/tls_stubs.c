#include <stdbool.h>
#include <stdint.h>
#include "lwip/app_config.h"
#include "lwip/logging.h"
#include "lwip/sntp_time.h"

void lwip_log_set_enabled(uint8_t module_mask)
{
    (void)module_mask;
}

void lwip_log_event(uint8_t module, uint8_t code)
{
    (void)module;
    (void)code;
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

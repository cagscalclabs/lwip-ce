#ifndef LWIP_LOGGING_H
#define LWIP_LOGGING_H

#include <stdbool.h>
#include <stdint.h>

#define LWIP_LOG_APPVAR "lwIPLOG"
#define LWIP_LOG_MAGIC "TICELOG"
#define LWIP_LOG_MAGIC_LEN 7u
#define LWIP_LOG_VERSION 1u

enum lwip_log_module
{
    LWIP_LOG_MODULE_USB = 1u,
    LWIP_LOG_MODULE_TLS = 2u
};

enum lwip_log_code
{
    LWIP_LOG_USB_ENDPOINT_STALL = 1u,
    LWIP_LOG_USB_ENDPOINT_NO_DEVICE = 2u,
    LWIP_LOG_USB_ENDPOINT_ERROR = 3u,
    LWIP_LOG_USB_FATAL_RETRY = 4u,
    LWIP_LOG_TLS_FATAL_ALERT = 10u,
    LWIP_LOG_TLS_TRUSTSTORE_FAIL = 11u
};

struct lwip_log_entry
{
    uint8_t year;
    uint8_t month;
    uint8_t day;
    uint8_t hour;
    uint8_t minute;
    uint8_t second;
    uint8_t module;
    uint8_t code;
};

struct lwip_log_header
{
    char magic[LWIP_LOG_MAGIC_LEN];
    uint8_t version;
    uint16_t max_bytes;
    uint16_t entry_size;
    uint16_t max_entries;
    uint16_t write_index;
    uint16_t count;
} __attribute__((packed));

void lwip_log_set_enabled(uint8_t module_mask);
void lwip_log_event(uint8_t module, uint8_t code);
void lwip_log_set_max_bytes(uint16_t max_bytes);
bool lwip_log_read_header(struct lwip_log_header *out_header);
bool lwip_log_read_entry_at(const struct lwip_log_header *header, uint16_t offset,
                            struct lwip_log_entry *out_entry);

#endif /* LWIP_LOGGING_H */

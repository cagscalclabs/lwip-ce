#ifndef LWIP_LOGGING_H
#define LWIP_LOGGING_H

#include <stdbool.h>
#include <stdint.h>

#define LWIP_LOG_APPVAR "lwIPLOG"
#define LWIP_LOG_MAGIC "TICELOG"
#define LWIP_LOG_MAGIC_LEN 7u
#define LWIP_LOG_VERSION 1u

enum lwip_log_type
{
    LWIP_LOG_TYPE_USB = 1u,
    LWIP_LOG_TYPE_TLS = 2u,
    LWIP_LOG_TYPE_LWIP = 4u
};

enum lwip_log_level
{
    LWIP_LOG_LEVEL_INFO = 1u,
    LWIP_LOG_LEVEL_WARN = 2u,
    LWIP_LOG_LEVEL_ERROR = 3u,
    LWIP_LOG_LEVEL_FATAL = 4u
};

enum lwip_log_reason
{
    LWIP_LOG_USB_ENDPOINT_STALL = 1u,
    LWIP_LOG_USB_ENDPOINT_NO_DEVICE = 2u,
    LWIP_LOG_USB_ENDPOINT_ERROR = 3u,
    LWIP_LOG_USB_FATAL_RETRY = 4u,
    LWIP_LOG_TLS_FATAL_ALERT = 10u,
    LWIP_LOG_TLS_TRUSTSTORE_FAIL = 11u,
    LWIP_LOG_TLS_CERTVERIFY_FAIL = 12u,
    LWIP_LOG_LWIP_ASSERT = 20u,
    LWIP_LOG_LWIP_ERROR = 21u
};

struct lwip_log_entry
{
    uint8_t year;
    uint8_t month;
    uint8_t day;
    uint8_t hour;
    uint8_t minute;
    uint8_t second;
    uint8_t level;
    uint8_t type;
    uint8_t reason;
    uint16_t line;
};

struct lwip_log_descriptor
{
    uint8_t level;
    uint8_t type;
    uint8_t reason;
    const char *level_label;
    const char *type_label;
    const char *reason_label;
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

typedef void (*lwip_log_fatal_handler_t)(uint8_t type, uint8_t reason);

void lwip_log_set_enabled(uint8_t type_mask);
void lwip_log_set_min_level(uint8_t min_level);
void lwip_log_event(uint8_t type, uint8_t reason);
void lwip_log_event_at(uint8_t type, uint8_t reason, uint16_t line);
void lwip_log_fatal(uint8_t type, uint8_t reason) __attribute__((noreturn));
void lwip_log_fatal_at(uint8_t type, uint8_t reason, uint16_t line) __attribute__((noreturn));
void lwip_log_set_fatal_handler(lwip_log_fatal_handler_t handler);
void lwip_log_set_max_bytes(uint16_t max_bytes);
const struct lwip_log_descriptor *lwip_log_describe(uint8_t type, uint8_t reason);
bool lwip_log_read_header(struct lwip_log_header *out_header);
bool lwip_log_read_entry_at(const struct lwip_log_header *header, uint16_t offset,
                            struct lwip_log_entry *out_entry);

#endif /* LWIP_LOGGING_H */

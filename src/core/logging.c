#include <stdlib.h>
#include <string.h>

#include <fileioc.h>
#include <sys/rtc.h>

#include "lwip/logging.h"

static uint8_t g_log_enabled_mask = 0;
static uint8_t g_log_min_level = LWIP_LOG_LEVEL_ERROR;
static uint16_t g_log_max_bytes = 4096u;
static lwip_log_fatal_handler_t g_log_fatal_handler = NULL;
static bool g_log_in_fatal = false;

static const struct lwip_log_descriptor g_log_descriptors[] = {
    {
        LWIP_LOG_LEVEL_WARN,
        LWIP_LOG_TYPE_USB,
        LWIP_LOG_USB_ENDPOINT_STALL,
        "W",
        "USB",
        "STALL",
    },
    {
        LWIP_LOG_LEVEL_ERROR,
        LWIP_LOG_TYPE_USB,
        LWIP_LOG_USB_ENDPOINT_NO_DEVICE,
        "E",
        "USB",
        "UNPLUG",
    },
    {
        LWIP_LOG_LEVEL_ERROR,
        LWIP_LOG_TYPE_USB,
        LWIP_LOG_USB_ENDPOINT_ERROR,
        "E",
        "USB",
        "EPERR",
    },
    {
        LWIP_LOG_LEVEL_FATAL,
        LWIP_LOG_TYPE_USB,
        LWIP_LOG_USB_FATAL_RETRY,
        "F",
        "USB",
        "RETRY",
    },
    {
        LWIP_LOG_LEVEL_FATAL,
        LWIP_LOG_TYPE_TLS,
        LWIP_LOG_TLS_FATAL_ALERT,
        "F",
        "TLS",
        "ALERT",
    },
    {
        LWIP_LOG_LEVEL_ERROR,
        LWIP_LOG_TYPE_TLS,
        LWIP_LOG_TLS_TRUSTSTORE_FAIL,
        "E",
        "TLS",
        "TSTORE",
    },
    {
        LWIP_LOG_LEVEL_ERROR,
        LWIP_LOG_TYPE_TLS,
        LWIP_LOG_TLS_CERTVERIFY_FAIL,
        "E",
        "TLS",
        "CVFY",
    },
    {
        LWIP_LOG_LEVEL_FATAL,
        LWIP_LOG_TYPE_LWIP,
        LWIP_LOG_LWIP_ASSERT,
        "F",
        "LWIP",
        "ASSERT",
    },
    {
        LWIP_LOG_LEVEL_ERROR,
        LWIP_LOG_TYPE_LWIP,
        LWIP_LOG_LWIP_ERROR,
        "E",
        "LWIP",
        "ERROR",
    },
};

static const struct lwip_log_descriptor g_unknown_log_descriptor = {
    LWIP_LOG_LEVEL_ERROR,
    0u,
    0u,
    "E",
    "UNK",
    "UNKNOWN",
};

const struct lwip_log_descriptor *lwip_log_describe(uint8_t type, uint8_t reason)
{
    for (uint8_t i = 0; i < (uint8_t)(sizeof(g_log_descriptors) / sizeof(g_log_descriptors[0])); i++)
    {
        if (g_log_descriptors[i].type == type &&
            g_log_descriptors[i].reason == reason)
        {
            return &g_log_descriptors[i];
        }
    }
    return &g_unknown_log_descriptor;
}

static uint16_t lwip_log_calc_max_entries(uint16_t max_bytes)
{
    uint16_t header_size = (uint16_t)sizeof(struct lwip_log_header);
    uint16_t entry_size = (uint16_t)sizeof(struct lwip_log_entry);
    if (max_bytes <= header_size + entry_size)
    {
        return 0;
    }
    return (uint16_t)((max_bytes - header_size) / entry_size);
}

static void lwip_log_init_header(struct lwip_log_header *header, uint16_t max_bytes)
{
    memset(header, 0, sizeof(*header));
    memcpy(header->magic, LWIP_LOG_MAGIC, LWIP_LOG_MAGIC_LEN);
    header->version = LWIP_LOG_VERSION;
    header->max_bytes = max_bytes;
    header->entry_size = (uint16_t)sizeof(struct lwip_log_entry);
    header->max_entries = lwip_log_calc_max_entries(max_bytes);
    header->write_index = 0;
    header->count = 0;
}

static bool lwip_log_write_header(uint8_t handle, const struct lwip_log_header *header)
{
    if (!handle || !header)
    {
        return false;
    }
    ti_SetArchiveStatus(false, handle);
    ti_Rewind(handle);
    if (ti_Write(header, sizeof(*header), 1, handle) != 1)
    {
        return false;
    }
    ti_SetArchiveStatus(true, handle);
    return true;
}

void lwip_log_set_enabled(uint8_t type_mask)
{
    g_log_enabled_mask = type_mask;
}

void lwip_log_set_min_level(uint8_t min_level)
{
    if (min_level < LWIP_LOG_LEVEL_INFO || min_level > LWIP_LOG_LEVEL_FATAL)
    {
        min_level = LWIP_LOG_LEVEL_ERROR;
    }
    g_log_min_level = min_level;
}

void lwip_log_set_fatal_handler(lwip_log_fatal_handler_t handler)
{
    g_log_fatal_handler = handler;
}

void lwip_log_set_max_bytes(uint16_t max_bytes)
{
    g_log_max_bytes = max_bytes;
}

static void lwip_log_write_event(uint8_t type, uint8_t reason, uint16_t line, bool force)
{
    const struct lwip_log_descriptor *desc = lwip_log_describe(type, reason);

    if (!force && (g_log_enabled_mask & type) == 0)
    {
        return;
    }
    if (!force && desc->level < g_log_min_level)
    {
        return;
    }

    uint16_t max_bytes = g_log_max_bytes;
    if (max_bytes < sizeof(struct lwip_log_header) + sizeof(struct lwip_log_entry))
    {
        return;
    }

    uint8_t handle = ti_Open(LWIP_LOG_APPVAR, "r+");
    if (!handle)
    {
        handle = ti_Open(LWIP_LOG_APPVAR, "w");
    }
    if (!handle)
    {
        return;
    }

    struct lwip_log_header header;
    bool valid_header = false;
    uint16_t size = ti_GetSize(handle);
    if (size == max_bytes)
    {
        ti_Rewind(handle);
        if (ti_Read(&header, sizeof(header), 1, handle) == 1)
        {
            if (memcmp(header.magic, LWIP_LOG_MAGIC, LWIP_LOG_MAGIC_LEN) == 0 &&
                header.version == LWIP_LOG_VERSION &&
                header.entry_size == sizeof(struct lwip_log_entry) &&
                header.max_bytes == max_bytes &&
                header.max_entries == lwip_log_calc_max_entries(max_bytes))
            {
                valid_header = true;
            }
        }
    }

    if (!valid_header)
    {
        if (size != max_bytes)
        {
            ti_Resize(max_bytes, handle);
        }
        lwip_log_init_header(&header, max_bytes);
        if (!lwip_log_write_header(handle, &header))
        {
            ti_Close(handle);
            return;
        }
    }

    if (header.max_entries == 0)
    {
        ti_Close(handle);
        return;
    }

    uint8_t day = 0;
    uint8_t month = 0;
    uint16_t year = 0;
    uint8_t hour = 0;
    uint8_t minute = 0;
    uint8_t second = 0;

    boot_GetDate(&day, &month, &year);
    boot_GetTime(&second, &minute, &hour);

    struct lwip_log_entry entry;
    entry.year = (uint8_t)(year % 100u);
    entry.month = month;
    entry.day = day;
    entry.hour = hour;
    entry.minute = minute;
    entry.second = second;
    entry.level = desc->level;
    entry.type = type;
    entry.reason = reason;
    entry.line = line;

    uint16_t entry_offset = (uint16_t)sizeof(struct lwip_log_header) +
                            (uint16_t)(header.write_index * sizeof(struct lwip_log_entry));
    ti_Seek(entry_offset, SEEK_SET, handle);
    ti_Write(&entry, sizeof(entry), 1, handle);

    header.write_index++;
    if (header.write_index >= header.max_entries)
    {
        header.write_index = 0;
    }
    if (header.count < header.max_entries)
    {
        header.count++;
    }

    lwip_log_write_header(handle, &header);
    ti_Close(handle);
}

void lwip_log_event(uint8_t type, uint8_t reason)
{
    lwip_log_write_event(type, reason, 0u, false);
}

void lwip_log_event_at(uint8_t type, uint8_t reason, uint16_t line)
{
    lwip_log_write_event(type, reason, line, false);
}

void lwip_log_fatal(uint8_t type, uint8_t reason)
{
    lwip_log_fatal_at(type, reason, 0u);
}

void lwip_log_fatal_at(uint8_t type, uint8_t reason, uint16_t line)
{
    if (g_log_in_fatal)
    {
        exit(1);
    }
    g_log_in_fatal = true;
    lwip_log_write_event(type, reason, line, true);
    if (g_log_fatal_handler)
    {
        g_log_fatal_handler(type, reason);
    }
    exit(1);
}

bool lwip_log_read_header(struct lwip_log_header *out_header)
{
    if (!out_header)
    {
        return false;
    }

    uint8_t handle = ti_Open(LWIP_LOG_APPVAR, "r");
    if (!handle)
    {
        return false;
    }

    uint16_t size = ti_GetSize(handle);
    if (size < sizeof(*out_header))
    {
        ti_Close(handle);
        return false;
    }

    if (ti_Read(out_header, sizeof(*out_header), 1, handle) != 1)
    {
        ti_Close(handle);
        return false;
    }
    ti_Close(handle);

    if (memcmp(out_header->magic, LWIP_LOG_MAGIC, LWIP_LOG_MAGIC_LEN) != 0 ||
        out_header->version != LWIP_LOG_VERSION ||
        out_header->entry_size != sizeof(struct lwip_log_entry) ||
        out_header->max_entries == 0 ||
        out_header->max_bytes < sizeof(*out_header))
    {
        return false;
    }

    return true;
}

bool lwip_log_read_entry_at(const struct lwip_log_header *header, uint16_t offset,
                            struct lwip_log_entry *out_entry)
{
    if (!header || !out_entry || offset >= header->count || header->max_entries == 0)
    {
        return false;
    }

    uint16_t idx = header->write_index + header->max_entries - 1 - offset;
    idx %= header->max_entries;

    uint8_t handle = ti_Open(LWIP_LOG_APPVAR, "r");
    if (!handle)
    {
        return false;
    }

    uint16_t entry_offset = (uint16_t)sizeof(struct lwip_log_header) +
                            (uint16_t)(idx * sizeof(struct lwip_log_entry));
    ti_Seek(entry_offset, SEEK_SET, handle);
    bool ok = (ti_Read(out_entry, sizeof(*out_entry), 1, handle) == 1);
    ti_Close(handle);
    return ok;
}

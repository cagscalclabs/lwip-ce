#include <string.h>

#include <fileioc.h>
#include <sys/rtc.h>

#include "lwip/logging.h"

static uint8_t g_log_enabled_mask = 0;
static uint16_t g_log_max_bytes = 4096u;

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

void lwip_log_set_enabled(uint8_t module_mask)
{
    g_log_enabled_mask = module_mask;
}

void lwip_log_set_max_bytes(uint16_t max_bytes)
{
    g_log_max_bytes = max_bytes;
}

void lwip_log_event(uint8_t module, uint8_t code)
{
    if ((g_log_enabled_mask & module) == 0)
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
    uint8_t year = 0;
    uint8_t hour = 0;
    uint8_t minute = 0;
    uint8_t second = 0;

    boot_GetDate(&day, &month, &year);
    boot_GetTime(&second, &minute, &hour);

    struct lwip_log_entry entry;
    entry.year = year;
    entry.month = month;
    entry.day = day;
    entry.hour = hour;
    entry.minute = minute;
    entry.second = second;
    entry.module = module;
    entry.code = code;

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

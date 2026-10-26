#include <stddef.h>
#include <stdint.h>

#include "parsers/xml.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    xml_ctx_t ctx;
    xml_event_t evt;
    char ring[256], text[96], attrs[128];
    size_t off = 1, chunk;
    unsigned steps = 0;
    xml_err_t err;

    if (!size) return 0;
    chunk = (data[0] & 0x3f) + 1;
    xml_init(&ctx, ring, sizeof(ring), data[0] & 0x80 ? XML_FLAG_LAX : 0);
    while (steps++ < 100000)
    {
        err = xml_next(&ctx, &evt);
        if (err == XML_ERR_NEED_MORE)
        {
            size_t n = size - off < chunk ? size - off : chunk;
            if (!n)
            {
                xml_finish(&ctx);
                continue;
            }
            off += xml_take(&ctx, (const char *)data + off, n);
            continue;
        }
        if (err != XML_OK) break;
        if (evt.type == XML_EVT_ELEMENT_START)
        {
            xml_get_attr(&evt, "id", text, sizeof(text));
            xml_list_attrs(&evt, attrs, sizeof(attrs));
            if (data[0] & 0x40) xml_get_inner_text(&ctx, text, sizeof(text));
        }
    }
    {
        const char *src = (const char *)data, *end = src + size;
        char out[8];
        size_t written;
        while (src < end)
        {
            const char *before = src;
            if (!xml_decode_entity(&src, end, out, &written) || src == before) src = before + 1;
        }
    }
    return 0;
}

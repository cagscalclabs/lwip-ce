#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "drivers/pcap_decode.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct pcap_decoded d = pcap_decode(data, size);
    size_t off = 0;
    assert(d.count <= sizeof(d.section) / sizeof(d.section[0]));
    for (unsigned i = 0; i < d.count; i++)
    {
        assert(d.section[i].offset == off);
        assert(d.section[i].length <= size - off);
        assert(d.section[i].name && strlen(d.section[i].name));
        off += d.section[i].length;
    }
    return 0;
}

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "drivers/pcap_record.h"
#include "drivers/pcap_decode.h"

/* Arbitrary lwIPPCAP appvar contents: walk every record the way pcap_read_next
 * and the config app viewer do, then decode each frame. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    size_t off = 0, total = 0;
    const uint8_t *hdr, *frame;
    uint16_t len;

    while (pcap_record_next(data, size, &off, &hdr, &frame, &len))
    {
        assert(hdr >= data && frame == hdr + PCAP_REC_HDR_LEN);
        assert((size_t)(frame - data) + len <= size);
        total += PCAP_REC_HDR_LEN + len;
        assert(off == total);

        uint32_t sec, frac, packed = pcap_rec_ts(hdr);
        if (pcap_ts_unpack(packed, &sec, &frac))
        {
            assert(sec < PCAP_TS_SECS_PER_DAY && frac < PCAP_TS_FRAC_PER_SEC);
            assert(pcap_ts_pack(sec, frac) == packed);
        }
        else
        {
            assert(packed == PCAP_TS_NONE || packed > PCAP_TS_MAX);
        }

        struct pcap_decoded d = pcap_decode(frame, len);
        size_t doff = 0;
        assert(d.count <= sizeof(d.section) / sizeof(d.section[0]));
        for (unsigned i = 0; i < d.count; i++)
        {
            assert(d.section[i].offset == doff);
            assert(d.section[i].length <= (size_t)len - doff);
            doff += d.section[i].length;
        }
    }
    /* Whatever is left is a truncated record or nothing. */
    assert(off <= size);
    assert(size - off < PCAP_REC_HDR_LEN || size - off - PCAP_REC_HDR_LEN < pcap_rec_len(data + off));
    return 0;
}

/* lwIPPCAP record format: timestamp packing, header field offsets, and the
 * bounds-checked record walker (src/drivers/pcap_record.h). */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../../../src/drivers/pcap_record.h"

/* Append one record (header + frame) at buf[*n]. */
static void put_record(uint8_t *buf, size_t *n, uint32_t ts, const char ifname[2], uint8_t ifnum,
                       uint8_t dir, const uint8_t *frame, uint16_t len)
{
    uint8_t *h = buf + *n;
    memset(h, 0xEE, PCAP_REC_HDR_LEN); /* padding byte must not matter */
    pcap_rec_set_ts(h, ts);
    h[PCAP_REC_OFF_IFNAME] = (uint8_t)ifname[0];
    h[PCAP_REC_OFF_IFNAME + 1] = (uint8_t)ifname[1];
    h[PCAP_REC_OFF_IFNUM] = ifnum;
    h[PCAP_REC_OFF_DIR] = dir;
    h[PCAP_REC_OFF_LEN] = (uint8_t)len;
    h[PCAP_REC_OFF_LEN + 1] = (uint8_t)(len >> 8);
    memcpy(h + PCAP_REC_HDR_LEN, frame, len);
    *n += PCAP_REC_HDR_LEN + len;
}

static void test_timestamps(void)
{
    uint32_t sec, frac;

    /* 0 is "no timestamp": every capture written before timestamps existed. */
    assert(!pcap_ts_unpack(PCAP_TS_NONE, &sec, &frac));
    assert(!pcap_ts_unpack(PCAP_TS_MAX + 1, &sec, &frac));
    assert(!pcap_ts_unpack(0xFFFFFFu, &sec, &frac));
    assert(PCAP_TS_MAX <= 0xFFFFFFu); /* fits the 3-byte field */

    /* Round trip over the whole day at every fraction edge. */
    for (uint32_t s = 0; s < PCAP_TS_SECS_PER_DAY; s += 7) {
        const uint32_t fracs[] = {0, 1, 63, 127};
        for (unsigned i = 0; i < 4; i++) {
            uint32_t p = pcap_ts_pack(s, fracs[i]);
            assert(p != PCAP_TS_NONE && p <= PCAP_TS_MAX);
            assert(pcap_ts_unpack(p, &sec, &frac));
            assert(sec == s && frac == fracs[i]);
        }
    }
    assert(pcap_ts_unpack(pcap_ts_pack(86399, 127), &sec, &frac) && sec == 86399 && frac == 127);
    assert(pcap_ts_pack(86399, 127) == PCAP_TS_MAX);

    /* Seconds wrap at midnight; fraction saturates. */
    assert(pcap_ts_unpack(pcap_ts_pack(86400 + 5, 0), &sec, NULL) && sec == 5);
    assert(pcap_ts_unpack(pcap_ts_pack(10, 500), NULL, &frac) && frac == 127);

    /* Ordering: packed values sort like times of day. */
    assert(pcap_ts_pack(100, 127) < pcap_ts_pack(101, 0));

    /* Byte encoding is little-endian in [0..2] and leaves the rest alone. */
    uint8_t h[PCAP_REC_HDR_LEN];
    memset(h, 0xAA, sizeof h);
    pcap_rec_set_ts(h, 0x123456u);
    assert(h[0] == 0x56 && h[1] == 0x34 && h[2] == 0x12 && h[3] == 0xAA);
    assert(pcap_rec_ts(h) == 0x123456u);
    pcap_rec_set_ts(h, PCAP_TS_MAX);
    assert(pcap_rec_ts(h) == PCAP_TS_MAX);
}

static void test_walker(void)
{
    static uint8_t buf[4096];
    size_t n = 0;
    const uint8_t f1[60] = {[12] = 0x08, [13] = 0x00};
    const uint8_t f2[1] = {0x42};

    put_record(buf, &n, pcap_ts_pack(43200, 64), "en", 0, 1, f1, sizeof f1);
    put_record(buf, &n, PCAP_TS_NONE, "en", 1, 0, NULL, 0); /* old-format, empty frame */
    put_record(buf, &n, pcap_ts_pack(43201, 0), "wl", 2, 0, f2, sizeof f2);
    assert(n == 3 * PCAP_REC_HDR_LEN + sizeof f1 + sizeof f2);

    size_t off = 0;
    const uint8_t *hdr, *frame;
    uint16_t len;
    uint32_t sec, frac;

    assert(pcap_record_next(buf, n, &off, &hdr, &frame, &len));
    assert(hdr == buf && frame == buf + PCAP_REC_HDR_LEN && len == sizeof f1);
    assert(!memcmp(frame, f1, sizeof f1));
    assert(hdr[PCAP_REC_OFF_IFNAME] == 'e' && hdr[PCAP_REC_OFF_IFNUM] == 0 && hdr[PCAP_REC_OFF_DIR] == 1);
    assert(pcap_ts_unpack(pcap_rec_ts(hdr), &sec, &frac) && sec == 43200 && frac == 64);

    assert(pcap_record_next(buf, n, &off, &hdr, &frame, &len));
    assert(len == 0 && hdr[PCAP_REC_OFF_IFNUM] == 1);
    assert(!pcap_ts_unpack(pcap_rec_ts(hdr), &sec, &frac));

    assert(pcap_record_next(buf, n, &off, &hdr, &frame, &len));
    assert(len == 1 && frame[0] == 0x42 && hdr[PCAP_REC_OFF_IFNAME + 1] == 'l');
    assert(off == n);
    assert(!pcap_record_next(buf, n, &off, &hdr, &frame, &len));
    assert(off == n);

    /* Every truncation stops cleanly at the last complete record. */
    for (size_t cut = 0; cut < n; cut++) {
        size_t o = 0, complete = 0;
        while (pcap_record_next(buf, cut, &o, NULL, NULL, NULL))
            complete = o;
        assert(o == complete && o <= cut);
        size_t again = o;
        assert(!pcap_record_next(buf, cut, &again, NULL, NULL, NULL) && again == o);
    }

    /* A length that overruns the buffer is rejected without advancing. */
    uint8_t bad[PCAP_REC_HDR_LEN + 4] = {0};
    bad[PCAP_REC_OFF_LEN] = 5;
    off = 0;
    assert(!pcap_record_next(bad, sizeof bad, &off, &hdr, &frame, &len) && off == 0);
    bad[PCAP_REC_OFF_LEN] = 4;
    assert(pcap_record_next(bad, sizeof bad, &off, &hdr, &frame, &len) && off == sizeof bad);

    /* Offset past the end, NULL buffer. */
    off = n + 1;
    assert(!pcap_record_next(buf, n, &off, NULL, NULL, NULL) && off == n + 1);
    off = 0;
    assert(!pcap_record_next(NULL, 10, &off, NULL, NULL, NULL));

    /* Max-length record header. */
    uint8_t big[PCAP_REC_HDR_LEN] = {[PCAP_REC_OFF_LEN] = 0xFF, [PCAP_REC_OFF_LEN + 1] = 0xFF};
    assert(pcap_rec_len(big) == 0xFFFF);
    off = 0;
    assert(!pcap_record_next(big, sizeof big, &off, NULL, NULL, NULL));
}

int main(void)
{
    test_timestamps();
    test_walker();
    puts("PCAP record: timestamp packing, field offsets, and record walker passed");
    return 0;
}

#ifndef PCAP_RECORD_H
#define PCAP_RECORD_H

/*
 * On-disk format of the lwIPPCAP capture appvar: concatenated records, each a
 * 10-byte header (struct pcap in pcap.h) followed by the frame bytes.
 * Little-endian, eZ80 layout (uint16_t is 2-aligned, hence the pad byte):
 *
 *   [0..2]  ts         24-bit timestamp, see PCAP_TS_* below
 *   [3..4]  ifname     two-character interface name ("en")
 *   [5]     ifnum      interface number
 *   [6]     direction  pcap_direction_t (0 = RX, 1 = TX)
 *   [7]     (padding)
 *   [8..9]  len        frame length
 *   [10..]  frame      len bytes
 *
 * Header-only and free of CE/lwIP dependencies so the same definitions are
 * used by the driver, the host tests (tests/host/pcap_record) and the fuzz
 * harness (tests/fuzz/fuzz_pcap_record.c). The bug reporter's converter
 * (cagscalclabs bugreport.js, convertToPcapFile) mirrors this layout.
 *
 * Timestamps. Bytes [0..2] used to hold a struct netif pointer, meaningless
 * once written to a file and always zero, so 0 means "no timestamp" and
 * captures written before timestamps existed still read correctly. Otherwise:
 *
 *   packed = seconds_since_midnight * PCAP_TS_FRAC_PER_SEC + fraction + 1
 *
 * seconds_since_midnight is the RTC's wall-clock time of day (rtc_tod.h), the
 * same clock and the same HH:MM:SS as log-file lines, so capture frames line
 * up with log events and with the time the user saw. fraction is in 1/128 s (~7.8 ms).
 * The RTC has whole seconds only; the fraction is the time since the first
 * frame captured in that second (see pcap_timestamp() in pcap.c), so it is
 * monotonic within a second but not aligned to the RTC tick.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PCAP_REC_HDR_LEN     10u
#define PCAP_REC_OFF_TS      0u
#define PCAP_REC_OFF_IFNAME  3u
#define PCAP_REC_OFF_IFNUM   5u
#define PCAP_REC_OFF_DIR     6u
#define PCAP_REC_OFF_LEN     8u

#define PCAP_TS_NONE         0u
#define PCAP_TS_FRAC_PER_SEC 128u
#define PCAP_TS_SECS_PER_DAY 86400u
/* Largest valid packed value: 23:59:59 + 127/128 s. Fits in 24 bits. */
#define PCAP_TS_MAX          ((uint32_t)PCAP_TS_SECS_PER_DAY * PCAP_TS_FRAC_PER_SEC)

/** Pack a time of day. Seconds wrap at midnight; fraction saturates at 127. */
static inline uint32_t pcap_ts_pack(uint32_t sec, uint32_t frac)
{
    sec %= PCAP_TS_SECS_PER_DAY;
    if (frac >= PCAP_TS_FRAC_PER_SEC)
        frac = PCAP_TS_FRAC_PER_SEC - 1u;
    return sec * PCAP_TS_FRAC_PER_SEC + frac + 1u;
}

/** Unpack; false for PCAP_TS_NONE or an out-of-range value. */
static inline bool pcap_ts_unpack(uint32_t packed, uint32_t *sec, uint32_t *frac)
{
    if (packed == PCAP_TS_NONE || packed > PCAP_TS_MAX)
        return false;
    packed -= 1u;
    if (sec)
        *sec = packed / PCAP_TS_FRAC_PER_SEC;
    if (frac)
        *frac = packed % PCAP_TS_FRAC_PER_SEC;
    return true;
}

static inline uint32_t pcap_rec_ts(const uint8_t *hdr)
{
    return (uint32_t)hdr[PCAP_REC_OFF_TS]
         | ((uint32_t)hdr[PCAP_REC_OFF_TS + 1] << 8)
         | ((uint32_t)hdr[PCAP_REC_OFF_TS + 2] << 16);
}

static inline void pcap_rec_set_ts(uint8_t *hdr, uint32_t packed)
{
    hdr[PCAP_REC_OFF_TS]     = (uint8_t)packed;
    hdr[PCAP_REC_OFF_TS + 1] = (uint8_t)(packed >> 8);
    hdr[PCAP_REC_OFF_TS + 2] = (uint8_t)(packed >> 16);
}

static inline uint16_t pcap_rec_len(const uint8_t *hdr)
{
    return (uint16_t)(hdr[PCAP_REC_OFF_LEN] | (hdr[PCAP_REC_OFF_LEN + 1] << 8));
}

/**
 * Bounds-checked walk over a capture buffer. On success sets *hdr, *frame and
 * *len for the record at *off and advances *off past it. Returns false (and
 * leaves *off unchanged) at the end of the buffer or on a record whose header
 * or frame would run past `size`.
 */
static inline bool pcap_record_next(const uint8_t *buf, size_t size, size_t *off,
                                    const uint8_t **hdr, const uint8_t **frame, uint16_t *len)
{
    if (!buf || !off || *off > size || size - *off < PCAP_REC_HDR_LEN)
        return false;
    const uint8_t *h = buf + *off;
    uint16_t n = pcap_rec_len(h);
    if (size - *off - PCAP_REC_HDR_LEN < n)
        return false;
    if (hdr)
        *hdr = h;
    if (frame)
        *frame = h + PCAP_REC_HDR_LEN;
    if (len)
        *len = n;
    *off += PCAP_REC_HDR_LEN + n;
    return true;
}

#endif

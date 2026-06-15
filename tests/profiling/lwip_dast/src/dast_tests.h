/* AUTO-GENERATED from tests/profiling/lwip_dast/dast_tests.json.
 * Do not edit by hand; run:
 *     python3 build-tools/dast/lwip-dast.py --gen-header
 * Keeps the calc-side harness in lockstep with the probe runner. */
#ifndef LWIP_DAST_TESTS_H
#define LWIP_DAST_TESTS_H

#include <stdint.h>

typedef enum {
    DAST_STATE_IDLE = 0,
    DAST_STATE_UDP_RECV,
    DAST_STATE_TCP_LISTEN,
    DAST_STATE_RAW_RECV
} dast_state_t;

typedef struct {
    const char  *id;
    const char  *name;
    dast_state_t state;
    uint16_t     port;
    const char  *intent;
} dast_test_t;

#define DAST_TEST_COUNT 16

static const dast_test_t dast_tests[DAST_TEST_COUNT] = {
    { "icmp-echo-baseline", "ICMP echo baseline", DAST_STATE_IDLE, 0, "Liveness baseline: a well-formed ping must be answered." },
    { "arp-malformed", "Malformed ARP", DAST_STATE_IDLE, 0, "Bogus hlen/plen and truncated ARP must not corrupt the ARP cache or crash." },
    { "arp-flood", "ARP request flood", DAST_STATE_IDLE, 0, "Rapid gratuitous/who-has flood: bounded ARP table, no OOM crash." },
    { "icmp-oversize", "Oversized ICMP echo (fragmented)", DAST_STATE_IDLE, 0, "Multi-fragment ICMP (3KB, 2-3 fragments) must reassemble or drop cleanly without crashing." },
    { "icmp-malformed", "Malformed ICMP", DAST_STATE_IDLE, 0, "Bad ICMP checksum / truncated header must be dropped, not parsed." },
    { "ip-bad-checksum", "IP bad header checksum", DAST_STATE_IDLE, 0, "Corrupt IPv4 header checksum must cause a silent drop." },
    { "ip-frag-overlap", "Overlapping IP fragments", DAST_STATE_IDLE, 0, "Teardrop-style overlapping fragments must not mis-reassemble or crash." },
    { "ip-frag-bomb", "Incomplete fragment bomb", DAST_STATE_IDLE, 0, "Many never-completed fragments must be reaped (bounded reassembly memory)." },
    { "udp-recv-baseline", "UDP recv baseline", DAST_STATE_UDP_RECV, 9999, "A well-formed datagram reaches the recv callback and is handled." },
    { "udp-oversize", "Oversized fragmented UDP", DAST_STATE_UDP_RECV, 9999, "Large fragmented UDP payload must not overflow the recv path." },
    { "udp-malformed-len", "UDP bad length/checksum", DAST_STATE_UDP_RECV, 9999, "UDP length field longer than the packet / bad checksum must be dropped." },
    { "tcp-syn-closed", "SYN to closed port", DAST_STATE_IDLE, 0, "SYN to an unbound port must elicit a RST, not a hang or crash." },
    { "tcp-listen-baseline", "TCP listen baseline", DAST_STATE_TCP_LISTEN, 9998, "A normal connect + data exchange must be accepted and read." },
    { "tcp-malformed-flags", "Malformed TCP flags", DAST_STATE_TCP_LISTEN, 9998, "NULL / FIN / XMAS / SYN+FIN flag combos must be dropped or RST, not crash." },
    { "tcp-tiny-window", "Tiny/zero window + overlap", DAST_STATE_TCP_LISTEN, 9998, "Zero-window probes and overlapping segments must not desync or overrun." },
    { "tcp-data-overflow", "Oversized TCP data burst", DAST_STATE_TCP_LISTEN, 9998, "A data burst far larger than the app recv buffer must be bounded (no overflow)." },
};

#endif /* LWIP_DAST_TESTS_H */

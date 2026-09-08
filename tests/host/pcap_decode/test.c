#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "../../../src/drivers/pcap_decode.h"

static void bounds(const uint8_t *p, size_t n)
{
    struct pcap_decoded d = pcap_decode(p, n);
    size_t off = 0;
    assert(d.count <= 5);
    for (unsigned i = 0; i < d.count; i++) {
        assert(d.section[i].offset == off);
        assert(d.section[i].length <= n - off);
        off += d.section[i].length;
    }
    assert(off == n);
}
int main(void)
{
    uint8_t packet[512] = {0};
    packet[12] = 8; packet[14] = 0x45;
    packet[16] = 1; packet[17] = 16; /* IP total 272 */
    packet[23] = 17;
    packet[35] = 68; packet[37] = 67;
    packet[38] = 0; packet[39] = 252;
    memcpy(packet + 42 + 236, "\x63\x82\x53\x63\x35\x01\x01\xff", 8);
    struct pcap_decoded d = pcap_decode(packet, 286);
    assert(d.count == 4);
    assert(!strcmp(d.section[3].detail, "dhcp-discover"));
    assert(d.section[3].offset == 42);
    for (size_t n = 0; n <= sizeof(packet); n++) bounds(packet, n);
    /* Deterministic malformed captures: all output ranges stay within input. */
    uint32_t seed = 7;
    for (unsigned k = 0; k < 20000; k++) {
        for (unsigned i = 0; i < sizeof(packet); i++) {
            seed = seed * 1664525u + 1013904223u;
            packet[i] = seed >> 24;
        }
        if (k % 3 == 0) { packet[12] = 8; packet[13] = 0; packet[14] = 0x45; }
        if (k % 3 == 1) { packet[12] = 0x86; packet[13] = 0xdd; packet[14] = 0x60; }
        bounds(packet, k % 513);
    }
    puts("PCAP decoder: DHCP fixture and truncated/malformed bounds passed");
}

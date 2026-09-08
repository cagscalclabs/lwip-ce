#ifndef PCAP_DECODE_H
#define PCAP_DECODE_H

#include <stdint.h>
#include <stddef.h>

/* Byte ranges partition the capture, including unparsed/truncated bytes. */
struct pcap_section {
    const char *name;
    const char *detail;
    size_t offset, length;
};
struct pcap_decoded {
    struct pcap_section section[5];
    unsigned count;
};
static unsigned pcap_be16(const uint8_t *p)
{
    return ((unsigned)p[0] << 8) | p[1];
}
static void pcap_section_add(struct pcap_decoded *d, const char *name,
                             const char *detail, size_t off, size_t len)
{
    struct pcap_section *s = &d->section[d->count++];
    s->name = name; s->detail = detail; s->offset = off; s->length = len;
}
static const char *pcap_udp_name(const uint8_t *p, size_t n,
                                unsigned src, unsigned dst)
{
    if ((src == 67 && dst == 68) || (src == 68 && dst == 67))
    {
        if (n >= 240 && p[236] == 99 && p[237] == 130 &&
            p[238] == 83 && p[239] == 99)
        {
            size_t i = 240;
            while (i < n)
            {
                unsigned tag = p[i++];
                if (tag == 255) break;
                if (!tag) continue;
                if (i == n) break;
                unsigned len = p[i++];
                if (len > n - i) break;
                if (tag == 53 && len == 1)
                {
                    switch (p[i]) {
                    case 1: return "dhcp-discover";
                    case 2: return "dhcp-offer";
                    case 3: return "dhcp-request";
                    case 4: return "dhcp-decline";
                    case 5: return "dhcp-ack";
                    case 6: return "dhcp-nak";
                    case 7: return "dhcp-release";
                    case 8: return "dhcp-inform";
                    }
                }
                i += len;
            }
            return "DHCP";
        }
        return "BOOTP/DHCP ports";
    }
    if (src == 123 || dst == 123)
    {
        if (n >= 48 && ((p[0] >> 3) & 7) >= 1 && ((p[0] >> 3) & 7) <= 4)
        {
            if ((p[0] & 7) == 3) return "NTP/SNTP request";
            if ((p[0] & 7) == 4) return "NTP/SNTP response";
        }
        return "NTP/SNTP port";
    }
    if (src == 53 || dst == 53)
        return n >= 12 ? ((p[2] & 128) ? "dns-response" : "dns-query") : "DNS port";
    if (src == 5353 || dst == 5353) return "mDNS port";
    return NULL;
}
static struct pcap_decoded pcap_decode(const uint8_t *p, size_t n)
{
    struct pcap_decoded d = {0};
    size_t off = 0, end = n, h;
    unsigned type, proto = 0;
    const char *app = NULL;
    if (n < 14) {
        pcap_section_add(&d, "Ethernet", "truncated", 0, n); return d;
    }
    type = pcap_be16(p + 12); off = 14;
    while ((type == 0x8100 || type == 0x88a8) && n - off >= 4) {
        type = pcap_be16(p + off + 2); off += 4;
    }
    pcap_section_add(&d, "Ethernet", off > 14 ? "MAC + VLAN" : "MAC", 0, off);
    if (type == 0x0800 && n - off >= 20 && (p[off] >> 4) == 4) {
        h = (p[off] & 15) * 4u;
        unsigned total = pcap_be16(p + off + 2);
        if (h < 20 || h > n - off || total < h) goto raw;
        if (total < n - off) end = off + total;
        proto = p[off + 9];
        /* Leave fragments opaque rather than identifying partial app messages. */
        if (pcap_be16(p + off + 6) & 0x3fff) proto = 0;
        pcap_section_add(&d, "IP", proto ? "IPv4" : "IPv4 fragment/unknown", off, h);
        off += h;
    } else if (type == 0x86dd && n - off >= 40 && (p[off] >> 4) == 6) {
        unsigned total = pcap_be16(p + off + 4);
        if (total && total < n - off - 40) end = off + 40 + total;
        proto = p[off + 6];
        pcap_section_add(&d, "IP", "IPv6", off, 40); off += 40;
        /* Extension headers stay visible as raw payload until decoded. */
    } else if (type == 0x0806 && n - off >= 8) {
        h = 8u + 2u * p[off + 4] + 2u * p[off + 5];
        if (h > n - off) goto raw;
        unsigned op = pcap_be16(p + off + 6);
        pcap_section_add(&d, "Protocol", op == 1 ? "arp-request" : op == 2 ? "arp-reply" : "ARP", off, h);
        off += h; goto raw;
    } else goto raw;
    if (proto == 17 && end - off >= 8) {
        unsigned len = pcap_be16(p + off + 4);
        if (len < 8 || len > end - off) goto raw;
        app = pcap_udp_name(p + off + 8, len - 8, pcap_be16(p + off), pcap_be16(p + off + 2));
        pcap_section_add(&d, "Protocol", "UDP", off, 8); off += 8;
        end = off + len - 8;
    } else if (proto == 6 && end - off >= 20) {
        h = (p[off + 12] >> 4) * 4u;
        if (h < 20 || h > end - off) goto raw;
        pcap_section_add(&d, "Protocol", "TCP", off, h); off += h;
    } else if ((proto == 1 || proto == 58) && end - off >= 8) {
        unsigned t = p[off];
        app = (proto == 1 && t == 8) || (proto == 58 && t == 128) ? "echo-request" :
              (proto == 1 && t == 0) || (proto == 58 && t == 129) ? "echo-reply" : NULL;
        pcap_section_add(&d, "Protocol", proto == 1 ? "ICMP" : "ICMPv6", off, 8); off += 8;
    }
raw:
    pcap_section_add(&d, "Payload", app, off, end - off);
    if (end < n) pcap_section_add(&d, "Trailing bytes", "padding/unparsed", end, n - end);
    return d;
}
#endif

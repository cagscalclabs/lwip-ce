/*
 * netbridge — ARP + DHCP responder (stage 1).
 *
 * The emulated calc is on a virtual /24 with the bridge as gateway:
 *   gateway/bridge : 10.0.2.2     MAC 02:00:5E:10:00:02
 *   DNS (proxied)  : 10.0.2.3
 *   calc (leased)  : 10.0.2.15
 *
 * Stage 1 answers ARP-for-gateway and the DHCP DISCOVER/REQUEST so the calc
 * obtains its IP, default route, and DNS. Later stages forward the calc's IP
 * traffic to real host sockets.
 */
#include "netbridge.h"
#include "emu.h"          /* gui_console_printf */
#include "usb/usb.h"      /* ecm_inject_frame, ecm_set_tx_sink, ecm_rx_ready */
#include "usb/device.h"

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>    /* htons/htonl */

/* ---- network constants ------------------------------------------- */

static const uint8_t kBridgeMac[6] = { 0x02, 0x00, 0x5E, 0x10, 0x00, 0x02 };
#define IP_GATEWAY   0x0A000202u   /* 10.0.2.2  */
#define IP_DNS       0x0A000203u   /* 10.0.2.3  */
#define IP_CALC      0x0A00020Fu   /* 10.0.2.15 */
#define IP_NETMASK   0xFFFFFF00u   /* /24       */

/* The calc's MAC, learned from the first frame it sends. */
static uint8_t g_calc_mac[6];
static bool    g_have_calc_mac;

/* ---- helpers ----------------------------------------------------- */

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] << 8) | p[1]; }
static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
           (uint32_t)p[2] << 8  | p[3];
}
static void wr16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = (uint8_t)v; }
static void wr32(uint8_t *p, uint32_t v) {
    p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = (uint8_t)v;
}

/* Internet checksum over buf[0..len). */
static uint16_t inet_csum(const uint8_t *buf, size_t len, uint32_t seed) {
    uint32_t sum = seed;
    while (len > 1) { sum += rd16(buf); buf += 2; len -= 2; }
    if (len) sum += (uint32_t)buf[0] << 8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

/* Build an ethernet header into out (14 bytes). */
static void eth_hdr(uint8_t *out, const uint8_t *dst, const uint8_t *src,
                    uint16_t ethertype) {
    memcpy(out, dst, 6);
    memcpy(out + 6, src, 6);
    wr16(out + 12, ethertype);
}

/* ---- ARP --------------------------------------------------------- */

static void handle_arp(const uint8_t *f, uint16_t len) {
    if (len < 14 + 28) return;
    const uint8_t *arp = f + 14;
    uint16_t oper = rd16(arp + 6);
    uint32_t tpa = rd32(arp + 24);   /* target protocol (IP) addr */
    if (oper != 1) return;            /* only replies to requests */
    /* Reply for the gateway or DNS IP (the calc ARPs its gateway). */
    if (tpa != IP_GATEWAY && tpa != IP_DNS) return;

    const uint8_t *sha = arp + 8;     /* sender hw addr (calc)  */
    uint32_t spa = rd32(arp + 14);    /* sender proto addr      */

    uint8_t reply[14 + 28];
    eth_hdr(reply, sha, kBridgeMac, 0x0806);
    uint8_t *r = reply + 14;
    wr16(r + 0, 1);          /* htype ethernet */
    wr16(r + 2, 0x0800);     /* ptype IPv4     */
    r[4] = 6; r[5] = 4;      /* hlen, plen     */
    wr16(r + 6, 2);          /* oper = reply   */
    memcpy(r + 8, kBridgeMac, 6);  /* sender hw = bridge */
    wr32(r + 14, tpa);             /* sender proto = the asked-for IP */
    memcpy(r + 18, sha, 6);        /* target hw = calc */
    wr32(r + 24, spa);             /* target proto = calc IP */
    ecm_inject_frame(reply, sizeof reply);
    gui_console_printf("[bridge] ARP reply: %u.%u.%u.%u is-at bridge\n",
        (tpa >> 24) & 0xFF, (tpa >> 16) & 0xFF, (tpa >> 8) & 0xFF, tpa & 0xFF);
}

/* ---- DHCP -------------------------------------------------------- */

/* Build + inject a DHCP reply (OFFER or ACK) for the calc. xid/chaddr come
 * from the request. msg_type: 2=OFFER, 5=ACK. */
static void send_dhcp_reply(uint32_t xid, const uint8_t *chaddr, uint8_t msg_type) {
    uint8_t pkt[14 + 20 + 8 + 240 + 64];
    memset(pkt, 0, sizeof pkt);

    /* ethernet: to calc, from bridge, IPv4 */
    eth_hdr(pkt, chaddr, kBridgeMac, 0x0800);

    uint8_t *ip = pkt + 14;
    uint8_t *udp = ip + 20;
    uint8_t *dhcp = udp + 8;

    /* ---- DHCP payload ---- */
    dhcp[0] = 2;           /* op = BOOTREPLY */
    dhcp[1] = 1;           /* htype ethernet */
    dhcp[2] = 6;           /* hlen */
    wr32(dhcp + 4, xid);   /* xid */
    wr32(dhcp + 16, IP_CALC);     /* yiaddr = offered IP */
    wr32(dhcp + 20, IP_GATEWAY);  /* siaddr = next server (us) */
    memcpy(dhcp + 28, chaddr, 6); /* chaddr */
    wr32(dhcp + 236, 0x63825363); /* magic cookie */

    uint8_t *o = dhcp + 240;
    *o++ = 53; *o++ = 1; *o++ = msg_type;             /* DHCP msg type */
    *o++ = 54; *o++ = 4; wr32(o, IP_GATEWAY); o += 4; /* server id */
    *o++ = 51; *o++ = 4; wr32(o, 86400);     o += 4;  /* lease time 1 day */
    *o++ = 1;  *o++ = 4; wr32(o, IP_NETMASK); o += 4; /* subnet mask */
    *o++ = 3;  *o++ = 4; wr32(o, IP_GATEWAY); o += 4; /* router */
    *o++ = 6;  *o++ = 4; wr32(o, IP_DNS);     o += 4; /* DNS server */
    *o++ = 255;                                       /* end */
    size_t dhcp_len = (size_t)(o - dhcp);
    if (dhcp_len < 300) dhcp_len = 300;  /* BOOTP minimum payload */

    /* ---- UDP (67 -> 68) ---- */
    size_t udp_len = 8 + dhcp_len;
    wr16(udp + 0, 67);
    wr16(udp + 2, 68);
    wr16(udp + 4, (uint16_t)udp_len);
    wr16(udp + 6, 0);   /* 0 = "no UDP checksum" (legal for IPv4); lwIP skips
                         * the check. Isolates whether our computed checksum
                         * was the reason the OFFER was rejected. */

    /* ---- IPv4 ---- */
    size_t ip_len = 20 + udp_len;
    ip[0] = 0x45;                 /* v4, ihl 5 */
    ip[1] = 0;
    wr16(ip + 2, (uint16_t)ip_len);
    wr16(ip + 4, 0);              /* id */
    wr16(ip + 6, 0);              /* flags/frag */
    ip[8] = 64;                   /* ttl */
    ip[9] = 17;                   /* proto UDP */
    wr16(ip + 10, 0);             /* checksum (fill below) */
    wr32(ip + 12, IP_GATEWAY);    /* src = us */
    /* dst = 255.255.255.255: the client has NO IP yet, so the lwIP IP input
     * layer would drop a packet addressed to the offered IP (netif ip is
     * still 0.0.0.0). Real DHCP servers broadcast the reply for this reason. */
    wr32(ip + 16, 0xFFFFFFFFu);
    wr16(ip + 10, inet_csum(ip, 20, 0));

    size_t frame_len = 14 + ip_len;
    bool ok = ecm_inject_frame(pkt, (uint16_t)frame_len);
    gui_console_printf("[bridge] DHCP %s -> 10.0.2.15 (len=%zu inject=%s)\n",
                       msg_type == 2 ? "OFFER" : "ACK", frame_len,
                       ok ? "ok" : "FAIL");
    /* dump the OFFER's DHCP options region (from magic cookie/opt start). */
    {
        size_t opt_off = (size_t)(dhcp + 240 - pkt);  /* first option byte */
        char hx[3 * 80 + 1]; size_t k = 0;
        for (size_t i = opt_off; i < frame_len && k < 80; i++, k++)
            snprintf(hx + k * 3, 4, "%02X ", pkt[i]);
        gui_console_printf("[bridge] offer opts: %s\n", hx);
    }
}

static void handle_dhcp(const uint8_t *f, uint16_t len, const uint8_t *ip,
                        const uint8_t *udp) {
    const uint8_t *dhcp = udp + 8;
    size_t dhcp_off = (size_t)(dhcp - f);
    if (len < dhcp_off + 240) return;
    if (rd32(dhcp + 236) != 0x63825363) return;  /* magic cookie */

    uint32_t xid = rd32(dhcp + 4);
    uint16_t flags = rd16(dhcp + 10);   /* bit 15 = broadcast requested */
    const uint8_t *chaddr = dhcp + 28;
    gui_console_printf("[bridge] DHCP req: xid=%08X flags=%04X%s len=%u\n",
        xid, flags, (flags & 0x8000) ? " (BROADCAST)" : " (unicast)", len);
    /* dump the DHCP options region (from magic cookie on) to see what the
     * calc requests (esp. option 55 parameter request list). */
    {
        size_t opt_off = (size_t)(dhcp + 240 - f);
        char hx[3 * 80 + 1]; size_t k = 0;
        for (size_t i = opt_off; i < len && k < 80; i++)
            snprintf(hx + (i - opt_off) * 3, 4, "%02X ", f[i]), k++;
        gui_console_printf("[bridge] req opts: %s\n", hx);
    }

    /* find option 53 (message type) */
    const uint8_t *o = dhcp + 240;
    const uint8_t *end = f + len;
    uint8_t mtype = 0;
    while (o + 1 < end && *o != 255) {
        if (*o == 0) { o++; continue; }
        uint8_t code = o[0], olen = o[1];
        if (o + 2 + olen > end) break;
        if (code == 53 && olen >= 1) mtype = o[2];
        o += 2 + olen;
    }
    (void)ip;
    if (mtype == 1) {        /* DISCOVER -> OFFER */
        send_dhcp_reply(xid, chaddr, 2);
    } else if (mtype == 3) { /* REQUEST -> ACK */
        send_dhcp_reply(xid, chaddr, 5);
    }
}

/* ---- TX sink (frames from the calc) ------------------------------ */

static void on_calc_tx(void *ctx, const uint8_t *f, uint16_t len) {
    (void)ctx;
    if (len < 14) return;
    if (!g_have_calc_mac) {
        memcpy(g_calc_mac, f + 6, 6);
        g_have_calc_mac = true;
    }
    uint16_t ethertype = rd16(f + 12);

    if (ethertype == 0x0806) {
        handle_arp(f, len);
        return;
    }
    if (ethertype == 0x0800 && len >= 14 + 20) {
        const uint8_t *ip = f + 14;
        uint8_t ihl = (ip[0] & 0x0F) * 4;
        if (ip[9] == 17 && len >= 14u + ihl + 8u) {   /* UDP */
            const uint8_t *udp = ip + ihl;
            uint16_t dport = rd16(udp + 2);
            if (dport == 67) { handle_dhcp(f, len, ip, udp); return; }
            /* TODO: DNS (53) + general UDP proxy */
        }
        /* TODO: TCP proxy, ICMP */
        gui_console_printf("[bridge] (unhandled IPv4 proto=%u dport)\n", ip[9]);
        return;
    }
}

void netbridge_init(void) {
    ecm_set_tx_sink(on_calc_tx, NULL);
    gui_console_printf("[bridge] installed (gw 10.0.2.2, calc 10.0.2.15)\n");
}

void netbridge_poll(uint32_t now_ms) {
    (void)now_ms;
    /* stage 1: nothing time-based yet */
}

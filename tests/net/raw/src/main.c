/* NETRAW: lwIP's own raw APIs and protocol machinery against tests/net/run.py. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "net.h"

#define PORT_RAW_SERVER 7203
#define PORT_EXPECT_RST 7012
#define PORT_BCAST      7013
#define PORT_FRAG_RX    7030
#define PORT_MCAST4     7020
#define PORT_MCAST6     7021
#define PORT_LOOP_UDP   7040
#define PORT_UDP_LEN    7014

static struct netif *ext;
static char host_ll[48], host_mac[24];
static uint32_t host_time;

static struct netif *find_ext(void)
{
    for (u8_t i = 1; i < 8; i++)
    {
        struct netif *n = netif_get_by_index(i);
        if (n && n->hwaddr_len == 6) return n;
    }
    return NULL;
}

static bool flag_set(void *arg) { return *(volatile bool *)arg; }

/* ---- utilities, pbufs and timers -------------------------------------- */

static void test_utils(void)
{
    ip4_addr_t a4;
    ip6_addr_t a6;
    char name[8];
    static const uint8_t rfc1071[] = {0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7};
    check("ip4addr_aton/ntoa", ip4addr_aton("10.20.30.40", &a4) && !strcmp(ip4addr_ntoa(&a4), "10.20.30.40"));
    check("ip4addr_aton rejects junk", !ip4addr_aton("300.1.2.3", &a4));
    check("ip6addr_aton/ntoa", ip6addr_aton("2001:db8::84", &a6) && !lwip_stricmp(ip6addr_ntoa(&a6), "2001:db8::84"));
    check("byte order", lwip_htons(0x1234) == 0x3412 && lwip_htonl(0x01020304ul) == 0x04030201ul);
    check("inet_chksum RFC 1071 vector", inet_chksum(rfc1071, sizeof(rfc1071)) == lwip_htons(0x220d));
    check("lwip_strnstr", lwip_strnstr("lwip-ce stack", "ce", 13) != NULL && !lwip_strnstr("abc", "d", 3));
    check("lwip_stricmp", !lwip_stricmp("LwIP", "lwip"));
    check("netif index/name round trip",
          ext && netif_index_to_name(netif_get_index(ext), name) && netif_name_to_index(name) == netif_get_index(ext));
    check("netif_find", netif_find(name) == ext);
    note("  resident newer: %u", lwip_is_newer());
}

static void test_pbufs(void)
{
    struct pbuf *p = pbuf_alloc(PBUF_RAW, 1500, PBUF_POOL);
    struct pbuf *q, *c;
    bool ok;
    if (!check("pbuf_alloc pool chain", p != NULL)) return;
    for (u16_t i = 0; i < 1500; i++) buf[i] = pattern(i);
    check("pbuf_take", pbuf_take(p, buf, 1500) == ERR_OK);
    note("  chain length %u", pbuf_clen(p));
    ok = pbuf_copy_partial(p, buf + 1500, 300, 1000) == 300 && !memcmp(buf + 1500, buf + 1000, 300);
    check("pbuf_copy_partial across segments", ok);
    check("pbuf_get_at / put_at", pbuf_get_at(p, 1234) == pattern(1234) &&
                                      (pbuf_put_at(p, 1234, 0x5a), pbuf_get_at(p, 1234) == 0x5a));
    pbuf_put_at(p, 1234, pattern(1234));
    check("pbuf_memfind", pbuf_memfind(p, buf + 700, 16, 512) == 700);
    check("pbuf_memcmp", pbuf_memcmp(p, 100, buf + 100, 200) == 0);
    q = pbuf_alloc(PBUF_RAW, 6, PBUF_RAM);
    pbuf_take(q, "needle", 6);
    pbuf_cat(p, q);
    check("pbuf_cat + strstr", p->tot_len == 1506 && pbuf_strstr(p, "needle") == 1500);
    c = pbuf_clone(PBUF_RAW, PBUF_RAM, p);
    check("pbuf_clone contiguous copy", c && c->len == 1506 && !memcmp(c->payload, buf, 1500));
    check("pbuf_add/remove_header", c && pbuf_add_header(c, 0) == 0 && pbuf_remove_header(c, 6) == 0 && c->len == 1500 &&
                                        !memcmp(c->payload, buf + 6, 1494));
    pbuf_ref(c);
    check("pbuf_ref / free counts", pbuf_free(c) == 0 && pbuf_free(c) == 1);
    check("pbuf_free chain", pbuf_free(p) >= 2);
}

static uint8_t order[4], order_n;

static void timer_cb(void *arg)
{
    if (order_n < 4) order[order_n++] = (uint8_t)(uintptr_t)arg;
}

static bool three_fired(void *arg)
{
    (void)arg;
    return order_n >= 3;
}

static void test_timers(void)
{
    order_n = 0;
    sys_timeout(300, timer_cb, (void *)3);
    sys_timeout(100, timer_cb, (void *)1);
    sys_timeout(200, timer_cb, (void *)2);
    sys_timeout(150, timer_cb, (void *)9);
    sys_untimeout(timer_cb, (void *)9);
    pump(three_fired, NULL, 5000);
    settle(400);
    check("sys_timeout fires in deadline order", order_n == 3 && order[0] == 1 && order[1] == 2 && order[2] == 3);
}

/* ---- ICMP ---------------------------------------------------------------- */

static volatile bool echo_reply;
static uint16_t echo_seq;

static u8_t icmp_recv(void *arg, struct raw_pcb *pcb, struct pbuf *p, const ip_addr_t *addr)
{
    uint8_t hdr[28];
    (void)arg; (void)pcb; (void)addr;
    if (pbuf_copy_partial(p, hdr, sizeof(hdr), 0) == sizeof(hdr) && hdr[20] == 0 && hdr[24] == 0x84 &&
        hdr[25] == 0xce && ((hdr[26] << 8) | hdr[27]) == echo_seq)
    {
        echo_reply = true;
        pbuf_free(p);
        return 1;
    }
    return 0;
}

static void test_icmp(void)
{
    struct raw_pcb *pcb = raw_new(IP_PROTO_ICMP);
    ip_addr_t host;
    unsigned replies = 0;
    uint32_t total = 0, worst = 0;
    char reply[32];
    if (!check("raw_new ICMP", pcb != NULL)) return;
    raw_recv(pcb, icmp_recv, NULL);
    ipaddr_aton(HOST, &host);
    for (echo_seq = 1; echo_seq <= 5; echo_seq++)
    {
        struct pbuf *p = pbuf_alloc(PBUF_IP, 40, PBUF_RAM);
        uint8_t *b = p->payload;
        uint32_t t0;
        memset(b, 0, 40);
        b[0] = 8;
        b[4] = 0x84;
        b[5] = 0xce;
        b[6] = echo_seq >> 8;
        b[7] = echo_seq & 0xff;
        memcpy(b + 8, "lwip-ce raw icmp", 16);
        *(uint16_t *)(b + 2) = inet_chksum(b, 40);
        echo_reply = false;
        t0 = lwip_now_ms();
        raw_sendto(pcb, p, &host);
        pbuf_free(p);
        if (pump(flag_set, (void *)&echo_reply, 3000))
        {
            uint32_t rtt = lwip_now_ms() - t0;
            replies++;
            total += rtt;
            if (rtt > worst) worst = rtt;
        }
    }
    raw_remove(pcb);
    check("raw ICMP echo to host 5/5", replies == 5);
    if (replies)
    {
        metric("icmp_rtt_avg", total / replies, "ms");
        metric("icmp_rtt_max", worst, "ms");
    }
    check("host pings calc", host_call("ping 3", reply, sizeof(reply), 15000) && !strcmp(reply, "3/3"));
    check("closed UDP port answers ICMP unreachable",
          host_call("udp-unreach 7999", reply, sizeof(reply), 10000) && !strcmp(reply, "refused"));
}

/* ---- raw TCP ------------------------------------------------------------- */

struct tcp_test { size_t rx, acked; unsigned polls; bool connected, error, closed; uint8_t data[4096]; };

static err_t tcp_client_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    struct tcp_test *s = arg;
    (void)err;
    if (!p)
    {
        s->closed = true;
        return ERR_OK;
    }
    s->rx += pbuf_copy_partial(p, s->data + (s->rx < sizeof(s->data) ? s->rx : 0),
                               (u16_t)(s->rx + p->tot_len <= sizeof(s->data) ? p->tot_len : 0), 0);
    tcp_recved(pcb, p->tot_len);
    pbuf_free(p);
    return ERR_OK;
}

static err_t tcp_client_sent(void *arg, struct tcp_pcb *pcb, u16_t len)
{
    (void)pcb;
    ((struct tcp_test *)arg)->acked += len;
    return ERR_OK;
}

static err_t tcp_client_poll(void *arg, struct tcp_pcb *pcb)
{
    (void)pcb;
    ((struct tcp_test *)arg)->polls++;
    return ERR_OK;
}

static void tcp_client_err(void *arg, err_t err)
{
    (void)err;
    ((struct tcp_test *)arg)->error = true;
}

static err_t tcp_client_connected(void *arg, struct tcp_pcb *pcb, err_t err)
{
    (void)pcb;
    ((struct tcp_test *)arg)->connected = err == ERR_OK;
    return ERR_OK;
}

static bool tcp_connected(void *arg) { return ((struct tcp_test *)arg)->connected || ((struct tcp_test *)arg)->error; }
static bool tcp_got_all(void *arg) { return ((struct tcp_test *)arg)->rx >= 4096 || ((struct tcp_test *)arg)->error; }

static struct tcp_pcb *tcp_open(struct tcp_test *s, u8_t type, const char *addr, u16_t port)
{
    struct tcp_pcb *pcb = tcp_new_ip_type(type);
    ip_addr_t ip;
    memset(s, 0, sizeof(*s));
    if (!pcb || !ipaddr_aton(addr, &ip)) return NULL;
    if (IP_IS_V6(&ip)) ip6_addr_assign_zone(ip_2_ip6(&ip), IP6_UNICAST, ext);
    tcp_arg(pcb, s);
    tcp_recv(pcb, tcp_client_recv);
    tcp_sent(pcb, tcp_client_sent);
    tcp_poll(pcb, tcp_client_poll, 2);
    tcp_err(pcb, tcp_client_err);
    if (tcp_connect(pcb, &ip, port, tcp_client_connected) != ERR_OK || !pump(tcp_connected, s, 15000) || !s->connected)
    {
        if (!s->error) tcp_abort(pcb);
        return NULL;
    }
    return pcb;
}

static bool raw_echo(const char *name, u8_t type, const char *addr)
{
    static struct tcp_test s;
    struct tcp_pcb *pcb = tcp_open(&s, type, addr, PORT_ECHO);
    size_t queued = 0;
    bool ok;
    snprintf(line, sizeof(line), "%s connect", name);
    if (!check(line, pcb != NULL)) return false;
    while (queued < 4096 && !s.error)
    {
        u16_t n = tcp_sndbuf(pcb) < 512 ? tcp_sndbuf(pcb) : 512;
        for (u16_t i = 0; i < n; i++) buf[i] = pattern(queued + i);
        if (n && tcp_write(pcb, buf, n, TCP_WRITE_FLAG_COPY) == ERR_OK)
        {
            queued += n;
            tcp_output(pcb);
        }
        lwip_service_events();
    }
    pump(tcp_got_all, &s, 20000);
    ok = s.rx == 4096;
    for (size_t i = 0; ok && i < 4096; i++) ok = s.data[i] == pattern(i);
    snprintf(line, sizeof(line), "%s 4096 bytes", name);
    check(line, ok);
    snprintf(line, sizeof(line), "%s sent callbacks ack all", name);
    check(line, s.acked == 4096);
    if (!s.error) tcp_close(pcb);
    return ok;
}

static unsigned served;

static err_t server_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    (void)arg; (void)err;
    if (!p)
    {
        tcp_arg(pcb, NULL);
        tcp_close(pcb);
        return ERR_OK;
    }
    for (struct pbuf *q = p; q; q = q->next) tcp_write(pcb, q->payload, q->len, TCP_WRITE_FLAG_COPY);
    tcp_output(pcb);
    tcp_recved(pcb, p->tot_len);
    pbuf_free(p);
    return ERR_OK;
}

static err_t server_accept(void *arg, struct tcp_pcb *pcb, err_t err)
{
    (void)arg;
    if (err != ERR_OK || !pcb) return ERR_VAL;
    served++;
    tcp_recv(pcb, server_recv);
    return ERR_OK;
}

static void test_raw_tcp(void)
{
    static struct tcp_test s;
    struct tcp_pcb *listener = tcp_new_ip_type(IPADDR_TYPE_ANY), *pcb;
    char reply[32];
    raw_echo("raw tcp echo", IPADDR_TYPE_V4, HOST);

    if (check("tcp_bind server", listener && tcp_bind(listener, IP_ANY_TYPE, PORT_RAW_SERVER) == ERR_OK))
    {
        struct tcp_pcb *l = tcp_listen_with_backlog(listener, 2);
        served = 0;
        if (check("tcp_listen_with_backlog", l != NULL))
        {
            tcp_accept(l, server_accept);
            check("host connects to raw server", host_call("connect 7203 2", NULL, 0, 5000));
            check("raw server echoed 2 clients",
                  host_call("connect-result 2", reply, sizeof(reply), 30000) && !strcmp(reply, "2/2") && served == 2);
            tcp_close(l);
        }
    }

    pcb = tcp_open(&s, IPADDR_TYPE_V4, HOST, PORT_EXPECT_RST);
    if (check("abort connect", pcb != NULL))
    {
        settle(300);
        tcp_abort(pcb);
        check("tcp_abort sends RST", host_call("rst-result", reply, sizeof(reply), 5000) && strstr(reply, "rst"));
    }
    pcb = tcp_open(&s, IPADDR_TYPE_V4, HOST, PORT_ECHO);
    if (pcb)
    {
        settle(2500);
        check("tcp_poll callback fires", s.polls > 0);
        tcp_close(pcb);
    }
}

/* ---- raw UDP, broadcast, fragmentation, loopback ------------------------ */

struct udp_state { size_t len; bool bad; uint8_t first[16]; };

static void udp_rx(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port)
{
    struct udp_state *s = arg;
    (void)pcb; (void)addr; (void)port;
    s->len = p->tot_len;
    s->bad = false;
    pbuf_copy_partial(p, s->first, sizeof(s->first), 0);
    for (u16_t i = 0; i < p->tot_len; i += 97)
        if (pbuf_get_at(p, i) != pattern(i)) s->bad = true;
    pbuf_free(p);
}

static bool udp_got(void *arg) { return ((struct udp_state *)arg)->len != 0; }

static bool udp_roundtrip(struct udp_pcb *pcb, struct udp_state *s, const ip_addr_t *to, u16_t port, u16_t len)
{
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, len, PBUF_RAM);
    if (!p) return false;
    for (u16_t i = 0; i < len; i++) ((uint8_t *)p->payload)[i] = pattern(i);
    s->len = 0;
    udp_sendto(pcb, p, to, port);
    pbuf_free(p);
    return pump(udp_got, s, 8000) && s->len == len && !s->bad;
}

static void test_raw_udp(void)
{
    static struct udp_state s;
    struct udp_pcb *pcb = udp_new_ip_type(IPADDR_TYPE_ANY);
    ip_addr_t host, bcast;
    char reply[48];
    ipaddr_aton(HOST, &host);
    if (!check("udp_new + bind", pcb && udp_bind(pcb, IP_ANY_TYPE, PORT_FRAG_RX) == ERR_OK)) return;
    udp_recv(pcb, udp_rx, &s);
    check("udp echo 64 bytes", udp_roundtrip(pcb, &s, &host, PORT_UDP, 64));
    check("udp fragmented tx+rx 2800 bytes", udp_roundtrip(pcb, &s, &host, PORT_UDP, 2800));
    udp_roundtrip(pcb, &s, &host, PORT_UDP_LEN, 8000);
    check("udp fragmented tx 8000 bytes", s.len == 4 && !memcmp(s.first, "8000", 4));
    s.len = 0;
    host_call("frag-send 2900 7030", NULL, 0, 5000);
    check("ip4 reassembly 2900 bytes", pump(udp_got, &s, 8000) && s.len == 2900 && !s.bad);
    s.len = 0;
    host_call("frag-send 6000 7030", NULL, 0, 5000);
    pump(udp_got, &s, 4000);
    note("  6000-byte datagram: %u bytes delivered", (unsigned)s.len);
    check("oversize reassembly dropped cleanly", s.len == 0 || s.len == 6000);
    check("stack healthy after reassembly overflow", udp_roundtrip(pcb, &s, &host, PORT_UDP, 64));
    check("udp_connect + send", udp_connect(pcb, &host, PORT_UDP) == ERR_OK);
    {
        struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, 16, PBUF_RAM);
        for (u16_t i = 0; i < 16; i++) ((uint8_t *)p->payload)[i] = pattern(i);
        s.len = 0;
        udp_send(pcb, p);
        pbuf_free(p);
        check("udp_send echoed", pump(udp_got, &s, 5000) && s.len == 16);
    }
    udp_disconnect(pcb);
    ip_set_option(pcb, SOF_BROADCAST);
    ipaddr_aton("192.168.84.255", &bcast);
    {
        struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, 17, PBUF_RAM);
        pbuf_take(p, "lwip-ce-broadcast", 17);
        udp_sendto(pcb, p, &bcast, PORT_BCAST);
        pbuf_free(p);
        check("subnet broadcast reaches host",
              host_call("bcast-result", reply, sizeof(reply), 5000) && !strcmp(reply, "lwip-ce-broadcast"));
    }
    udp_remove(pcb);

    pcb = udp_new();
    if (pcb && udp_bind(pcb, IP_ANY_TYPE, PORT_LOOP_UDP) == ERR_OK)
    {
        ip_addr_t lo;
        udp_recv(pcb, udp_rx, &s);
        ipaddr_aton("127.0.0.1", &lo);
        check("udp over loopback netif", udp_roundtrip(pcb, &s, &lo, PORT_LOOP_UDP, 300));
    }
    udp_remove(pcb);
}

/* ---- DNS ------------------------------------------------------------------ */

struct dns_state { bool done, found; ip_addr_t addr; };

static void dns_found(const char *name, const ip_addr_t *addr, void *arg)
{
    struct dns_state *s = arg;
    (void)name;
    s->done = true;
    s->found = addr != NULL;
    if (addr) s->addr = *addr;
}

static bool dns_done(void *arg) { return ((struct dns_state *)arg)->done; }

static err_t lookup(const char *name, u8_t type, struct dns_state *s, uint32_t *ms)
{
    err_t err;
    uint32_t t0 = lwip_now_ms();
    memset(s, 0, sizeof(*s));
    err = dns_gethostbyname_addrtype(name, &s->addr, dns_found, s, type);
    if (err == ERR_OK) s->done = s->found = true;
    else if (err == ERR_INPROGRESS) pump(dns_done, s, 20000);
    *ms = lwip_now_ms() - t0;
    return err;
}

static void test_dns(void)
{
    struct dns_state s;
    uint32_t ms;
    err_t err = lookup("example.com", LWIP_DNS_ADDRTYPE_IPV4, &s, &ms);
    check("dns A example.com", err == ERR_INPROGRESS && s.found && IP_IS_V4(&s.addr));
    metric("dns_lookup_ms", ms, "ms");
    check("dns cache hit", lookup("example.com", LWIP_DNS_ADDRTYPE_IPV4, &s, &ms) == ERR_OK && s.found);
    err = lookup("one.one.one.one", LWIP_DNS_ADDRTYPE_IPV6, &s, &ms);
    note("  AAAA err %d found %u", err, s.found);
    check("dns AAAA one.one.one.one", s.found && IP_IS_V6(&s.addr));
    lookup("example.com", LWIP_DNS_ADDRTYPE_IPV6, &s, &ms);
    note("  AAAA for cached A name: found %u v6 %u", s.found, s.found && IP_IS_V6(&s.addr));
    lookup("lwip-ce-nettest.invalid", LWIP_DNS_ADDRTYPE_IPV4, &s, &ms);
    check("dns NXDOMAIN reports not found", s.done && !s.found);
    check("dns literal address resolves inline",
          dns_gethostbyname("192.168.84.1", &s.addr, dns_found, &s) == ERR_OK);
    check("dns server configured", !ip_addr_isany(dns_getserver(0)));
}

/* ---- IGMP --------------------------------------------------------------- */

static void test_igmp(void)
{
    static struct udp_state s;
    struct udp_pcb *pcb = udp_new();
    ip4_addr_t group;
    char reply[48];
    IP4_ADDR(&group, 239, 84, 0, 1);
    if (!check("igmp join", pcb && udp_bind(pcb, IP_ANY_TYPE, PORT_MCAST4) == ERR_OK &&
                                igmp_joingroup_netif(ext, &group) == ERR_OK)) return;
    udp_recv(pcb, udp_rx, &s);
    check("IGMP report sent", host_call("sniffed igmp 239.84.0.1", reply, sizeof(reply), 15000));
    s.len = 0;
    host_call("mcast4 239.84.0.1 7020", NULL, 0, 5000);
    check("multicast datagram received", pump(udp_got, &s, 5000) && !memcmp(s.first, "lwip-ce-mcast4", 14));
    check("igmp leave", igmp_leavegroup_netif(ext, &group) == ERR_OK);
    check("IGMP leave sent", host_call("sniffed igmp 0x17", reply, sizeof(reply), 15000));
    udp_remove(pcb);
}

/* ---- IPv6 --------------------------------------------------------------- */

static int ip6_slot(const char *prefix)
{
    for (int i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++)
        if (ip6_addr_ispreferred(netif_ip6_addr_state(ext, i)) &&
            !lwip_strnicmp(ip6addr_ntoa(netif_ip6_addr(ext, i)), prefix, strlen(prefix)))
            return i;
    return -1;
}

static bool have_global(void *arg)
{
    (void)arg;
    return ip6_slot("fd00:84:") >= 0;
}

static void test_ipv6(void)
{
    static struct udp_state s;
    struct udp_pcb *pcb = udp_new_ip_type(IPADDR_TYPE_V6);
    ip_addr_t host;
    ip6_addr_t group;
    char reply[48], cmd[80];
    int ll = ip6_slot("fe80::"), global;

    if (!check("ipv6 link-local preferred", ll >= 0)) return;
    note("  ll %s", ip6addr_ntoa(netif_ip6_addr(ext, ll)));
    snprintf(cmd, sizeof(cmd), "ping6 %s 3", ip6addr_ntoa(netif_ip6_addr(ext, ll)));
    check("host ping6 calc link-local", host_call(cmd, reply, sizeof(reply), 15000) && !strcmp(reply, "3/3"));

    ipaddr_aton(host_ll, &host);
    ip6_addr_assign_zone(ip_2_ip6(&host), IP6_UNICAST, ext);
    if (check("udp6 bind", pcb && udp_bind(pcb, IP6_ADDR_ANY, PORT_FRAG_RX) == ERR_OK))
    {
        udp_recv(pcb, udp_rx, &s);
        check("udp6 echo via host link-local", udp_roundtrip(pcb, &s, &host, PORT_UDP, 200));
        check("ipv6 fragmented tx+rx 2600 bytes", udp_roundtrip(pcb, &s, &host, PORT_UDP, 2600));
        snprintf(cmd, sizeof(cmd), "frag6-send %s 2700 7030", ip6addr_ntoa(netif_ip6_addr(ext, ll)));
        s.len = 0;
        host_call(cmd, NULL, 0, 5000);
        check("ip6 reassembly 2700 bytes", pump(udp_got, &s, 8000) && s.len == 2700 && !s.bad);
    }

    check("router advertisement sent", host_call("ra fd00:84::", NULL, 0, 10000));
    check("SLAAC global address", pump(have_global, NULL, 30000));
    global = ip6_slot("fd00:84:");
    if (global >= 0)
    {
        note("  global %s", ip6addr_ntoa(netif_ip6_addr(ext, global)));
        snprintf(cmd, sizeof(cmd), "ping6 %s 3", ip6addr_ntoa(netif_ip6_addr(ext, global)));
        check("host ping6 calc global", host_call(cmd, reply, sizeof(reply), 15000) && !strcmp(reply, "3/3"));
        raw_echo("tcp6 echo via SLAAC route", IPADDR_TYPE_V6, "fd00:84::1");
    }

    ip6addr_aton("ff15::84", &group);
    ip6_addr_assign_zone(&group, IP6_MULTICAST, ext);
    if (check("mld6 join", mld6_joingroup_netif(ext, &group) == ERR_OK))
    {
        struct udp_pcb *m = udp_new_ip_type(IPADDR_TYPE_V6);
        check("MLD report sent", host_call("sniffed mld ff15::84", reply, sizeof(reply), 15000));
        if (m && udp_bind(m, IP6_ADDR_ANY, PORT_MCAST6) == ERR_OK)
        {
            udp_recv(m, udp_rx, &s);
            s.len = 0;
            host_call("mcast6 ff15::84 7021", NULL, 0, 5000);
            check("ipv6 multicast datagram received", pump(udp_got, &s, 5000) && !memcmp(s.first, "lwip-ce-mcast6", 14));
        }
        udp_remove(m);
        check("mld6 leave", mld6_leavegroup_netif(ext, &group) == ERR_OK);
    }
    udp_remove(pcb);
}

/* ---- ARP, ACD, DHCP, SNTP --------------------------------------------- */

static void test_arp(void)
{
    struct eth_addr *eth = NULL;
    const ip4_addr_t *ip = NULL;
    ip4_addr_t host;
    char mac[24];
    IP4_ADDR(&host, 192, 168, 84, 1);
    if (!check("arp entry for gateway", etharp_find_addr(ext, &host, &eth, &ip) >= 0 && eth)) return;
    snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x", eth->addr[0], eth->addr[1], eth->addr[2],
             eth->addr[3], eth->addr[4], eth->addr[5]);
    note("  gateway %s", mac);
    check("arp mac matches host", !strcmp(mac, host_mac));
    check("etharp_request", etharp_request(ext, &host) == ERR_OK);
}

static volatile int acd_result = -1;

static void acd_cb(struct netif *netif, acd_callback_enum_t state)
{
    (void)netif;
    acd_result = state;
}

static bool acd_done(void *arg)
{
    (void)arg;
    return acd_result >= 0;
}

static void test_acd(void)
{
    static struct acd acd;
    ip4_addr_t addr;
    char reply[48];
    if (!check("acd_add", acd_add(ext, &acd, acd_cb) == ERR_OK)) return;
    IP4_ADDR(&addr, 192, 168, 84, 78);
    acd_result = -1;
    acd_start(ext, &acd, addr);
    check("acd free address accepted", pump(acd_done, NULL, 20000) && acd_result == ACD_IP_OK);
    check("ACD probe seen on wire", host_call("sniffed acd-probe 192.168.84.78", reply, sizeof(reply), 5000));
    acd_stop(&acd);
    host_call("acd-claim 192.168.84.77", NULL, 0, 5000);
    IP4_ADDR(&addr, 192, 168, 84, 77);
    acd_result = -1;
    acd_start(ext, &acd, addr);
    pump(acd_done, NULL, 20000);
    note("  acd conflict result %d", acd_result);
    check("acd conflict detected", acd_result == ACD_DECLINE || acd_result == ACD_RESTART_CLIENT);
    acd_stop(&acd);
    acd_remove(ext, &acd);
}

static bool lease_lost(void *arg)
{
    (void)arg;
    return !dhcp_supplied_address(ext);
}

static bool lease_back(void *arg)
{
    (void)arg;
    return dhcp_supplied_address(ext);
}

static void test_dhcp(void)
{
    uint32_t t0;
    char reply[32];
    check("dhcp supplied address", dhcp_supplied_address(ext));
    check("dhcp_renew", dhcp_renew(ext) == ERR_OK);
    settle(3000);
    check("lease kept after renew", dhcp_supplied_address(ext));
    dhcp_release_and_stop(ext);
    check("release drops address", pump(lease_lost, NULL, 5000) && ip4_addr_isany_val(*netif_ip4_addr(ext)));
    t0 = lwip_now_ms();
    check("dhcp_start", dhcp_start(ext) == ERR_OK);
    check("new lease after restart", pump(lease_back, NULL, 60000));
    metric("dhcp_relese_relet_ms", lwip_now_ms() - t0, "ms");
    check("network usable after re-lease", host_call("time", reply, sizeof(reply), 10000));
}

static bool sntp_set(void *arg)
{
    (void)arg;
    return lwip_sntp_time_was_set();
}

static void test_sntp(void)
{
    char reply[32];
    long skew;
    lwip_request_services(LWIP_SOCKET_SVC_SNTP, 30000);
    if (!check("sntp time set", pump(sntp_set, NULL, 40000))) return;
    if (!host_call("time", reply, sizeof(reply), 5000)) return;
    skew = (long)lwip_sntp_get_unix_time() - atol(reply);
    note("  sntp skew %ld s", skew);
    check("sntp clock within 5 minutes of host", skew > -300 && skew < 300);
}

int main(void)
{
    if (net_begin("raw"))
    {
        ext = find_ext();
        check("external netif", ext != NULL);
        if (ext && host_call("hello", line, sizeof(line), 5000) &&
            sscanf(line, "%47s %23s %lu", host_ll, host_mac, (unsigned long *)&host_time) == 3)
        {
            test_utils();
            test_pbufs();
            test_timers();
            test_icmp();
            test_raw_tcp();
            test_raw_udp();
            test_dns();
            test_arp();
            test_igmp();
            test_ipv6();
            test_acd();
            test_sntp();
            test_dhcp();
        }
        else
        {
            check("host hello", false);
        }
    }
    return net_end();
}

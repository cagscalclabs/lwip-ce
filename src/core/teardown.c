#include "lwip/opt.h"
#include "lwip/teardown.h"

#include <stdbool.h>

#include "lwip/tcp.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/udp.h"
#include "lwip/raw.h"
#include "lwip/netif.h"
#include "lwip/ip_addr.h"

#if LWIP_RAW
extern void raw_remove_all_pcbs(void);
#endif

static void lwip_teardown_detach_tcp(struct tcp_pcb *pcb)
{
    if (!pcb)
    {
        return;
    }

    tcp_arg(pcb, NULL);
#if LWIP_CALLBACK_API
    pcb->recv = NULL;
    pcb->sent = NULL;
    pcb->connected = NULL;
    pcb->poll = NULL;
    pcb->errf = NULL;
#endif
    pcb->pollinterval = 0;
}

static void lwip_teardown_detach_listener(struct tcp_pcb_listen *pcb)
{
    if (!pcb)
    {
        return;
    }

    tcp_arg((struct tcp_pcb *)pcb, NULL);
#if LWIP_CALLBACK_API
    pcb->accept = NULL;
#endif
}

void lwip_teardown_abort_pcbs(void)
{
#if LWIP_TCP
    while (tcp_active_pcbs)
    {
        struct tcp_pcb *pcb = tcp_active_pcbs;
        lwip_teardown_detach_tcp(pcb);
        tcp_abort(pcb);
    }

    while (tcp_tw_pcbs)
    {
        tcp_abort(tcp_tw_pcbs);
    }

    while (tcp_bound_pcbs)
    {
        struct tcp_pcb *pcb = tcp_bound_pcbs;
        lwip_teardown_detach_tcp(pcb);
        tcp_abort(pcb);
    }

    while (tcp_listen_pcbs.listen_pcbs)
    {
        struct tcp_pcb_listen *pcb = tcp_listen_pcbs.listen_pcbs;
        lwip_teardown_detach_listener(pcb);
        tcp_close((struct tcp_pcb *)pcb);
    }
#endif

#if LWIP_UDP
    while (udp_pcbs)
    {
        struct udp_pcb *pcb = udp_pcbs;
        udp_recv(pcb, NULL, NULL);
        udp_remove(pcb);
    }
#endif

#if LWIP_RAW
    raw_remove_all_pcbs();
#endif
}


/* Predicate: does this PCB's binding belong to `netif`? Matches by
 * netif_idx if the PCB was bound via tcp_bind_netif/udp_bind_netif,
 * else by local_ip equality against the netif's primary v4/v6 addresses.
 * Unbound (any-addr) PCBs are NOT matched — they're shared across all
 * interfaces and shouldn't be killed when a single interface drops. */
static bool pcb_belongs_to_netif(const struct ip_pcb *pcb, const struct netif *netif)
{
    if (!pcb || !netif)
    {
        return false;
    }
    if (pcb->netif_idx != NETIF_NO_INDEX &&
        pcb->netif_idx == netif_get_index(netif))
    {
        return true;
    }
#if LWIP_IPV4
    if (IP_IS_V4(&pcb->local_ip) &&
        !ip_addr_isany_val(pcb->local_ip) &&
        ip_addr_eq(&pcb->local_ip, &netif->ip_addr))
    {
        return true;
    }
#endif
#if LWIP_IPV6
    if (IP_IS_V6(&pcb->local_ip))
    {
        for (int i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++)
        {
            if (!ip6_addr_isvalid(netif_ip6_addr_state(netif, i)))
            {
                continue;
            }
            if (ip_addr_eq(&pcb->local_ip,
                           (const ip_addr_t *)netif_ip_addr6(netif, i)))
            {
                return true;
            }
        }
    }
#endif
    return false;
}


void lwip_teardown_abort_pcbs_on_netif(const struct netif *netif)
{
    if (!netif)
    {
        return;
    }

#if LWIP_TCP
    /* tcp_abort mutates tcp_active_pcbs by removing the aborted pcb, so
     * advance the iterator before aborting. The same pattern is used in
     * tcp_netif_ip_addr_changed. */
    struct tcp_pcb *tpcb = tcp_active_pcbs;
    while (tpcb)
    {
        struct tcp_pcb *next = tpcb->next;
        if (pcb_belongs_to_netif((const struct ip_pcb *)tpcb, netif))
        {
            lwip_teardown_detach_tcp(tpcb);
            tcp_abort(tpcb);
        }
        tpcb = next;
    }

    /* TIME_WAIT pcbs hold no callbacks worth firing; just clear them. */
    tpcb = tcp_tw_pcbs;
    while (tpcb)
    {
        struct tcp_pcb *next = tpcb->next;
        if (pcb_belongs_to_netif((const struct ip_pcb *)tpcb, netif))
        {
            tcp_abort(tpcb);
        }
        tpcb = next;
    }

    tpcb = tcp_bound_pcbs;
    while (tpcb)
    {
        struct tcp_pcb *next = tpcb->next;
        if (pcb_belongs_to_netif((const struct ip_pcb *)tpcb, netif))
        {
            lwip_teardown_detach_tcp(tpcb);
            tcp_abort(tpcb);
        }
        tpcb = next;
    }

    /* Listening PCBs: tcp_close is the documented teardown for them. */
    struct tcp_pcb_listen *lpcb = tcp_listen_pcbs.listen_pcbs;
    while (lpcb)
    {
        struct tcp_pcb_listen *next = lpcb->next;
        if (pcb_belongs_to_netif((const struct ip_pcb *)lpcb, netif))
        {
            lwip_teardown_detach_listener(lpcb);
            tcp_close((struct tcp_pcb *)lpcb);
        }
        lpcb = next;
    }
#endif

#if LWIP_UDP
    struct udp_pcb *upcb = udp_pcbs;
    while (upcb)
    {
        struct udp_pcb *next = upcb->next;
        if (pcb_belongs_to_netif((const struct ip_pcb *)upcb, netif))
        {
            udp_recv(upcb, NULL, NULL);
            udp_remove(upcb);
        }
        upcb = next;
    }
#endif
}

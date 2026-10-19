#ifndef LWIP_WIRELESS_WIFI_HOOK_H
#define LWIP_WIRELESS_WIFI_HOOK_H

#include "lwip/err.h"

struct pbuf;
struct netif;

err_t lwip_wifi_eth_input(struct pbuf *p, struct netif *netif);

/* Clears request state left behind by a program that exited mid-request. */
void lwip_wifi_reset(void);

#define LWIP_HOOK_UNKNOWN_ETH_PROTOCOL(pbuf, netif) lwip_wifi_eth_input(pbuf, netif)

#endif

#ifndef LWIP_WIRELESS_WIFI_HOOK_H
#define LWIP_WIRELESS_WIFI_HOOK_H

#include <stdint.h>

#include "lwip/err.h"

struct pbuf;
struct netif;

err_t lwip_wifi_eth_input(struct pbuf *p, struct netif *netif);

/* Clears request state left behind by a program that exited mid-request. */
void lwip_wifi_reset(void);

/* Allocates a control frame addressed to the bridge with body_len bytes of room
 * after the header; *seq receives its sequence number. NULL when no bridge. */
struct pbuf *lwip_wifi_frame(uint8_t op, uint16_t body_len, uint8_t *seq);

/* Sends a frame from lwip_wifi_frame, then wipes and frees it. */
err_t lwip_wifi_frame_send(struct pbuf *p);

#define LWIP_HOOK_UNKNOWN_ETH_PROTOCOL(pbuf, netif) lwip_wifi_eth_input(pbuf, netif)

#endif

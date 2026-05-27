#ifndef LWIP_TEARDOWN_H
#define LWIP_TEARDOWN_H

#include "lwip/opt.h"
#include "lwip/netif.h"

/** Abort every TCP/UDP/RAW PCB in the stack. Used at program exit and on
 *  fatal handler invocation; not intended for normal connection
 *  lifecycle. */
void lwip_teardown_abort_pcbs(void);

/** Abort every TCP/UDP/RAW PCB bound to the given netif (by netif_idx).
 *  Each PCB's err callback fires with ERR_RST so the application can
 *  release its own state. Designed to be called from a netif link
 *  callback when a backing transport has gone down so consumers see a
 *  clean reset rather than a stuck connection.
 *
 *  @param netif The netif whose bound PCBs should be aborted.
 */
void lwip_teardown_abort_pcbs_on_netif(const struct netif *netif);

#endif /* LWIP_TEARDOWN_H */

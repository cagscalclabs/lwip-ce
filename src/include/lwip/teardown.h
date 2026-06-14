#ifndef LWIP_TEARDOWN_H
#define LWIP_TEARDOWN_H

#include "lwip/opt.h"
#include "lwip/netif.h"

#include <stdbool.h>

struct tcp_pcb;

/** Abort every TCP/UDP/RAW PCB in the stack. Used at program exit and on
 *  fatal handler invocation; not intended for normal connection
 *  lifecycle. */
void lwip_teardown_abort_pcbs(void);

/** Ask every TCP PCB not already closing to close gracefully. This sends
 *  FIN where the PCB state allows it and leaves closing PCBs alive for
 *  the normal TCP timers / ACK path to finish. */
void lwip_teardown_begin_tcp_close(void);

/** True while TCP listen/bound/active PCBs still exist. TIME_WAIT PCBs
 *  are excluded because their FIN handshake has already completed. */
bool lwip_teardown_tcp_pcbs_pending(void);

/** True while a specific TCP PCB address is still present in the
 *  listen/bound/active lists. The pointer may already be unsafe to
 *  dereference after tcp_close(); callers must treat this as an address
 *  identity check only. */
bool lwip_teardown_tcp_pcb_pending(const struct tcp_pcb *target);

/** Abort a specific TCP PCB if it is still present in a live list. */
void lwip_teardown_abort_tcp_pcb(struct tcp_pcb *target);

/** Abort every remaining listen/bound/active TCP PCB. */
void lwip_teardown_abort_tcp_pcbs(void);

/** Clear TIME_WAIT PCBs after graceful close has completed. */
void lwip_teardown_abort_time_wait_pcbs(void);

/** Remove non-TCP PCBs after their owning services have been stopped. */
void lwip_teardown_remove_non_tcp_pcbs(void);

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

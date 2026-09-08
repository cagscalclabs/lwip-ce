/*
 * netbridge — host-side network bridge for the emulated CEmu ECM device.
 *
 * Registers as the ECM TX sink (frames the calc sends) and injects replies via
 * ecm_inject_frame (frames the calc receives), making the emulated calc behave
 * as if attached to a real network. This first stage answers ARP and DHCP so
 * the calc obtains an IP; later stages add DNS + a per-flow TCP/UDP socket
 * proxy to reach the real internet.
 */
#ifndef CEDBG_NETBRIDGE_H
#define CEDBG_NETBRIDGE_H

#include <stdbool.h>
#include <stdint.h>

/* Install the bridge as the ECM TX sink. Idempotent. */
void netbridge_init(void);

/* Pump time-based work (DHCP lease timers, socket polling later). Call
 * periodically from the run loop. now_ms is a host millisecond clock. */
void netbridge_poll(uint32_t now_ms);

#endif

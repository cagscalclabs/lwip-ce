/**
 * @file dispatch.h
 * @brief Coalesced periodic dispatcher for lwIP-CE owned timers.
 *
 * lwIP-CE has several periodic activities that all rode separate
 * sys_timeout chains: ethernet RX drain (10 ms), ethernet RX scheduler
 * re-arm (20 ms base), TLS RNG request pump (50 ms), TLS RNG health
 * check (30 s). Each separate timer adds an entry to lwIP's cyclic
 * timer wheel and risks phase drift relative to the others.
 *
 * This module collapses every lwIP-CE owned periodic into a single
 * master tick (LWIP_DISPATCH_TICK_MS, the GCD of all sub-cadences).
 * Each sub-dispatcher has its own period_ticks counter; on rollover
 * the dispatcher fires. Ethernet RX uses a fixed cadence; memory
 * pressure is expressed through TCP receive-window release timing
 * instead of slowing ingress.
 *
 * lwIP's own cyclic timers (TCP, ARP, DHCP, etc.) are NOT routed
 * through this dispatcher. They keep using sys_timeout/cyclic_timer
 * unchanged.
 */
#ifndef LWIP_DISPATCH_H
#define LWIP_DISPATCH_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Master tick period. GCD of every sub-dispatcher's cadence — bump
 *  this only if a new sub-dispatcher needs a finer grain. Coarser is
 *  fine; sub-dispatcher periods are quantized to multiples of this. */
#define LWIP_DISPATCH_TICK_MS 10u

/** Sub-dispatcher identifier. Each dispatcher has its own period and
 *  enable bit. Add new entries here and in the dispatcher table in
 *  dispatch.c. */
typedef enum {
    LWIP_DISPATCH_ETH_RX_DRAIN = 0,
    LWIP_DISPATCH_ETH_RX_SCHEDULE,
    LWIP_DISPATCH_TLS_RNG_REQUEST,
    LWIP_DISPATCH_TLS_RNG_HEALTHCHECK,
    LWIP_DISPATCH_TLS_RX_RECVD,      /**< TLS receive-window release */
    LWIP_DISPATCH_CONN_SERVICES,    /**< lwip_conn waiting-for-services poll */
    LWIP_DISPATCH_COUNT
} lwip_dispatch_id_t;

/** Per-dispatcher callback. Fires on the master tick when the
 *  dispatcher's counter rolls over. No arg — dispatchers operate on
 *  module-global state. */
typedef void (*lwip_dispatch_fn)(void);

/** Wire a sub-dispatcher's callback function. Each module owning a
 *  dispatcher slot calls this once at init. Until attached, the
 *  dispatcher slot is inert even if its period has been set. */
void lwip_dispatch_attach(lwip_dispatch_id_t id, lwip_dispatch_fn fn);

/** Set a dispatcher's period in master ticks. Period of 0 disables the
 *  dispatcher (it stops firing until set back to a non-zero value).
 *  Safe to call at any time — the change applies on the next master
 *  tick. */
void lwip_dispatch_set_period(lwip_dispatch_id_t id, uint16_t period_ticks);

/** Get the current period (in master ticks). Returns 0 if disabled. */
uint16_t lwip_dispatch_get_period(lwip_dispatch_id_t id);

/** Convenience: convert a millisecond cadence to a tick period (rounded
 *  up so the dispatcher never fires *faster* than the caller asked).
 *  A cadence of 0 returns 0 (disable). */
uint16_t lwip_dispatch_period_from_ms(uint32_t ms);

/** Start the master tick. Idempotent — repeat calls are no-ops. The
 *  master tick stays armed until lwip_dispatch_stop() is called or the
 *  process exits. Sub-dispatchers default to disabled until their
 *  owning module calls lwip_dispatch_set_period. */
void lwip_dispatch_start(void);

/** Stop the master tick. Used during stack shutdown; cancels the
 *  outstanding sys_timeout so the dispatcher doesn't fire against a
 *  partially-torn-down stack. */
void lwip_dispatch_stop(void);

#ifdef __cplusplus
}
#endif

#endif /* LWIP_DISPATCH_H */

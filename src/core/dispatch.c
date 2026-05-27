/**
 * @file dispatch.c
 * @brief Master-tick implementation. See lwip/dispatch.h for the
 *        design rationale.
 */

#include "lwip/dispatch.h"

#include "lwip/opt.h"
#include "lwip/timeouts.h"

#include <stddef.h>

/* Per-dispatcher mutable state. The fn pointer is registered lazily by
 * the owning module (eth driver, RNG, etc.) via the public attach API
 * below; until attached, the dispatcher slot is inert even if its
 * period is set. */
struct dispatcher_state {
    lwip_dispatch_fn fn;
    uint16_t period;   /* in master ticks; 0 disables */
    uint16_t counter;  /* counts down from period to 0 on each tick */
};

static struct dispatcher_state g_dispatchers[LWIP_DISPATCH_COUNT];
static bool g_master_running = false;


/* Public registration. Modules call this once at init to wire their fn
 * into the table; subsequent set_period calls control the firing
 * cadence. Defined as a weak-ish indirection through a registration
 * function rather than a public global so callers can't accidentally
 * trample each other's slots. */
void lwip_dispatch_attach(lwip_dispatch_id_t id, lwip_dispatch_fn fn);
void lwip_dispatch_attach(lwip_dispatch_id_t id, lwip_dispatch_fn fn)
{
    if ((unsigned)id >= LWIP_DISPATCH_COUNT) {
        return;
    }
    g_dispatchers[id].fn = fn;
}


void lwip_dispatch_set_period(lwip_dispatch_id_t id, uint16_t period_ticks)
{
    if ((unsigned)id >= LWIP_DISPATCH_COUNT) {
        return;
    }
    g_dispatchers[id].period = period_ticks;
    /* Reset counter so a freshly-set period gets a full window before
     * its first fire (avoids back-to-back fires when raising the
     * cadence). */
    g_dispatchers[id].counter = period_ticks;
}


uint16_t lwip_dispatch_get_period(lwip_dispatch_id_t id)
{
    if ((unsigned)id >= LWIP_DISPATCH_COUNT) {
        return 0;
    }
    return g_dispatchers[id].period;
}


uint16_t lwip_dispatch_period_from_ms(uint32_t ms)
{
    if (ms == 0) {
        return 0;
    }
    /* Round up: never fire faster than the caller requested. */
    uint32_t ticks = (ms + LWIP_DISPATCH_TICK_MS - 1) / LWIP_DISPATCH_TICK_MS;
    if (ticks == 0) {
        ticks = 1;
    }
    if (ticks > UINT16_MAX) {
        ticks = UINT16_MAX;
    }
    return (uint16_t)ticks;
}


static void lwip_dispatch_master(void *arg);

static void lwip_dispatch_master(void *arg)
{
    (void)arg;
    if (!g_master_running) {
        return;
    }

    /* Decrement-and-fire. We snapshot fn/period locally so a dispatcher
     * that calls set_period on itself (legitimate) only takes effect on
     * the next tick. */
    for (unsigned i = 0; i < LWIP_DISPATCH_COUNT; i++) {
        struct dispatcher_state *d = &g_dispatchers[i];
        if (d->period == 0 || d->fn == NULL) {
            continue;
        }
        if (d->counter > 0) {
            d->counter--;
        }
        if (d->counter == 0) {
            d->counter = d->period;
            d->fn();
        }
    }

    sys_timeout(LWIP_DISPATCH_TICK_MS, lwip_dispatch_master, NULL);
}


void lwip_dispatch_start(void)
{
    if (g_master_running) {
        return;
    }
    g_master_running = true;
    sys_timeout(LWIP_DISPATCH_TICK_MS, lwip_dispatch_master, NULL);
}


void lwip_dispatch_stop(void)
{
    if (!g_master_running) {
        return;
    }
    g_master_running = false;
    sys_untimeout(lwip_dispatch_master, NULL);
}

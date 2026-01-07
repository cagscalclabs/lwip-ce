#ifndef MEM_BUFFER_H
#define MEM_BUFFER_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

struct mem_buffer;

/* Memory/buffer helpers for lwIP drivers and ring/pool allocations. */
typedef void *(*mem_malloc_fn)(size_t size);
typedef void (*mem_free_fn)(void *ptr);
typedef void *(*mem_realloc_fn)(void *ptr, size_t size);
/* Pressure tiers reported to throttling and user callbacks. */
enum mem_pressure_level
{
    MEM_PRESSURE_NONE = 0,
    MEM_PRESSURE_MILD,
    MEM_PRESSURE_HIGH,
    MEM_PRESSURE_CRITICAL
};

/* Low-memory callback with requested size and pressure tier. */
typedef void (*mem_low_mem_cb)(struct mem_buffer *mb, size_t requested, enum mem_pressure_level level);
/* Drain callback for ring buffers: consume up to budget items and return count drained. */
typedef size_t (*mem_drain_fn)(struct mem_buffer *mb, void *user, size_t budget);

/* Owner tags used for pressure routing. */
enum mem_buffer_owner
{
    MEM_BUF_OWNER_UNKNOWN = 0,
    MEM_BUF_OWNER_LWIP_POOL,
    MEM_BUF_OWNER_ETH_RX,
    MEM_BUF_OWNER_ETH_TX,
    MEM_BUF_OWNER_TLS_RX,
    MEM_BUF_OWNER_TLS_TX,
    MEM_BUF_OWNER_FILEIO
};

/* Pressure hooks for backpressure throttling (e.g. ethernet/tls RX). */
struct mem_pressure_hooks
{
    void (*eth_rx_throttle)(enum mem_pressure_level level);
    void (*tls_rx_throttle)(enum mem_pressure_level level);
};

/* Global allocator config shared by all mem_buffer instances. */
struct mem_buffer_config
{
    size_t max_heap;
    size_t heap_used;
    size_t step;
    uint8_t grow_threshold_pct;
    uint8_t shrink_threshold_pct;
    uint16_t shrink_hold_count;
    mem_malloc_fn malloc_fn;
    mem_free_fn free_fn;
    mem_realloc_fn realloc_fn;
    mem_low_mem_cb internal_low_mem_cb;
};

/* Ring buffer or pool allocator instance. */
struct mem_buffer
{
    struct mem_buffer_config *cfg;
    uint8_t *buf;
    size_t cap;
    size_t max_cap;
    enum mem_buffer_owner owner;
    uint8_t flags;
    enum mem_pressure_level last_pressure_level;
    size_t step;
    uint8_t grow_threshold_pct;
    uint8_t shrink_threshold_pct;
    uint16_t shrink_hold_count;
    uint16_t shrink_hold_base;
    uint16_t shrink_hold_next;
    uint8_t shrink_stage;
    uint16_t shrink_hits;
    mem_low_mem_cb low_mem_cb;
    mem_drain_fn drain_fn;
    void *drain_fn_data;
    union
    {
        struct
        {
            size_t len;
            size_t head;
            size_t lock_size;
        } ring;
        struct
        {
            size_t pool_block_size;
            size_t pool_block_count;
            size_t pool_used_blocks;
            uint8_t *pool_bitmap;
            size_t pool_bitmap_bytes;
        } pool;
    } u;
};

/* Buffer behavior flags. */
enum mem_buffer_flags
{
    BUFFER_SECURE_MODE = 1u << 0,
    BUFFER_LOCK_SIZE = 1u << 1,
    BUFFER_MALLOC_TYPE = 1u << 2,
    BUFFER_FILEIO_TYPE = 1u << 3
};

/* Pool config for lwIP custom allocator. */
struct mem_buffer_pool_cfg
{
    size_t block_size;
    size_t block_count;
    size_t max_cap;
    uint8_t flags;
    mem_low_mem_cb low_mem_cb;
    enum mem_buffer_owner owner;
};

/* Initialize allocator system (required before mem_buffer_create). */
bool mem_init(size_t max_heap,
              mem_malloc_fn malloc_fn,
              mem_free_fn free_fn,
              mem_realloc_fn realloc_fn);
bool mem_is_ready(void);
void mem_set_internal_lowmem_cb(mem_low_mem_cb low_mem_cb);
void mem_register_pressure_hook_eth_rx(void (*hook)(enum mem_pressure_level level));
void mem_register_pressure_hook_tls_rx(void (*hook)(enum mem_pressure_level level));
void mem_set_pressure_clear_pct(uint8_t pct);

/* Create/destroy a ring or pool buffer. For malloc buffers, lock_size or step 0 uses one block at cap. */
struct mem_buffer *mem_buffer_create(size_t initial_cap,
                                     size_t max_cap,
                                     size_t lock_size,
                                     uint8_t flags,
                                     mem_low_mem_cb low_mem_cb);
void mem_buffer_destroy(struct mem_buffer *mb);

/* Ring buffer helpers. */
size_t mem_buffer_len(const struct mem_buffer *mb);
size_t mem_buffer_capacity(const struct mem_buffer *mb);
size_t mem_buffer_space(const struct mem_buffer *mb);
bool mem_buffer_peek(const struct mem_buffer *mb, size_t offset, uint8_t *out, size_t len);
bool mem_buffer_reserve(struct mem_buffer *mb, size_t len);

bool mem_buffer_push(struct mem_buffer *mb, const uint8_t *data, size_t len);
size_t mem_buffer_pop(struct mem_buffer *mb, uint8_t *out, size_t len);

/* Pool allocator helpers. */
void *mem_buffer_malloc(struct mem_buffer *mb, size_t size);
void mem_buffer_free(struct mem_buffer *mb, void *ptr);
void mem_buffer_set_owner(struct mem_buffer *mb, enum mem_buffer_owner owner);
enum mem_buffer_owner mem_buffer_get_owner(const struct mem_buffer *mb);
void mem_buffer_set_drain(struct mem_buffer *mb, mem_drain_fn drain_fn, void *drain_fn_data);

/* Per-buffer tuning. */
void mem_buffer_set_grow(struct mem_buffer *mb, uint8_t threshold_pct, size_t step);
void mem_buffer_set_shrink(struct mem_buffer *mb, uint8_t threshold_pct, size_t step);
void mem_buffer_set_max_size(struct mem_buffer *mb, size_t max_cap);

/* lwIP pool wiring. */
bool mem_buffer_set_lwip_heap(struct mem_buffer *mb);
bool mem_buffer_lwip_init_pools(const struct mem_buffer_pool_cfg *pools,
                                size_t pool_count);
bool mem_buffer_is_lwip_pool(const struct mem_buffer *mb);
void *mem_buffer_custom_malloc(size_t size);
void mem_buffer_custom_free(void *ptr);
void *mem_buffer_custom_calloc(size_t count, size_t size);

/*
 * Memory Mngmt & Pressure overview:
 * - Buffers of type POOL or RING, initial dynamic allocation at starting size.
 * - As buffer fills to `high_threshold`, buffer reallocates to `step` bytes larger (or multiple
 *   of `step` large enough to absorb all incoming data)
 * - When buffer clears to `low_threshold` for a period of time, buffer shrinks by `step` in stages.
 * - This allows lwIP to occupy only as much memory as it truly needs. Pre-reserving large static
 *   blocks ‘just in case’ may be simpler, but on this platform it’s also how you lose half your
 *   RAM before you do anything.
 * - Buffers are tagged with an owner (lwIP pools, ETH RX, TLS RX) so pressure can
 *   be routed to the correct throttling hooks.
 * - Pressure tiers are derived from usage vs max capacity (or lwIP max heap):
 *   mild >= 70%, high >= 85%, critical when growth fails.
 * - Relief is tiered in reverse (critical -> high -> mild -> none) as usage drops.
 * - Low-memory callbacks receive the requested size and current tier, and are
 *   invoked before user-defined callbacks.
 * - Per-buffer drain functions allow decoupled ingestion (e.g., ethernet RX ring
 *   buffers drained into pbufs on a sys_timeout timer) without dropping data.
 * - Internally actions are taken in response to memory pressure: Eth RX ring buffer
 *   drain frequency slows, altcp_recved() is deferred for more processing, in critical pressure
 *   RX callbacks are stopped. Recovery occurs automatically in stages once pressure state lifts.
 * - Eth pressure causes eth slowdown, TLS pressure causes TLS slowdown. lwIP core pool
 *   pressure activates all throttling hooks.
 */

#endif

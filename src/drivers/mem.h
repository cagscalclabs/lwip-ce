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
    MEM_PRESSURE_SEVERE,
    MEM_PRESSURE_CRITICAL,
    MEM_PRESSURE_GLOBAL = 0x800000u
};

/* Pressure change callback - called when buffer pressure level changes (including relief). */
typedef void (*mem_pressure_cb)(struct mem_buffer *mb, size_t requested, enum mem_pressure_level level);
/* Drain callback for ring buffers: consume up to budget items and return count drained. */
typedef size_t (*mem_drain_fn)(struct mem_buffer *mb, void *user, size_t budget);

/* Buffer type determines allocation strategy. */
enum mem_buffer_type
{
    MEM_BUFFER_RING, /* FIFO ring buffer for streaming data */
    MEM_BUFFER_POOL, /* Block allocator for malloc/free style usage */
    MEM_BUFFER_FILE  /* Pool with secure mode for file I/O */
};

/* Ring buffer or pool allocator instance. */
struct mem_buffer
{
    enum mem_buffer_type type;
    uint8_t *buf;
    size_t initial_size;
    size_t current_size;
    size_t max_size;
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
    mem_pressure_cb pressure_cb;
    union
    {
        struct
        {
            size_t len;
            size_t head;
            mem_drain_fn drain_fn;
            void *drain_fn_data;
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
    BUFFER_SECURE_MODE = 1u << 0, /* Auto-erase used/freed/released memory */
    BUFFER_LOCK_SIZE = 1u << 1,   /* Prohibit grow/shrink, lock to initial size */
    BUFFER_USER_ALLOC = 1u << 2   /* User buffer, doesn't count toward lwIP heap */
};

/* Pool config for lwIP custom allocator. */
struct mem_buffer_pool_cfg
{
    size_t block_size;
    size_t block_count;
    size_t max_size;
    uint8_t flags;
};

/* Public API (exposed). */
bool mem_init(size_t max_heap,
              mem_malloc_fn malloc_fn,
              mem_free_fn free_fn,
              mem_realloc_fn realloc_fn);
struct mem_buffer *mem_buffer_create(enum mem_buffer_type type,
                                     size_t initial_size,
                                     size_t max_size,
                                     size_t step_size,
                                     uint8_t flags);
void mem_buffer_destroy(struct mem_buffer *mb);
bool mem_buffer_push(struct mem_buffer *mb, const uint8_t *data, size_t len);
size_t mem_buffer_pop(struct mem_buffer *mb, uint8_t *out, size_t len);
void *mem_buffer_malloc(struct mem_buffer *mb, size_t size);
void mem_buffer_free(struct mem_buffer *mb, void *ptr);
bool mem_buffer_set_drain(struct mem_buffer *mb, mem_drain_fn drain_fn, void *drain_fn_data);
void mem_buffer_set_pressure_cb(struct mem_buffer *mb, mem_pressure_cb cb);
void mem_buffer_set_grow(struct mem_buffer *mb, uint8_t threshold_pct, size_t step);
void mem_buffer_set_shrink(struct mem_buffer *mb, uint8_t threshold_pct, size_t step);
void mem_buffer_set_max_size(struct mem_buffer *mb, size_t max_size);
bool mem_buffer_peek(const struct mem_buffer *mb, size_t offset, uint8_t *out, size_t len);

/* Optional helpers (internal/advanced). */
bool mem_is_ready(void);
enum mem_pressure_level mem_get_global_pressure_level(void);
size_t mem_buffer_len(const struct mem_buffer *mb);
size_t mem_buffer_capacity(const struct mem_buffer *mb);
size_t mem_buffer_space(const struct mem_buffer *mb);
bool mem_buffer_reserve(struct mem_buffer *mb, size_t len);

bool mem_buffer_set_lwip_heap(struct mem_buffer *mb);
bool mem_buffer_lwip_init_pools(const struct mem_buffer_pool_cfg *pools,
                                size_t pool_count);
bool mem_buffer_is_lwip_pool(const struct mem_buffer *mb);
void *mem_buffer_custom_malloc(size_t size);
void mem_buffer_custom_free(void *ptr);
void *mem_buffer_custom_calloc(size_t count, size_t size);

/*
 * Memory Management & Pressure Overview:
 *
 * Buffer Types:
 * - MEM_BUFFER_RING: FIFO ring buffer for streaming data
 * - MEM_BUFFER_POOL: Block allocator for malloc/free style usage
 * - MEM_BUFFER_FILE: Pool with BUFFER_SECURE_MODE for file I/O
 *
 * Dynamic Sizing:
 * - Buffers start at initial_size and grow/shrink dynamically
 * - As buffer fills to grow_threshold, it reallocates by step_size bytes
 * - When buffer clears to shrink_threshold for a period, it shrinks in stages
 * - BUFFER_LOCK_SIZE flag disables dynamic sizing
 *
 * Pressure System:
 * - Each buffer tracks its own pressure level based on usage vs capacity
 * - Pressure tiers: NONE -> MILD (>70%) -> HIGH (>85%) -> SEVERE (>90%) -> CRITICAL (>95% or cannot grow)
 * - Per-buffer pressure callbacks notify on level changes (both raise and relief)
 * - Global pressure level derived from overall heap usage (heap_used / max_heap)
 * - Global pressure notifications set MEM_PRESSURE_GLOBAL in the level
 * - BUFFER_USER_ALLOC buffers don't count toward global heap pressure
 *
 * Drain Functions:
 * - Per-buffer drain callbacks allow decoupled ingestion (e.g., ethernet RX
 *   ring buffers drained into pbufs on a sys_timeout timer)
 */

#endif

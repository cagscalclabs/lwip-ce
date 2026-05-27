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
    MEM_BUFFER_FILE  /* Slot-based allocator for file I/O (lazy allocations) */
};

enum
{
    MEM_FILE_MAX_SLOTS = 5
};

struct mem_file_slot
{
    uint8_t *ptr;
    size_t size;
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
        struct
        {
            size_t used_bytes;
            size_t max_slots;
            struct mem_file_slot *slots;
        } file;
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

/* Optional helpers (internal/advanced). */

#endif

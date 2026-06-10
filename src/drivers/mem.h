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
/* Effective lwIP pressure callback. Receives the max of global heap and lwIP pool pressure. */
typedef void (*mem_global_pressure_cb)(enum mem_pressure_level level);
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
/**
 * @brief Initialize allocator backend and global heap accounting.
 * @param max_heap Maximum bytes allowed for accounting (SIZE_MAX to disable).
 * @param malloc_fn Allocator for raw allocations.
 * @param free_fn Deallocator for raw allocations.
 * @param realloc_fn Reallocator for raw allocations.
 * @return true on success, false on error.
 */
bool mem_init(size_t max_heap,
              mem_malloc_fn malloc_fn,
              mem_free_fn free_fn,
              mem_realloc_fn realloc_fn);

/**
 * @brief Initialize memory system with caller-provided dynamic allocators.
 *
 * Equivalent to mem_init(...), but explicit naming for dynamic mode.
 */
bool mem_init_dynamic(size_t max_heap,
                      mem_malloc_fn malloc_fn,
                      mem_free_fn free_fn,
                      mem_realloc_fn realloc_fn);

/**
 * @brief Initialize memory system in static mode from a fixed arena.
 *
 * The arena is internally managed by a lightweight allocator. No external
 * malloc/free/realloc callbacks are required after this call.
 *
 * Static mode characteristics:
 * - no ring/pool grow or shrink,
 * - no pressure callbacks/levels,
 * - FILE buffers still allocate lazily, but from the fixed arena.
 *
 * @param buffer Fixed backing storage.
 * @param buffer_size Size in bytes of @p buffer.
 * @return true on success, false on invalid arena.
 */
bool mem_init_static(void *buffer, size_t buffer_size);
/**
 * @brief Create a ring/pool buffer with sizing rules and flags.
 * @param type Buffer type.
 * @param initial_size Initial capacity in bytes (ignored for MEM_BUFFER_FILE).
 * @param max_size Maximum capacity in bytes (SIZE_MAX for no cap).
 * @param step_size Grow/shrink step size in bytes (ignored for MEM_BUFFER_FILE).
 * @param flags Buffer behavior flags.
 * @return Pointer to buffer or NULL on failure.
 */
struct mem_buffer *mem_buffer_create(enum mem_buffer_type type,
                                     size_t initial_size,
                                     size_t max_size,
                                     size_t step_size,
                                     uint8_t flags);
/**
 * @brief Destroy a buffer and release its memory.
 * @param mb Buffer to destroy (NULL-safe).
 */
void mem_buffer_destroy(struct mem_buffer *mb);
/**
 * @brief Append data to a ring buffer.
 * @param mb Ring buffer.
 * @param data Data to append.
 * @param len Number of bytes to append.
 * @return true on success, false on error or lack of space.
 */
bool mem_buffer_push(struct mem_buffer *mb, const uint8_t *data, size_t len);
/**
 * @brief Pop up to len bytes from a ring buffer.
 * @param mb Ring buffer.
 * @param out Destination buffer (can be NULL to discard).
 * @param len Max bytes to pop.
 * @return Number of bytes popped.
 */
size_t mem_buffer_pop(struct mem_buffer *mb, uint8_t *out, size_t len);
/**
 * @brief Allocate from a pool buffer.
 * @param mb Pool buffer.
 * @param size Allocation size in bytes.
 * @return Pointer to allocation or NULL on failure.
 */
void *mem_buffer_malloc(struct mem_buffer *mb, size_t size);
/**
 * @brief Free to a pool buffer.
 * @param mb Pool buffer.
 * @param ptr Pointer to allocation.
 */
void mem_buffer_free(struct mem_buffer *mb, void *ptr);
/**
 * @brief Register a ring drain callback and user data.
 * @param mb Ring buffer.
 * @param drain_fn Callback to drain items.
 * @param drain_fn_data User data passed to callback.
 * @return true on success, false on error.
 */
bool mem_buffer_set_drain(struct mem_buffer *mb, mem_drain_fn drain_fn, void *drain_fn_data);
/**
 * @brief Invoke the registered drain callback with a budget.
 * @param mb Ring buffer.
 * @param budget Max items to drain.
 * @return Number of items drained.
 */
size_t mem_buffer_drain(struct mem_buffer *mb, size_t budget);
/**
 * @brief Register a pressure level change callback.
 * @param mb Buffer.
 * @param cb Callback to invoke on pressure changes.
 */
void mem_buffer_set_pressure_cb(struct mem_buffer *mb, mem_pressure_cb cb);
/**
 * @brief Configure proactive growth threshold and step.
 * @param mb Buffer.
 * @param threshold_pct Usage percentage to trigger growth.
 * @param step Growth step size in bytes.
 */
void mem_buffer_set_grow(struct mem_buffer *mb, uint8_t threshold_pct, size_t step);
/**
 * @brief Configure shrink threshold and step.
 * @param mb Buffer.
 * @param threshold_pct Usage percentage to allow shrink.
 * @param step Shrink step size in bytes.
 */
void mem_buffer_set_shrink(struct mem_buffer *mb, uint8_t threshold_pct, size_t step);
/**
 * @brief Set a hard maximum size limit.
 * @param mb Buffer.
 * @param max_size Maximum capacity in bytes.
 */
void mem_buffer_set_max_size(struct mem_buffer *mb, size_t max_size);
/**
 * @brief Peek len bytes at offset without consuming.
 * @param mb Ring buffer.
 * @param offset Byte offset from head.
 * @param out Destination buffer.
 * @param len Number of bytes to read.
 * @return true on success, false on error.
 */
bool mem_buffer_peek(const struct mem_buffer *mb, size_t offset, uint8_t *out, size_t len);

/* Optional helpers (internal/advanced). */
/**
 * @brief Query allocator readiness.
 * @return true if initialized and ready, false otherwise.
 */
bool mem_is_ready(void);
/**
 * @brief Get last reported global pressure level.
 * @return Current global pressure level.
 */
enum mem_pressure_level mem_get_global_pressure_level(void);
/**
 * @brief Register an observer for effective lwIP memory pressure.
 *
 * The reported level is the maximum of the global allocator pressure
 * and every lwIP allocation pool. This is intended for transport-level
 * backpressure such as delaying tcp_recved window updates.
 *
 * @param cb Callback to receive pressure changes, or NULL to clear.
 */
void mem_set_global_pressure_cb(mem_global_pressure_cb cb);
/**
 * @brief Get current ring length (bytes).
 * @param mb Ring buffer.
 * @return Number of bytes stored.
 */
size_t mem_buffer_len(const struct mem_buffer *mb);
/**
 * @brief Get current capacity (bytes).
 * @param mb Buffer.
 * @return Capacity in bytes.
 */
size_t mem_buffer_capacity(const struct mem_buffer *mb);
/**
 * @brief Get remaining ring space (bytes).
 * @param mb Ring buffer.
 * @return Free space in bytes.
 */
size_t mem_buffer_space(const struct mem_buffer *mb);
/**
 * @brief Ensure ring can accept len bytes (may grow).
 * @param mb Ring buffer.
 * @param len Bytes to reserve.
 * @return true if capacity is available, false otherwise.
 */
bool mem_buffer_reserve(struct mem_buffer *mb, size_t len);

/**
 * @brief Use this pool as the lwIP heap backing store.
 * @param mb Pool buffer.
 * @return true on success, false on error.
 */
bool mem_buffer_set_lwip_heap(struct mem_buffer *mb);
/**
 * @brief Initialize lwIP pools using the provided configs.
 * @param pools Pool configs array.
 * @param pool_count Number of configs.
 * @return true on success, false on error.
 */
bool mem_buffer_lwip_init_pools(const struct mem_buffer_pool_cfg *pools,
                                size_t pool_count);
/**
 * @brief Destroy all registered lwIP pools and clear the registry.
 * @note Teardown counterpart to mem_buffer_lwip_init_pools. Call only
 *       after USB/transport is quiesced so nothing is mid-allocation.
 *       Each pool is destroyed and its slot NULLed.
 */
void mem_buffer_lwip_release_pools(void);
/**
 * @brief Check if a buffer is an lwIP pool.
 * @param mb Buffer.
 * @return true if lwIP pool, false otherwise.
 */
bool mem_buffer_is_lwip_pool(const struct mem_buffer *mb);
/**
 * @brief lwIP-compatible malloc wrapper.
 * @param size Allocation size in bytes.
 * @return Pointer to allocation or NULL on failure.
 */
void *mem_buffer_custom_malloc(size_t size);
/**
 * @brief lwIP-compatible free wrapper.
 * @param ptr Pointer to allocation.
 */
void mem_buffer_custom_free(void *ptr);
/**
 * @brief lwIP-compatible calloc wrapper.
 * @param count Number of elements.
 * @param size Element size in bytes.
 * @return Pointer to allocation or NULL on failure.
 */
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

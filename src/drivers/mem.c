#include "mem.h"
#include <string.h>
#include "../tls/includes/bytes.h"

#define MEM_POOL_HEADER_SIZE (sizeof(uint16_t))

static size_t threshold_bytes(size_t cap, uint8_t pct)
{
    return (cap * (size_t)pct) / 100u;
}

static void mem_buffer_notify_pressure(struct mem_buffer *rb, size_t requested, enum mem_pressure_level level);
static bool mem_buffer_maybe_grow(struct mem_buffer *rb, size_t incoming_len);
static bool mem_buffer_is_pool_type(const struct mem_buffer *rb);
static enum mem_pressure_level mem_pressure_level_from_usage(uint8_t usage_pct);

#define MEM_SHRINK_HOLD_DEFAULT 1u

static size_t align_step(size_t value, size_t step)
{
    if (step == 0)
    {
        return value;
    }
    size_t rem = value % step;
    if (rem == 0)
    {
        return value;
    }
    return value + (step - rem);
}

struct mem_global_config
{
    size_t max_heap;
    size_t heap_used;
    mem_malloc_fn malloc_fn;
    mem_free_fn free_fn;
    mem_realloc_fn realloc_fn;
};

static struct mem_global_config g_mem_cfg;
static bool g_mem_cfg_ready = false;
static enum mem_pressure_level g_global_pressure_level = MEM_PRESSURE_NONE;

static size_t mem_buffer_used_bytes(const struct mem_buffer *rb)
{
    if (!rb)
    {
        return 0;
    }
    if (mem_buffer_is_pool_type(rb))
    {
        return rb->u.pool.pool_used_blocks * rb->u.pool.pool_block_size;
    }
    return rb->u.ring.len;
}

static void mem_global_pressure_update(void)
{
    if (!g_mem_cfg_ready || g_mem_cfg.max_heap == 0)
    {
        return;
    }
    uint8_t usage_pct = (uint8_t)((g_mem_cfg.heap_used * 100u) / g_mem_cfg.max_heap);
    g_global_pressure_level = mem_pressure_level_from_usage(usage_pct);
}

static bool mem_buffer_charge(size_t bytes)
{
    if (g_mem_cfg.max_heap == 0)
    {
        return true;
    }
    if (g_mem_cfg.heap_used + bytes > g_mem_cfg.max_heap)
    {
        return false;
    }
    g_mem_cfg.heap_used += bytes;
    mem_global_pressure_update();
    return true;
}

static void mem_buffer_release(size_t bytes)
{
    if (g_mem_cfg.heap_used >= bytes)
    {
        g_mem_cfg.heap_used -= bytes;
    }
    else
    {
        g_mem_cfg.heap_used = 0;
    }
    mem_global_pressure_update();
}

static uint16_t mem_buffer_hold_for_stage(uint16_t base, uint8_t stage)
{
    if (base == 0)
    {
        return 0;
    }
    if (stage >= 15)
    {
        return (uint16_t)(base << 15);
    }
    return (uint16_t)(base << stage);
}

static bool mem_buffer_resize(struct mem_buffer *rb, size_t new_cap)
{
    /* For ring buffers, check len; for pools, just check cap */
    size_t current_len = (rb->type == MEM_BUFFER_RING) ? rb->u.ring.len : 0;
    if (new_cap < current_len || new_cap == rb->current_size)
    {
        return (new_cap == rb->current_size);
    }

    if ((rb->flags & BUFFER_LOCK_SIZE) != 0)
    {
        return false;
    }

    if (new_cap < rb->initial_size)
    {
        return false;
    }

    if (rb->max_size != SIZE_MAX && new_cap > rb->max_size)
    {
        return false;
    }

    bool skip_heap_accounting = (rb->flags & BUFFER_USER_ALLOC) != 0;
    size_t old_cap = rb->current_size;
    size_t grow = (new_cap > old_cap) ? (new_cap - old_cap) : 0;
    size_t shrink = (old_cap > new_cap) ? (old_cap - new_cap) : 0;
    if (grow > 0 && !skip_heap_accounting && !mem_buffer_charge(grow))
    {
        mem_buffer_notify_pressure(rb, new_cap, MEM_PRESSURE_CRITICAL);
        return false;
    }

    uint8_t *new_buf = NULL;
    size_t current_head = (rb->type == MEM_BUFFER_RING) ? rb->u.ring.head : 0;
    if (g_mem_cfg.realloc_fn && current_head == 0 && current_len <= old_cap)
    {
        if ((rb->flags & BUFFER_SECURE_MODE) != 0 && shrink > 0)
        {
            tls_secure_memzero(rb->buf + new_cap, shrink);
        }
        new_buf = (uint8_t *)g_mem_cfg.realloc_fn(rb->buf, new_cap);
        if (!new_buf)
        {
            mem_buffer_notify_pressure(rb, new_cap, MEM_PRESSURE_CRITICAL);
            if (grow > 0 && !skip_heap_accounting)
            {
                mem_buffer_release(grow);
            }
            return false;
        }
    }
    else
    {
        new_buf = (uint8_t *)g_mem_cfg.malloc_fn(new_cap);
        if (!new_buf)
        {
            if (grow > 0 && !skip_heap_accounting)
            {
                mem_buffer_release(grow);
            }
            mem_buffer_notify_pressure(rb, new_cap, MEM_PRESSURE_CRITICAL);
            return false;
        }

        if (rb->type == MEM_BUFFER_RING && current_len > 0)
        {
            size_t first = rb->current_size - rb->u.ring.head;
            if (first > current_len)
            {
                first = current_len;
            }
            memcpy(new_buf, rb->buf + rb->u.ring.head, first);
            memcpy(new_buf + first, rb->buf, current_len - first);
        }
        else if (mem_buffer_is_pool_type(rb))
        {
            /* For pools, copy entire buffer content */
            memcpy(new_buf, rb->buf, (old_cap < new_cap) ? old_cap : new_cap);
        }

        if ((rb->flags & BUFFER_SECURE_MODE) != 0)
        {
            tls_secure_memzero(rb->buf, rb->current_size);
        }
        g_mem_cfg.free_fn(rb->buf);
    }

    rb->buf = new_buf;
    rb->current_size = new_cap;
    if (rb->type == MEM_BUFFER_RING)
    {
        rb->u.ring.head = 0;
    }
    rb->shrink_hits = 0;
    rb->shrink_stage = 0;
    rb->shrink_hold_next = rb->shrink_hold_base;
    if (shrink > 0 && !skip_heap_accounting)
    {
        mem_buffer_release(shrink);
    }
    return true;
}

static struct mem_buffer *g_lwip_heap = NULL;
#define MEM_LWIP_MAX_POOLS 6
static struct mem_buffer *g_lwip_pools[MEM_LWIP_MAX_POOLS];
static size_t g_lwip_pool_count = 0;

static uint8_t mem_buffer_usage_pct(const struct mem_buffer *rb, size_t used_bytes)
{
    if (!rb)
    {
        return 0;
    }
    size_t limit = rb->max_size;
    if (limit == 0 || limit == SIZE_MAX)
    {
        limit = rb->current_size;
    }
    if (limit == 0)
    {
        return 0;
    }
    if (limit < rb->current_size)
    {
        limit = rb->current_size;
    }
    if (used_bytes > limit)
    {
        used_bytes = limit;
    }
    uint8_t buf_pct = (uint8_t)((used_bytes * 100u) / limit);
    return buf_pct;
}

enum {
    MEM_PRESSURE_MILD_PCT = 70,
    MEM_PRESSURE_HIGH_PCT = 85,
    MEM_PRESSURE_SEVERE_PCT = 90,
    MEM_PRESSURE_CRITICAL_PCT = 95,
    MEM_PRESSURE_RELIEF_MARGIN = 10
};

static enum mem_pressure_level mem_pressure_level_from_usage(uint8_t usage_pct)
{
    if (usage_pct > MEM_PRESSURE_CRITICAL_PCT)
    {
        return MEM_PRESSURE_CRITICAL;
    }
    if (usage_pct > MEM_PRESSURE_SEVERE_PCT)
    {
        return MEM_PRESSURE_SEVERE;
    }
    if (usage_pct > MEM_PRESSURE_HIGH_PCT)
    {
        return MEM_PRESSURE_HIGH;
    }
    if (usage_pct > MEM_PRESSURE_MILD_PCT)
    {
        return MEM_PRESSURE_MILD;
    }
    return MEM_PRESSURE_NONE;
}

static enum mem_pressure_level mem_pressure_level_relief(enum mem_pressure_level current, uint8_t usage_pct)
{
    enum mem_pressure_level level = mem_pressure_level_from_usage(usage_pct);
    if (current == MEM_PRESSURE_CRITICAL)
    {
        if (usage_pct < (MEM_PRESSURE_CRITICAL_PCT - MEM_PRESSURE_RELIEF_MARGIN))
        {
            return MEM_PRESSURE_SEVERE;
        }
        return MEM_PRESSURE_CRITICAL;
    }
    if (current == MEM_PRESSURE_SEVERE)
    {
        if (usage_pct < (MEM_PRESSURE_SEVERE_PCT - MEM_PRESSURE_RELIEF_MARGIN))
        {
            return MEM_PRESSURE_HIGH;
        }
        return MEM_PRESSURE_SEVERE;
    }
    if (current == MEM_PRESSURE_HIGH)
    {
        if (usage_pct < (MEM_PRESSURE_HIGH_PCT - MEM_PRESSURE_RELIEF_MARGIN))
        {
            return MEM_PRESSURE_MILD;
        }
        return MEM_PRESSURE_HIGH;
    }
    if (current == MEM_PRESSURE_MILD)
    {
        if (usage_pct < (MEM_PRESSURE_MILD_PCT - MEM_PRESSURE_RELIEF_MARGIN))
        {
            return MEM_PRESSURE_NONE;
        }
        return MEM_PRESSURE_MILD;
    }
    return level;
}


static bool mem_buffer_is_pool_type(const struct mem_buffer *rb)
{
    return rb && (rb->type == MEM_BUFFER_POOL || rb->type == MEM_BUFFER_FILE);
}

static void mem_pressure_maybe_clear(struct mem_buffer *rb)
{
    if (!rb)
    {
        return;
    }
    size_t used_bytes = mem_buffer_used_bytes(rb);
    uint8_t usage_pct = mem_buffer_usage_pct(rb, used_bytes);
    enum mem_pressure_level old_level = rb->last_pressure_level;
    enum mem_pressure_level level = mem_pressure_level_relief(old_level, usage_pct);

    /* Notify per-buffer callbacks when pressure level changes (including relief) */
    if (level != old_level)
    {
        mem_buffer_notify_pressure(rb, used_bytes, level);
    }
}

bool mem_init(size_t max_heap,
              mem_malloc_fn malloc_fn,
              mem_free_fn free_fn,
              mem_realloc_fn realloc_fn)
{
    if (!malloc_fn || !free_fn)
    {
        return false;
    }

    g_mem_cfg.max_heap = max_heap;
    g_mem_cfg.heap_used = 0;
    g_mem_cfg.malloc_fn = malloc_fn;
    g_mem_cfg.free_fn = free_fn;
    g_mem_cfg.realloc_fn = realloc_fn;
    g_global_pressure_level = MEM_PRESSURE_NONE;
    g_mem_cfg_ready = true;
    return true;
}

bool mem_is_ready(void)
{
    return g_mem_cfg_ready;
}

enum mem_pressure_level mem_get_global_pressure_level(void)
{
    if (!g_mem_cfg_ready)
    {
        return MEM_PRESSURE_NONE;
    }
    return g_global_pressure_level;
}


struct mem_buffer *mem_buffer_create(enum mem_buffer_type type,
                                     size_t initial_size,
                                     size_t max_size,
                                     size_t step_size,
                                     uint8_t flags)
{
    if (!g_mem_cfg_ready)
    {
        return NULL;
    }
    if (initial_size == 0 || !g_mem_cfg.malloc_fn || !g_mem_cfg.free_fn)
    {
        return NULL;
    }

    /* BUFFER_USER_ALLOC buffers don't count toward heap */
    bool skip_heap_accounting = (flags & BUFFER_USER_ALLOC) != 0;
    if (!skip_heap_accounting)
    {
        if (!mem_buffer_charge(sizeof(struct mem_buffer) + initial_size))
        {
            return NULL;
        }
    }

    /* MEM_BUFFER_FILE implies secure mode */
    if (type == MEM_BUFFER_FILE)
    {
        flags |= BUFFER_SECURE_MODE;
    }

    struct mem_buffer *rb = (struct mem_buffer *)g_mem_cfg.malloc_fn(sizeof(struct mem_buffer));
    if (!rb)
    {
        if (!skip_heap_accounting)
        {
            mem_buffer_release(sizeof(struct mem_buffer) + initial_size);
        }
        return NULL;
    }

    rb->buf = (uint8_t *)g_mem_cfg.malloc_fn(initial_size);
    if (!rb->buf)
    {
        g_mem_cfg.free_fn(rb);
        if (!skip_heap_accounting)
        {
            mem_buffer_release(sizeof(struct mem_buffer) + initial_size);
        }
        return NULL;
    }

    rb->type = type;
    rb->flags = flags;
    rb->initial_size = initial_size;
    rb->current_size = initial_size;
    rb->max_size = (max_size == 0 || max_size == (size_t)-1) ? SIZE_MAX : max_size;
    if (rb->max_size != SIZE_MAX && rb->max_size < rb->current_size)
    {
        rb->max_size = rb->current_size;
    }
    rb->last_pressure_level = MEM_PRESSURE_NONE;
    rb->step = step_size;
    rb->grow_threshold_pct = 100;
    rb->shrink_threshold_pct = 0;
    rb->shrink_hold_count = MEM_SHRINK_HOLD_DEFAULT;
    rb->shrink_hold_base = MEM_SHRINK_HOLD_DEFAULT;
    rb->shrink_hold_next = MEM_SHRINK_HOLD_DEFAULT;
    rb->shrink_stage = 0;
    rb->shrink_hits = 0;
    rb->pressure_cb = NULL;

    /* Initialize type-specific fields */
    if (type == MEM_BUFFER_RING)
    {
        rb->u.ring.len = 0;
        rb->u.ring.head = 0;
        rb->u.ring.drain_fn = NULL;
        rb->u.ring.drain_fn_data = NULL;
    }
    else
    {
        /* Pool or File type */
        size_t block_size = step_size;
        if (block_size == 0)
        {
            block_size = 256u;
        }
        if (rb->current_size < block_size)
        {
            g_mem_cfg.free_fn(rb->buf);
            g_mem_cfg.free_fn(rb);
            if (!skip_heap_accounting)
            {
                mem_buffer_release(sizeof(struct mem_buffer) + initial_size);
            }
            return NULL;
        }
        rb->u.pool.pool_block_size = block_size;
        rb->u.pool.pool_block_count = rb->current_size / block_size;
        rb->u.pool.pool_used_blocks = 0;
        rb->u.pool.pool_bitmap_bytes = (rb->u.pool.pool_block_count + 7u) / 8u;
        if (!skip_heap_accounting)
        {
            if (!mem_buffer_charge(rb->u.pool.pool_bitmap_bytes))
            {
                g_mem_cfg.free_fn(rb->buf);
                g_mem_cfg.free_fn(rb);
                mem_buffer_release(sizeof(struct mem_buffer) + initial_size);
                return NULL;
            }
        }
        rb->u.pool.pool_bitmap = (uint8_t *)g_mem_cfg.malloc_fn(rb->u.pool.pool_bitmap_bytes);
        if (!rb->u.pool.pool_bitmap)
        {
            if (!skip_heap_accounting)
            {
                mem_buffer_release(rb->u.pool.pool_bitmap_bytes);
            }
            g_mem_cfg.free_fn(rb->buf);
            g_mem_cfg.free_fn(rb);
            if (!skip_heap_accounting)
            {
                mem_buffer_release(sizeof(struct mem_buffer) + initial_size);
            }
            return NULL;
        }
        memset(rb->u.pool.pool_bitmap, 0, rb->u.pool.pool_bitmap_bytes);
    }
    return rb;
}

void mem_buffer_set_pressure_cb(struct mem_buffer *mb, mem_pressure_cb cb)
{
    if (mb)
    {
        mb->pressure_cb = cb;
    }
}

void mem_buffer_destroy(struct mem_buffer *rb)
{
    if (!rb)
    {
        return;
    }
    bool skip_heap_accounting = (rb->flags & BUFFER_USER_ALLOC) != 0;

    if (rb->buf)
    {
        if ((rb->flags & BUFFER_SECURE_MODE) != 0)
        {
            tls_secure_memzero(rb->buf, rb->current_size);
        }
        g_mem_cfg.free_fn(rb->buf);
        if (!skip_heap_accounting)
        {
            mem_buffer_release(rb->current_size);
        }
        rb->buf = NULL;
    }
    if (mem_buffer_is_pool_type(rb) && rb->u.pool.pool_bitmap)
    {
        if ((rb->flags & BUFFER_SECURE_MODE) != 0)
        {
            tls_secure_memzero(rb->u.pool.pool_bitmap, rb->u.pool.pool_bitmap_bytes);
        }
        g_mem_cfg.free_fn(rb->u.pool.pool_bitmap);
        if (!skip_heap_accounting)
        {
            mem_buffer_release(rb->u.pool.pool_bitmap_bytes);
        }
        rb->u.pool.pool_bitmap = NULL;
        rb->u.pool.pool_bitmap_bytes = 0;
    }
    g_mem_cfg.free_fn(rb);
    if (!skip_heap_accounting)
    {
        mem_buffer_release(sizeof(struct mem_buffer));
    }
}

size_t mem_buffer_len(const struct mem_buffer *rb)
{
    return rb ? rb->u.ring.len : 0;
}

size_t mem_buffer_capacity(const struct mem_buffer *rb)
{
    return rb ? rb->current_size : 0;
}

size_t mem_buffer_space(const struct mem_buffer *rb)
{
    if (!rb || rb->current_size < rb->u.ring.len)
    {
        return 0;
    }
    return rb->current_size - rb->u.ring.len;
}

bool mem_buffer_peek(const struct mem_buffer *rb, size_t offset, uint8_t *out, size_t len)
{
    if (!rb || !out || len == 0 || offset + len > rb->u.ring.len)
    {
        return false;
    }

    size_t pos = (rb->u.ring.head + offset) % rb->current_size;
    size_t first = rb->current_size - pos;
    if (first > len)
    {
        first = len;
    }
    memcpy(out, rb->buf + pos, first);
    memcpy(out + first, rb->buf, len - first);
    return true;
}

bool mem_buffer_reserve(struct mem_buffer *rb, size_t len)
{
    if (!rb || len == 0)
    {
        return false;
    }
    if (rb->type != MEM_BUFFER_RING)
    {
        return false;
    }
    return mem_buffer_maybe_grow(rb, len);
}

bool mem_buffer_set_drain(struct mem_buffer *rb, mem_drain_fn drain_fn, void *drain_fn_data)
{
    if (rb && rb->type == MEM_BUFFER_RING)
    {
        rb->u.ring.drain_fn = drain_fn;
        rb->u.ring.drain_fn_data = drain_fn_data;
        return true;
    }
    return false;
}

static void mem_buffer_notify_pressure(struct mem_buffer *rb, size_t requested, enum mem_pressure_level level)
{
    if (!rb)
    {
        return;
    }
    enum mem_pressure_level old_level = rb->last_pressure_level;
    rb->last_pressure_level = level;
    /* Only notify on level changes */
    if (level != old_level && rb->pressure_cb)
    {
        rb->pressure_cb(rb, requested, level);
    }
}

static bool mem_buffer_maybe_grow(struct mem_buffer *rb, size_t incoming_len)
{
    if ((rb->flags & BUFFER_LOCK_SIZE) != 0)
    {
        size_t needed = rb->u.ring.len + incoming_len;
        uint8_t usage_pct = mem_buffer_usage_pct(rb, needed);
        enum mem_pressure_level level = mem_pressure_level_from_usage(usage_pct);
        if (level != MEM_PRESSURE_NONE && level != rb->last_pressure_level)
        {
            mem_buffer_notify_pressure(rb, needed, level);
        }
        if (needed > rb->current_size)
        {
            mem_buffer_notify_pressure(rb, needed, MEM_PRESSURE_CRITICAL);
        }
        return needed <= rb->current_size;
    }

    size_t needed = rb->u.ring.len + incoming_len;
    uint8_t usage_pct = mem_buffer_usage_pct(rb, needed);
    enum mem_pressure_level level = mem_pressure_level_from_usage(usage_pct);
    if (level != MEM_PRESSURE_NONE && level != rb->last_pressure_level)
    {
        mem_buffer_notify_pressure(rb, needed, level);
    }
    size_t grow_threshold = threshold_bytes(rb->current_size, rb->grow_threshold_pct);
    if (needed <= rb->current_size && needed < grow_threshold)
    {
        return true;
    }

    /* Grow by step * N where N is minimum steps to fit needed + 1 step headroom */
    size_t step = rb->step ? rb->step : 256u;
    size_t target;
    if (needed <= rb->current_size)
    {
        /* Proactive grow at threshold - add one step */
        target = rb->current_size + step;
    }
    else
    {
        /* Must grow to fit: calculate steps needed for data + 1 step headroom */
        size_t shortfall = needed - rb->current_size;
        size_t steps_needed = (shortfall + step - 1) / step; /* ceil division */
        steps_needed += 1; /* +1 for headroom */
        target = rb->current_size + (steps_needed * step);
    }
    if (rb->max_size != SIZE_MAX && target > rb->max_size)
    {
        target = rb->max_size;
        if (target < needed)
        {
            mem_buffer_notify_pressure(rb, needed, MEM_PRESSURE_CRITICAL);
            return false;
        }
    }
    if (!mem_buffer_resize(rb, target))
    {
        mem_buffer_notify_pressure(rb, needed, MEM_PRESSURE_CRITICAL);
        return false;
    }
    return true;
}

static void mem_buffer_maybe_shrink(struct mem_buffer *rb, bool wrapped)
{
    if ((rb->flags & BUFFER_LOCK_SIZE) != 0)
    {
        return;
    }

    if (rb->step == 0 || rb->current_size <= rb->step)
    {
        return;
    }

    if (!wrapped || rb->u.ring.head != 0)
    {
        return;
    }

    size_t shrink_threshold = threshold_bytes(rb->current_size, rb->shrink_threshold_pct);
    if (rb->u.ring.len > shrink_threshold)
    {
        rb->shrink_hits = 0;
        rb->shrink_stage = 0;
        rb->shrink_hold_next = rb->shrink_hold_base;
        return;
    }

    if (rb->shrink_hold_count == 0)
    {
        return;
    }

    rb->shrink_hits++;
    if (rb->shrink_hits < rb->shrink_hold_next)
    {
        return;
    }

    size_t target = rb->current_size - rb->step;
    if (target < rb->u.ring.len)
    {
        target = rb->u.ring.len;
    }
    if (target < rb->initial_size)
    {
        target = rb->initial_size;
    }
    mem_buffer_resize(rb, target);
    rb->shrink_hits = 0;
    if (rb->shrink_hold_base != 0)
    {
        rb->shrink_stage++;
    }
    rb->shrink_hold_next = mem_buffer_hold_for_stage(rb->shrink_hold_base, rb->shrink_stage);
}

bool mem_buffer_push(struct mem_buffer *rb, const uint8_t *data, size_t len)
{
    if (!rb || !data || len == 0)
    {
        return false;
    }

    if (rb->type != MEM_BUFFER_RING)
    {
        return false;
    }

    if (!mem_buffer_maybe_grow(rb, len))
    {
        return false;
    }

    size_t tail = (rb->u.ring.head + rb->u.ring.len) % rb->current_size;
    size_t first = rb->current_size - tail;
    if (first > len)
    {
        first = len;
    }
    memcpy(rb->buf + tail, data, first);
    memcpy(rb->buf, data + first, len - first);
    rb->u.ring.len += len;
    return true;
}

size_t mem_buffer_pop(struct mem_buffer *rb, uint8_t *out, size_t len)
{
    if (!rb || !out || len == 0 || len > rb->u.ring.len)
    {
        return 0;
    }

    if (rb->type != MEM_BUFFER_RING)
    {
        return 0;
    }

    size_t first = rb->current_size - rb->u.ring.head;
    if (first > len)
    {
        first = len;
    }
    memcpy(out, rb->buf + rb->u.ring.head, first);
    memcpy(out + first, rb->buf, len - first);

    if ((rb->flags & BUFFER_SECURE_MODE) != 0)
    {
        tls_secure_memzero(rb->buf + rb->u.ring.head, first);
        tls_secure_memzero(rb->buf, len - first);
    }

    size_t old_head = rb->u.ring.head;
    rb->u.ring.head = (rb->u.ring.head + len) % rb->current_size;
    rb->u.ring.len -= len;
    bool wrapped = (old_head + len) >= rb->current_size;
    mem_buffer_maybe_shrink(rb, wrapped);
    mem_pressure_maybe_clear(rb);
    return len;
}

void *mem_buffer_malloc(struct mem_buffer *rb, size_t size)
{
    if (!rb || !mem_buffer_is_pool_type(rb) || size == 0)
    {
        return NULL;
    }

    size_t needed = size + MEM_POOL_HEADER_SIZE;
    if (rb->u.pool.pool_block_size == 0)
    {
        return NULL;
    }

    if (needed > rb->current_size && (rb->flags & BUFFER_LOCK_SIZE) == 0)
    {
        bool skip_heap_accounting = (rb->flags & BUFFER_USER_ALLOC) != 0;
        size_t step = rb->step ? rb->step : 256u;
        /* Grow by step * N where N is minimum steps to fit needed + 1 step headroom */
        size_t shortfall = needed - rb->current_size;
        size_t steps_needed = (shortfall + step - 1) / step; /* ceil division */
        steps_needed += 1; /* +1 for headroom */
        size_t desired = rb->current_size + (steps_needed * step);
        if (rb->max_size != SIZE_MAX && desired > rb->max_size)
        {
            desired = rb->max_size;
        }
        if (desired < needed || desired <= rb->current_size)
        {
            mem_buffer_notify_pressure(rb, needed, MEM_PRESSURE_CRITICAL);
            return NULL;
        }

        size_t grow = desired - rb->current_size;
        if (!skip_heap_accounting && !mem_buffer_charge(grow))
        {
            mem_buffer_notify_pressure(rb, desired, MEM_PRESSURE_CRITICAL);
            return NULL;
        }
        size_t old_cap = rb->current_size;
        size_t old_blocks = rb->u.pool.pool_block_count;
        size_t old_bitmap_bytes = rb->u.pool.pool_bitmap_bytes;

        if (!mem_buffer_resize(rb, desired))
        {
            if (!skip_heap_accounting)
            {
                mem_buffer_release(grow);
            }
            mem_buffer_notify_pressure(rb, desired, MEM_PRESSURE_CRITICAL);
            return NULL;
        }

        size_t new_block_count = rb->current_size / rb->u.pool.pool_block_size;
        size_t new_bitmap_bytes = (new_block_count + 7u) / 8u;
        if (new_bitmap_bytes > rb->u.pool.pool_bitmap_bytes)
        {
            size_t bitmap_grow = new_bitmap_bytes - rb->u.pool.pool_bitmap_bytes;
            if (!skip_heap_accounting && !mem_buffer_charge(bitmap_grow))
            {
                mem_buffer_resize(rb, old_cap);
                if (!skip_heap_accounting)
                {
                    mem_buffer_release(grow);
                }
                mem_buffer_notify_pressure(rb, desired, MEM_PRESSURE_CRITICAL);
                return NULL;
            }
            uint8_t *new_bitmap = NULL;
            if (g_mem_cfg.realloc_fn)
            {
                new_bitmap = (uint8_t *)g_mem_cfg.realloc_fn(rb->u.pool.pool_bitmap, new_bitmap_bytes);
            }
            else
            {
                new_bitmap = (uint8_t *)g_mem_cfg.malloc_fn(new_bitmap_bytes);
                if (new_bitmap)
                {
                    memcpy(new_bitmap, rb->u.pool.pool_bitmap, rb->u.pool.pool_bitmap_bytes);
                    g_mem_cfg.free_fn(rb->u.pool.pool_bitmap);
                }
            }
            if (!new_bitmap)
            {
                if (!skip_heap_accounting)
                {
                    mem_buffer_release(bitmap_grow);
                }
                mem_buffer_resize(rb, old_cap);
                if (!skip_heap_accounting)
                {
                    mem_buffer_release(grow);
                }
                mem_buffer_notify_pressure(rb, desired, MEM_PRESSURE_CRITICAL);
                return NULL;
            }
            memset(new_bitmap + old_bitmap_bytes, 0, new_bitmap_bytes - old_bitmap_bytes);
            rb->u.pool.pool_bitmap = new_bitmap;
            rb->u.pool.pool_bitmap_bytes = new_bitmap_bytes;
        }

        rb->u.pool.pool_block_count = new_block_count;
        if (rb->u.pool.pool_used_blocks > new_block_count)
        {
            rb->u.pool.pool_used_blocks = new_block_count;
        }
        if (old_blocks != new_block_count)
        {
            mem_pressure_maybe_clear(rb);
        }
    }

    size_t blocks_needed = (needed + rb->u.pool.pool_block_size - 1) / rb->u.pool.pool_block_size;
    if (blocks_needed == 0 || blocks_needed > rb->u.pool.pool_block_count)
    {
        return NULL;
    }

    size_t run = 0;
    size_t start = 0;
    for (size_t i = 0; i < rb->u.pool.pool_block_count; i++)
    {
        size_t byte = i / 8u;
        uint8_t mask = (uint8_t)(1u << (i % 8u));
        bool used = (rb->u.pool.pool_bitmap[byte] & mask) != 0;
        if (!used)
        {
            if (run == 0)
            {
                start = i;
            }
            run++;
            if (run == blocks_needed)
            {
                for (size_t j = 0; j < blocks_needed; j++)
                {
                    size_t idx = start + j;
                    size_t b = idx / 8u;
                    uint8_t m = (uint8_t)(1u << (idx % 8u));
                    rb->u.pool.pool_bitmap[b] |= m;
                }
                uint8_t *base = rb->buf + (start * rb->u.pool.pool_block_size);
                *(uint16_t *)base = (uint16_t)blocks_needed;
                rb->u.pool.pool_used_blocks += blocks_needed;
                return (void *)(base + MEM_POOL_HEADER_SIZE);
            }
        }
        else
        {
            run = 0;
        }
    }

    return NULL;
}

void mem_buffer_free(struct mem_buffer *rb, void *ptr)
{
    if (!rb || !mem_buffer_is_pool_type(rb) || !ptr)
    {
        return;
    }

    uint8_t *base = (uint8_t *)ptr - MEM_POOL_HEADER_SIZE;
    if (base < rb->buf || base >= (rb->buf + rb->current_size))
    {
        return;
    }
    size_t offset = (size_t)(base - rb->buf);
    if ((offset % rb->u.pool.pool_block_size) != 0)
    {
        return;
    }
    size_t start = offset / rb->u.pool.pool_block_size;
    uint16_t blocks = *(uint16_t *)base;
    if (blocks == 0 || start + blocks > rb->u.pool.pool_block_count)
    {
        return;
    }

    if ((rb->flags & BUFFER_SECURE_MODE) != 0)
    {
        tls_secure_memzero(base, blocks * rb->u.pool.pool_block_size);
    }

    for (size_t j = 0; j < blocks; j++)
    {
        size_t idx = start + j;
        size_t b = idx / 8u;
        uint8_t m = (uint8_t)(1u << (idx % 8u));
        rb->u.pool.pool_bitmap[b] &= (uint8_t)~m;
    }
    if (rb->u.pool.pool_used_blocks >= blocks)
    {
        rb->u.pool.pool_used_blocks -= blocks;
    }
    else
    {
        rb->u.pool.pool_used_blocks = 0;
    }

    if (rb->step == 0 || rb->u.pool.pool_block_size == 0)
    {
        mem_pressure_maybe_clear(rb);
        return;
    }

    size_t used_bytes = rb->u.pool.pool_used_blocks * rb->u.pool.pool_block_size;
    size_t shrink_threshold = threshold_bytes(rb->current_size, rb->shrink_threshold_pct);
    if (used_bytes > shrink_threshold)
    {
        rb->shrink_hits = 0;
        rb->shrink_stage = 0;
        rb->shrink_hold_next = rb->shrink_hold_base;
        mem_pressure_maybe_clear(rb);
        return;
    }

    size_t free_blocks = 0;
    for (size_t i = rb->u.pool.pool_block_count; i > 0; i--)
    {
        size_t idx = i - 1;
        size_t b = idx / 8u;
        uint8_t m = (uint8_t)(1u << (idx % 8u));
        if ((rb->u.pool.pool_bitmap[b] & m) != 0)
        {
            break;
        }
        free_blocks++;
    }

    if (free_blocks == 0)
    {
        mem_pressure_maybe_clear(rb);
        return;
    }

    size_t step = rb->step ? rb->step : rb->u.pool.pool_block_size;
    if (step < rb->u.pool.pool_block_size)
    {
        step = rb->u.pool.pool_block_size;
    }
    step = (step / rb->u.pool.pool_block_size) * rb->u.pool.pool_block_size;
    if (step == 0)
    {
        step = rb->u.pool.pool_block_size;
    }

    size_t max_shrink_bytes = free_blocks * rb->u.pool.pool_block_size;
    if (rb->shrink_hold_count == 0)
    {
        mem_pressure_maybe_clear(rb);
        return;
    }

    rb->shrink_hits++;
    if (rb->shrink_hits < rb->shrink_hold_next)
    {
        mem_pressure_maybe_clear(rb);
        return;
    }

    if (max_shrink_bytes < step)
    {
        mem_pressure_maybe_clear(rb);
        return;
    }

    size_t new_cap = rb->current_size - step;
    if (new_cap < rb->u.pool.pool_block_size)
    {
        mem_pressure_maybe_clear(rb);
        return;
    }
    if (new_cap < rb->initial_size)
    {
        new_cap = rb->initial_size;
    }

    if (!mem_buffer_resize(rb, new_cap))
    {
        mem_pressure_maybe_clear(rb);
        return;
    }

    rb->u.pool.pool_block_count = new_cap / rb->u.pool.pool_block_size;
    rb->shrink_hits = 0;
    if (rb->shrink_hold_base != 0)
    {
        rb->shrink_stage++;
    }
    rb->shrink_hold_next = mem_buffer_hold_for_stage(rb->shrink_hold_base, rb->shrink_stage);
    mem_pressure_maybe_clear(rb);
}

void mem_buffer_set_grow(struct mem_buffer *mb, uint8_t threshold_pct, size_t step)
{
    if (!mb || threshold_pct > 100)
    {
        return;
    }
    mb->grow_threshold_pct = threshold_pct;
    mb->step = step;
}

void mem_buffer_set_shrink(struct mem_buffer *mb, uint8_t threshold_pct, size_t step)
{
    if (!mb || threshold_pct > 100)
    {
        return;
    }
    mb->shrink_threshold_pct = threshold_pct;
    mb->step = step;
    mb->shrink_hold_count = MEM_SHRINK_HOLD_DEFAULT;
    mb->shrink_hold_base = MEM_SHRINK_HOLD_DEFAULT;
    mb->shrink_hold_next = MEM_SHRINK_HOLD_DEFAULT;
    mb->shrink_stage = 0;
    mb->shrink_hits = 0;
}

void mem_buffer_set_max_size(struct mem_buffer *mb, size_t max_size)
{
    if (!mb)
    {
        return;
    }
    if (max_size == (size_t)-1)
    {
        mb->max_size = SIZE_MAX;
        return;
    }
    if (max_size < mb->current_size)
    {
        mb->max_size = mb->current_size;
        return;
    }
    mb->max_size = max_size;
}

bool mem_buffer_set_lwip_heap(struct mem_buffer *mb)
{
    if (!mb || !mem_buffer_is_pool_type(mb))
    {
        return false;
    }
    g_lwip_heap = mb;
    return true;
}

static void mem_buffer_sort_pools(void)
{
    for (size_t i = 0; i + 1 < g_lwip_pool_count; i++)
    {
        for (size_t j = i + 1; j < g_lwip_pool_count; j++)
        {
            if (!g_lwip_pools[i] || !g_lwip_pools[j])
            {
                continue;
            }
            if (g_lwip_pools[j]->u.pool.pool_block_size < g_lwip_pools[i]->u.pool.pool_block_size)
            {
                struct mem_buffer *tmp = g_lwip_pools[i];
                g_lwip_pools[i] = g_lwip_pools[j];
                g_lwip_pools[j] = tmp;
            }
        }
    }
}

bool mem_buffer_lwip_init_pools(const struct mem_buffer_pool_cfg *pools,
                                size_t pool_count)
{
    if (!pools || pool_count == 0)
    {
        return false;
    }

    if (!g_mem_cfg_ready)
    {
        return false;
    }

    if (pool_count > MEM_LWIP_MAX_POOLS)
    {
        pool_count = MEM_LWIP_MAX_POOLS;
    }

    g_lwip_pool_count = 0;
    for (size_t i = 0; i < pool_count; i++)
    {
        const struct mem_buffer_pool_cfg *cfg = &pools[i];
        if (cfg->block_size == 0 || cfg->block_count == 0)
        {
            continue;
        }
        size_t initial_cap = cfg->block_size * cfg->block_count;
        size_t max_cap = cfg->max_size ? cfg->max_size : initial_cap;
        struct mem_buffer *mb = mem_buffer_create(MEM_BUFFER_POOL, initial_cap, max_cap, cfg->block_size, cfg->flags);
        if (mb)
        {
            g_lwip_pools[g_lwip_pool_count++] = mb;
        }
    }

    if (g_lwip_pool_count == 0)
    {
        return false;
    }

    mem_buffer_sort_pools();
    return true;
}

bool mem_buffer_is_lwip_pool(const struct mem_buffer *mb)
{
    if (!mb)
    {
        return false;
    }
    for (size_t i = 0; i < g_lwip_pool_count; i++)
    {
        if (g_lwip_pools[i] == mb)
        {
            return true;
        }
    }
    return false;
}

void *mem_buffer_custom_malloc(size_t size)
{
    if (g_lwip_pool_count > 0)
    {
        if (size > (SIZE_MAX - MEM_POOL_HEADER_SIZE))
        {
            return NULL;
        }
        size_t needed = size + MEM_POOL_HEADER_SIZE;
        struct mem_buffer *preferred = NULL;
        bool tried_large = false;
        for (size_t i = 0; i < g_lwip_pool_count; i++)
        {
            if (!g_lwip_pools[i])
            {
                continue;
            }
            size_t max_bytes = g_lwip_pools[i]->u.pool.pool_block_size * g_lwip_pools[i]->u.pool.pool_block_count;
            if (needed > max_bytes)
            {
                continue;
            }
            if (g_lwip_pools[i]->u.pool.pool_block_size >= needed)
            {
                tried_large = true;
                if (!preferred)
                {
                    preferred = g_lwip_pools[i];
                }
                size_t used_bytes = g_lwip_pools[i]->u.pool.pool_used_blocks * g_lwip_pools[i]->u.pool.pool_block_size;
                uint8_t usage_pct = mem_buffer_usage_pct(g_lwip_pools[i], used_bytes);
                enum mem_pressure_level level = mem_pressure_level_from_usage(usage_pct);
                if (level != MEM_PRESSURE_NONE && level != g_lwip_pools[i]->last_pressure_level)
                {
                    mem_buffer_notify_pressure(g_lwip_pools[i], needed, level);
                }
                void *ptr = mem_buffer_malloc(g_lwip_pools[i], size);
                if (ptr)
                {
                    return ptr;
                }
            }
        }

        if (tried_large)
        {
            mem_buffer_notify_pressure(preferred, needed, MEM_PRESSURE_CRITICAL);
        }

        for (size_t i = 0; i < g_lwip_pool_count; i++)
        {
            if (!g_lwip_pools[i])
            {
                continue;
            }
            size_t max_bytes = g_lwip_pools[i]->u.pool.pool_block_size * g_lwip_pools[i]->u.pool.pool_block_count;
            if (needed > max_bytes || g_lwip_pools[i]->u.pool.pool_block_size >= needed)
            {
                continue;
            }
            void *ptr = mem_buffer_malloc(g_lwip_pools[i], size);
            if (ptr)
            {
                return ptr;
            }
        }
        return NULL;
    }

    if (!g_lwip_heap)
    {
        return NULL;
    }
    return mem_buffer_malloc(g_lwip_heap, size);
}

void mem_buffer_custom_free(void *ptr)
{
    if (!ptr)
    {
        return;
    }

    if (g_lwip_pool_count > 0)
    {
        for (size_t i = 0; i < g_lwip_pool_count; i++)
        {
            struct mem_buffer *mb = g_lwip_pools[i];
            if (!mb || !mb->buf)
            {
                continue;
            }
            uint8_t *start = mb->buf;
            uint8_t *end = mb->buf + mb->current_size;
            if ((uint8_t *)ptr > start && (uint8_t *)ptr < end)
            {
                mem_buffer_free(mb, ptr);
                return;
            }
        }
    }

    if (g_lwip_heap)
    {
        mem_buffer_free(g_lwip_heap, ptr);
    }
}

void *mem_buffer_custom_calloc(size_t count, size_t size)
{
    if (count == 0 || size == 0)
    {
        return NULL;
    }
    if (size > (SIZE_MAX / count))
    {
        return NULL;
    }
    size_t total = count * size;
    void *ptr = mem_buffer_custom_malloc(total);
    if (ptr)
    {
        memset(ptr, 0, total);
    }
    return ptr;
}

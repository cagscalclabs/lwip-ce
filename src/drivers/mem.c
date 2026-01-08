#include "mem.h"
#include <string.h>

#define MEM_POOL_HEADER_SIZE (sizeof(uint16_t))

static size_t threshold_bytes(size_t cap, uint8_t pct)
{
    return (cap * (size_t)pct) / 100u;
}

static void mem_buffer_notify_lowmem(struct mem_buffer *rb, size_t requested, enum mem_pressure_level level);
static bool mem_buffer_maybe_grow(struct mem_buffer *rb, size_t incoming_len);

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

static bool mem_buffer_charge(struct mem_buffer_config *cfg, size_t bytes)
{
    if (cfg->max_heap == 0)
    {
        return true;
    }
    if (cfg->heap_used + bytes > cfg->max_heap)
    {
        return false;
    }
    cfg->heap_used += bytes;
    return true;
}

static void mem_buffer_release(struct mem_buffer_config *cfg, size_t bytes)
{
    if (cfg->heap_used >= bytes)
    {
        cfg->heap_used -= bytes;
    }
    else
    {
        cfg->heap_used = 0;
    }
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
    if (new_cap < rb->u.ring.len || new_cap == rb->cap)
    {
        return (new_cap == rb->cap);
    }

    if ((rb->flags & BUFFER_LOCK_SIZE) != 0)
    {
        return false;
    }

    if (rb->max_cap != SIZE_MAX && new_cap > rb->max_cap)
    {
        return false;
    }

    size_t old_cap = rb->cap;
    size_t grow = (new_cap > old_cap) ? (new_cap - old_cap) : 0;
    size_t shrink = (old_cap > new_cap) ? (old_cap - new_cap) : 0;
    if (grow > 0 && !mem_buffer_charge(rb->cfg, grow))
    {
        return false;
    }

    uint8_t *new_buf = NULL;
    if (rb->cfg->realloc_fn && rb->u.ring.head == 0 && rb->u.ring.len <= old_cap)
    {
        if ((rb->flags & BUFFER_SECURE_MODE) != 0 && shrink > 0)
        {
            memset(rb->buf + new_cap, 0, shrink);
        }
        new_buf = (uint8_t *)rb->cfg->realloc_fn(rb->buf, new_cap);
        if (!new_buf)
        {
            mem_buffer_notify_lowmem(rb, new_cap, MEM_PRESSURE_CRITICAL);
            if (grow > 0)
            {
                mem_buffer_release(rb->cfg, grow);
            }
            return false;
        }
    }
    else
    {
        new_buf = (uint8_t *)rb->cfg->malloc_fn(new_cap);
        if (!new_buf)
        {
            if (grow > 0)
            {
                mem_buffer_release(rb->cfg, grow);
            }
            return false;
        }

        if (rb->u.ring.len > 0)
        {
            size_t first = rb->cap - rb->u.ring.head;
            if (first > rb->u.ring.len)
            {
                first = rb->u.ring.len;
            }
            memcpy(new_buf, rb->buf + rb->u.ring.head, first);
            memcpy(new_buf + first, rb->buf, rb->u.ring.len - first);
        }

        if ((rb->flags & BUFFER_SECURE_MODE) != 0)
        {
            memset(rb->buf, 0, rb->cap);
        }
        rb->cfg->free_fn(rb->buf);
    }

    rb->buf = new_buf;
    rb->cap = new_cap;
    rb->u.ring.head = 0;
    rb->shrink_hits = 0;
    rb->shrink_stage = 0;
    rb->shrink_hold_next = rb->shrink_hold_base;
    if (shrink > 0)
    {
        mem_buffer_release(rb->cfg, shrink);
    }
    return true;
}

static struct mem_buffer_config g_mem_cfg;
static bool g_mem_cfg_ready = false;
static struct mem_buffer *g_lwip_heap = NULL;
#define MEM_LWIP_MAX_POOLS 6
static struct mem_buffer *g_lwip_pools[MEM_LWIP_MAX_POOLS];
static size_t g_lwip_pool_count = 0;
static struct mem_pressure_hooks g_pressure_hooks;
static bool g_pressure_global_active = false;
static bool g_pressure_eth_active = false;
static bool g_pressure_tls_active = false;
static enum mem_pressure_level g_pressure_global_level = MEM_PRESSURE_NONE;
static enum mem_pressure_level g_pressure_eth_level = MEM_PRESSURE_NONE;
static enum mem_pressure_level g_pressure_tls_level = MEM_PRESSURE_NONE;
static enum mem_pressure_level g_pressure_eth_effective = MEM_PRESSURE_NONE;
static enum mem_pressure_level g_pressure_tls_effective = MEM_PRESSURE_NONE;
static uint8_t g_pressure_clear_pct = 50;

static uint8_t mem_buffer_usage_pct(const struct mem_buffer *rb, size_t used_bytes)
{
    if (!rb || rb->cap == 0)
    {
        return 0;
    }
    size_t limit = rb->cap;
    if (rb->max_cap != SIZE_MAX && rb->max_cap > 0)
    {
        limit = rb->max_cap;
        if (limit < rb->cap)
        {
            limit = rb->cap;
        }
    }
    if (used_bytes > limit)
    {
        used_bytes = limit;
    }
    uint8_t buf_pct = (uint8_t)((used_bytes * 100u) / limit);

    uint8_t heap_pct = 0;
    if (rb->cfg && rb->cfg->max_heap > 0)
    {
        size_t heap_used = rb->cfg->heap_used;
        if (heap_used > rb->cfg->max_heap)
        {
            heap_used = rb->cfg->max_heap;
        }
        heap_pct = (uint8_t)((heap_used * 100u) / rb->cfg->max_heap);
    }

    return (heap_pct > buf_pct) ? heap_pct : buf_pct;
}

enum {
    MEM_PRESSURE_MILD_PCT = 70,
    MEM_PRESSURE_HIGH_PCT = 85,
    MEM_PRESSURE_SEVERE_PCT = 95,
    MEM_PRESSURE_RELIEF_MARGIN = 5
};

static enum mem_pressure_level mem_pressure_level_from_usage(uint8_t usage_pct)
{
    if (usage_pct >= MEM_PRESSURE_SEVERE_PCT)
    {
        return MEM_PRESSURE_SEVERE;
    }
    if (usage_pct >= MEM_PRESSURE_HIGH_PCT)
    {
        return MEM_PRESSURE_HIGH;
    }
    if (usage_pct >= MEM_PRESSURE_MILD_PCT)
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
        if (usage_pct < (MEM_PRESSURE_SEVERE_PCT - MEM_PRESSURE_RELIEF_MARGIN))
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

static void mem_pressure_update_effective(void)
{
    enum mem_pressure_level eth_effective = g_pressure_global_active ? g_pressure_global_level : g_pressure_eth_level;
    if (g_pressure_global_active && g_pressure_global_level == MEM_PRESSURE_CRITICAL)
    {
        eth_effective = MEM_PRESSURE_SEVERE;
    }
    if (g_pressure_eth_active && g_pressure_eth_level > eth_effective)
    {
        eth_effective = g_pressure_eth_level;
    }
    if (eth_effective != g_pressure_eth_effective)
    {
        if (g_pressure_hooks.eth_rx_throttle)
        {
            g_pressure_hooks.eth_rx_throttle(eth_effective);
        }
        g_pressure_eth_effective = eth_effective;
    }

    enum mem_pressure_level tls_effective = g_pressure_global_active ? g_pressure_global_level : g_pressure_tls_level;
    if (g_pressure_tls_active && g_pressure_tls_level > tls_effective)
    {
        tls_effective = g_pressure_tls_level;
    }
    if (tls_effective != g_pressure_tls_effective)
    {
        if (g_pressure_hooks.tls_rx_throttle)
        {
            g_pressure_hooks.tls_rx_throttle(tls_effective);
        }
        g_pressure_tls_effective = tls_effective;
    }
}

static bool mem_pressure_pools_below_clear(void)
{
    for (size_t i = 0; i < g_lwip_pool_count; i++)
    {
        size_t used_bytes = g_lwip_pools[i]->u.pool.pool_used_blocks * g_lwip_pools[i]->u.pool.pool_block_size;
        if (mem_buffer_usage_pct(g_lwip_pools[i], used_bytes) > g_pressure_clear_pct)
        {
            return false;
        }
    }
    return true;
}

static enum mem_pressure_level mem_pressure_pools_level(void)
{
    enum mem_pressure_level level = MEM_PRESSURE_NONE;
    bool any_over_clear = false;
    for (size_t i = 0; i < g_lwip_pool_count; i++)
    {
        size_t used_bytes = g_lwip_pools[i]->u.pool.pool_used_blocks * g_lwip_pools[i]->u.pool.pool_block_size;
        uint8_t usage = mem_buffer_usage_pct(g_lwip_pools[i], used_bytes);
        if (usage > g_pressure_clear_pct)
        {
            any_over_clear = true;
        }
        enum mem_pressure_level candidate = mem_pressure_level_relief(g_lwip_pools[i]->last_pressure_level, usage);
        if (candidate > level)
        {
            level = candidate;
        }
    }
    if (level == MEM_PRESSURE_NONE && any_over_clear)
    {
        level = MEM_PRESSURE_MILD;
    }
    return level;
}

static void mem_pressure_mark(struct mem_buffer *rb, enum mem_pressure_level level)
{
    if (!rb)
    {
        return;
    }
    if (level == MEM_PRESSURE_NONE)
    {
        return;
    }
    switch (rb->owner)
    {
        case MEM_BUF_OWNER_LWIP_POOL:
            g_pressure_global_active = true;
            if (level > g_pressure_global_level)
            {
                g_pressure_global_level = level;
            }
            break;
        case MEM_BUF_OWNER_ETH_RX:
            g_pressure_eth_active = true;
            if (level > g_pressure_eth_level)
            {
                g_pressure_eth_level = level;
            }
            break;
        case MEM_BUF_OWNER_TLS_RX:
            g_pressure_tls_active = true;
            if (level > g_pressure_tls_level)
            {
                g_pressure_tls_level = level;
            }
            break;
        default:
            break;
    }
    mem_pressure_update_effective();
}

static void mem_pressure_maybe_clear(struct mem_buffer *rb)
{
    if (!rb || g_pressure_clear_pct > 100)
    {
        return;
    }
    size_t used_bytes = (rb->flags & BUFFER_MALLOC_TYPE) != 0 ?
        (rb->u.pool.pool_used_blocks * rb->u.pool.pool_block_size) :
        rb->u.ring.len;
    uint8_t usage_pct = mem_buffer_usage_pct(rb, used_bytes);
    enum mem_pressure_level level = mem_pressure_level_relief(rb->last_pressure_level, usage_pct);
    rb->last_pressure_level = level;
    switch (rb->owner)
    {
        case MEM_BUF_OWNER_LWIP_POOL:
            if (g_pressure_global_active && mem_pressure_pools_below_clear())
            {
                g_pressure_global_active = false;
                g_pressure_global_level = MEM_PRESSURE_NONE;
                mem_pressure_update_effective();
            }
            else
            {
                enum mem_pressure_level pool_level = mem_pressure_pools_level();
                if (pool_level == MEM_PRESSURE_NONE)
                {
                    g_pressure_global_active = false;
                    g_pressure_global_level = MEM_PRESSURE_NONE;
                }
                else
                {
                    g_pressure_global_active = true;
                    g_pressure_global_level = pool_level;
                }
                mem_pressure_update_effective();
            }
            break;
        case MEM_BUF_OWNER_ETH_RX:
            if (level == MEM_PRESSURE_NONE)
            {
                g_pressure_eth_active = false;
                g_pressure_eth_level = MEM_PRESSURE_NONE;
                mem_pressure_update_effective();
            }
            else
            {
                g_pressure_eth_active = true;
                g_pressure_eth_level = level;
                mem_pressure_update_effective();
            }
            break;
        case MEM_BUF_OWNER_TLS_RX:
            if (level == MEM_PRESSURE_NONE)
            {
                g_pressure_tls_active = false;
                g_pressure_tls_level = MEM_PRESSURE_NONE;
                mem_pressure_update_effective();
            }
            else
            {
                g_pressure_tls_active = true;
                g_pressure_tls_level = level;
                mem_pressure_update_effective();
            }
            break;
        default:
            break;
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
    g_mem_cfg.step = 0;
    g_mem_cfg.grow_threshold_pct = 0;
    g_mem_cfg.shrink_threshold_pct = 0;
    g_mem_cfg.shrink_hold_count = MEM_SHRINK_HOLD_DEFAULT;
    g_mem_cfg.malloc_fn = malloc_fn;
    g_mem_cfg.free_fn = free_fn;
    g_mem_cfg.realloc_fn = realloc_fn;
    g_mem_cfg.internal_low_mem_cb = NULL;
    g_mem_cfg_ready = true;
    return true;
}

bool mem_is_ready(void)
{
    return g_mem_cfg_ready;
}

void mem_set_internal_lowmem_cb(mem_low_mem_cb low_mem_cb)
{
    g_mem_cfg.internal_low_mem_cb = low_mem_cb;
}

void mem_register_pressure_hook_eth_rx(void (*hook)(enum mem_pressure_level level))
{
    g_pressure_hooks.eth_rx_throttle = hook;
    mem_pressure_update_effective();
}

void mem_register_pressure_hook_tls_rx(void (*hook)(enum mem_pressure_level level))
{
    g_pressure_hooks.tls_rx_throttle = hook;
    mem_pressure_update_effective();
}

enum mem_pressure_level mem_get_global_pressure_level(void)
{
    return g_pressure_global_active ? g_pressure_global_level : MEM_PRESSURE_NONE;
}
void mem_set_pressure_clear_pct(uint8_t pct)
{
    if (pct <= 100)
    {
        g_pressure_clear_pct = pct;
    }
}

struct mem_buffer *mem_buffer_create(size_t initial_cap,
                                     size_t max_cap,
                                     size_t lock_size,
                                     uint8_t flags,
                                     mem_low_mem_cb low_mem_cb)
{
    struct mem_buffer_config *cfg = &g_mem_cfg;
    if (!g_mem_cfg_ready)
    {
        return NULL;
    }
    if (!cfg || initial_cap == 0 || !cfg->malloc_fn || !cfg->free_fn)
    {
        return NULL;
    }

    if (!mem_buffer_charge(cfg, sizeof(struct mem_buffer) + initial_cap))
    {
        return NULL;
    }

    if ((flags & BUFFER_FILEIO_TYPE) != 0)
    {
        flags |= BUFFER_MALLOC_TYPE;
    }

    struct mem_buffer *rb = (struct mem_buffer *)cfg->malloc_fn(sizeof(struct mem_buffer));
    if (!rb)
    {
        mem_buffer_release(cfg, sizeof(struct mem_buffer) + initial_cap);
        return NULL;
    }

    rb->buf = (uint8_t *)cfg->malloc_fn(initial_cap);
    if (!rb->buf)
    {
        cfg->free_fn(rb);
        mem_buffer_release(cfg, sizeof(struct mem_buffer) + initial_cap);
        return NULL;
    }

    rb->cfg = cfg;
    rb->flags = flags;
    rb->u.ring.lock_size = lock_size;
    rb->cap = ((flags & BUFFER_LOCK_SIZE) != 0 && lock_size > 0) ? lock_size : initial_cap;
    rb->max_cap = (max_cap == (size_t)-1) ? SIZE_MAX : max_cap;
    if (rb->max_cap != SIZE_MAX && rb->max_cap < rb->cap)
    {
        rb->max_cap = rb->cap;
    }
    rb->u.ring.len = 0;
    rb->u.ring.head = 0;
    rb->shrink_hits = 0;
    rb->u.pool.pool_block_size = 0;
    rb->u.pool.pool_block_count = 0;
    rb->u.pool.pool_used_blocks = 0;
    rb->u.pool.pool_bitmap = NULL;
    rb->u.pool.pool_bitmap_bytes = 0;
    rb->owner = ((flags & BUFFER_FILEIO_TYPE) != 0) ? MEM_BUF_OWNER_FILEIO : MEM_BUF_OWNER_UNKNOWN;
    rb->last_pressure_level = MEM_PRESSURE_NONE;
    rb->step = cfg->step;
    rb->grow_threshold_pct = cfg->grow_threshold_pct;
    rb->shrink_threshold_pct = cfg->shrink_threshold_pct;
    rb->shrink_hold_count = cfg->shrink_hold_count;
    rb->shrink_hold_base = cfg->shrink_hold_count;
    rb->shrink_hold_next = cfg->shrink_hold_count;
    rb->shrink_stage = 0;
    rb->low_mem_cb = low_mem_cb;
    rb->drain_fn = NULL;
    rb->drain_fn_data = NULL;

    if ((flags & BUFFER_LOCK_SIZE) != 0 && rb->cap != initial_cap)
    {
        if (rb->cap > initial_cap)
        {
            size_t grow = rb->cap - initial_cap;
            if (!mem_buffer_charge(cfg, grow))
            {
                cfg->free_fn(rb->buf);
                cfg->free_fn(rb);
                mem_buffer_release(cfg, sizeof(struct mem_buffer) + initial_cap);
                return NULL;
            }
            uint8_t *new_buf = NULL;
            if (cfg->realloc_fn)
            {
                new_buf = (uint8_t *)cfg->realloc_fn(rb->buf, rb->cap);
            }
            else
            {
                new_buf = (uint8_t *)cfg->malloc_fn(rb->cap);
                if (new_buf)
                {
                    memcpy(new_buf, rb->buf, rb->u.ring.len);
                    cfg->free_fn(rb->buf);
                }
            }
            if (!new_buf)
            {
                mem_buffer_release(cfg, grow);
                cfg->free_fn(rb->buf);
                cfg->free_fn(rb);
                mem_buffer_release(cfg, sizeof(struct mem_buffer) + initial_cap);
                return NULL;
            }
            rb->buf = new_buf;
        }
        else if (rb->cap < initial_cap)
        {
            size_t shrink = initial_cap - rb->cap;
            uint8_t *new_buf = NULL;
            if (cfg->realloc_fn)
            {
                new_buf = (uint8_t *)cfg->realloc_fn(rb->buf, rb->cap);
            }
            else
            {
                new_buf = (uint8_t *)cfg->malloc_fn(rb->cap);
                if (new_buf)
                {
                    memcpy(new_buf, rb->buf, rb->u.ring.len);
                    cfg->free_fn(rb->buf);
                }
            }
            if (new_buf)
            {
                rb->buf = new_buf;
                mem_buffer_release(cfg, shrink);
            }
        }
    }

    if ((flags & BUFFER_MALLOC_TYPE) != 0)
    {
        size_t block_size = lock_size ? lock_size : rb->step;
        if (block_size == 0)
        {
            block_size = 256u;
        }
        if (rb->cap < block_size)
        {
            mem_buffer_destroy(rb);
            return NULL;
        }
        rb->u.pool.pool_block_size = block_size;
        rb->u.pool.pool_block_count = rb->cap / block_size;
        rb->u.pool.pool_bitmap_bytes = (rb->u.pool.pool_block_count + 7u) / 8u;
        if (!mem_buffer_charge(cfg, rb->u.pool.pool_bitmap_bytes))
        {
            mem_buffer_destroy(rb);
            return NULL;
        }
        rb->u.pool.pool_bitmap = (uint8_t *)cfg->malloc_fn(rb->u.pool.pool_bitmap_bytes);
        if (!rb->u.pool.pool_bitmap)
        {
            mem_buffer_release(cfg, rb->u.pool.pool_bitmap_bytes);
            mem_buffer_destroy(rb);
            return NULL;
        }
        memset(rb->u.pool.pool_bitmap, 0, rb->u.pool.pool_bitmap_bytes);
    }
    return rb;
}

void mem_buffer_destroy(struct mem_buffer *rb)
{
    if (!rb || !rb->cfg)
    {
        return;
    }

    struct mem_buffer_config *cfg = rb->cfg;
    if (rb->buf)
    {
        if ((rb->flags & BUFFER_SECURE_MODE) != 0)
        {
            memset(rb->buf, 0, rb->cap);
        }
        cfg->free_fn(rb->buf);
        mem_buffer_release(cfg, rb->cap);
        rb->buf = NULL;
    }
    if (rb->u.pool.pool_bitmap)
    {
        if ((rb->flags & BUFFER_SECURE_MODE) != 0)
        {
            memset(rb->u.pool.pool_bitmap, 0, rb->u.pool.pool_bitmap_bytes);
        }
        cfg->free_fn(rb->u.pool.pool_bitmap);
        mem_buffer_release(cfg, rb->u.pool.pool_bitmap_bytes);
        rb->u.pool.pool_bitmap = NULL;
        rb->u.pool.pool_bitmap_bytes = 0;
    }
    cfg->free_fn(rb);
    mem_buffer_release(cfg, sizeof(struct mem_buffer));
}

size_t mem_buffer_len(const struct mem_buffer *rb)
{
    return rb ? rb->u.ring.len : 0;
}

size_t mem_buffer_capacity(const struct mem_buffer *rb)
{
    return rb ? rb->cap : 0;
}

size_t mem_buffer_space(const struct mem_buffer *rb)
{
    if (!rb || rb->cap < rb->u.ring.len)
    {
        return 0;
    }
    return rb->cap - rb->u.ring.len;
}

bool mem_buffer_peek(const struct mem_buffer *rb, size_t offset, uint8_t *out, size_t len)
{
    if (!rb || !out || len == 0 || offset + len > rb->u.ring.len)
    {
        return false;
    }

    size_t pos = (rb->u.ring.head + offset) % rb->cap;
    size_t first = rb->cap - pos;
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
    if ((rb->flags & BUFFER_MALLOC_TYPE) != 0)
    {
        return false;
    }
    return mem_buffer_maybe_grow(rb, len);
}

void mem_buffer_set_owner(struct mem_buffer *rb, enum mem_buffer_owner owner)
{
    if (rb)
    {
        rb->owner = owner;
    }
}

enum mem_buffer_owner mem_buffer_get_owner(const struct mem_buffer *rb)
{
    return rb ? rb->owner : MEM_BUF_OWNER_UNKNOWN;
}

void mem_buffer_set_drain(struct mem_buffer *rb, mem_drain_fn drain_fn, void *drain_fn_data)
{
    if (rb)
    {
        rb->drain_fn = drain_fn;
        rb->drain_fn_data = drain_fn_data;
    }
}

static void mem_buffer_notify_lowmem(struct mem_buffer *rb, size_t requested, enum mem_pressure_level level)
{
    if (!rb)
    {
        return;
    }
    mem_pressure_mark(rb, level);
    rb->last_pressure_level = level;
    if (rb->cfg && rb->cfg->internal_low_mem_cb)
    {
        rb->cfg->internal_low_mem_cb(rb, requested, level);
    }
    if (rb->low_mem_cb)
    {
        rb->low_mem_cb(rb, requested, level);
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
            mem_buffer_notify_lowmem(rb, needed, level);
        }
        if (needed > rb->cap)
        {
            mem_buffer_notify_lowmem(rb, needed, MEM_PRESSURE_CRITICAL);
        }
        return needed <= rb->cap;
    }

    size_t needed = rb->u.ring.len + incoming_len;
    uint8_t usage_pct = mem_buffer_usage_pct(rb, needed);
    enum mem_pressure_level level = mem_pressure_level_from_usage(usage_pct);
    if (level != MEM_PRESSURE_NONE && level != rb->last_pressure_level)
    {
        mem_buffer_notify_lowmem(rb, needed, level);
    }
    size_t grow_threshold = threshold_bytes(rb->cap, rb->grow_threshold_pct);
    if (needed <= rb->cap && needed < grow_threshold)
    {
        return true;
    }

    size_t target = rb->cap;
    if (needed > target)
    {
        target = needed;
    }
    target = align_step(target, rb->step);
    if (target <= rb->cap)
    {
        target = rb->cap + rb->step;
    }
    if (target < needed)
    {
        target = needed;
    }
    if (rb->max_cap != SIZE_MAX && target > rb->max_cap)
    {
        target = rb->max_cap;
        if (target < needed)
        {
            mem_buffer_notify_lowmem(rb, needed, MEM_PRESSURE_CRITICAL);
            return false;
        }
    }
    if (!mem_buffer_resize(rb, target))
    {
        mem_buffer_notify_lowmem(rb, needed, MEM_PRESSURE_CRITICAL);
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

    if (rb->step == 0 || rb->cap <= rb->step)
    {
        return;
    }

    if (!wrapped || rb->u.ring.head != 0)
    {
        return;
    }

    size_t shrink_threshold = threshold_bytes(rb->cap, rb->shrink_threshold_pct);
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

    size_t target = rb->cap - rb->step;
    if (target < rb->u.ring.len)
    {
        target = rb->u.ring.len;
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

    if ((rb->flags & BUFFER_MALLOC_TYPE) != 0)
    {
        return false;
    }

    if (!mem_buffer_maybe_grow(rb, len))
    {
        return false;
    }

    size_t tail = (rb->u.ring.head + rb->u.ring.len) % rb->cap;
    size_t first = rb->cap - tail;
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

    if ((rb->flags & BUFFER_MALLOC_TYPE) != 0)
    {
        return 0;
    }

    size_t first = rb->cap - rb->u.ring.head;
    if (first > len)
    {
        first = len;
    }
    memcpy(out, rb->buf + rb->u.ring.head, first);
    memcpy(out + first, rb->buf, len - first);

    if ((rb->flags & BUFFER_SECURE_MODE) != 0)
    {
        memset(rb->buf + rb->u.ring.head, 0, first);
        memset(rb->buf, 0, len - first);
    }

    size_t old_head = rb->u.ring.head;
    rb->u.ring.head = (rb->u.ring.head + len) % rb->cap;
    rb->u.ring.len -= len;
    bool wrapped = (old_head + len) >= rb->cap;
    mem_buffer_maybe_shrink(rb, wrapped);
    mem_pressure_maybe_clear(rb);
    return len;
}

void *mem_buffer_malloc(struct mem_buffer *rb, size_t size)
{
    if (!rb || (rb->flags & BUFFER_MALLOC_TYPE) == 0 || size == 0)
    {
        return NULL;
    }

    size_t needed = size + MEM_POOL_HEADER_SIZE;
    if (rb->u.pool.pool_block_size == 0)
    {
        return NULL;
    }

    if (needed > rb->cap && (rb->flags & BUFFER_LOCK_SIZE) == 0)
    {
        size_t step = rb->step ? rb->step : 256u;
        size_t desired = align_step(needed, step);
        if (desired < needed)
        {
            return NULL;
        }
        if (rb->max_cap != SIZE_MAX && desired > rb->max_cap)
        {
            desired = rb->max_cap;
        }
        if (desired < needed || desired <= rb->cap)
        {
            return NULL;
        }

        size_t grow = desired - rb->cap;
        if (!mem_buffer_charge(rb->cfg, grow))
        {
            mem_buffer_notify_lowmem(rb, desired, MEM_PRESSURE_CRITICAL);
            return NULL;
        }
        size_t old_cap = rb->cap;
        size_t old_blocks = rb->u.pool.pool_block_count;
        size_t old_bitmap_bytes = rb->u.pool.pool_bitmap_bytes;

        if (!mem_buffer_resize(rb, desired))
        {
            mem_buffer_release(rb->cfg, grow);
            mem_buffer_notify_lowmem(rb, desired, MEM_PRESSURE_CRITICAL);
            return NULL;
        }

        size_t new_block_count = rb->cap / rb->u.pool.pool_block_size;
        size_t new_bitmap_bytes = (new_block_count + 7u) / 8u;
        if (new_bitmap_bytes > rb->u.pool.pool_bitmap_bytes)
        {
            size_t bitmap_grow = new_bitmap_bytes - rb->u.pool.pool_bitmap_bytes;
            if (!mem_buffer_charge(rb->cfg, bitmap_grow))
            {
                mem_buffer_resize(rb, old_cap);
                mem_buffer_release(rb->cfg, grow);
                mem_buffer_notify_lowmem(rb, desired, MEM_PRESSURE_CRITICAL);
                return NULL;
            }
            uint8_t *new_bitmap = NULL;
            if (rb->cfg->realloc_fn)
            {
                new_bitmap = (uint8_t *)rb->cfg->realloc_fn(rb->u.pool.pool_bitmap, new_bitmap_bytes);
            }
            else
            {
                new_bitmap = (uint8_t *)rb->cfg->malloc_fn(new_bitmap_bytes);
                if (new_bitmap)
                {
                    memcpy(new_bitmap, rb->u.pool.pool_bitmap, rb->u.pool.pool_bitmap_bytes);
                    rb->cfg->free_fn(rb->u.pool.pool_bitmap);
                }
            }
            if (!new_bitmap)
            {
                mem_buffer_release(rb->cfg, bitmap_grow);
                mem_buffer_resize(rb, old_cap);
                mem_buffer_release(rb->cfg, grow);
                mem_buffer_notify_lowmem(rb, desired, MEM_PRESSURE_CRITICAL);
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
    if (!rb || (rb->flags & BUFFER_MALLOC_TYPE) == 0 || !ptr)
    {
        return;
    }

    uint8_t *base = (uint8_t *)ptr - MEM_POOL_HEADER_SIZE;
    if (base < rb->buf || base >= (rb->buf + rb->cap))
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
        memset(base, 0, blocks * rb->u.pool.pool_block_size);
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
    size_t shrink_threshold = threshold_bytes(rb->cap, rb->shrink_threshold_pct);
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

    size_t new_cap = rb->cap - step;
    if (new_cap < rb->u.pool.pool_block_size)
    {
        mem_pressure_maybe_clear(rb);
        return;
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

void mem_buffer_set_max_size(struct mem_buffer *mb, size_t max_cap)
{
    if (!mb)
    {
        return;
    }
    if (max_cap == (size_t)-1)
    {
        mb->max_cap = SIZE_MAX;
        return;
    }
    if (max_cap < mb->cap)
    {
        mb->max_cap = mb->cap;
        return;
    }
    mb->max_cap = max_cap;
}

bool mem_buffer_set_lwip_heap(struct mem_buffer *mb)
{
    if (!mb || (mb->flags & BUFFER_MALLOC_TYPE) == 0)
    {
        return false;
    }
    g_lwip_heap = mb;
    mem_buffer_set_owner(mb, MEM_BUF_OWNER_LWIP_POOL);
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
        size_t max_cap = cfg->max_cap ? cfg->max_cap : initial_cap;
        uint8_t flags = (uint8_t)(cfg->flags | BUFFER_MALLOC_TYPE);
        struct mem_buffer *mb = mem_buffer_create(initial_cap, max_cap, cfg->block_size, flags, cfg->low_mem_cb);
        if (mb)
        {
            enum mem_buffer_owner owner = cfg->owner ? cfg->owner : MEM_BUF_OWNER_LWIP_POOL;
            mem_buffer_set_owner(mb, owner);
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
                    mem_buffer_notify_lowmem(g_lwip_pools[i], needed, level);
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
            mem_buffer_notify_lowmem(preferred, needed, MEM_PRESSURE_CRITICAL);
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
            uint8_t *end = mb->buf + mb->cap;
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

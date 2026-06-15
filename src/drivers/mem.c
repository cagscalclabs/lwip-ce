#include "mem.h"
#include <string.h>
#include "../tls/includes/bytes.h"

#define MEM_POOL_HEADER_SIZE (sizeof(uint16_t))
#define MEM_STATIC_ALIGN 8u
#define MEM_DIRECT_MAGIC 0x4D42u
#define MEM_DIRECT_FLAG_USER 0x0001u

enum mem_init_mode
{
    MEM_INIT_MODE_DYNAMIC = 0,
    MEM_INIT_MODE_STATIC = 1
};

static size_t threshold_bytes(size_t cap, uint8_t pct)
{
    return (cap * (size_t)pct) / 100u;
}

static void mem_buffer_notify_pressure(struct mem_buffer *rb, size_t requested, enum mem_pressure_level level);
static bool mem_buffer_maybe_grow(struct mem_buffer *rb, size_t incoming_len);
static bool mem_buffer_is_pool_type(const struct mem_buffer *rb);
static enum mem_pressure_level mem_pressure_level_from_usage(uint8_t usage_pct);
static void mem_global_pressure_update(void);
static void mem_effective_pressure_update(void);

#define MEM_SHRINK_HOLD_DEFAULT 1u

struct mem_global_config
{
    size_t max_heap;
    size_t heap_used;
    size_t user_reserved;
    mem_malloc_fn malloc_fn;
    mem_free_fn free_fn;
    mem_realloc_fn realloc_fn;
};

struct mem_direct_header
{
    uint16_t magic;
    uint16_t flags;
    size_t size;
};

static struct mem_global_config g_mem_cfg;
static bool g_mem_cfg_ready = false;
static enum mem_pressure_level g_global_pressure_level = MEM_PRESSURE_NONE;
static enum mem_pressure_level g_effective_pressure_level = MEM_PRESSURE_NONE;
static mem_global_pressure_cb g_global_pressure_cb = NULL;
static enum mem_init_mode g_mem_mode = MEM_INIT_MODE_DYNAMIC;

#define MEM_LWIP_MAX_POOLS 6
static struct mem_buffer *g_lwip_pools[MEM_LWIP_MAX_POOLS];
static size_t g_lwip_pool_count = 0;
static struct mem_buffer *g_lwip_pbuf_pool = NULL;
static struct mem_buffer *g_mem_buffer_stats_head = NULL;
static size_t g_mem_tls_direct_used = 0;
static size_t g_mem_tls_direct_limit = 0;

struct mem_static_block
{
    size_t size;
    struct mem_static_block *next;
    struct mem_static_block *prev;
    uint8_t free;
};

static struct
{
    uint8_t *base;
    size_t size;
    struct mem_static_block *head;
    bool ready;
} g_mem_static;

static size_t mem_static_used_bytes(void)
{
    if (!g_mem_static.ready)
    {
        return 0;
    }

    size_t free_payload = 0;
    struct mem_static_block *blk = g_mem_static.head;
    while (blk)
    {
        if (blk->free)
        {
            free_payload += blk->size;
        }
        blk = blk->next;
    }

    if (g_mem_static.size < free_payload)
    {
        return g_mem_static.size;
    }
    return g_mem_static.size - free_payload;
}

static size_t mem_pbuf_pool_size(void)
{
    return g_lwip_pbuf_pool ? g_lwip_pbuf_pool->current_size : 0;
}

static size_t mem_pbuf_pool_used(void)
{
    if (!g_lwip_pbuf_pool)
    {
        return 0;
    }
    return g_lwip_pbuf_pool->u.pool.pool_used_blocks *
           g_lwip_pbuf_pool->u.pool.pool_block_size;
}

static void mem_buffer_stats_register(struct mem_buffer *rb)
{
    if (!rb)
    {
        return;
    }
    rb->stats_next = g_mem_buffer_stats_head;
    g_mem_buffer_stats_head = rb;
}

static void mem_buffer_stats_unregister(struct mem_buffer *rb)
{
    if (!rb)
    {
        return;
    }
    struct mem_buffer **slot = &g_mem_buffer_stats_head;
    while (*slot)
    {
        if (*slot == rb)
        {
            *slot = rb->stats_next;
            rb->stats_next = NULL;
            return;
        }
        slot = &(*slot)->stats_next;
    }
}

static size_t mem_nonpool_limit(void)
{
    if (!g_mem_cfg_ready || g_mem_cfg.max_heap == 0 ||
        g_mem_cfg.max_heap == SIZE_MAX)
    {
        return SIZE_MAX;
    }

    size_t reserved = mem_pbuf_pool_size() + g_mem_cfg.user_reserved;
    if (reserved >= g_mem_cfg.max_heap)
    {
        return 0;
    }
    return g_mem_cfg.max_heap - reserved;
}

static size_t mem_static_align_up(size_t n)
{
    return (n + (MEM_STATIC_ALIGN - 1u)) & ~(MEM_STATIC_ALIGN - 1u);
}

static void mem_static_init(void *buffer, size_t buffer_size)
{
    uint8_t *base = (uint8_t *)buffer;
    size_t aligned_addr = mem_static_align_up((size_t)base);
    size_t delta = aligned_addr - (size_t)base;

    if (buffer_size <= delta + sizeof(struct mem_static_block))
    {
        memset(&g_mem_static, 0, sizeof(g_mem_static));
        return;
    }

    g_mem_static.base = (uint8_t *)aligned_addr;
    g_mem_static.size = buffer_size - delta;
    g_mem_static.head = (struct mem_static_block *)g_mem_static.base;
    g_mem_static.head->size = g_mem_static.size - sizeof(struct mem_static_block);
    g_mem_static.head->next = NULL;
    g_mem_static.head->prev = NULL;
    g_mem_static.head->free = 1u;
    g_mem_static.ready = true;
    mem_global_pressure_update();
}

static void mem_static_split_block(struct mem_static_block *blk, size_t need)
{
    size_t remain = blk->size - need;
    if (remain <= sizeof(struct mem_static_block) + MEM_STATIC_ALIGN)
    {
        return;
    }

    struct mem_static_block *nxt =
        (struct mem_static_block *)((uint8_t *)blk + sizeof(struct mem_static_block) + need);
    nxt->size = remain - sizeof(struct mem_static_block);
    nxt->free = 1u;
    nxt->next = blk->next;
    nxt->prev = blk;
    if (nxt->next)
    {
        nxt->next->prev = nxt;
    }
    blk->next = nxt;
    blk->size = need;
}

static void *mem_static_malloc(size_t size)
{
    if (!g_mem_static.ready || size == 0)
    {
        return NULL;
    }

    size_t need = mem_static_align_up(size);
    struct mem_static_block *blk = g_mem_static.head;
    while (blk)
    {
        if (blk->free && blk->size >= need)
        {
            mem_static_split_block(blk, need);
            blk->free = 0u;
            mem_global_pressure_update();
            return (uint8_t *)blk + sizeof(struct mem_static_block);
        }
        blk = blk->next;
    }
    return NULL;
}

static void mem_static_merge_forward(struct mem_static_block *blk)
{
    while (blk && blk->next && blk->next->free)
    {
        struct mem_static_block *nxt = blk->next;
        blk->size += sizeof(struct mem_static_block) + nxt->size;
        blk->next = nxt->next;
        if (blk->next)
        {
            blk->next->prev = blk;
        }
    }
}

static void mem_static_free(void *ptr)
{
    if (!g_mem_static.ready || !ptr)
    {
        return;
    }

    struct mem_static_block *blk =
        (struct mem_static_block *)((uint8_t *)ptr - sizeof(struct mem_static_block));
    blk->free = 1u;
    mem_static_merge_forward(blk);
    if (blk->prev && blk->prev->free)
    {
        mem_static_merge_forward(blk->prev);
    }
    mem_global_pressure_update();
}

static void *mem_static_realloc(void *ptr, size_t size)
{
    if (!ptr)
    {
        return mem_static_malloc(size);
    }
    if (size == 0)
    {
        mem_static_free(ptr);
        return NULL;
    }
    if (!g_mem_static.ready)
    {
        return NULL;
    }

    size_t need = mem_static_align_up(size);
    struct mem_static_block *blk =
        (struct mem_static_block *)((uint8_t *)ptr - sizeof(struct mem_static_block));
    if (blk->size >= need)
    {
        mem_static_split_block(blk, need);
        mem_global_pressure_update();
        return ptr;
    }

    if (blk->next && blk->next->free &&
        blk->size + sizeof(struct mem_static_block) + blk->next->size >= need)
    {
        mem_static_merge_forward(blk);
        mem_static_split_block(blk, need);
        blk->free = 0u;
        mem_global_pressure_update();
        return ptr;
    }

    void *np = mem_static_malloc(size);
    if (!np)
    {
        return NULL;
    }
    memcpy(np, ptr, blk->size < size ? blk->size : size);
    mem_static_free(ptr);
    mem_global_pressure_update();
    return np;
}

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
    if (rb->type == MEM_BUFFER_FILE)
    {
        return rb->u.file.used_bytes;
    }
    return rb->u.ring.len;
}

static enum mem_pressure_level mem_pressure_base(enum mem_pressure_level level)
{
    return (enum mem_pressure_level)((unsigned)level & ~MEM_PRESSURE_GLOBAL);
}

static enum mem_pressure_level mem_pressure_max(enum mem_pressure_level a,
                                                enum mem_pressure_level b)
{
    enum mem_pressure_level base_a = mem_pressure_base(a);
    enum mem_pressure_level base_b = mem_pressure_base(b);
    return (base_b > base_a) ? base_b : base_a;
}

static enum mem_pressure_level mem_effective_pressure_compute(void)
{
    enum mem_pressure_level level = mem_pressure_base(g_global_pressure_level);
    if (g_lwip_pbuf_pool)
    {
        level = mem_pressure_max(level, g_lwip_pbuf_pool->last_pressure_level);
    }
    return level;
}

static void mem_effective_pressure_update(void)
{
    enum mem_pressure_level level = mem_effective_pressure_compute();
    if (level == g_effective_pressure_level)
    {
        return;
    }
    g_effective_pressure_level = level;
    if (g_global_pressure_cb)
    {
        g_global_pressure_cb(level);
    }
}

static void mem_global_pressure_update(void)
{
    if (g_mem_mode == MEM_INIT_MODE_STATIC)
    {
        if (!g_mem_cfg_ready || !g_mem_static.ready || g_mem_static.size == 0)
        {
            g_global_pressure_level = MEM_PRESSURE_NONE;
            mem_effective_pressure_update();
            return;
        }
        size_t used = mem_static_used_bytes();
        uint8_t usage_pct = (uint8_t)((used * 100u) / g_mem_static.size);
        g_global_pressure_level = mem_pressure_level_from_usage(usage_pct);
        mem_effective_pressure_update();
        return;
    }
    if (!g_mem_cfg_ready || g_mem_cfg.max_heap == 0)
    {
        g_global_pressure_level = MEM_PRESSURE_NONE;
        mem_effective_pressure_update();
        return;
    }
    size_t limit = mem_nonpool_limit();
    if (limit == 0 || limit == SIZE_MAX)
    {
        g_global_pressure_level = MEM_PRESSURE_NONE;
        mem_effective_pressure_update();
        return;
    }
    uint8_t usage_pct = (uint8_t)((g_mem_cfg.heap_used * 100u) / limit);
    g_global_pressure_level = mem_pressure_level_from_usage(usage_pct);
    mem_effective_pressure_update();
}

static bool mem_buffer_charge(size_t bytes)
{
    size_t limit = mem_nonpool_limit();
    if (limit == SIZE_MAX)
    {
        return true;
    }
    if (bytes > limit || g_mem_cfg.heap_used > limit - bytes)
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

    bool skip_heap_accounting =
        (rb->flags & (BUFFER_USER_ALLOC | BUFFER_LWIP_PBUF_POOL)) != 0;
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
    return rb && (rb->type == MEM_BUFFER_POOL);
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
    return mem_init_dynamic(max_heap, malloc_fn, free_fn, realloc_fn);
}

bool mem_init_dynamic(size_t max_heap,
                      mem_malloc_fn malloc_fn,
                      mem_free_fn free_fn,
                      mem_realloc_fn realloc_fn)
{
    if (!malloc_fn || !free_fn)
    {
        return false;
    }

    memset(&g_mem_static, 0, sizeof(g_mem_static));
    g_mem_cfg.max_heap = max_heap;
    g_mem_cfg.heap_used = 0;
    g_mem_cfg.user_reserved = 0;
    g_mem_cfg.malloc_fn = malloc_fn;
    g_mem_cfg.free_fn = free_fn;
    g_mem_cfg.realloc_fn = realloc_fn;
    g_global_pressure_level = MEM_PRESSURE_NONE;
    memset(g_lwip_pools, 0, sizeof(g_lwip_pools));
    g_lwip_pool_count = 0;
    g_lwip_pbuf_pool = NULL;
    g_mem_buffer_stats_head = NULL;
    g_mem_tls_direct_used = 0;
    g_mem_tls_direct_limit = 0;
    g_mem_mode = MEM_INIT_MODE_DYNAMIC;
    g_mem_cfg_ready = true;
    mem_effective_pressure_update();
    return true;
}

bool mem_init_static(void *buffer, size_t buffer_size)
{
    if (!buffer || buffer_size < (sizeof(struct mem_static_block) + MEM_STATIC_ALIGN))
    {
        return false;
    }

    mem_static_init(buffer, buffer_size);
    if (!g_mem_static.ready)
    {
        return false;
    }

    g_mem_cfg.max_heap = 0;
    g_mem_cfg.heap_used = 0;
    g_mem_cfg.user_reserved = 0;
    g_mem_cfg.malloc_fn = mem_static_malloc;
    g_mem_cfg.free_fn = mem_static_free;
    g_mem_cfg.realloc_fn = mem_static_realloc;
    g_global_pressure_level = MEM_PRESSURE_NONE;
    memset(g_lwip_pools, 0, sizeof(g_lwip_pools));
    g_lwip_pool_count = 0;
    g_lwip_pbuf_pool = NULL;
    g_mem_buffer_stats_head = NULL;
    g_mem_tls_direct_used = 0;
    g_mem_tls_direct_limit = 0;
    g_mem_mode = MEM_INIT_MODE_STATIC;
    g_mem_cfg_ready = true;
    mem_effective_pressure_update();
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

bool mem_get_stats(struct mem_accounting_stats *stats)
{
    if (!stats || !g_mem_cfg_ready)
    {
        return false;
    }

    memset(stats, 0, sizeof(*stats));
    stats->total_heap = (g_mem_mode == MEM_INIT_MODE_STATIC) ?
        g_mem_static.size : g_mem_cfg.max_heap;
    stats->pbuf_pool_size = mem_pbuf_pool_size();
    stats->pbuf_pool_used = mem_pbuf_pool_used();
    stats->heap_limit = mem_nonpool_limit();
    if (stats->heap_limit == SIZE_MAX)
    {
        stats->heap_limit = 0;
    }
    stats->heap_used = (g_mem_mode == MEM_INIT_MODE_STATIC) ?
        mem_static_used_bytes() : g_mem_cfg.heap_used;
    stats->heap_free = (stats->heap_limit > stats->heap_used) ?
        (stats->heap_limit - stats->heap_used) : 0;
    stats->user_reserved = g_mem_cfg.user_reserved;
    stats->tls_used = g_mem_tls_direct_used;
    stats->tls_limit = g_mem_tls_direct_limit;
    for (struct mem_buffer *rb = g_mem_buffer_stats_head; rb; rb = rb->stats_next)
    {
        size_t used = mem_buffer_used_bytes(rb);
        size_t size = rb->current_size;
        if (rb->type == MEM_BUFFER_FILE)
        {
            size = (rb->max_size == SIZE_MAX) ? rb->current_size : rb->max_size;
        }
        if (rb->flags & BUFFER_RX_RING)
        {
            stats->rx_ring_used += used;
            stats->rx_ring_size += size;
        }
        if (rb->flags & BUFFER_SOCKET_RING)
        {
            stats->socket_ring_used += used;
            stats->socket_ring_size += size;
        }
        if (rb->flags & BUFFER_TLS_ALLOC)
        {
            stats->tls_used += used;
            stats->tls_limit += size;
        }
    }
    stats->pbuf_pressure = g_lwip_pbuf_pool ?
        g_lwip_pbuf_pool->last_pressure_level : MEM_PRESSURE_NONE;
    stats->heap_pressure = g_global_pressure_level;
    stats->effective_pressure = g_effective_pressure_level;
    return true;
}

void mem_stats_tls_direct_add(size_t used, size_t limit)
{
    g_mem_tls_direct_used += used;
    g_mem_tls_direct_limit += limit;
}

void mem_stats_tls_direct_release(size_t used, size_t limit)
{
    g_mem_tls_direct_used = (g_mem_tls_direct_used >= used) ?
        (g_mem_tls_direct_used - used) : 0;
    g_mem_tls_direct_limit = (g_mem_tls_direct_limit >= limit) ?
        (g_mem_tls_direct_limit - limit) : 0;
}

void mem_set_global_pressure_cb(mem_global_pressure_cb cb)
{
    g_global_pressure_cb = cb;
    if (g_global_pressure_cb)
    {
        g_global_pressure_cb(g_effective_pressure_level);
    }
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
    if ((initial_size == 0 && type != MEM_BUFFER_FILE) || !g_mem_cfg.malloc_fn || !g_mem_cfg.free_fn)
    {
        return NULL;
    }

    if (g_mem_mode == MEM_INIT_MODE_STATIC)
    {
        flags |= BUFFER_LOCK_SIZE;
    }

    /* BUFFER_USER_ALLOC buffers don't count toward heap */
    bool skip_heap_accounting =
        (flags & (BUFFER_USER_ALLOC | BUFFER_LWIP_PBUF_POOL)) != 0;
    if (type == MEM_BUFFER_FILE)
    {
        skip_heap_accounting = true;
    }
    if (!skip_heap_accounting)
    {
        if (!mem_buffer_charge(sizeof(struct mem_buffer) + initial_size))
        {
            return NULL;
        }
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

    rb->buf = NULL;
    if (type != MEM_BUFFER_FILE)
    {
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
    }

    rb->type = type;
    rb->flags = flags;
    rb->initial_size = initial_size;
    rb->current_size = (type == MEM_BUFFER_FILE) ? 0 : initial_size;
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
    rb->stats_next = NULL;

    /* Initialize type-specific fields */
    if (type == MEM_BUFFER_RING)
    {
        rb->u.ring.len = 0;
        rb->u.ring.head = 0;
        rb->u.ring.drain_fn = NULL;
        rb->u.ring.drain_fn_data = NULL;
    }
    else if (type == MEM_BUFFER_FILE)
    {
        rb->u.file.used_bytes = 0;
        rb->u.file.max_slots = MEM_FILE_MAX_SLOTS;
        rb->u.file.slots = (struct mem_file_slot *)g_mem_cfg.malloc_fn(sizeof(struct mem_file_slot) * MEM_FILE_MAX_SLOTS);
        if (!rb->u.file.slots)
        {
            g_mem_cfg.free_fn(rb);
            if (rb->buf)
            {
                g_mem_cfg.free_fn(rb->buf);
            }
            if (!skip_heap_accounting)
            {
                mem_buffer_release(sizeof(struct mem_buffer) + initial_size);
            }
            return NULL;
        }
        memset(rb->u.file.slots, 0, sizeof(struct mem_file_slot) * MEM_FILE_MAX_SLOTS);
    }
    else
    {
        /* Pool type */
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
    mem_buffer_stats_register(rb);
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
    mem_buffer_stats_unregister(rb);
    bool skip_heap_accounting =
        (rb->flags & (BUFFER_USER_ALLOC | BUFFER_LWIP_PBUF_POOL)) != 0;

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
    if (rb->type == MEM_BUFFER_FILE && rb->u.file.slots)
    {
        for (size_t i = 0; i < rb->u.file.max_slots; i++)
        {
            if (rb->u.file.slots[i].ptr)
            {
                if ((rb->flags & BUFFER_SECURE_MODE) != 0)
                {
                    tls_secure_memzero(rb->u.file.slots[i].ptr, rb->u.file.slots[i].size);
                }
                g_mem_cfg.free_fn(rb->u.file.slots[i].ptr);
                rb->u.file.slots[i].ptr = NULL;
                rb->u.file.slots[i].size = 0;
            }
        }
        g_mem_cfg.free_fn(rb->u.file.slots);
        rb->u.file.slots = NULL;
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
    if (!rb)
    {
        return 0;
    }
    if (rb->type == MEM_BUFFER_FILE)
    {
        return rb->u.file.used_bytes;
    }
    return rb->u.ring.len;
}

size_t mem_buffer_capacity(const struct mem_buffer *rb)
{
    if (!rb)
    {
        return 0;
    }
    if (rb->type == MEM_BUFFER_FILE)
    {
        return rb->max_size;
    }
    return rb->current_size;
}

size_t mem_buffer_space(const struct mem_buffer *rb)
{
    if (!rb)
    {
        return 0;
    }
    if (rb->type == MEM_BUFFER_FILE)
    {
        if (rb->max_size == SIZE_MAX)
        {
            return SIZE_MAX;
        }
        if (rb->max_size < rb->u.file.used_bytes)
        {
            return 0;
        }
        return rb->max_size - rb->u.file.used_bytes;
    }
    if (rb->current_size < rb->u.ring.len)
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

size_t mem_buffer_drain(struct mem_buffer *rb, size_t budget)
{
    if (!rb || rb->type != MEM_BUFFER_RING || !rb->u.ring.drain_fn || budget == 0)
    {
        return 0;
    }
    return rb->u.ring.drain_fn(rb, rb->u.ring.drain_fn_data, budget);
}

static void mem_buffer_notify_pressure(struct mem_buffer *rb, size_t requested, enum mem_pressure_level level)
{
    if (g_mem_mode == MEM_INIT_MODE_STATIC)
    {
        if (rb)
        {
            rb->last_pressure_level = MEM_PRESSURE_NONE;
        }
        (void)requested;
        (void)level;
        return;
    }
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
    if (level != old_level && mem_buffer_is_lwip_pool(rb))
    {
        mem_effective_pressure_update();
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
    if (!rb || size == 0)
    {
        return NULL;
    }
    if (rb->type == MEM_BUFFER_FILE)
    {
        if (rb->max_size != SIZE_MAX && rb->u.file.used_bytes + size > rb->max_size)
        {
            return NULL;
        }
        for (size_t i = 0; i < rb->u.file.max_slots; i++)
        {
            if (!rb->u.file.slots[i].ptr)
            {
                uint8_t *ptr = (uint8_t *)g_mem_cfg.malloc_fn(size);
                if (!ptr)
                {
                    return NULL;
                }
                rb->u.file.slots[i].ptr = ptr;
                rb->u.file.slots[i].size = size;
                rb->u.file.used_bytes += size;
                return ptr;
            }
        }
        return NULL;
    }
    if (!mem_buffer_is_pool_type(rb))
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
        bool skip_heap_accounting =
            (rb->flags & (BUFFER_USER_ALLOC | BUFFER_LWIP_PBUF_POOL)) != 0;
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
    if (!rb || !ptr)
    {
        return;
    }
    if (rb->type == MEM_BUFFER_FILE)
    {
        for (size_t i = 0; i < rb->u.file.max_slots; i++)
        {
            if (rb->u.file.slots[i].ptr == ptr)
            {
                if ((rb->flags & BUFFER_SECURE_MODE) != 0)
                {
                    tls_secure_memzero(rb->u.file.slots[i].ptr, rb->u.file.slots[i].size);
                }
                g_mem_cfg.free_fn(rb->u.file.slots[i].ptr);
                if (rb->u.file.used_bytes >= rb->u.file.slots[i].size)
                {
                    rb->u.file.used_bytes -= rb->u.file.slots[i].size;
                }
                else
                {
                    rb->u.file.used_bytes = 0;
                }
                rb->u.file.slots[i].ptr = NULL;
                rb->u.file.slots[i].size = 0;
                return;
            }
        }
        return;
    }
    if (!mem_buffer_is_pool_type(rb))
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

    /* Re-initialization can happen after a failed stack start or a manual
     * lwip_init retry. Release any previous pools before clearing the registry;
     * otherwise the old pbuf pool becomes unreachable and permanently leaks. */
    mem_buffer_lwip_release_pools();

    if (pool_count > MEM_LWIP_MAX_POOLS)
    {
        pool_count = MEM_LWIP_MAX_POOLS;
    }

    for (size_t i = 0; i < pool_count; i++)
    {
        const struct mem_buffer_pool_cfg *cfg = &pools[i];
        if (cfg->block_size == 0 || cfg->block_count == 0)
        {
            continue;
        }
        if ((cfg->flags & BUFFER_LWIP_PBUF_POOL) == 0)
        {
            continue;
        }
        size_t initial_cap = cfg->block_size * cfg->block_count;
        if (g_mem_cfg.max_heap != 0 && g_mem_cfg.max_heap != SIZE_MAX &&
            initial_cap + g_mem_cfg.user_reserved > g_mem_cfg.max_heap)
        {
            continue;
        }
        size_t max_cap = initial_cap;
        uint8_t flags = cfg->flags | BUFFER_LOCK_SIZE | BUFFER_LWIP_PBUF_POOL;
        struct mem_buffer *mb = mem_buffer_create(MEM_BUFFER_POOL, initial_cap, max_cap, cfg->block_size, flags);
        if (mb)
        {
            g_lwip_pbuf_pool = mb;
            g_lwip_pools[g_lwip_pool_count++] = mb;
        }
    }

    if (g_lwip_pool_count == 0)
    {
        return false;
    }

    mem_buffer_sort_pools();
    mem_effective_pressure_update();
    return true;
}

void mem_buffer_lwip_release_pools(void)
{
    /* Destroy every registered lwIP pool and clear the registry. Called
     * during stack teardown, after USB is quiesced, so nothing can be
     * allocating from these pools as they go away. Each slot is NULLed as
     * it is destroyed. */
    for (size_t i = 0; i < g_lwip_pool_count; i++)
    {
        if (g_lwip_pools[i])
        {
            mem_buffer_destroy(g_lwip_pools[i]);
            g_lwip_pools[i] = NULL;
        }
    }
    g_lwip_pool_count = 0;
    g_lwip_pbuf_pool = NULL;
    mem_effective_pressure_update();
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

static bool mem_user_charge(size_t bytes)
{
    if (mem_nonpool_limit() == SIZE_MAX)
    {
        g_mem_cfg.user_reserved += bytes;
        mem_global_pressure_update();
        return true;
    }

    size_t pbuf_reserved = mem_pbuf_pool_size();
    if (g_mem_cfg.max_heap <= pbuf_reserved)
    {
        return false;
    }
    size_t limit = g_mem_cfg.max_heap - pbuf_reserved;
    if (g_mem_cfg.heap_used > limit || bytes > limit - g_mem_cfg.heap_used)
    {
        return false;
    }
    size_t free_for_user = limit - g_mem_cfg.heap_used;
    if (g_mem_cfg.user_reserved > free_for_user ||
        bytes > free_for_user - g_mem_cfg.user_reserved)
    {
        return false;
    }
    g_mem_cfg.user_reserved += bytes;
    mem_global_pressure_update();
    return true;
}

static void mem_user_release(size_t bytes)
{
    if (g_mem_cfg.user_reserved >= bytes)
    {
        g_mem_cfg.user_reserved -= bytes;
    }
    else
    {
        g_mem_cfg.user_reserved = 0;
    }
    mem_global_pressure_update();
}

static void *mem_direct_alloc(size_t size, uint16_t flags)
{
    if (!g_mem_cfg_ready || !g_mem_cfg.malloc_fn || size == 0)
    {
        return NULL;
    }
    if (size > SIZE_MAX - sizeof(struct mem_direct_header))
    {
        return NULL;
    }
    size_t raw_size = size + sizeof(struct mem_direct_header);
    bool user = (flags & MEM_DIRECT_FLAG_USER) != 0;
    if (user)
    {
        if (!mem_user_charge(raw_size))
        {
            return NULL;
        }
    }
    else if (!mem_buffer_charge(raw_size))
    {
        return NULL;
    }

    struct mem_direct_header *hdr =
        (struct mem_direct_header *)g_mem_cfg.malloc_fn(raw_size);
    if (!hdr)
    {
        if (user)
        {
            mem_user_release(raw_size);
        }
        else
        {
            mem_buffer_release(raw_size);
        }
        return NULL;
    }
    hdr->magic = MEM_DIRECT_MAGIC;
    hdr->flags = flags;
    hdr->size = raw_size;
    return (void *)(hdr + 1);
}

static struct mem_direct_header *mem_direct_header_from_ptr(void *ptr)
{
    if (!ptr)
    {
        return NULL;
    }
    struct mem_direct_header *hdr = ((struct mem_direct_header *)ptr) - 1;
    if (hdr->magic != MEM_DIRECT_MAGIC)
    {
        return NULL;
    }
    return hdr;
}

static void mem_direct_free(void *ptr)
{
    struct mem_direct_header *hdr = mem_direct_header_from_ptr(ptr);
    if (!hdr)
    {
        return;
    }
    size_t raw_size = hdr->size;
    bool user = (hdr->flags & MEM_DIRECT_FLAG_USER) != 0;
    hdr->magic = 0;
    g_mem_cfg.free_fn(hdr);
    if (user)
    {
        mem_user_release(raw_size);
    }
    else
    {
        mem_buffer_release(raw_size);
    }
}

static void *mem_direct_resize(void *ptr, size_t size, uint16_t flags)
{
    if (!ptr)
    {
        return mem_direct_alloc(size, flags);
    }
    if (size == 0)
    {
        mem_direct_free(ptr);
        return NULL;
    }

    struct mem_direct_header *hdr = mem_direct_header_from_ptr(ptr);
    if (!hdr || size > SIZE_MAX - sizeof(struct mem_direct_header))
    {
        return NULL;
    }
    size_t old_raw = hdr->size;
    size_t new_raw = size + sizeof(struct mem_direct_header);
    bool user = (hdr->flags & MEM_DIRECT_FLAG_USER) != 0;

    if (new_raw > old_raw)
    {
        size_t grow = new_raw - old_raw;
        if (user)
        {
            if (!mem_user_charge(grow))
            {
                return NULL;
            }
        }
        else if (!mem_buffer_charge(grow))
        {
            return NULL;
        }
    }

    struct mem_direct_header *new_hdr = NULL;
    if (g_mem_cfg.realloc_fn)
    {
        new_hdr = (struct mem_direct_header *)g_mem_cfg.realloc_fn(hdr, new_raw);
    }
    else
    {
        new_hdr = (struct mem_direct_header *)g_mem_cfg.malloc_fn(new_raw);
        if (new_hdr)
        {
            size_t copy = old_raw < new_raw ? old_raw : new_raw;
            memcpy(new_hdr, hdr, copy);
            g_mem_cfg.free_fn(hdr);
        }
    }
    if (!new_hdr)
    {
        if (new_raw > old_raw)
        {
            size_t grow = new_raw - old_raw;
            if (user)
            {
                mem_user_release(grow);
            }
            else
            {
                mem_buffer_release(grow);
            }
        }
        return NULL;
    }

    new_hdr->magic = MEM_DIRECT_MAGIC;
    new_hdr->flags = flags;
    new_hdr->size = new_raw;
    if (old_raw > new_raw)
    {
        size_t shrink = old_raw - new_raw;
        if (user)
        {
            mem_user_release(shrink);
        }
        else
        {
            mem_buffer_release(shrink);
        }
    }
    return (void *)(new_hdr + 1);
}

void *mem_buffer_custom_malloc(size_t size)
{
    return mem_direct_alloc(size, 0);
}

void mem_buffer_custom_free(void *ptr)
{
    if (!ptr)
    {
        return;
    }

    if (g_lwip_pbuf_pool && g_lwip_pbuf_pool->buf)
    {
        uint8_t *start = g_lwip_pbuf_pool->buf;
        uint8_t *end = g_lwip_pbuf_pool->buf + g_lwip_pbuf_pool->current_size;
        if ((uint8_t *)ptr > start && (uint8_t *)ptr < end)
        {
            mem_buffer_free(g_lwip_pbuf_pool, ptr);
            return;
        }
    }

    mem_direct_free(ptr);
}

void *mem_buffer_custom_malloc_pbuf(size_t size)
{
    if (!g_lwip_pbuf_pool)
    {
        return NULL;
    }
    void *ptr = mem_buffer_malloc(g_lwip_pbuf_pool, size);
    if (!ptr)
    {
        mem_buffer_notify_pressure(g_lwip_pbuf_pool, size, MEM_PRESSURE_CRITICAL);
        return NULL;
    }
    size_t used = mem_pbuf_pool_used();
    uint8_t usage_pct = mem_buffer_usage_pct(g_lwip_pbuf_pool, used);
    enum mem_pressure_level level = mem_pressure_level_from_usage(usage_pct);
    if (level != g_lwip_pbuf_pool->last_pressure_level)
    {
        mem_buffer_notify_pressure(g_lwip_pbuf_pool, used, level);
    }
    return ptr;
}

void mem_buffer_custom_free_pbuf(void *ptr)
{
    if (!g_lwip_pbuf_pool || !ptr)
    {
        return;
    }
    mem_buffer_free(g_lwip_pbuf_pool, ptr);
}

void *mem_request(size_t size)
{
    return mem_direct_alloc(size, MEM_DIRECT_FLAG_USER);
}

void *mem_resize(void *ptr, size_t size)
{
    return mem_direct_resize(ptr, size, MEM_DIRECT_FLAG_USER);
}

void mem_release(void *ptr)
{
    mem_direct_free(ptr);
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

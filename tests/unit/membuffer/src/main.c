#include <ti/screen.h>
#include <ti/getkey.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mem.h"

#define TRACK_ALLOC_MAX 32
#define TRACK_FREE_MAX 32

struct tracked_alloc
{
    void *ptr;
    size_t size;
};

struct tracked_free
{
    size_t size;
    bool zeroed;
};

static struct tracked_alloc g_allocs[TRACK_ALLOC_MAX];
static struct tracked_free g_frees[TRACK_FREE_MAX];
static size_t g_free_count;
static bool g_realloc_shrink_seen;
static bool g_realloc_shrink_zeroed;
static size_t g_realloc_shrink_size;

static bool bytes_zeroed(const void *ptr, size_t len)
{
    const uint8_t *bytes = (const uint8_t *)ptr;
    for (size_t i = 0; i < len; i++)
    {
        if (bytes[i] != 0)
        {
            return false;
        }
    }
    return true;
}

static int find_alloc(void *ptr)
{
    for (size_t i = 0; i < TRACK_ALLOC_MAX; i++)
    {
        if (g_allocs[i].ptr == ptr)
        {
            return (int)i;
        }
    }
    return -1;
}

static bool track_alloc(void *ptr, size_t size)
{
    if (!ptr)
    {
        return false;
    }
    for (size_t i = 0; i < TRACK_ALLOC_MAX; i++)
    {
        if (!g_allocs[i].ptr)
        {
            g_allocs[i].ptr = ptr;
            g_allocs[i].size = size;
            return true;
        }
    }
    return false;
}

static void record_free(size_t size, bool zeroed)
{
    if (g_free_count < TRACK_FREE_MAX)
    {
        g_frees[g_free_count].size = size;
        g_frees[g_free_count].zeroed = zeroed;
        g_free_count++;
    }
}

static void reset_free_events(void)
{
    memset(g_frees, 0, sizeof(g_frees));
    g_free_count = 0;
}

static void reset_realloc_shrink_event(void)
{
    g_realloc_shrink_seen = false;
    g_realloc_shrink_zeroed = false;
    g_realloc_shrink_size = 0;
}

static bool saw_zeroed_free(size_t size)
{
    for (size_t i = 0; i < g_free_count; i++)
    {
        if (g_frees[i].size == size && g_frees[i].zeroed)
        {
            return true;
        }
    }
    return false;
}

static void *tracked_malloc(size_t size)
{
    size_t actual_size = size ? size : 1u;
    void *ptr = malloc(actual_size);
    if (!track_alloc(ptr, actual_size))
    {
        free(ptr);
        return NULL;
    }
    return ptr;
}

static void tracked_free(void *ptr)
{
    if (!ptr)
    {
        return;
    }

    int index = find_alloc(ptr);
    if (index >= 0)
    {
        record_free(g_allocs[index].size, bytes_zeroed(ptr, g_allocs[index].size));
        g_allocs[index].ptr = NULL;
        g_allocs[index].size = 0;
    }
    free(ptr);
}

static void *tracked_realloc(void *ptr, size_t size)
{
    if (!ptr)
    {
        return tracked_malloc(size);
    }

    if (size == 0)
    {
        tracked_free(ptr);
        return NULL;
    }

    int index = find_alloc(ptr);
    if (index >= 0 && size < g_allocs[index].size)
    {
        size_t shrink_size = g_allocs[index].size - size;
        g_realloc_shrink_seen = true;
        g_realloc_shrink_size = shrink_size;
        g_realloc_shrink_zeroed = bytes_zeroed((uint8_t *)ptr + size, shrink_size);
    }

    void *new_ptr = realloc(ptr, size);
    if (!new_ptr)
    {
        return NULL;
    }

    if (index >= 0)
    {
        g_allocs[index].ptr = new_ptr;
        g_allocs[index].size = size;
    }
    else
    {
        track_alloc(new_ptr, size);
    }
    return new_ptr;
}

static void fill_pattern(uint8_t *data, size_t len, uint8_t seed)
{
    for (size_t i = 0; i < len; i++)
    {
        data[i] = (uint8_t)(seed + i);
    }
}

static void set_shrink_hysteresis(struct mem_buffer *mb, uint16_t hold_count)
{
    mb->shrink_hold_count = hold_count;
    mb->shrink_hold_base = hold_count;
    mb->shrink_hold_next = hold_count;
    mb->shrink_stage = 0;
    mb->shrink_hits = 0;
}

static bool test_ring_buffer(void)
{
    uint8_t data[32];
    uint8_t out[32];
    struct mem_buffer *ring;

    fill_pattern(data, sizeof(data), 0x31);
    ring = mem_buffer_create(MEM_BUFFER_RING, 8, 24, 8, BUFFER_SECURE_MODE);
    if (!ring)
    {
        return false;
    }
    mem_buffer_set_grow(ring, 100, 8);
    mem_buffer_set_shrink(ring, 25, 8);
    set_shrink_hysteresis(ring, 2);

    if (!mem_buffer_push(ring, data, 16) || ring->current_size != 24)
    {
        return false;
    }
    if (mem_buffer_pop(ring, out, 12) != 12)
    {
        return false;
    }
    if (!bytes_zeroed(ring->buf, 12) || ring->u.ring.head != 12 || ring->u.ring.len != 4)
    {
        return false;
    }
    if (!mem_buffer_push(ring, data, 12))
    {
        return false;
    }
    if (mem_buffer_pop(ring, out, 12) != 12)
    {
        return false;
    }
    if (ring->current_size != 24 || ring->shrink_hits != 1)
    {
        return false;
    }
    if (!bytes_zeroed(ring->buf + 12, 12))
    {
        return false;
    }
    if (mem_buffer_pop(ring, out, 4) != 4 || !bytes_zeroed(ring->buf, 4))
    {
        return false;
    }
    if (!mem_buffer_push(ring, data, 20))
    {
        return false;
    }

    reset_realloc_shrink_event();
    if (mem_buffer_pop(ring, out, 20) != 20)
    {
        return false;
    }
    if (ring->current_size != 16 || !g_realloc_shrink_seen ||
        !g_realloc_shrink_zeroed || g_realloc_shrink_size != 8)
    {
        return false;
    }
    if (!bytes_zeroed(ring->buf + 4, 12))
    {
        return false;
    }

    memset(ring->buf, 0x5a, ring->current_size);
    reset_free_events();
    mem_buffer_destroy(ring);
    return saw_zeroed_free(16);
}

static bool test_pool_buffer(void)
{
    uint8_t *small;
    uint8_t *big;
    uint8_t *again;
    struct mem_buffer *pool;

    pool = mem_buffer_create(MEM_BUFFER_POOL, 16, 40, 8, BUFFER_SECURE_MODE);
    if (!pool)
    {
        return false;
    }
    mem_buffer_set_grow(pool, 100, 8);
    mem_buffer_set_shrink(pool, 25, 8);
    set_shrink_hysteresis(pool, 2);

    small = (uint8_t *)mem_buffer_malloc(pool, 6);
    if (!small)
    {
        return false;
    }
    memset(small, 0xa5, 6);
    mem_buffer_free(pool, small);
    if (!bytes_zeroed(small - 2, 8))
    {
        return false;
    }

    big = (uint8_t *)mem_buffer_malloc(pool, 22);
    if (!big || pool->current_size != 32)
    {
        return false;
    }
    memset(big, 0x66, 22);
    set_shrink_hysteresis(pool, 2);
    mem_buffer_free(pool, big);
    if (pool->current_size != 32 || pool->shrink_hits != 1)
    {
        return false;
    }
    if (!bytes_zeroed(big - 2, 24))
    {
        return false;
    }

    again = (uint8_t *)mem_buffer_malloc(pool, 6);
    if (!again)
    {
        return false;
    }
    memset(again, 0x77, 6);
    reset_realloc_shrink_event();
    mem_buffer_free(pool, again);
    if (pool->current_size != 24 || !g_realloc_shrink_seen ||
        !g_realloc_shrink_zeroed || g_realloc_shrink_size != 8)
    {
        return false;
    }

    memset(pool->buf, 0x5a, pool->current_size);
    memset(pool->u.pool.pool_bitmap, 0xff, pool->u.pool.pool_bitmap_bytes);
    reset_free_events();
    mem_buffer_destroy(pool);
    return saw_zeroed_free(24) && saw_zeroed_free(1);
}

static bool test_file_buffer(void)
{
    uint8_t *slot;
    uint8_t *release_slot;
    struct mem_buffer *file;

    file = mem_buffer_create(MEM_BUFFER_FILE, 0, 32, 0, BUFFER_SECURE_MODE);
    if (!file || file->current_size != 0 || file->u.file.used_bytes != 0)
    {
        return false;
    }

    slot = (uint8_t *)mem_buffer_malloc(file, 8);
    if (!slot || file->u.file.used_bytes != 8)
    {
        return false;
    }
    memset(slot, 0x44, 8);
    if (mem_buffer_malloc(file, 28) != NULL)
    {
        return false;
    }

    reset_free_events();
    mem_buffer_free(file, slot);
    if (file->u.file.used_bytes != 0 || !saw_zeroed_free(8))
    {
        return false;
    }

    release_slot = (uint8_t *)mem_buffer_malloc(file, 12);
    if (!release_slot || file->u.file.used_bytes != 12)
    {
        return false;
    }
    memset(release_slot, 0x45, 12);

    reset_free_events();
    mem_buffer_destroy(file);
    return saw_zeroed_free(12);
}

static bool show_result(bool ok)
{
    printf(ok ? "success" : "failed");
    os_GetKey();
    os_ClrHome();
    return ok;
}

int main(void)
{
    bool ready;

    os_ClrHome();
    memset(g_allocs, 0, sizeof(g_allocs));
    reset_free_events();
    reset_realloc_shrink_event();

    ready = mem_init_dynamic(4096, tracked_malloc, tracked_free, tracked_realloc);
    if (!show_result(ready && test_ring_buffer()))
    {
        return 1;
    }
    if (!show_result(test_pool_buffer()))
    {
        return 1;
    }
    if (!show_result(test_file_buffer()))
    {
        return 1;
    }
    return 0;
}

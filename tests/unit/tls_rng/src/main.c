#include <ti/screen.h>
#include <ti/getkey.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include "drivers/mem.h"
#include "lwip/timeouts.h"
#include "tls.h"
#include "random.h"

/* lwIP mem.h comments out mem_init declaration; declare locally for unit harness. */

#define TLS_TEST_STATIC_ARENA (48u * 1024u)
static uint8_t tls_test_arena[TLS_TEST_STATIC_ARENA];
static struct mem_buffer *g_test_lwip_heap = NULL;

void sys_timeout(uint32_t msecs, sys_timeout_handler handler, void *arg)
{
    (void)msecs;
    (void)handler;
    (void)arg;
}

void sys_untimeout(sys_timeout_handler handler, void *arg)
{
    (void)handler;
    (void)arg;
}

static volatile bool g_cb_called = false;
static volatile bool g_cb_ok = false;

static void rng_cb(bool ok, void *arg)
{
    (void)arg;
    g_cb_called = true;
    g_cb_ok = ok;
}

static void reset_cb_state(void)
{
    g_cb_called = false;
    g_cb_ok = false;
}

static bool is_all_zero(const uint8_t *buf, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++)
    {
        if (buf[i] != 0)
        {
            return false;
        }
    }
    return true;
}

static bool init_rng_with_retries(void)
{
    int tries;
    for (tries = 0; tries < 10; tries++)
    {
        if (tls_random_init_entropy())
        {
            return true;
        }
    }
    return false;
}

static bool init_test_memory(void)
{
    if (!mem_init_static(tls_test_arena, sizeof(tls_test_arena)))
    {
        return false;
    }

    g_test_lwip_heap = mem_buffer_create(MEM_BUFFER_POOL, 8u * 1024u, 8u * 1024u, 256u, BUFFER_LOCK_SIZE);
    if (g_test_lwip_heap == NULL)
    {
        return false;
    }
    if (!mem_buffer_set_lwip_heap(g_test_lwip_heap))
    {
        mem_buffer_destroy(g_test_lwip_heap);
        g_test_lwip_heap = NULL;
        return false;
    }
    return true;
}

int main(void)
{
    uint8_t r1[32];
    uint8_t r2[32];
    uint8_t rb[16];
    uint8_t rl[80];
    bool pass;

    os_ClrHome();
    if (!init_test_memory())
    {
        printf("failed");
        os_GetKey();
        return 1;
    }
    memset(r1, 0, sizeof(r1));
    memset(r2, 0, sizeof(r2));
    pass = init_rng_with_retries();
    if (pass)
    {
        tls_random_bytes(r1, sizeof(r1));
        tls_random_bytes(r2, sizeof(r2));
        pass = (!is_all_zero(r1, sizeof(r1))) && (!is_all_zero(r2, sizeof(r2))) &&
               (memcmp(r1, r2, sizeof(r1)) != 0);
    }
    printf(pass ? "success" : "failed");
    os_GetKey();
    os_ClrHome();

    memset(rb, 0, sizeof(rb));
    reset_cb_state();
    pass = tls_init();
    if (!pass)
    {
        printf("tls init failed");
        os_GetKey();
        return 1;
    }
    if (pass)
    {
        pass = tls_request_random_bytes(rb, sizeof(rb), rng_cb, NULL, true);
    }
    else
    {
        printf("failed to request random bytes");
        os_GetKey();
        return 1;
    }
    if (pass)
    {
        pass = g_cb_called && g_cb_ok && (!is_all_zero(rb, sizeof(rb)));
    }
    printf(pass ? "success" : "failed");
    os_GetKey();
    os_ClrHome();

    memset(rl, 0, sizeof(rl));
    reset_cb_state();
    pass = tls_request_random_bytes(rl, sizeof(rl), rng_cb, NULL, true);
    if (pass)
    {
        pass = g_cb_called && g_cb_ok && (!is_all_zero(rl, sizeof(rl))) && !tls_rng_is_busy();
    }
    printf(pass ? "success" : "failed");
    os_GetKey();

    tls_cleanup();
    if (g_test_lwip_heap != NULL)
    {
        mem_buffer_destroy(g_test_lwip_heap);
        g_test_lwip_heap = NULL;
    }
    return 0;
}

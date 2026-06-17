/**
 * @file main.c
 * @brief TLS Truststore Unit Test
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ti/getkey.h>
#include <ti/screen.h>
#include <ti/vars.h>
#include <stdlib.h>

#include "truststore.h"
#include "lwip/mem.h"
#include "drivers/mem.h"
#include "rsa.h"

#define TLS_TEST_MAX_HEAP (20u * 1024u)
#define TLS_TEST_POOL_BYTES (16u * 1024u)
#define TLS_TEST_POOL_BLOCK 256u

#define TLS_TRUSTSTORE_VERSION 1

static struct mem_buffer *tls_test_heap;
static int text_y = 20;

static void draw_line(const char *msg)
{
    os_FontDrawText(msg, 2, text_y);
    text_y += 12;
}

static const char *truststore_status_str(tls_truststore_status_t status)
{
    switch (status)
    {
    case TLS_STORE_OK:
        return "ok";
    case TLS_STORE_NOT_FOUND:
        return "not found";
    case TLS_STORE_SIZE_INVALID:
        return "size bad";
    case TLS_STORE_VERSION_MISMATCH:
        return "version bad";
    case TLS_STORE_HASH_FAIL:
        return "hash fail";
    case TLS_STORE_SIG_INVALID:
        return "sig invalid";
    default:
        return "unknown";
    }
}

static bool tls_test_mem_init(void)
{
    if (!mem_init(TLS_TEST_MAX_HEAP, malloc, free, realloc))
    {
        return false;
    }
    tls_test_heap = mem_buffer_create(
        MEM_BUFFER_POOL,
        TLS_TEST_POOL_BYTES,
        TLS_TEST_POOL_BYTES,
        TLS_TEST_POOL_BLOCK,
        0);
    if (!tls_test_heap)
    {
        return false;
    }
    mem_buffer_set_lwip_heap(tls_test_heap);
    return true;
}

static const struct tls_truststore_entry *tls_truststore_first_entry(void)
{
    var_t *truststore_var = os_GetAppVarData("lwIPCERT", NULL);
    if (!truststore_var)
    {
        return NULL;
    }

    uint16_t truststore_size = *((uint16_t *)truststore_var);
    if (truststore_size < TLS_TRUSTSTORE_HEADER_LEN)
    {
        return NULL;
    }

    uint8_t *base = (uint8_t *)truststore_var + 2;
    struct tls_truststore_header *header =
        (struct tls_truststore_header *)base;
    if (header->entry_count == 0)
    {
        return NULL;
    }

    const uint8_t *db_start = (const uint8_t *)header + TLS_TRUSTSTORE_HEADER_LEN;
    return (const struct tls_truststore_entry *)db_start;
}

int main(void)
{
    os_ClrHome();
    os_FontSelect(os_SmallFont);
    text_y = 30;

    if (!tls_test_mem_init())
    {
        draw_line("mem init failed");
        os_GetKey();
        return 1;
    }

    {
        int archived = 0;
        var_t *truststore_var = os_GetAppVarData("lwIPCERT", &archived);
        if (!truststore_var)
        {
            draw_line("appvar missing");
            os_GetKey();
            return 1;
        }
        uint16_t truststore_size = *((uint16_t *)truststore_var);
        (void)archived;
        if (truststore_size < TLS_TRUSTSTORE_HEADER_LEN)
        {
            draw_line("appvar size bad");
            os_GetKey();
            return 1;
        }
        uint8_t *base = (uint8_t *)truststore_var + 2;
        struct tls_truststore_header *header =
            (struct tls_truststore_header *)base;
        if (header->version != TLS_TRUSTSTORE_VERSION)
        {
            draw_line("appvar version bad");
            os_GetKey();
            return 1;
        }
    }

    tls_truststore_status_t status = tls_truststore_init();
    bool sig_ok = (status == TLS_STORE_OK);
    if (sig_ok)
    {
        draw_line("Test 1 (Sig verified): pass");
    }
    else
    {
        char msg[32];
        snprintf(msg, sizeof(msg), "Test 1 failed: %s", truststore_status_str(status));
        draw_line(msg);
    }
    os_GetKey();

    const struct tls_truststore_entry *entry = tls_truststore_first_entry();
    bool owner_ok = (entry != NULL) && (entry->subject[0] != '\0');
    draw_line(owner_ok ? "Test 2 (First entry): pass" : "Test 2 (First entry): fail");
    os_GetKey();

    return (sig_ok && owner_ok) ? 0 : 1;
}

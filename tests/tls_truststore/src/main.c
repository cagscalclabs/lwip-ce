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
#include "tls.h"
#include "lwip/mem.h"
#include "drivers/mem.h"
#include "rsa.h"

#define TLS_TEST_MAX_HEAP (20u * 1024u)
#define TLS_TEST_POOL_BYTES (16u * 1024u)
#define TLS_TEST_POOL_BLOCK 256u

#define TRUSTSTORE_SIG_LEN 256

static struct mem_buffer *tls_test_heap;
static int text_y = 0;

static void draw_line(const char *msg)
{
    os_FontDrawText(msg, 2, text_y);
    text_y += 10;
}

static bool tls_test_mem_init(void)
{
    if (!mem_init(TLS_TEST_MAX_HEAP, malloc, free, realloc))
    {
        return false;
    }
    tls_test_heap = mem_buffer_create(
        TLS_TEST_POOL_BYTES,
        TLS_TEST_POOL_BYTES,
        TLS_TEST_POOL_BLOCK,
        BUFFER_MALLOC_TYPE,
        NULL);
    if (!tls_test_heap)
    {
        return false;
    }
    mem_buffer_set_lwip_heap(tls_test_heap);
    mem_buffer_set_owner(tls_test_heap, MEM_BUF_OWNER_TLS_RX);
    return true;
}

static const struct tls_spki_entry *tls_truststore_first_entry(void)
{
    var_t *truststore_var = os_GetAppVarData("lwIPSPKI", NULL);
    if (!truststore_var)
    {
        return NULL;
    }

    uint16_t truststore_size = *((uint16_t *)truststore_var);
    if (truststore_size < TRUSTSTORE_SIG_LEN + TLS_SPKI_HEADER_LEN + 2)
    {
        return NULL;
    }

    uint8_t *base = (uint8_t *)truststore_var + 2;
    struct tls_truststore_header *header =
        (struct tls_truststore_header *)(base + TRUSTSTORE_SIG_LEN);
    if (header->entry_count == 0)
    {
        return NULL;
    }

    const uint8_t *spki_db_start = (const uint8_t *)header + TLS_SPKI_HEADER_LEN;
    return (const struct tls_spki_entry *)spki_db_start;
}

int main(void)
{
    os_ClrHome();
    os_FontSelect(os_SmallFont);
    text_y = 0;

    if (!tls_test_mem_init())
    {
        draw_line("mem init failed");
        os_GetKey();
        return 1;
    }

    if (!tls_init())
    {
        draw_line("tls init failed");
        os_GetKey();
        return 1;
    }

    bool sig_ok = tls_truststore_init();
    draw_line(sig_ok ? "Test 1 (Sig verified): pass" : "Test 1 (Sig verified): fail");
    os_GetKey();
    os_ClrHome();
    text_y = 0;

    const struct tls_spki_entry *entry = tls_truststore_first_entry();
    bool owner_ok = false;
    if (entry)
    {
        const char expected[] = "COMODO Certification Authority";
        size_t expected_len = sizeof(expected) - 1;
        size_t owner_len = strnlen((const char *)entry->owner_id, TLS_SPKI_OWNER_ID_LEN);
        owner_ok = (owner_len == expected_len) &&
                   (memcmp(entry->owner_id, expected, expected_len) == 0);
    }
    draw_line(owner_ok ? "Test 2 (First entry): pass" : "Test 2 (First entry): fail");
    os_GetKey();
    tls_cleanup();
    return (sig_ok && owner_ok) ? 0 : 1;
}

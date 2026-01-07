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
    void *truststore_data = NULL;
    if (!os_ChkFindSym(OS_TYPE_APPVAR, "lwIPSPKI", NULL, &truststore_data))
    {
        return NULL;
    }

    uint16_t truststore_size = *((uint16_t *)truststore_data);
    printf("size: %u\n", truststore_size);
    if (truststore_size < TRUSTSTORE_SIG_LEN + TLS_SPKI_HEADER_LEN + 2)
    {
        return NULL;
    }

    uint8_t *sig = (uint8_t *)truststore_data + 2;
    printf("sig: %02x %02x %02x %02x\n", sig[0], sig[1], sig[2], sig[3]);

    struct tls_truststore_header *header =
        (struct tls_truststore_header *)((uint8_t *)truststore_data + 2 + TRUSTSTORE_SIG_LEN);
    printf("hdr: %02x %02x %02x %02x\n",
           ((uint8_t *)header)[0], ((uint8_t *)header)[1],
           ((uint8_t *)header)[2], ((uint8_t *)header)[3]);
    printf("cnt: %u\n", header->entry_count);
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

    if (!tls_test_mem_init())
    {
        printf("mem init failed\n");
        os_GetKey();
        return 1;
    }

    if (!tls_init())
    {
        printf("tls init failed\n");
        os_GetKey();
        return 1;
    }

    if (!tls_truststore_init())
    {
        printf("truststore sig bad\n");
        os_GetKey();
        tls_cleanup();
        // return 1;
    }

    const struct tls_spki_entry *entry = tls_truststore_first_entry();
    if (!entry)
    {
        printf("no entries\n");
        os_GetKey();
        tls_cleanup();
        return 1;
    }

    printf("owner: %.*s\n", TLS_SPKI_OWNER_ID_LEN, entry->owner_id);
    os_GetKey();
    tls_cleanup();
    return 0;
}

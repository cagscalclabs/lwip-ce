#include <ti/screen.h>
#include <ti/getkey.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "keyobject.h"
#include "lwip/mem.h"
#include "drivers/mem.h"

#define TLS_TEST_MAX_HEAP (64u * 1024u)
#define TLS_TEST_POOL_BYTES (48u * 1024u)
#define TLS_TEST_POOL_BLOCK 256u

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

// test vectors
const char *test1 = "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDGyysU2q4d1q5X2gC4cSZIgRScpt6W0w3ypyYWrM+85s4YeIniKhjuA7EUSWlAG3BJuElaEJNsWFtDFItptYzIkLLvPzz4ecJfvfFu5o4r3H//a7DpyiXwe2e4GEwwCV8FtHlrZaUcqb/mjRiziEwvmKPTCO/GkQyXI0wHQCOijQIDAQAB\n-----END PUBLIC KEY-----";

const char *test2 = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhhE3TnZBQDSZiLQzxYhdrMSD7Y1fJVijgONxCi4f7nbggjZous05eRjeDoVjw1960Vci2ueuUFNsG7A1mjkPow==\n-----END PUBLIC KEY-----";

/* Main function, called first */
int main(void)
{
    char buf[128];

    /* Clear the homescreen */
    os_ClrHome();
    os_FontSelect(os_SmallFont);

    /* Set up memory allocator for lwIP's custom malloc */
    if (!tls_test_mem_init())
    {
        printf("error");
        os_GetKey();
        os_ClrHome();
        return 1;
    }

    // PKCS#8 RSA public key
    struct tls_keyobject *pk = tls_keyobject_import_public(test1, strlen(test1));
    if (pk == NULL)
    {
        printf("error");
        os_GetKey();
        os_ClrHome();
        return 1;
    }
    for (int i = 0; i < 2; i++)
    {
        sprintf(buf, "%s:tag=%u, size=%u: %02x%02x..%02x%02x",
                pk->meta.pubkey.rsa.fields[i].name,
                pk->meta.pubkey.rsa.fields[i].tag,
                pk->meta.pubkey.rsa.fields[i].len,
                pk->meta.pubkey.rsa.fields[i].data[0],
                pk->meta.pubkey.rsa.fields[i].data[1],
                pk->meta.pubkey.rsa.fields[i].data[pk->meta.pubkey.rsa.fields[i].len - 2],
                pk->meta.pubkey.rsa.fields[i].data[pk->meta.pubkey.rsa.fields[i].len - 1]);
        os_FontDrawText(buf, 5, 40 + i * 12);
    }
    tls_keyobject_destroy(pk);
    os_GetKey();
    os_ClrHome();

    // PKCS#8 EC public key
    pk = tls_keyobject_import_public(test2, strlen(test2));
    if (pk == NULL)
    {
        printf("error");
        os_GetKey();
        os_ClrHome();
        return 1;
    }
    for (int i = 0; i < 1; i++)
    {
        sprintf(buf, "%s:tag=%u, size=%u: %02x%02x..%02x%02x",
                pk->meta.pubkey.ec.fields[i].name,
                pk->meta.pubkey.ec.fields[i].tag,
                pk->meta.pubkey.ec.fields[i].len,
                pk->meta.pubkey.ec.fields[i].data[0],
                pk->meta.pubkey.ec.fields[i].data[1],
                pk->meta.pubkey.ec.fields[i].data[pk->meta.pubkey.ec.fields[i].len - 2],
                pk->meta.pubkey.ec.fields[i].data[pk->meta.pubkey.ec.fields[i].len - 1]);
        os_FontDrawText(buf, 5, 40 + i * 12);
    }
    tls_keyobject_destroy(pk);

    os_GetKey();
    return 0;
}

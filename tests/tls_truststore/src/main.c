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
#include "x509.h"
#include "lwip/mem.h"
#include "drivers/mem.h"
#include "rsa.h"

#define TLS_TEST_MAX_HEAP (20u * 1024u)
#define TLS_TEST_POOL_BYTES (16u * 1024u)
#define TLS_TEST_POOL_BLOCK 256u

#define TLS_TRUSTSTORE_VERSION 0

static struct mem_buffer *tls_test_heap;
static int text_y = 20;
static uint8_t tls_cert_der[1800];
static uint8_t tls_cert_der_ca_false[1800];
static const char ca_test_cert_pem[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDnzCCAoegAwIBAgIUHE/g0NoguFZkQL9VBbXbIm/7WDswDQYJKoZIhvcNAQEL\n"
    "BQAwXzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5ZMQswCQYDVQQHDAJOWTERMA8G\n"
    "A1UECgwIY2Fnc3RlY2gxETAPBgNVBAsMCGNhZ3N0ZWNoMRAwDgYDVQQDDAdBbnRo\n"
    "b255MB4XDTI0MDkwODA1NDc1M1oXDTI1MDkwODA1NDc1M1owXzELMAkGA1UEBhMC\n"
    "VVMxCzAJBgNVBAgMAk5ZMQswCQYDVQQHDAJOWTERMA8GA1UECgwIY2Fnc3RlY2gx\n"
    "ETAPBgNVBAsMCGNhZ3N0ZWNoMRAwDgYDVQQDDAdBbnRob255MIIBIjANBgkqhkiG\n"
    "9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8q4s1a+ReNvXPOhFhdpNGwCwfR6WHzRoksko\n"
    "2SJCqwhO9b9+0cUM6WQxCPDtAxba8g6FgJTc2m9x/I1gybyn7++ZrtNaMXgICIFz\n"
    "a5rh5pBNbtHiL+5v1fy7wIkKo34jK3VryRNQTbb5VJqfGD33OJYUp3BfpShRkIwg\n"
    "xocloqXqwB9UOzUF99icUvC3wDy85y4zolIpNEM8zQqEuQSJIISUQuevo0DlvMtB\n"
    "/DMeGQP64pE5/HDz89+agFka1sDWguGyp3TbzvXxiEoigxsj2208unqozsNIYTRG\n"
    "xPF5deNJ/x+3kW4ivBVzpC01/3ETpiMYotxaEARoO0maBDpKzQIDAQABo1MwUTAd\n"
    "BgNVHQ4EFgQUrv2AiZkx1XiN7qY3wGkpiJ5GCjMwHwYDVR0jBBgwFoAUrv2AiZkx\n"
    "1XiN7qY3wGkpiJ5GCjMwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC\n"
    "AQEA6YccSZu9vRgEZ3oHSpB7LRxYF5FxwH2WCUtnxz3uIafzbjnyP7tLkTL845Je\n"
    "VFgAi/ZHpJGKLOxXIqIffGnUe6wuaYFr2M2QdzkKIRvr0/Mi5XFRX0PI7/dAFZhj\n"
    "5DFtdM9avzdczka4r8AB8nHZwcmlQbxdbs/hv1nVsr6mfh5FntuPY3cNulkLwOhq\n"
    "UCKEFl1CoCpz68ejKhszhTrYWVLTfNrm3HwQlMRqXvmv1jWsh9X8sm/IM1psUPmm\n"
    "95VY+2OxBwJRHh1hYVlBn8RxnCM4EGTAqowTv/r8sktY2gW2HulwdMSzxOlApL5f\n"
    "5yiwKkSmPVU7SIUuC5UVOujblw==\n"
    "-----END CERTIFICATE-----\n";

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

static bool tls_patch_basic_constraints_ca_false(uint8_t *der, size_t der_len)
{
    size_t i = 0;
    if (!der || der_len < 5)
    {
        return false;
    }

    /* BasicConstraints CA:TRUE encoding: 30 03 01 01 FF */
    for (i = 0; i + 5 <= der_len; i++)
    {
        if (der[i] == 0x30 && der[i + 1] == 0x03 &&
            der[i + 2] == 0x01 && der[i + 3] == 0x01 &&
            der[i + 4] == 0xFF)
        {
            der[i + 4] = 0x00;
            return true;
        }
    }

    return false;
}

static const struct tls_spki_entry *tls_truststore_first_entry(void)
{
    var_t *truststore_var = os_GetAppVarData("lwIPSPKI", NULL);
    if (!truststore_var)
    {
        return NULL;
    }

    uint16_t truststore_size = *((uint16_t *)truststore_var);
    if (truststore_size < TLS_SPKI_HEADER_LEN)
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

    const uint8_t *spki_db_start = (const uint8_t *)header + TLS_SPKI_HEADER_LEN;
    return (const struct tls_spki_entry *)spki_db_start;
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

    if (!tls_init())
    {
        draw_line("tls init failed");
        os_GetKey();
        return 1;
    }

    {
        int archived = 0;
        var_t *truststore_var = os_GetAppVarData("lwIPSPKI", &archived);
        if (!truststore_var)
        {
            draw_line("appvar missing");
            os_GetKey();
            return 1;
        }
        uint16_t truststore_size = *((uint16_t *)truststore_var);
        (void)archived;
        if (truststore_size < TLS_SPKI_HEADER_LEN)
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

    bool lookup_ok = false;
    if (entry)
    {
        struct tls_spki_entry found = {0};
        if (tls_truststore_lookup((uint8_t *)entry->hash, &found))
        {
            const char expected[] = "COMODO Certification Authority";
            size_t expected_len = sizeof(expected) - 1;
            size_t owner_len = strnlen((const char *)found.owner_id, TLS_SPKI_OWNER_ID_LEN);
            lookup_ok = (owner_len == expected_len) &&
                        (memcmp(found.owner_id, expected, expected_len) == 0);
        }
    }
    draw_line(lookup_ok ? "Test 3 (Hash lookup): pass" : "Test 3 (Hash lookup): fail");
    os_GetKey();
    bool constraints_ok = false;
    {
        size_t cert_der_len = 0;
        struct tls_asn1_serialization parsed_fields[13];
        struct tls_x509_parse_result parsed = {0};

        if (tls_x509_import_and_parse_certificate(ca_test_cert_pem,
                                                  strlen(ca_test_cert_pem),
                                                  tls_cert_der,
                                                  sizeof(tls_cert_der),
                                                  &cert_der_len,
                                                  parsed_fields,
                                                  &parsed))
        {
            if (cert_der_len <= sizeof(tls_cert_der_ca_false))
            {
                constraints_ok = true;
                memcpy(tls_cert_der_ca_false, tls_cert_der, cert_der_len);
                constraints_ok &= tls_x509_has_required_ca_constraints(tls_cert_der, cert_der_len);
                if (tls_patch_basic_constraints_ca_false(tls_cert_der_ca_false, cert_der_len))
                {
                    constraints_ok &= !tls_x509_has_required_ca_constraints(tls_cert_der_ca_false, cert_der_len);
                }
            }
        }
    }
    draw_line(constraints_ok ? "Test 4 (Constraints): pass" : "Test 4 (Constraints): fail");

    os_GetKey();
    tls_cleanup();
    return (sig_ok && owner_ok && lookup_ok && constraints_ok) ? 0 : 1;
}

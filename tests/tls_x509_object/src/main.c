#include <ti/screen.h>
#include <ti/getkey.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "lwip/mem.h"
#include "keyobject.h"
#include "hash.h"

// test vectors
const char *test1 = "-----BEGIN CERTIFICATE-----\nMIIDnzCCAoegAwIBAgIUHE/g0NoguFZkQL9VBbXbIm/7WDswDQYJKoZIhvcNAQELBQAwXzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5ZMQswCQYDVQQHDAJOWTERMA8GA1UECgwIY2Fnc3RlY2gxETAPBgNVBAsMCGNhZ3N0ZWNoMRAwDgYDVQQDDAdBbnRob255MB4XDTI0MDkwODA1NDc1M1oXDTI1MDkwODA1NDc1M1owXzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5ZMQswCQYDVQQHDAJOWTERMA8GA1UECgwIY2Fnc3RlY2gxETAPBgNVBAsMCGNhZ3N0ZWNoMRAwDgYDVQQDDAdBbnRob255MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8q4s1a+ReNvXPOhFhdpNGwCwfR6WHzRoksko2SJCqwhO9b9+0cUM6WQxCPDtAxba8g6FgJTc2m9x/I1gybyn7++ZrtNaMXgICIFza5rh5pBNbtHiL+5v1fy7wIkKo34jK3VryRNQTbb5VJqfGD33OJYUp3BfpShRkIwgxocloqXqwB9UOzUF99icUvC3wDy85y4zolIpNEM8zQqEuQSJIISUQuevo0DlvMtB/DMeGQP64pE5/HDz89+agFka1sDWguGyp3TbzvXxiEoigxsj2208unqozsNIYTRGxPF5deNJ/x+3kW4ivBVzpC01/3ETpiMYotxaEARoO0maBDpKzQIDAQABo1MwUTAdBgNVHQ4EFgQUrv2AiZkx1XiN7qY3wGkpiJ5GCjMwHwYDVR0jBBgwFoAUrv2AiZkx1XiN7qY3wGkpiJ5GCjMwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEA6YccSZu9vRgEZ3oHSpB7LRxYF5FxwH2WCUtnxz3uIafzbjnyP7tLkTL845JeVFgAi/ZHpJGKLOxXIqIffGnUe6wuaYFr2M2QdzkKIRvr0/Mi5XFRX0PI7/dAFZhj5DFtdM9avzdczka4r8AB8nHZwcmlQbxdbs/hv1nVsr6mfh5FntuPY3cNulkLwOhqUCKEFl1CoCpz68ejKhszhTrYWVLTfNrm3HwQlMRqXvmv1jWsh9X8sm/IM1psUPmm95VY+2OxBwJRHh1hYVlBn8RxnCM4EGTAqowTv/r8sktY2gW2HulwdMSzxOlApL5f5yiwKkSmPVU7SIUuC5UVOujblw==\n-----END CERTIFICATE-----";

const char *test2 = "-----BEGIN CERTIFICATE-----\nMIICGTCCAb6gAwIBAgIUelyvLQVjwgP/NKxkCEhKNR4+ihYwCgYIKoZIzj0EAwIwfjELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5ZMQwwCgYDVQQHDANOWUMxGjAYBgNVBAoMEUNhZ3NUZWNoIFNlcnZpY2VzMRUwEwYDVQQDDAxjYWdzdGVjaC5jb20xITAfBgkqhkiG9w0BCQEWEmFkbWluQGNhZ3N0ZWNoLmNvbTAeFw0yNDA5MDgxNzI4NTNaFw0yNTA5MDgxNzI4NTNaMFYxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJOWTEMMAoGA1UEBwwDTllDMRUwEwYDVQQKDAxsd0lQLUNFIFRlc3QxFTATBgNVBAMMDGx3SVAtQ0UgVGVzdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABK8QfpEyfVr5muIzTlM1zkRG3ggoaXNZi1FDX1JUDDWi49+wFgZTjY9+Jljb6qQB6rdBFGPH+suhcI5Pk52bc3qjQjBAMB0GA1UdDgQWBBQzpfSZI6ZuFuN3md3gLlCT+w3EljAfBgNVHSMEGDAWgBSXy6NjMevtANrQhdJ6whQX/GAmVTAKBggqhkjOPQQDAgNJADBGAiEA7+TFhvDMTydQ9boop5kODjMydBoSH56wBl+40OjEz+ICIQCfmxOLuQTDHsvBvaP8w0OkYQgz4rSAt09ZNmit+vq4Hw==-----END CERTIFICATE\n-----";

/* Main function, called first */
int main(void)
{
    /* Clear the homescreen */
    os_ClrHome();
    os_FontSelect(os_SmallFont);

    /* lwIP memory allocator function pointers */
    extern void *(*caller_malloc_ref)(size_t);
    extern void (*caller_free_ref)(void *);

    /* Set up memory allocator for lwIP's custom malloc */
    caller_malloc_ref = malloc;
    caller_free_ref = free;
    mem_init();

    int i;
    char buf[128];

    struct tls_keyobject *pk = NULL;
    pk = tls_keyobject_import_certificate(test1, strlen(test1));
    if (pk == NULL)
    {
        printf("error");
        os_GetKey();
        os_ClrHome();
        return 1;
    }
    os_FontDrawText("--certificate--", 5, 40);

    char *sigalg = "unknown";
    char *casigalg = "unknown";
    if (memcmp(pk->meta.certificate.field.subj_signature_alg.data, tls_objectid_bytes[TLS_OID_SHA256_RSA_ENCRYPTION], pk->meta.certificate.field.subj_signature_alg.len) == 0)
        sigalg = "rsa-sha256";
    else if (memcmp(pk->meta.certificate.field.subj_signature_alg.data, tls_objectid_bytes[TLS_OID_SHA256_ECDSA], pk->meta.certificate.field.subj_signature_alg.len) == 0)
        sigalg = "ecdsa-sha256";

    if (memcmp(pk->meta.certificate.field.ca_signature_alg.data, tls_objectid_bytes[TLS_OID_SHA256_RSA_ENCRYPTION], pk->meta.certificate.field.ca_signature_alg.len) == 0)
        casigalg = "rsa-sha256";
    else if (memcmp(pk->meta.certificate.field.ca_signature_alg.data, tls_objectid_bytes[TLS_OID_SHA256_ECDSA], pk->meta.certificate.field.ca_signature_alg.len) == 0)
        casigalg = "ecdsa-sha256";

    sprintf(buf, "sigAlg: %s", sigalg);
    os_FontDrawText(buf, 10, 52);
    sprintf(buf, "issuer: %.*s", pk->meta.certificate.field.issuer.len, pk->meta.certificate.field.issuer.data);
    os_FontDrawText(buf, 10, 64);
    sprintf(buf, "subject: %.*s", pk->meta.certificate.field.subject.len, pk->meta.certificate.field.subject.data);
    os_FontDrawText(buf, 10, 76);
    os_FontDrawText("expiry:", 10, 88);
    sprintf(buf, "before: %.*s", pk->meta.certificate.field.valid_before.len, pk->meta.certificate.field.valid_before.data);
    os_FontDrawText(buf, 20, 100);
    sprintf(buf, "after: %.*s", pk->meta.certificate.field.valid_after.len, pk->meta.certificate.field.valid_after.data);
    os_FontDrawText(buf, 20, 112);
    sprintf(buf, "caSigAlg: %s", casigalg);
    os_FontDrawText(buf, 10, 124);
    for (i = 0; i < 2; i++)
    {
        sprintf(buf, "%s:tag=%u, size=%u: %02x%02x..%02x%02x",
                pk->meta.certificate.field.pubkey.rsa.fields[i].name,
                pk->meta.certificate.field.pubkey.rsa.fields[i].tag,
                pk->meta.certificate.field.pubkey.rsa.fields[i].len,
                pk->meta.certificate.field.pubkey.rsa.fields[i].data[0],
                pk->meta.certificate.field.pubkey.rsa.fields[i].data[1],
                pk->meta.certificate.field.pubkey.rsa.fields[i].data[pk->meta.certificate.field.pubkey.rsa.fields[i].len - 2],
                pk->meta.certificate.field.pubkey.rsa.fields[i].data[pk->meta.certificate.field.pubkey.rsa.fields[i].len - 1]);
        os_FontDrawText(buf, 10, 136 + i * 12);
    }
    sprintf(buf, "%s:tag=%u, size=%u: %02x%02x..%02x%02x",
            pk->meta.certificate.field.ca_signature.name,
            pk->meta.certificate.field.ca_signature.tag,
            pk->meta.certificate.field.ca_signature.len,
            pk->meta.certificate.field.ca_signature.data[0],
            pk->meta.certificate.field.ca_signature.data[1],
            pk->meta.certificate.field.ca_signature.data[pk->meta.certificate.field.ca_signature.len - 2],
            pk->meta.certificate.field.ca_signature.data[pk->meta.certificate.field.ca_signature.len - 1]);
    os_FontDrawText(buf, 10, 136 + i * 12);

    /* SPKI expected hashes */
    const uint8_t expected_spki_rsa[32] = {
        0x42, 0xf2, 0x45, 0x3b, 0x89, 0x48, 0xef, 0xda,
        0x76, 0x7b, 0xb2, 0xae, 0x8a, 0x79, 0x21, 0xe3,
        0xb6, 0xe5, 0x17, 0x04, 0x4f, 0x74, 0x01, 0x02,
        0xbe, 0x46, 0xaa, 0x08, 0x49, 0xb4, 0xfb, 0x0d};

    const uint8_t expected_spki_ec[32] = {
        0x2f, 0x8f, 0x21, 0x2a, 0x1a, 0xe9, 0x8e, 0x5c,
        0xdc, 0x7b, 0x92, 0xe2, 0xdc, 0xca, 0xa7, 0x90,
        0xfe, 0x44, 0x93, 0x89, 0x34, 0x4a, 0x7d, 0xb7,
        0x06, 0xe8, 0x5f, 0x44, 0xdf, 0x25, 0x5c, 0x2a};

    uint8_t computed_spki[32];
    struct tls_hash_context hash_ctx;

    /* Compute SPKI hash for RSA cert BEFORE destroying */
    if (!tls_hash_context_init(&hash_ctx, TLS_HASH_SHA256))
    {
        printf("Hash init failed\n");
        tls_keyobject_destroy(pk);
        os_GetKey();
        return 1;
    }

    hash_ctx.update(&hash_ctx._private, pk->meta.certificate.field.spki_raw.data,
                    pk->meta.certificate.field.spki_raw.len);
    hash_ctx.digest(&hash_ctx._private, computed_spki);

    bool rsa_match = (memcmp(computed_spki, expected_spki_rsa, 32) == 0);
    sprintf(buf, "SPKI Hash 1: %s", rsa_match ? "Pass" : "Fail");
    os_FontDrawText(buf, 10, 178);

    tls_keyobject_destroy(pk);
    pk = NULL;

    os_GetKey();
    os_ClrHome();

    /* Test 2: EC certificate - show components + SPKI test */
    pk = tls_keyobject_import_certificate(test2, strlen(test2));
    if (pk == NULL)
    {
        printf("error");
        os_GetKey();
        os_ClrHome();
        return 1;
    }
    os_FontDrawText("--certificate 2--", 5, 40);

    sigalg = "unknown";
    casigalg = "unknown";
    if (memcmp(pk->meta.certificate.field.subj_signature_alg.data, tls_objectid_bytes[TLS_OID_SHA256_RSA_ENCRYPTION], pk->meta.certificate.field.subj_signature_alg.len) == 0)
        sigalg = "rsa-sha256";
    else if (memcmp(pk->meta.certificate.field.subj_signature_alg.data, tls_objectid_bytes[TLS_OID_SHA256_ECDSA], pk->meta.certificate.field.subj_signature_alg.len) == 0)
        sigalg = "ecdsa-sha256";

    if (memcmp(pk->meta.certificate.field.ca_signature_alg.data, tls_objectid_bytes[TLS_OID_SHA256_RSA_ENCRYPTION], pk->meta.certificate.field.ca_signature_alg.len) == 0)
        casigalg = "rsa-sha256";
    else if (memcmp(pk->meta.certificate.field.ca_signature_alg.data, tls_objectid_bytes[TLS_OID_SHA256_ECDSA], pk->meta.certificate.field.ca_signature_alg.len) == 0)
        casigalg = "ecdsa-sha256";

    sprintf(buf, "sigAlg: %s", sigalg);
    os_FontDrawText(buf, 10, 52);
    sprintf(buf, "issuer: %.*s", pk->meta.certificate.field.issuer.len, pk->meta.certificate.field.issuer.data);
    os_FontDrawText(buf, 10, 64);
    sprintf(buf, "subject: %.*s", pk->meta.certificate.field.subject.len, pk->meta.certificate.field.subject.data);
    os_FontDrawText(buf, 10, 76);
    os_FontDrawText("expiry:", 10, 88);
    sprintf(buf, "before: %.*s", pk->meta.certificate.field.valid_before.len, pk->meta.certificate.field.valid_before.data);
    os_FontDrawText(buf, 20, 100);
    sprintf(buf, "after: %.*s", pk->meta.certificate.field.valid_after.len, pk->meta.certificate.field.valid_after.data);
    os_FontDrawText(buf, 20, 112);
    sprintf(buf, "caSigAlg: %s", casigalg);
    os_FontDrawText(buf, 10, 124);
    for (i = 0; i < 1; i++)
    {
        sprintf(buf, "%s:tag=%u, size=%u: %02x%02x..%02x%02x",
                pk->meta.certificate.field.pubkey.ec.ec_point.name,
                pk->meta.certificate.field.pubkey.ec.ec_point.tag,
                pk->meta.certificate.field.pubkey.ec.ec_point.len,
                pk->meta.certificate.field.pubkey.ec.ec_point.data[0],
                pk->meta.certificate.field.pubkey.ec.ec_point.data[1],
                pk->meta.certificate.field.pubkey.ec.ec_point.data[pk->meta.certificate.field.pubkey.ec.ec_point.len - 2],
                pk->meta.certificate.field.pubkey.ec.ec_point.data[pk->meta.certificate.field.pubkey.ec.ec_point.len - 1]);
        os_FontDrawText(buf, 10, 136 + i * 12);
    }
    sprintf(buf, "%s:tag=%u, size=%u: %02x%02x..%02x%02x",
            pk->meta.certificate.field.ca_signature.name,
            pk->meta.certificate.field.ca_signature.tag,
            pk->meta.certificate.field.ca_signature.len,
            pk->meta.certificate.field.ca_signature.data[0],
            pk->meta.certificate.field.ca_signature.data[1],
            pk->meta.certificate.field.ca_signature.data[pk->meta.certificate.field.ca_signature.len - 2],
            pk->meta.certificate.field.ca_signature.data[pk->meta.certificate.field.ca_signature.len - 1]);
    os_FontDrawText(buf, 10, 136 + i * 12);

    /* Compute SPKI hash for EC cert BEFORE destroying */
    if (!tls_hash_context_init(&hash_ctx, TLS_HASH_SHA256))
    {
        printf("Hash init failed\n");
        tls_keyobject_destroy(pk);
        os_GetKey();
        return 1;
    }

    hash_ctx.update(&hash_ctx._private, pk->meta.certificate.field.spki_raw.data,
                    pk->meta.certificate.field.spki_raw.len);
    hash_ctx.digest(&hash_ctx._private, computed_spki);

    bool ec_match = (memcmp(computed_spki, expected_spki_ec, 32) == 0);
    sprintf(buf, "SPKI Hash 2: %s", ec_match ? "Pass" : "Fail");
    os_FontDrawText(buf, 10, 178);

    tls_keyobject_destroy(pk);
    pk = NULL;

    os_GetKey();
    os_ClrHome();

    return (rsa_match && ec_match) ? 0 : 1;
}

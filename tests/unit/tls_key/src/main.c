/**
 * @file main.c
 * @brief tls_key unit tests
 *
 * Tests the tls_key_* dispatch layer:
 *   1.  AES-128-GCM  round-trip (no AAD)
 *   2.  AES-128-GCM  round-trip with AAD
 *   3.  AES-256-GCM  round-trip with AAD
 *   4.  AES-128-GCM  bad-tag → decrypt returns NULL
 *   5.  AES-128-CCM  round-trip with AAD
 *   6.  AES-128-CBC  round-trip (no AAD)
 *   7.  AES-256-CBC  round-trip (no AAD)
 *   8.  tls_key_sign stub → TLS_KEY_OP_UNSUPPORTED
 *   9.  tls_key_verify with unknown alg → TLS_KEY_OP_UNKNOWN
 *
 * Encrypt returns a self-describing blob:
 *   <u16 iv_len><iv><u16 ct_len><ct><u16 tag_len><tag>
 * Decrypt returns a self-describing blob:
 *   <u16 plain_len><plaintext>
 * All u16 values are little-endian.
 *
 * Sources:
 *   GCM key/plaintext/aad: McGrew/Viega GCM Specification Appendix B, Test Case 4
 *   CBC key/plaintext:     NIST SP 800-38A Appendix F.2.1/F.2.5
 *   CCM key/plaintext/aad: RFC 3610 Section 8, Packet Vector #1
 */

#include <ti/screen.h>
#include <ti/getkey.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <lwip.h>
#include <lwip/cryptography/key.h>
#include <lwip/cryptography/random.h>

/* --------------------------------------------------------------------------
 * Test vectors
 * -------------------------------------------------------------------------- */

/* McGrew/Viega GCM Spec, Appendix B, Test Case 4 — 128-bit key */
static const uint8_t gcm128_key[] = {
    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
    0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
};
static const uint8_t gcm_plaintext[] = {
    0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
    0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
    0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
    0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
    0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
    0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
    0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
    0xba, 0x63, 0x7b, 0x39
};
static const uint8_t gcm_aad[] = {
    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
    0xab, 0xad, 0xda, 0xd2
};

/* GCM Test Case 4 with 256-bit key (same plaintext, different key) */
static const uint8_t gcm256_key[] = {
    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
    0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
    0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
};

/* NIST SP 800-38A Appendix F.2.1, CBC-AES128 */
static const uint8_t cbc128_key[] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};
static const uint8_t cbc_plaintext[] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
    0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
    0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};

/* NIST SP 800-38A Appendix F.2.5, CBC-AES256 */
static const uint8_t cbc256_key[] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
};

/* RFC 3610 Section 8, Packet Vector #1 — 128-bit key, 13-byte nonce */
static const uint8_t ccm128_key[] = {
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf
};
static const uint8_t ccm_aad[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
};
static const uint8_t ccm_plaintext[] = {
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e
};

/* --------------------------------------------------------------------------
 * Blob field accessors (little-endian u16 prefix convention)
 * -------------------------------------------------------------------------- */

static uint16_t blob_u16(const uint8_t *p)
{
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

/* Return pointer to the encrypt blob's tag field, or NULL if tag_len == 0. */
static uint8_t *encrypt_blob_tag(uint8_t *blob)
{
    uint16_t iv_len = blob_u16(blob);
    uint16_t ct_len = blob_u16(blob + 2 + iv_len);
    uint16_t tag_len = blob_u16(blob + 2 + iv_len + 2 + ct_len);
    if (tag_len == 0)
        return NULL;
    return blob + 2 + iv_len + 2 + ct_len + 2;
}

/* Return pointer to plaintext inside a decrypt blob, and set *len. */
static const uint8_t *decrypt_blob_plaintext(const uint8_t *blob, size_t *len)
{
    *len = blob_u16(blob);
    return blob + 2;
}

/* --------------------------------------------------------------------------
 * Helpers
 * -------------------------------------------------------------------------- */

static void show_result(bool ok)
{
    if (ok)
        printf("success");
    else
        printf("failed");
    os_GetKey();
    os_ClrHome();
}

/* --------------------------------------------------------------------------
 * Main
 * -------------------------------------------------------------------------- */

int main(void)
{
    if (!lwip_start()) return 1;
    os_ClrHome();

    /* One-shot encryption requires a healthy RNG for its fresh IV. On CEmu,
     * the entropy source may not be ready immediately after lwip_start(). */
    uint32_t rng_wait_start = lwip_now_ms();
    while (!tls_rng_healthcheck())
    {
        lwip_service_events();
        if ((uint32_t)(lwip_now_ms() - rng_wait_start) >= 10000u)
        {
            printf("RNG setup timed out");
            os_GetKey();
            return 1;
        }
    }

    struct tls_key k = {0};
    tls_alg_t alg;
    bool ok;

    /* ------------------------------------------------------------------
     * Test 1: AES-128-GCM round-trip, no AAD
     * ------------------------------------------------------------------ */
    k.type = TLS_KEY_TYPE_AES;
    alg = TLS_ALG_AES_128_GCM;
    k.aes.data = gcm128_key;
    k.aes.len  = sizeof gcm128_key;
    {
        uint8_t *enc = tls_cipher_encrypt(&k, alg, gcm_plaintext, sizeof gcm_plaintext);
        uint8_t *dec = enc ? tls_cipher_decrypt(&k, alg, enc) : NULL;
        size_t plen;
        const uint8_t *pt = dec ? decrypt_blob_plaintext(dec, &plen) : NULL;
        ok = pt && plen == sizeof gcm_plaintext &&
             memcmp(pt, gcm_plaintext, sizeof gcm_plaintext) == 0;
        tls_cipher_blob_free(enc);
        tls_cipher_blob_free(dec);
    }
    show_result(ok);

    /* ------------------------------------------------------------------
     * Test 2: AES-128-GCM round-trip with AAD
     * ------------------------------------------------------------------ */
    {
        uint8_t *enc = tls_cipher_encrypt_aad(&k, alg,
                                            gcm_aad, sizeof gcm_aad,
                                            gcm_plaintext, sizeof gcm_plaintext);
        uint8_t *dec = enc ? tls_cipher_decrypt_aad(&k, alg,
                                                   gcm_aad, sizeof gcm_aad,
                                                   enc) : NULL;
        size_t plen;
        const uint8_t *pt = dec ? decrypt_blob_plaintext(dec, &plen) : NULL;
        ok = pt && plen == sizeof gcm_plaintext &&
             memcmp(pt, gcm_plaintext, sizeof gcm_plaintext) == 0;
        tls_cipher_blob_free(enc);
        tls_cipher_blob_free(dec);
    }
    show_result(ok);

    /* ------------------------------------------------------------------
     * Test 3: AES-256-GCM round-trip with AAD
     * ------------------------------------------------------------------ */
    k.type = TLS_KEY_TYPE_AES;
    alg = TLS_ALG_AES_256_GCM;
    k.aes.data = gcm256_key;
    k.aes.len  = sizeof gcm256_key;
    {
        uint8_t *enc = tls_cipher_encrypt_aad(&k, alg,
                                            gcm_aad, sizeof gcm_aad,
                                            gcm_plaintext, sizeof gcm_plaintext);
        uint8_t *dec = enc ? tls_cipher_decrypt_aad(&k, alg,
                                                   gcm_aad, sizeof gcm_aad,
                                                   enc) : NULL;
        size_t plen;
        const uint8_t *pt = dec ? decrypt_blob_plaintext(dec, &plen) : NULL;
        ok = pt && plen == sizeof gcm_plaintext &&
             memcmp(pt, gcm_plaintext, sizeof gcm_plaintext) == 0;
        tls_cipher_blob_free(enc);
        tls_cipher_blob_free(dec);
    }
    show_result(ok);

    /* ------------------------------------------------------------------
     * Test 4: AES-128-GCM bad tag → decrypt must return NULL
     * ------------------------------------------------------------------ */
    k.type = TLS_KEY_TYPE_AES;
    alg = TLS_ALG_AES_128_GCM;
    k.aes.data = gcm128_key;
    k.aes.len  = sizeof gcm128_key;
    {
        uint8_t *enc = tls_cipher_encrypt(&k, alg, gcm_plaintext, sizeof gcm_plaintext);
        ok = enc != NULL;
        if (ok)
        {
            uint8_t *tag = encrypt_blob_tag(enc);
            ok = tag != NULL;
            if (ok)
                tag[0] ^= 0xFF;  /* corrupt the tag */
        }
        uint8_t *dec = ok ? tls_cipher_decrypt(&k, alg, enc) : NULL;
        ok = ok && dec == NULL;
        tls_cipher_blob_free(enc);
        /* dec is NULL, tls_cipher_blob_free(NULL) is safe but skip for clarity */
    }
    show_result(ok);

    /* ------------------------------------------------------------------
     * Test 5: AES-128-CCM round-trip with AAD
     * ------------------------------------------------------------------ */
    k.type = TLS_KEY_TYPE_AES;
    alg = TLS_ALG_AES_128_CCM;
    k.aes.data = ccm128_key;
    k.aes.len  = sizeof ccm128_key;
    {
        uint8_t *enc = tls_cipher_encrypt_aad(&k, alg,
                                            ccm_aad, sizeof ccm_aad,
                                            ccm_plaintext, sizeof ccm_plaintext);
        uint8_t *dec = enc ? tls_cipher_decrypt_aad(&k, alg,
                                                   ccm_aad, sizeof ccm_aad,
                                                   enc) : NULL;
        size_t plen;
        const uint8_t *pt = dec ? decrypt_blob_plaintext(dec, &plen) : NULL;
        ok = pt && plen == sizeof ccm_plaintext &&
             memcmp(pt, ccm_plaintext, sizeof ccm_plaintext) == 0;
        tls_cipher_blob_free(enc);
        tls_cipher_blob_free(dec);
    }
    show_result(ok);

    /* ------------------------------------------------------------------
     * Test 6: AES-128-CBC round-trip (no AAD, no tag)
     * ------------------------------------------------------------------ */
    k.type = TLS_KEY_TYPE_AES;
    alg = TLS_ALG_AES_128_CBC;
    k.aes.data = cbc128_key;
    k.aes.len  = sizeof cbc128_key;
    {
        uint8_t *enc = tls_cipher_encrypt(&k, alg, cbc_plaintext, sizeof cbc_plaintext);
        uint8_t *dec = enc ? tls_cipher_decrypt(&k, alg, enc) : NULL;
        size_t plen;
        const uint8_t *pt = dec ? decrypt_blob_plaintext(dec, &plen) : NULL;
        ok = pt && plen == sizeof cbc_plaintext &&
             memcmp(pt, cbc_plaintext, sizeof cbc_plaintext) == 0;
        tls_cipher_blob_free(enc);
        tls_cipher_blob_free(dec);
    }
    show_result(ok);

    /* ------------------------------------------------------------------
     * Test 7: AES-256-CBC round-trip (no AAD, no tag)
     * ------------------------------------------------------------------ */
    k.type = TLS_KEY_TYPE_AES;
    alg = TLS_ALG_AES_256_CBC;
    k.aes.data = cbc256_key;
    k.aes.len  = sizeof cbc256_key;
    {
        uint8_t *enc = tls_cipher_encrypt(&k, alg, cbc_plaintext, sizeof cbc_plaintext);
        uint8_t *dec = enc ? tls_cipher_decrypt(&k, alg, enc) : NULL;
        size_t plen;
        const uint8_t *pt = dec ? decrypt_blob_plaintext(dec, &plen) : NULL;
        ok = pt && plen == sizeof cbc_plaintext &&
             memcmp(pt, cbc_plaintext, sizeof cbc_plaintext) == 0;
        tls_cipher_blob_free(enc);
        tls_cipher_blob_free(dec);
    }
    show_result(ok);

    /* ------------------------------------------------------------------
     * Test 8: tls_key_sign stub → UNSUPPORTED for signing algs,
     *         UNKNOWN for encryption-range algs (wrong key type for sign)
     * ------------------------------------------------------------------ */
    uint8_t sig_buf[256];
    size_t  sig_len = 0;
    k.type = TLS_KEY_TYPE_RSA;
    alg = TLS_ALG_RSA_PSS_RSAE_SHA256;
    k.aes.data = NULL;
    k.aes.len  = 0;
    ok = (tls_key_sign(gcm_plaintext, sizeof gcm_plaintext,
                       sig_buf, &sig_len, &k, alg) == TLS_KEY_OP_UNSUPPORTED);
    k.type = TLS_KEY_TYPE_EC_P256;
    alg = TLS_ALG_ECDSA_SECP256R1_SHA256;
    ok = ok && (tls_key_sign(gcm_plaintext, sizeof gcm_plaintext,
                             sig_buf, &sig_len, &k, alg) == TLS_KEY_OP_UNSUPPORTED);
    /* Encryption-range alg passed to sign → UNKNOWN (wrong key type) */
    k.type = TLS_KEY_TYPE_AES;
    alg = TLS_ALG_AES_128_GCM;
    ok = ok && (tls_key_sign(gcm_plaintext, sizeof gcm_plaintext,
                             sig_buf, &sig_len, &k, alg) == TLS_KEY_OP_UNKNOWN);
    show_result(ok);

    /* ------------------------------------------------------------------
     * Test 9: cross-type rejection
     *   a) tls_key_verify with encryption-range alg → TLS_KEY_OP_UNKNOWN
     *   b) tls_cipher_encrypt with signing-range alg   → NULL
     *   c) tls_cipher_decrypt with signing-range alg   → NULL
     * ------------------------------------------------------------------ */
    k.type = TLS_KEY_TYPE_AES;
    alg = TLS_ALG_AES_128_GCM;
    k.aes.data = gcm128_key;
    k.aes.len  = sizeof gcm128_key;
    ok = (tls_key_verify(gcm_plaintext, sizeof gcm_plaintext,
                         sig_buf, 16, &k, alg) == TLS_KEY_OP_UNKNOWN);
    /* Signing-range alg (RSA-PSS) has no encrypt/decrypt dispatch → NULL */
    k.type = TLS_KEY_TYPE_RSA;
    alg = TLS_ALG_RSA_PSS_RSAE_SHA256;
    k.rsa.mod_len  = 0;
    k.rsa.modulus  = NULL;
    k.rsa.exp_len  = 0;
    k.rsa.exponent = NULL;
    {
        uint8_t *rej_enc = tls_cipher_encrypt(&k, alg, gcm_plaintext, sizeof gcm_plaintext);
        ok = ok && rej_enc == NULL;
        /* Build a dummy blob to pass to decrypt */
        uint8_t dummy_blob[6] = {0};  /* all-zero: iv_len=0, ct_len=0, tag_len=0 */
        uint8_t *rej_dec = tls_cipher_decrypt(&k, alg, dummy_blob);
        ok = ok && rej_dec == NULL;
    }
    show_result(ok);

    return 0;
}

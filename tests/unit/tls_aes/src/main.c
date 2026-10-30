#include <ti/screen.h>
#include <ti/getkey.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <lwip/cryptography/aes.h>
#include <lwip.h>

/*
 * AES-128-GCM Test Case 4 (with AAD)
 * Source: McGrew/Viega GCM Specification, Appendix B, Test Case 4
 */
uint8_t gcm_key[] = {
    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08};
uint8_t gcm_iv[] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88};
uint8_t gcm_plaintext[] = {
    0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
    0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
    0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
    0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39};
uint8_t gcm_aad[] = {
    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
    0xab, 0xad, 0xda, 0xd2};
uint8_t gcm_ciphertext[] = {
    0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c,
    0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0, 0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e,
    0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c, 0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05,
    0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97, 0x3d, 0x58, 0xe0, 0x91};
uint8_t gcm_tag[] = {
    0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb, 0x94, 0xfa, 0xe9, 0x5a, 0xe7, 0x12, 0x1a, 0x47};

/*
 * NIST SP 800-38A AES-128-CBC Test Vector
 * Source: SP 800-38A, Appendix F.2.1 (CBC-AES128.Encrypt)
 */
uint8_t cbc_key[] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
uint8_t cbc_iv[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
uint8_t cbc_plaintext[] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};
uint8_t cbc_ciphertext[] = {
    0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
    0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
    0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
    0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7};

/*
 * NIST SP 800-38A AES-192-CBC Test Vector
 * Source: SP 800-38A, Appendix F.2.3 (CBC-AES192.Encrypt)
 */
uint8_t cbc192_key[] = {
    0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
    0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b};
uint8_t cbc192_ciphertext[] = {
    0x4f, 0x02, 0x1d, 0xb2, 0x43, 0xbc, 0x63, 0x3d, 0x71, 0x78, 0x18, 0x3a, 0x9f, 0xa0, 0x71, 0xe8,
    0xb4, 0xd9, 0xad, 0xa9, 0xad, 0x7d, 0xed, 0xf4, 0xe5, 0xe7, 0x38, 0x76, 0x3f, 0x69, 0x14, 0x5a,
    0x57, 0x1b, 0x24, 0x20, 0x12, 0xfb, 0x7a, 0xe0, 0x7f, 0xa9, 0xba, 0xac, 0x3d, 0xf1, 0x02, 0xe0,
    0x08, 0xb0, 0xe2, 0x79, 0x88, 0x59, 0x88, 0x81, 0xd9, 0x20, 0xa9, 0xe6, 0x4f, 0x56, 0x15, 0xcd};

/*
 * NIST SP 800-38A AES-256-CBC Test Vector
 * Source: SP 800-38A, Appendix F.2.5 (CBC-AES256.Encrypt)
 */
uint8_t cbc256_key[] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
uint8_t cbc256_ciphertext[] = {
    0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6,
    0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d,
    0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf, 0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61,
    0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc, 0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b};

/*
 * AES-CCM Packet Vectors #1 and #2
 * Source: RFC 3610, Section 8 (Test Vectors)
 * https://www.rfc-editor.org/rfc/rfc3610
 */
uint8_t ccm_key[] = {
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf};
uint8_t ccm_nonce_1[] = {
    0x00, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5};
uint8_t ccm_nonce_2[] = {
    0x00, 0x00, 0x00, 0x04, 0x03, 0x02, 0x01, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5};
uint8_t ccm_aad[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
uint8_t ccm_plaintext_1[] = {
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e};
uint8_t ccm_ciphertext_1[] = {
    0x58, 0x8c, 0x97, 0x9a, 0x61, 0xc6, 0x63, 0xd2, 0xf0, 0x66, 0xd0, 0xc2, 0xc0, 0xf9, 0x89, 0x80,
    0x6d, 0x5f, 0x6b, 0x61, 0xda, 0xc3, 0x84};
uint8_t ccm_tag_1[] = {
    0x17, 0xe8, 0xd1, 0x2c, 0xfd, 0xf9, 0x26, 0xe0};
uint8_t ccm_plaintext_2[] = {
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
uint8_t ccm_ciphertext_2[] = {
    0x72, 0xc9, 0x1a, 0x36, 0xe1, 0x35, 0xf8, 0xcf, 0x29, 0x1c, 0xa8, 0x94, 0x08, 0x5c, 0x87, 0xe3,
    0xcc, 0x15, 0xc4, 0x39, 0xc9, 0xe4, 0x3a, 0x3b};
uint8_t ccm_tag_2[] = {
    0xa0, 0x91, 0xd5, 0x6e, 0x10, 0x40, 0x09, 0x16};


/* AES-128-GCM over 9000 bytes of (i*7+3)&0xFF with the GCM Spec Test Case 4
 * key/IV/AAD. Reference tag computed with the Python `cryptography` AESGCM.
 * 9000 bytes = 72000 bits needs the length block's bits 16..23. */
#define GCM_BIG_LEN 9000u
uint8_t gcm_big_tag[] = {
    0x4c, 0xcb, 0x3b, 0x95, 0x8e, 0xf1, 0x6f, 0x25, 0x2e, 0x38, 0x42, 0x88, 0x12, 0x76, 0x7e, 0x42};

/* AES-256-GCM (McGrew/Viega GCM Spec, Test Case 16 with AAD). */
uint8_t gcm256_key[] = {
    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08};
uint8_t gcm256_ciphertext[] = {
    0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07, 0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d,
    0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9, 0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa,
    0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d, 0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
    0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a, 0xbc, 0xc9, 0xf6, 0x62};
uint8_t gcm256_tag[] = {
    0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68, 0xcd, 0xdf, 0x88, 0x53, 0xbb, 0x2d, 0x55, 0x1b};

/* AES-256-CCM, key 0x00..0x1f, RFC 3610-style packet layout. Reference
 * ciphertext/tag computed with the Python `cryptography` AESCCM. */
uint8_t ccm256_key[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
uint8_t ccm256_plaintext[] = {
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26};
uint8_t ccm256_ciphertext[] = {
    0xad, 0x0f, 0x3f, 0xd3, 0x38, 0xe8, 0x56, 0x77, 0x22, 0x11, 0x3a, 0xde, 0x50, 0x76, 0x5e, 0xaa,
    0xfe, 0x57, 0x69, 0x36, 0x50, 0x5f, 0x4d, 0x8e, 0xe5, 0x3e, 0x6b, 0xc6, 0xed, 0x3e, 0x2b};
uint8_t ccm256_tag[] = {
    0x88, 0xa0, 0x93, 0x94, 0x2b, 0x71, 0x2e, 0x03, 0x1f, 0xe8, 0xfe, 0x14, 0x75, 0x47, 0xd3, 0xbf};

/* TLS 1.3 record-level AES-256 vectors: 32-byte content + inner type 23
 * protected with AEAD AAD = the 5-byte record header, nonce = IV XOR seq 0.
 * Reference computed with Python AESGCM/AESCCM. */
uint8_t rec256_iv[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b};
uint8_t rec256_content[] = {
    0x01, 0x04, 0x07, 0x0a, 0x0d, 0x10, 0x13, 0x16, 0x19, 0x1c, 0x1f, 0x22, 0x25, 0x28, 0x2b, 0x2e,
    0x31, 0x34, 0x37, 0x3a, 0x3d, 0x40, 0x43, 0x46, 0x49, 0x4c, 0x4f, 0x52, 0x55, 0x58, 0x5b, 0x5e};
uint8_t rec256_aad[] = {0x17, 0x03, 0x03, 0x00, 0x21};
uint8_t rec256_gcm_plaintext[] = {
    0x01, 0x04, 0x07, 0x0a, 0x0d, 0x10, 0x13, 0x16, 0x19, 0x1c, 0x1f, 0x22, 0x25, 0x28, 0x2b, 0x2e,
    0x31, 0x34, 0x37, 0x3a, 0x3d, 0x40, 0x43, 0x46, 0x49, 0x4c, 0x4f, 0x52, 0x55, 0x58, 0x5b, 0x5e,
    0x17};
uint8_t rec256_gcm_ciphertext[] = {
    0xfd, 0x97, 0xd7, 0x6d, 0xe8, 0x55, 0x8a, 0xaf, 0x4a, 0x24, 0x97, 0x0a, 0xa2, 0x14, 0xee, 0x3c,
    0x6b, 0x73, 0x9b, 0x22, 0x66, 0x32, 0xa0, 0xc3, 0x0b, 0xc9, 0x84, 0x37, 0x4c, 0xcb, 0x0b, 0xff,
    0xc4};
uint8_t rec256_gcm_tag[] = {
    0x66, 0xe0, 0x27, 0x35, 0x5c, 0x97, 0x4e, 0xbd, 0x39, 0xe0, 0x53, 0xd2, 0x8b, 0x14, 0x78, 0xc0};
uint8_t rec256_ccm_ciphertext[] = {
    0x8b, 0xd1, 0xbf, 0x1c, 0x33, 0x3f, 0xda, 0x81, 0xb5, 0xd5, 0xae, 0x01, 0x28, 0x18, 0x77, 0x6a,
    0x0c, 0x40, 0x21, 0x4f, 0x04, 0x35, 0x1b, 0xff, 0x2c, 0xe9, 0xcc, 0x07, 0xc0, 0x40, 0x79, 0x2d,
    0xd2};
uint8_t rec256_ccm_tag[] = {
    0xd9, 0x86, 0x70, 0xd9, 0x2d, 0xa2, 0x20, 0x5e, 0x49, 0xee, 0xcc, 0xf4, 0x00, 0x48, 0xd3, 0xd5};

static bool ccm_encrypt(const uint8_t *key, size_t key_len,
                        const uint8_t *nonce, size_t nonce_len,
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *plaintext, size_t plaintext_len,
                        uint8_t *ciphertext, uint8_t *tag, size_t tag_len)
{
    struct tls_aes_context ctx;
    uint8_t digest[TLS_AES_AUTH_TAG_SIZE];
    memset(&ctx, 0, sizeof(ctx));
    bool ok = tag_len <= sizeof(digest) &&
              tls_aes_ccm_init(&ctx, key, key_len, nonce, nonce_len,
                               (uint8_t)tag_len, plaintext_len, aad_len) &&
              (!aad_len || tls_aes_update_aad(&ctx, aad, aad_len)) &&
              tls_aes_encrypt(&ctx, plaintext, plaintext_len, ciphertext) &&
              tls_aes_digest(&ctx, digest);
    if (ok)
        memcpy(tag, digest, tag_len);
    tls_aes_destroy_ctx(&ctx);
    memset(digest, 0, sizeof(digest));
    return ok;
}

static bool ccm_decrypt(const uint8_t *key, size_t key_len,
                        const uint8_t *nonce, size_t nonce_len,
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *ciphertext, size_t ciphertext_len,
                        const uint8_t *tag, size_t tag_len,
                        uint8_t *plaintext)
{
    struct tls_aes_context ctx;
    memset(&ctx, 0, sizeof(ctx));
    bool ok = tag_len <= UINT8_MAX &&
              tls_aes_ccm_init(&ctx, key, key_len, nonce, nonce_len,
                               (uint8_t)tag_len, ciphertext_len, aad_len);
    /* Authenticated modes must refuse caller-visible plaintext before verify. */
    if (ok)
        ok = !tls_aes_decrypt(&ctx, ciphertext, ciphertext_len, plaintext);
    if (ok)
        ok = tls_aes_verify(&ctx, aad, aad_len,
                            ciphertext, ciphertext_len, tag) &&
             tls_aes_decrypt(&ctx, ciphertext, ciphertext_len, plaintext);
    tls_aes_destroy_ctx(&ctx);
    return ok;
}

static void show_result(bool ok)
{
    if (ok)
        printf("success");
    else
        printf("failed");
    os_GetKey();
    os_ClrHome();
}

/* Main function, called first */
int main(void)
{
    struct tls_aes_context ctx;
    uint8_t tbuf[100] = {0};
    uint8_t tag[TLS_AES_AUTH_TAG_SIZE];
    bool status = true;
    bool ok;

    if (!lwip_start()) return 1;

    os_ClrHome();

    // Test 1: AES-GCM encrypt (GCM Spec Test Case 4)
    status = true;
    memset(tbuf, 0, sizeof(tbuf));
    status &= tls_aes_init(&ctx, TLS_AES_GCM, gcm_key, sizeof gcm_key, gcm_iv, sizeof gcm_iv);
    status &= tls_aes_update_aad(&ctx, gcm_aad, sizeof gcm_aad);
    status &= tls_aes_encrypt(&ctx, gcm_plaintext, sizeof gcm_plaintext, tbuf);
    status &= tls_aes_digest(&ctx, tag);
    ok = status &&
         (memcmp(tbuf, gcm_ciphertext, sizeof gcm_ciphertext) == 0) &&
         (memcmp(tag, gcm_tag, TLS_AES_AUTH_TAG_SIZE) == 0);
    show_result(ok);

    // Test 2: AES-GCM decrypt (GCM Spec Test Case 4)
    status = true;
    memset(tbuf, 0, sizeof(tbuf));
    status &= tls_aes_init(&ctx, TLS_AES_GCM, gcm_key, sizeof gcm_key, gcm_iv, sizeof gcm_iv);
    status &= !tls_aes_decrypt(&ctx, gcm_ciphertext, sizeof gcm_ciphertext, tbuf);
    status &= tls_aes_verify(&ctx, gcm_aad, sizeof gcm_aad, gcm_ciphertext, sizeof gcm_ciphertext, gcm_tag);
    status &= tls_aes_decrypt(&ctx, gcm_ciphertext, sizeof gcm_ciphertext, tbuf);
    status &= memcmp(tbuf, gcm_plaintext, sizeof gcm_plaintext) == 0;
    memcpy(tag, gcm_tag, sizeof gcm_tag);
    tag[0] ^= 0x01;
    memset(tbuf, 0xaa, sizeof(tbuf));
    status &= tls_aes_init(&ctx, TLS_AES_GCM, gcm_key, sizeof gcm_key, gcm_iv, sizeof gcm_iv);
    status &= !tls_aes_verify(&ctx, gcm_aad, sizeof gcm_aad,
                              gcm_ciphertext, sizeof gcm_ciphertext, tag);
    status &= !tls_aes_decrypt(&ctx, gcm_ciphertext,
                               sizeof gcm_ciphertext, tbuf);
    for (size_t i = 0; i < sizeof gcm_plaintext; i++)
        status &= tbuf[i] == 0xaa;
    ok = status;
    show_result(ok);

    // Test 3: AES-CBC encrypt (NIST SP 800-38A F.2.1)
    status = true;
    memset(tbuf, 0, sizeof(tbuf));
    status &= tls_aes_init(&ctx, TLS_AES_CBC, cbc_key, sizeof cbc_key, cbc_iv, sizeof cbc_iv);
    status &= tls_aes_encrypt(&ctx, cbc_plaintext, sizeof cbc_plaintext, tbuf);
    ok = status && (memcmp(tbuf, cbc_ciphertext, sizeof cbc_ciphertext) == 0);
    show_result(ok);

    // Test 4: AES-CBC decrypt (NIST SP 800-38A F.2.2)
    status = true;
    memset(tbuf, 0, sizeof(tbuf));
    status &= tls_aes_init(&ctx, TLS_AES_CBC, cbc_key, sizeof cbc_key, cbc_iv, sizeof cbc_iv);
    status &= !tls_aes_decrypt(&ctx, cbc_ciphertext, sizeof cbc_ciphertext, NULL);
    status &= tls_aes_decrypt(&ctx, cbc_ciphertext, sizeof cbc_ciphertext, tbuf);
    ok = status && (memcmp(tbuf, cbc_plaintext, sizeof cbc_plaintext) == 0);
    show_result(ok);

    // Test 5: AES-CCM encrypt (RFC 3610 Packet Vector #1)
    status = true;
    memset(tbuf, 0, sizeof(tbuf));
    memset(tag, 0, sizeof(tag));
    status &= ccm_encrypt(ccm_key, sizeof ccm_key,
                                  ccm_nonce_1, sizeof ccm_nonce_1,
                                  ccm_aad, sizeof ccm_aad,
                                  ccm_plaintext_1, sizeof ccm_plaintext_1,
                                  tbuf, tag, sizeof ccm_tag_1);
    ok = status &&
         (memcmp(tbuf, ccm_ciphertext_1, sizeof ccm_ciphertext_1) == 0) &&
         (memcmp(tag, ccm_tag_1, sizeof ccm_tag_1) == 0);
    show_result(ok);

    // Test 6: AES-CCM decrypt (RFC 3610 Packet Vector #1)
    status = true;
    memset(tbuf, 0, sizeof(tbuf));
    status &= ccm_decrypt(ccm_key, sizeof ccm_key,
                                  ccm_nonce_1, sizeof ccm_nonce_1,
                                  ccm_aad, sizeof ccm_aad,
                                  ccm_ciphertext_1, sizeof ccm_ciphertext_1,
                                  ccm_tag_1, sizeof ccm_tag_1,
                                  tbuf);
    ok = status && (memcmp(tbuf, ccm_plaintext_1, sizeof ccm_plaintext_1) == 0);
    show_result(ok);

    // Test 7: AES-CCM encrypt (RFC 3610 Packet Vector #2)
    status = true;
    memset(tbuf, 0, sizeof(tbuf));
    memset(tag, 0, sizeof(tag));
    status &= ccm_encrypt(ccm_key, sizeof ccm_key,
                                  ccm_nonce_2, sizeof ccm_nonce_2,
                                  ccm_aad, sizeof ccm_aad,
                                  ccm_plaintext_2, sizeof ccm_plaintext_2,
                                  tbuf, tag, sizeof ccm_tag_2);
    ok = status &&
         (memcmp(tbuf, ccm_ciphertext_2, sizeof ccm_ciphertext_2) == 0) &&
         (memcmp(tag, ccm_tag_2, sizeof ccm_tag_2) == 0);
    show_result(ok);

    // Test 8: AES-CCM decrypt (RFC 3610 Packet Vector #2)
    status = true;
    memset(tbuf, 0, sizeof(tbuf));
    status &= ccm_decrypt(ccm_key, sizeof ccm_key,
                                  ccm_nonce_2, sizeof ccm_nonce_2,
                                  ccm_aad, sizeof ccm_aad,
                                  ccm_ciphertext_2, sizeof ccm_ciphertext_2,
                                  ccm_tag_2, sizeof ccm_tag_2,
                                  tbuf);
    ok = status && (memcmp(tbuf, ccm_plaintext_2, sizeof ccm_plaintext_2) == 0);
    show_result(ok);

    // Test 9: AES-CCM decrypt rejects bad tag without releasing plaintext
    status = true;
    memset(tbuf, 0xaa, sizeof(tbuf));
    uint8_t bad_tag[sizeof ccm_tag_2];
    memcpy(bad_tag, ccm_tag_2, sizeof bad_tag);
    bad_tag[0] ^= 0x01;
    ok = ccm_decrypt(ccm_key, sizeof ccm_key,
                             ccm_nonce_2, sizeof ccm_nonce_2,
                             ccm_aad, sizeof ccm_aad,
                             ccm_ciphertext_2, sizeof ccm_ciphertext_2,
                             bad_tag, sizeof bad_tag,
                             tbuf);
    status &= !ok;
    for (size_t i = 0; i < sizeof ccm_plaintext_2; i++)
        status &= (tbuf[i] == 0xaa);
    show_result(status);

    // Test 10: AES-CCM chunked encrypt and authentication-only decrypt
    status = true;
    memset(tbuf, 0, sizeof(tbuf));
    memset(tag, 0, sizeof(tag));
    status &= tls_aes_ccm_init(&ctx, ccm_key, sizeof ccm_key,
                               ccm_nonce_2, sizeof ccm_nonce_2,
                               sizeof ccm_tag_2, sizeof ccm_plaintext_2,
                               sizeof ccm_aad);
    status &= tls_aes_update_aad(&ctx, ccm_aad, sizeof ccm_aad);
    status &= tls_aes_encrypt(&ctx, ccm_plaintext_2, 5, tbuf);
    status &= tls_aes_encrypt(&ctx, ccm_plaintext_2 + 5, 7, tbuf + 5);
    status &= tls_aes_encrypt(&ctx, ccm_plaintext_2 + 12,
                              sizeof ccm_plaintext_2 - 12, tbuf + 12);
    status &= tls_aes_digest(&ctx, tag);
    status &= memcmp(tbuf, ccm_ciphertext_2, sizeof ccm_ciphertext_2) == 0;
    status &= memcmp(tag, ccm_tag_2, sizeof ccm_tag_2) == 0;

    status &= tls_aes_ccm_init(&ctx, ccm_key, sizeof ccm_key,
                               ccm_nonce_2, sizeof ccm_nonce_2,
                               sizeof ccm_tag_2, sizeof ccm_ciphertext_2,
                               sizeof ccm_aad);
    status &= tls_aes_update_aad(&ctx, ccm_aad, sizeof ccm_aad);
    status &= tls_aes_decrypt(&ctx, ccm_ciphertext_2, 3, NULL);
    status &= tls_aes_decrypt(&ctx, ccm_ciphertext_2 + 3, 11, NULL);
    status &= tls_aes_decrypt(&ctx, ccm_ciphertext_2 + 14,
                              sizeof ccm_ciphertext_2 - 14, NULL);
    status &= tls_aes_digest(&ctx, tag);
    status &= memcmp(tag, ccm_tag_2, sizeof ccm_tag_2) == 0;
    show_result(status);

    // Test 11: AES192-CBC encrypt (NIST SP 800-38A F.2.3)
    status = true;
    memset(tbuf, 0, sizeof(tbuf));
    status &= tls_aes_init(&ctx, TLS_AES_CBC, cbc192_key, sizeof cbc192_key, cbc_iv, sizeof cbc_iv);
    status &= tls_aes_encrypt(&ctx, cbc_plaintext, sizeof cbc_plaintext, tbuf);
    ok = status && (memcmp(tbuf, cbc192_ciphertext, sizeof cbc192_ciphertext) == 0);
    show_result(ok);

    // Test 12: AES192-CBC decrypt (NIST SP 800-38A F.2.4)
    status = true;
    memset(tbuf, 0, sizeof(tbuf));
    status &= tls_aes_init(&ctx, TLS_AES_CBC, cbc192_key, sizeof cbc192_key, cbc_iv, sizeof cbc_iv);
    status &= tls_aes_decrypt(&ctx, cbc192_ciphertext, sizeof cbc192_ciphertext, tbuf);
    ok = status && (memcmp(tbuf, cbc_plaintext, sizeof cbc_plaintext) == 0);
    show_result(ok);

    // Test 13: AES256-CBC encrypt (NIST SP 800-38A F.2.5)
    status = true;
    memset(tbuf, 0, sizeof(tbuf));
    status &= tls_aes_init(&ctx, TLS_AES_CBC, cbc256_key, sizeof cbc256_key, cbc_iv, sizeof cbc_iv);
    status &= tls_aes_encrypt(&ctx, cbc_plaintext, sizeof cbc_plaintext, tbuf);
    ok = status && (memcmp(tbuf, cbc256_ciphertext, sizeof cbc256_ciphertext) == 0);
    show_result(ok);

    // Test 14: AES256-CBC decrypt (NIST SP 800-38A F.2.6)
    status = true;
    memset(tbuf, 0, sizeof(tbuf));
    status &= tls_aes_init(&ctx, TLS_AES_CBC, cbc256_key, sizeof cbc256_key, cbc_iv, sizeof cbc_iv);
    status &= tls_aes_decrypt(&ctx, cbc256_ciphertext, sizeof cbc256_ciphertext, tbuf);
    ok = status && (memcmp(tbuf, cbc_plaintext, sizeof cbc_plaintext) == 0);
    show_result(ok);

    // Test 15: AES-GCM tag over a record >= 8 KiB (length block bits 16..23)
    {
        uint8_t *big = (uint8_t *)malloc(GCM_BIG_LEN);
        uint8_t *out = (uint8_t *)malloc(GCM_BIG_LEN);
        ok = false;
        if (big && out)
        {
            for (size_t i = 0; i < GCM_BIG_LEN; i++)
                big[i] = (uint8_t)(i * 7u + 3u);
            status = true;
            status &= tls_aes_init(&ctx, TLS_AES_GCM, gcm_key, sizeof gcm_key, gcm_iv, sizeof gcm_iv);
            status &= tls_aes_update_aad(&ctx, gcm_aad, sizeof gcm_aad);
            status &= tls_aes_encrypt(&ctx, big, GCM_BIG_LEN, out);
            status &= tls_aes_digest(&ctx, tag);
            ok = status && memcmp(tag, gcm_big_tag, TLS_AES_AUTH_TAG_SIZE) == 0;
        }
        free(big);
        free(out);
        show_result(ok);
    }

    // Test 16: failed initialization and explicit destruction clear the context
    memset(&ctx, 0xa5, sizeof ctx);
    status = !tls_aes_init(&ctx, 0xff, gcm_key, sizeof gcm_key,
                           gcm_iv, sizeof gcm_iv);
    for (size_t i = 0; i < sizeof ctx; i++)
        status &= ((const uint8_t *)&ctx)[i] == 0;

    memset(&ctx, 0xa5, sizeof ctx);
    status &= !tls_aes_ccm_init(&ctx, ccm_key, sizeof ccm_key,
                                ccm_nonce_1, 1, sizeof ccm_tag_1,
                                sizeof ccm_plaintext_1, sizeof ccm_aad);
    for (size_t i = 0; i < sizeof ctx; i++)
        status &= ((const uint8_t *)&ctx)[i] == 0;

    status &= tls_aes_init(&ctx, TLS_AES_GCM, gcm_key, sizeof gcm_key,
                           gcm_iv, sizeof gcm_iv);
    tls_aes_destroy_ctx(&ctx);
    for (size_t i = 0; i < sizeof ctx; i++)
        status &= ((const uint8_t *)&ctx)[i] == 0;
    tls_aes_destroy_ctx(NULL);
    show_result(status);

    // Test 17: AES-256-GCM encrypt/decrypt and bad-tag rejection
    status = true;
    memset(tbuf, 0, sizeof(tbuf));
    memset(tag, 0, sizeof(tag));
    status &= tls_aes_init(&ctx, TLS_AES_GCM, gcm256_key, sizeof gcm256_key,
                           gcm_iv, sizeof gcm_iv);
    status &= tls_aes_update_aad(&ctx, gcm_aad, sizeof gcm_aad);
    status &= tls_aes_encrypt(&ctx, gcm_plaintext, sizeof gcm_plaintext, tbuf);
    status &= tls_aes_digest(&ctx, tag);
    status &= memcmp(tbuf, gcm256_ciphertext, sizeof gcm256_ciphertext) == 0;
    status &= memcmp(tag, gcm256_tag, sizeof gcm256_tag) == 0;
    memset(tbuf, 0, sizeof(tbuf));
    status &= tls_aes_init(&ctx, TLS_AES_GCM, gcm256_key, sizeof gcm256_key,
                           gcm_iv, sizeof gcm_iv);
    status &= !tls_aes_decrypt(&ctx, gcm256_ciphertext,
                               sizeof gcm256_ciphertext, tbuf);
    status &= tls_aes_verify(&ctx, gcm_aad, sizeof gcm_aad,
                             gcm256_ciphertext, sizeof gcm256_ciphertext,
                             gcm256_tag);
    status &= tls_aes_decrypt(&ctx, gcm256_ciphertext,
                              sizeof gcm256_ciphertext, tbuf);
    status &= memcmp(tbuf, gcm_plaintext, sizeof gcm_plaintext) == 0;
    memcpy(tag, gcm256_tag, sizeof gcm256_tag);
    tag[0] ^= 0x01;
    memset(tbuf, 0xaa, sizeof(tbuf));
    status &= tls_aes_init(&ctx, TLS_AES_GCM, gcm256_key, sizeof gcm256_key,
                           gcm_iv, sizeof gcm_iv);
    status &= !tls_aes_verify(&ctx, gcm_aad, sizeof gcm_aad,
                              gcm256_ciphertext, sizeof gcm256_ciphertext, tag);
    status &= !tls_aes_decrypt(&ctx, gcm256_ciphertext,
                               sizeof gcm256_ciphertext, tbuf);
    for (size_t i = 0; i < sizeof gcm_plaintext; i++)
        status &= tbuf[i] == 0xaa;
    show_result(status);

    // Test 18: AES-256-CCM encrypt/decrypt and bad-tag rejection
    status = true;
    memset(tbuf, 0, sizeof(tbuf));
    memset(tag, 0, sizeof(tag));
    status &= ccm_encrypt(ccm256_key, sizeof ccm256_key,
                          ccm_nonce_1, sizeof ccm_nonce_1,
                          ccm_aad, sizeof ccm_aad,
                          ccm256_plaintext, sizeof ccm256_plaintext,
                          tbuf, tag, sizeof ccm256_tag);
    status &= memcmp(tbuf, ccm256_ciphertext, sizeof ccm256_ciphertext) == 0;
    status &= memcmp(tag, ccm256_tag, sizeof ccm256_tag) == 0;
    memset(tbuf, 0, sizeof(tbuf));
    status &= ccm_decrypt(ccm256_key, sizeof ccm256_key,
                          ccm_nonce_1, sizeof ccm_nonce_1,
                          ccm_aad, sizeof ccm_aad,
                          ccm256_ciphertext, sizeof ccm256_ciphertext,
                          ccm256_tag, sizeof ccm256_tag, tbuf);
    status &= memcmp(tbuf, ccm256_plaintext, sizeof ccm256_plaintext) == 0;
    {
        uint8_t bad[sizeof ccm256_tag];
        memcpy(bad, ccm256_tag, sizeof bad);
        bad[0] ^= 0x01;
        memset(tbuf, 0xaa, sizeof(tbuf));
        status &= !ccm_decrypt(ccm256_key, sizeof ccm256_key,
                               ccm_nonce_1, sizeof ccm_nonce_1,
                               ccm_aad, sizeof ccm_aad,
                               ccm256_ciphertext, sizeof ccm256_ciphertext,
                               bad, sizeof bad, tbuf);
        for (size_t i = 0; i < sizeof ccm256_plaintext; i++)
            status &= tbuf[i] == 0xaa;
    }
    show_result(status);

    // Test 19: record-level AES-256-GCM with chunked encryption/decryption
    status = true;
    memset(tbuf, 0, sizeof(tbuf));
    memset(tag, 0, sizeof(tag));
    status &= tls_aes_init(&ctx, TLS_AES_GCM, gcm256_key, sizeof gcm256_key,
                           rec256_iv, sizeof rec256_iv);
    status &= tls_aes_update_aad(&ctx, rec256_aad, sizeof rec256_aad);
    status &= tls_aes_encrypt(&ctx, rec256_gcm_plaintext, 5, tbuf);
    status &= tls_aes_encrypt(&ctx, rec256_gcm_plaintext + 5, 7, tbuf + 5);
    status &= tls_aes_encrypt(&ctx, rec256_gcm_plaintext + 12,
                              sizeof rec256_gcm_plaintext - 12, tbuf + 12);
    status &= tls_aes_digest(&ctx, tag);
    status &= memcmp(tbuf, rec256_gcm_ciphertext,
                     sizeof rec256_gcm_ciphertext) == 0;
    status &= memcmp(tag, rec256_gcm_tag, sizeof rec256_gcm_tag) == 0;
    memset(tbuf, 0, sizeof(tbuf));
    status &= tls_aes_init(&ctx, TLS_AES_GCM, gcm256_key, sizeof gcm256_key,
                           rec256_iv, sizeof rec256_iv);
    status &= !tls_aes_decrypt(&ctx, rec256_gcm_ciphertext,
                               sizeof rec256_gcm_ciphertext, tbuf);
    status &= tls_aes_verify(&ctx, rec256_aad, sizeof rec256_aad,
                             rec256_gcm_ciphertext,
                             sizeof rec256_gcm_ciphertext, rec256_gcm_tag);
    status &= tls_aes_decrypt(&ctx, rec256_gcm_ciphertext, 9, tbuf);
    status &= tls_aes_decrypt(&ctx, rec256_gcm_ciphertext + 9,
                              sizeof rec256_gcm_ciphertext - 9, tbuf + 9);
    status &= memcmp(tbuf, rec256_gcm_plaintext,
                     sizeof rec256_gcm_plaintext) == 0;
    show_result(status);

    // Test 20: record-level AES-256-CCM with chunked encryption/decryption
    status = true;
    memset(tbuf, 0, sizeof(tbuf));
    memset(tag, 0, sizeof(tag));
    status &= tls_aes_ccm_init(&ctx, ccm256_key, sizeof ccm256_key,
                               rec256_iv, sizeof rec256_iv,
                               sizeof ccm256_tag, sizeof rec256_gcm_plaintext,
                               sizeof rec256_aad);
    status &= tls_aes_update_aad(&ctx, rec256_aad, sizeof rec256_aad);
    status &= tls_aes_encrypt(&ctx, rec256_gcm_plaintext, 3, tbuf);
    status &= tls_aes_encrypt(&ctx, rec256_gcm_plaintext + 3, 11, tbuf + 3);
    status &= tls_aes_encrypt(&ctx, rec256_gcm_plaintext + 14,
                              sizeof rec256_gcm_plaintext - 14, tbuf + 14);
    status &= tls_aes_digest(&ctx, tag);
    status &= memcmp(tbuf, rec256_ccm_ciphertext,
                     sizeof rec256_ccm_ciphertext) == 0;
    status &= memcmp(tag, rec256_ccm_tag, sizeof rec256_ccm_tag) == 0;
    memset(tbuf, 0, sizeof(tbuf));
    status &= tls_aes_ccm_init(&ctx, ccm256_key, sizeof ccm256_key,
                               rec256_iv, sizeof rec256_iv,
                               sizeof ccm256_tag, sizeof rec256_ccm_ciphertext,
                               sizeof rec256_aad);
    status &= tls_aes_update_aad(&ctx, rec256_aad, sizeof rec256_aad);
    status &= tls_aes_decrypt(&ctx, rec256_ccm_ciphertext, 4, NULL);
    status &= tls_aes_decrypt(&ctx, rec256_ccm_ciphertext + 4, 10, NULL);
    status &= tls_aes_decrypt(&ctx, rec256_ccm_ciphertext + 14,
                              sizeof rec256_ccm_ciphertext - 14, NULL);
    status &= tls_aes_digest(&ctx, tag);
    status &= memcmp(tag, rec256_ccm_tag, sizeof rec256_ccm_tag) == 0;
    {
        uint8_t bad[sizeof rec256_ccm_tag];
        memcpy(bad, rec256_ccm_tag, sizeof bad);
        bad[0] ^= 0x01;
        memset(tbuf, 0xaa, sizeof(tbuf));
        status &= !ccm_decrypt(ccm256_key, sizeof ccm256_key,
                               rec256_iv, sizeof rec256_iv,
                               rec256_aad, sizeof rec256_aad,
                               rec256_ccm_ciphertext,
                               sizeof rec256_ccm_ciphertext,
                               bad, sizeof bad, tbuf);
        for (size_t i = 0; i < sizeof rec256_gcm_plaintext; i++)
            status &= tbuf[i] == 0xaa;
    }
    show_result(status);

    return 0;
}

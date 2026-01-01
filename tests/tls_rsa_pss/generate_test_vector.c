/**
 * @file generate_test_vector.c
 * @brief Generate PSS test vector using OpenSSL
 *
 * Compile with: gcc generate_test_vector.c -o generate_test_vector -lcrypto
 * Run: ./generate_test_vector
 */

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>

void print_hex_array(const char *name, const unsigned char *data, size_t len) {
    printf("const uint8_t %s[%zu] = {\n    ", name, len);
    for (size_t i = 0; i < len; i++) {
        printf("0x%02x", data[i]);
        if (i < len - 1) printf(", ");
        if ((i + 1) % 8 == 0 && i < len - 1) printf("\n    ");
    }
    printf("\n};\n\n");
}

int main(void) {
    const char *message = "hello world";
    unsigned char mhash[32];
    unsigned char salt[32];
    unsigned char encoded_msg[128]; /* 1024-bit modulus */
    size_t em_len = 128;
    int em_bits = 1023; /* modBits - 1 */

    /* Compute SHA-256 hash of message */
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(md_ctx, message, strlen(message));
    unsigned int md_len;
    EVP_DigestFinal_ex(md_ctx, mhash, &md_len);
    EVP_MD_CTX_free(md_ctx);

    /* Use deterministic salt for reproducibility */
    const unsigned char fixed_salt[32] = {
        0xde, 0xe9, 0x59, 0xc7, 0xe0, 0x64, 0x11, 0x8b,
        0x7b, 0xd2, 0xf4, 0x9a, 0x02, 0x18, 0xf4, 0x27,
        0x76, 0xb6, 0x7a, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d
    };
    memcpy(salt, fixed_salt, 32);

    /*
     * Manually construct PSS encoding to control the salt
     * PSS structure: maskedDB || H || 0xBC
     * where DB = PS || 0x01 || salt
     * and H = Hash(0x00...00 || mHash || salt)
     */

    size_t db_len = em_len - md_len - 1; /* 128 - 32 - 1 = 95 */
    size_t ps_len = db_len - md_len - 1; /* 95 - 32 - 1 = 62 */

    /* Build DB: PS (zeros) || 0x01 || salt */
    unsigned char db[128];
    memset(db, 0, ps_len);           /* PS (padding string of zeros) */
    db[ps_len] = 0x01;               /* Separator */
    memcpy(db + ps_len + 1, salt, md_len); /* Salt */

    /* Compute H = Hash(0x00...00 || mHash || salt) */
    unsigned char m_prime[8 + 32 + 32];
    memset(m_prime, 0, 8);
    memcpy(m_prime + 8, mhash, md_len);
    memcpy(m_prime + 8 + md_len, salt, md_len);

    unsigned char H[32];
    md_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(md_ctx, m_prime, sizeof(m_prime));
    EVP_DigestFinal_ex(md_ctx, H, &md_len);
    EVP_MD_CTX_free(md_ctx);

    /* Generate dbMask = MGF1(H, db_len) */
    unsigned char dbMask[128];
    /* Simple MGF1 implementation */
    unsigned char counter[4];
    size_t generated = 0;
    unsigned int counter_val = 0;

    while (generated < db_len) {
        counter[0] = (counter_val >> 24) & 0xFF;
        counter[1] = (counter_val >> 16) & 0xFF;
        counter[2] = (counter_val >> 8) & 0xFF;
        counter[3] = counter_val & 0xFF;

        unsigned char hash_output[32];
        md_ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL);
        EVP_DigestUpdate(md_ctx, H, 32);
        EVP_DigestUpdate(md_ctx, counter, 4);
        EVP_DigestFinal_ex(md_ctx, hash_output, &md_len);
        EVP_MD_CTX_free(md_ctx);

        size_t to_copy = (db_len - generated < md_len) ? (db_len - generated) : md_len;
        memcpy(dbMask + generated, hash_output, to_copy);
        generated += to_copy;
        counter_val++;
    }

    /* maskedDB = DB XOR dbMask */
    unsigned char maskedDB[128];
    for (size_t i = 0; i < db_len; i++) {
        maskedDB[i] = db[i] ^ dbMask[i];
    }

    /* Clear leftmost bit (em_bits % 8 = 7, so 1 bit unused) */
    maskedDB[0] &= 0x7F;

    /* Construct final encoded message: maskedDB || H || 0xBC */
    memcpy(encoded_msg, maskedDB, db_len);
    memcpy(encoded_msg + db_len, H, md_len);
    encoded_msg[em_len - 1] = 0xBC;

    /* Print the test vectors as C arrays */
    printf("/* Generated PSS test vector using OpenSSL */\n");
    printf("/* Message: \"%s\" */\n", message);
    printf("/* PSS Structure: maskedDB[%zu] || H[%u] || 0xBC */\n\n", db_len, md_len);

    print_hex_array("mhash", mhash, 32);
    print_hex_array("salt", salt, 32);

    printf("/* H (extracted from encoded_msg[%zu:%zu]) */\n", db_len, db_len + md_len - 1);
    print_hex_array("H", H, md_len);

    print_hex_array("expected_encoded_msg", encoded_msg, em_len);

    printf("/* Test parameters */\n");
    printf("const size_t em_len = %zu;\n", em_len);
    printf("const uint16_t em_bits = %d;\n", em_bits);
    printf("\n/* Verification: H should equal Hash(0x00*8 || mhash || salt) */\n");
    printf("/* Trailer byte (last byte) should be 0xBC: 0x%02X */\n", encoded_msg[em_len - 1]);

    return 0;
}

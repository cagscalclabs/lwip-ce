#include <ti/vars.h>

#include "../includes/truststore.h"
#include "../includes/rsa.h"
#include "../includes/hash.h"
#include "../includes/bytes.h"

/*
 * Truststore appvar format:
 * +---------------------+
 * | size (2B)           |  <- TI's native length field
 * +---------------------+
 * | Signature (256B)    |  <- RSA-2048 sig over header + entries
 * +---------------------+
 * | Header (4B)         |  <- tls_truststore_header
 * +---------------------+
 * | SPKI entries...     |  <- Array of tls_spki_entry structs
 * +---------------------+
 *
 * struct tls_truststore_header {
 *    uint32_t created_timestamp;  // Unix timestamp
 * };
 *
 * struct tls_spki_entry {
 *    uint8_t owner_id[TLS_SPKI_OWNER_ID_LEN];  // 32 bytes
 *    uint8_t hash[TLS_SPKI_HASH_MAX_LEN];       // 32 bytes
 * };
 *
 * Backup pins for cert rotation: use multiple entries with same owner_id.
 * Verification matches if ANY entry has correct hash.
 *
 * [TODO] Age warning: if (now - created_timestamp) > TLS_TRUSTSTORE_AGE_WARN_DAYS,
 * library will print a warning suggesting truststore update.
 */

char *truststore_name = "lwIPSPKI";
bool truststore_valid_for_session = false;

uint8_t trust_store_pubkey[] = {
    0xA1, 0xD3, 0x45, 0x9D, 0xC3, 0xD2, 0x1D, 0x6A, 0x9B, 0xA1, 0xD2, 0xCD, 0xEB, 0x4A, 0x10, 0xD0,
    0x79, 0x34, 0xB1, 0x06, 0xDA, 0xB3, 0x6D, 0x36, 0x01, 0x75, 0x3E, 0xA3, 0x56, 0xBD, 0x74, 0xDB,
    0x5A, 0xBF, 0xC4, 0xF4, 0x25, 0x5A, 0xA6, 0x50, 0x8F, 0x5D, 0xDC, 0x1B, 0x99, 0x13, 0x0E, 0xD5,
    0x57, 0xE1, 0x47, 0x01, 0x9A, 0xCE, 0xC8, 0x78, 0x6E, 0x83, 0x0E, 0x38, 0xE5, 0xDB, 0xB9, 0x2B,
    0xB2, 0x09, 0x87, 0x29, 0x44, 0x2A, 0x19, 0xAB, 0xFD, 0xF9, 0xB0, 0x73, 0x61, 0xDA, 0x17, 0x3B,
    0xAC, 0x0C, 0x85, 0x41, 0x39, 0x74, 0x20, 0xF1, 0xD5, 0xC9, 0x59, 0x8E, 0xB0, 0x3C, 0xCC, 0x0A,
    0xF7, 0xB6, 0x18, 0x14, 0x24, 0x67, 0x14, 0x66, 0xF0, 0xB9, 0x26, 0x47, 0xDD, 0xAF, 0x40, 0x46,
    0x59, 0x29, 0x75, 0x5B, 0x6C, 0x85, 0x11, 0x3C, 0xD6, 0x32, 0xF1, 0x78, 0xA5, 0x02, 0xFC, 0x12,
    0xF6, 0x79, 0x4E, 0xDB, 0x1D, 0x53, 0xA8, 0xEC, 0xA7, 0x2C, 0x0E, 0x8F, 0x51, 0x14, 0x68, 0xDB,
    0x4C, 0x56, 0xB3, 0x40, 0xEA, 0x5E, 0x30, 0x2E, 0xE0, 0xBF, 0x1D, 0x33, 0xAB, 0x9F, 0x0E, 0x8D,
    0x85, 0x18, 0xED, 0xF7, 0xBA, 0xCC, 0xB2, 0xA7, 0xEE, 0xA6, 0xE0, 0xEC, 0xE5, 0xF5, 0x49, 0x44,
    0x74, 0x25, 0xD9, 0x8A, 0xCC, 0x71, 0xAA, 0x99, 0x05, 0x84, 0x64, 0x6A, 0x7E, 0x35, 0x8A, 0x01,
    0xFA, 0xA2, 0xD5, 0xE7, 0xA4, 0xF4, 0x3A, 0x6A, 0x94, 0x19, 0x75, 0x7F, 0xDD, 0xD3, 0x08, 0x58,
    0x20, 0x5C, 0xDA, 0xBB, 0x6E, 0xE3, 0xB5, 0x6E, 0x29, 0x7F, 0xA6, 0x01, 0x14, 0x33, 0x98, 0x81,
    0x72, 0xA5, 0x1A, 0x10, 0x78, 0x95, 0x97, 0x23, 0x19, 0x69, 0x0B, 0xC3, 0x59, 0x49, 0x3E, 0x6D,
    0x3D, 0x4D, 0xA5, 0x7B, 0x4B, 0xD5, 0x1A, 0xD0, 0x68, 0xD6, 0x59, 0x7B, 0xF6, 0x23, 0x69, 0x95};

#define TRUSTSTORE_SIG_LEN 256
bool tls_truststore_init(void)
{
    void *truststore_data;
    uint8_t d_sig[TRUSTSTORE_SIG_LEN];
    uint8_t tstore_hash[TLS_SHA256_DIGEST_LEN];
    struct tls_hash_context hash_ctx;

    // If hash init fails, error out early
    if (!tls_hash_context_init(&hash_ctx, TLS_HASH_SHA256))
        return false;

    // Attempt to load the trust store.
    // Return with error if not found.
    if (!os_ChkFindSym(OS_TYPE_APPVAR, truststore_name, NULL, &truststore_data))
        return false;

    // Get length of store, spki db len, and sig ptr
    uint16_t truststore_size = *((uint16_t *)truststore_data);
    if (truststore_size < TRUSTSTORE_SIG_LEN + TLS_SPKI_HEADER_LEN + 2)
        return false;
    uint16_t spki_store_len = truststore_size - TRUSTSTORE_SIG_LEN - 2;
    uint8_t *spki_store_sig = ((uint8_t *)truststore_data) + 2;
    uint8_t *spki_created_time = spki_store_sig + TRUSTSTORE_SIG_LEN;

    // Hash the SPKI store and created header
    tls_hash_update(&hash_ctx, spki_created_time, spki_store_len);
    tls_hash_digest(&hash_ctx, tstore_hash);

    // Decrypt the SPKI store signature
    if (!tls_rsa_decrypt_signature(spki_store_sig, TRUSTSTORE_SIG_LEN, d_sig, trust_store_pubkey, sizeof(trust_store_pubkey)))
        return false;

    // Verify the signature
    bool verified = tls_rsa_pss_verify(d_sig, sizeof(trust_store_pubkey), tstore_hash, hash_ctx.digestlen, TLS_HASH_SHA256);
    if (verified)
        truststore_valid_for_session = true;
    return verified;
}

bool tls_truststore_lookup(uint8_t *recvd_hash, struct tls_spki_entry *result)
{
    if (recvd_hash == NULL)
        return false;
    if (!truststore_valid_for_session)
        return false;

    // Attempt to load the trust store.
    // Return with error if not found.
    void *truststore_data;
    if (!os_ChkFindSym(OS_TYPE_APPVAR, truststore_name, NULL, &truststore_data))
        return false;

    // set up lookup pointers and size words
    uint16_t truststore_size = *((uint16_t *)truststore_data);
    if (truststore_size < TRUSTSTORE_SIG_LEN + TLS_SPKI_HEADER_LEN + 2)
        return false;

    uint8_t *spki_db_start = (uint8_t *)truststore_data + 2 + TRUSTSTORE_SIG_LEN + TLS_SPKI_HEADER_LEN;
    uint16_t spki_db_len = truststore_size - 2 - TRUSTSTORE_SIG_LEN - TLS_SPKI_HEADER_LEN;

    // the db length not being a multiple of struct size at this point
    // means something is wrong
    if (spki_db_len % sizeof(struct tls_spki_entry))
        return false;
    uint16_t spki_count = spki_db_len / sizeof(struct tls_spki_entry);
    for (uint16_t i = 0; i < spki_count; i++)
    {
        struct tls_spki_entry *entry = &((struct tls_spki_entry *)spki_db_start)[i];
        if (tls_bytes_compare(recvd_hash, entry->hash, TLS_SHA256_DIGEST_LEN))
        {
            // if match
            if (result)
                memcpy(result, entry, sizeof(*result));
            return true;
        }
    }
    return false;
}
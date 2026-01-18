#include <ti/vars.h>
#include <string.h>

#include "../includes/truststore.h"
#include "../includes/tls.h"
#include "../includes/rsa.h"
#include "../includes/hash.h"
#include "../includes/bytes.h"
#include "lwip/app_config.h"
#include <sys/rtc.h>

/*
 * Truststore appvar format:
 * +---------------------+
 * | size (2B)           |  <- TI's native length field
 * +---------------------+
 * | Signature (256B)    |  <- RSA-2048 sig over header + entries
 * +---------------------+
 * | Header (8B)         |  <- tls_truststore_header
 * +---------------------+
 * | SPKI entries...     |  <- Array of tls_spki_entry structs
 * +---------------------+
 *
 * struct tls_truststore_header {
 *    uint32_t created_timestamp;  // Unix timestamp
 *    uint16_t entry_count;        // Number of SPKI entries
 *    uint16_t version;            // Truststore format version
 * };
 *
 * struct tls_spki_entry {
 *    uint8_t owner_id[TLS_SPKI_OWNER_ID_LEN];  // 32 bytes
 *    uint8_t issuer_id[TLS_SPKI_ISSUER_LEN];   // 32 bytes
 *    uint32_t not_before;                      // Unix timestamp
 *    uint32_t not_after;                       // Unix timestamp
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


#define TLS_TRUSTSTORE_VERSION 0

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

static bool is_leap_year(uint16_t year)
{
    return ((year % 4u) == 0u) && (((year % 100u) != 0u) || ((year % 400u) == 0u));
}

static bool tls_truststore_get_utc(uint32_t *out_seconds)
{
    static const uint8_t days_in_month[] = {
        31u, 28u, 31u, 30u, 31u, 30u, 31u, 31u, 30u, 31u, 30u, 31u
    };
    uint8_t day = 0;
    uint8_t month = 0;
    uint16_t year = 0;
    uint8_t hours = 0;
    uint8_t minutes = 0;
    uint8_t seconds = 0;
    const lwip_app_config_t *cfg = lwip_app_config_get();

    boot_GetDate(&day, &month, &year);
    boot_GetTime(&seconds, &minutes, &hours);
    if (year < 1970u || month == 0u || month > 12u || day == 0u)
    {
        return false;
    }

    uint32_t days = 0;
    for (uint16_t y = 1970u; y < year; y++)
    {
        days += is_leap_year(y) ? 366u : 365u;
    }
    for (uint8_t m = 1u; m < month; m++)
    {
        uint8_t dim = days_in_month[m - 1u];
        if ((m == 2u) && is_leap_year(year))
        {
            dim = 29u;
        }
        days += dim;
    }
    days += (uint32_t)(day - 1u);

    uint32_t local = (days * 86400u) + ((uint32_t)hours * 3600u) +
                     ((uint32_t)minutes * 60u) + seconds;
    int64_t utc = (int64_t)local - ((int64_t)cfg->tz_offset_minutes * 60);
    if (cfg->dst_enabled)
    {
        utc -= 3600;
    }
    if (utc < 0)
    {
        return false;
    }
    *out_seconds = (uint32_t)utc;
    return true;
}

static bool tls_truststore_match_id(const uint8_t *entry_id, const uint8_t *id)
{
    if (!id)
    {
        return false;
    }
    size_t len = strnlen((const char *)id, TLS_SPKI_OWNER_ID_LEN);
    if (memcmp(entry_id, id, len) != 0)
    {
        return false;
    }
    for (size_t i = len; i < TLS_SPKI_OWNER_ID_LEN; i++)
    {
        if (entry_id[i] != 0)
        {
            return false;
        }
    }
    return true;
}
static void tls_truststore_set_status(enum tls_truststore_status status)
{
    tls_ctx.truststore.status = status;
}

enum tls_truststore_status tls_truststore_status(void)
{
    return tls_ctx.truststore.status;
}

bool tls_truststore_init(void)
{
    var_t *truststore_var;
    uint8_t d_sig[TRUSTSTORE_SIG_LEN];
    uint8_t tstore_hash[TLS_SHA256_DIGEST_LEN];
    struct tls_hash_context hash_ctx;

    // If hash init fails, error out early
    if (!tls_hash_context_init(&hash_ctx, TLS_HASH_SHA256))
    {
        tls_truststore_set_status(TLS_STORE_HASH_INIT_FAIL);
        return false;
    }

    // Attempt to load the trust store.
    // Return with error if not found.
    truststore_var = os_GetAppVarData(truststore_name, NULL);
    if (!truststore_var)
    {
        tls_truststore_set_status(TLS_STORE_NOT_FOUND);
        return false;
    }

    // Get length of store, spki db len, and sig ptr
    uint16_t truststore_size = *((uint16_t *)truststore_var);
    if (truststore_size < TRUSTSTORE_SIG_LEN + TLS_SPKI_HEADER_LEN + 2)
    {
        tls_truststore_set_status(TLS_STORE_SIZE_INVALID);
        return false;
    }
    uint16_t spki_store_len = truststore_size - TRUSTSTORE_SIG_LEN - 2;
    uint8_t *spki_store_sig = ((uint8_t *)truststore_var) + 2;
    uint8_t *spki_header = spki_store_sig + TRUSTSTORE_SIG_LEN;

    struct tls_truststore_header *header = (struct tls_truststore_header *)spki_header;
    if (header->version != TLS_TRUSTSTORE_VERSION)
    {
        tls_truststore_set_status(TLS_STORE_VERSION_MISMATCH);
        return false;
    }

    // Hash the SPKI store and created header
    tls_hash_update(&hash_ctx, spki_header, spki_store_len);
    tls_hash_digest(&hash_ctx, tstore_hash);

    // Decrypt the SPKI store signature
    if (!tls_rsa_decrypt_signature(spki_store_sig, TRUSTSTORE_SIG_LEN, d_sig, trust_store_pubkey, sizeof(trust_store_pubkey)))
    {
        tls_truststore_set_status(TLS_STORE_SIG_DECRYPT_FAIL);
        return false;
    }
    // Verify the signature
    bool verified = tls_rsa_pss_verify(d_sig, sizeof(trust_store_pubkey), tstore_hash, hash_ctx.digestlen, TLS_HASH_SHA256);
    if (!verified)
    {
        tls_truststore_set_status(TLS_STORE_SIG_INVALID);
        return false;
    }

    tls_ctx.truststore.size = truststore_size;
    tls_ctx.truststore.entry_count = header->entry_count;
    tls_ctx.truststore.version = header->version;
    tls_ctx.truststore.created_timestamp = header->created_timestamp;
    tls_truststore_set_status(TLS_STORE_OK);
    return true;
}

bool tls_truststore_lookup(uint8_t *recvd_hash, struct tls_spki_entry *result)
{
    return tls_truststore_lookup_ex(recvd_hash, NULL, NULL, result);
}

bool tls_truststore_lookup_ex(uint8_t *recvd_hash,
                              const uint8_t *owner_id,
                              const uint8_t *issuer_id,
                              struct tls_spki_entry *result)
{
    if (recvd_hash == NULL)
        return false;
    if (tls_ctx.truststore.status != TLS_STORE_OK)
        return false;

    const lwip_app_config_t *cfg = lwip_app_config_get();
    bool check_dates = (cfg->flags & LWIP_CFG_CERT_CHECK_DATES) != 0;
    bool check_owner = (cfg->flags & LWIP_CFG_CERT_CHECK_OWNER) != 0;

    // Attempt to load the trust store.
    // Return with error if not found.
    var_t *truststore_var = os_GetAppVarData(truststore_name, NULL);
    if (!truststore_var)
    {
        tls_truststore_set_status(TLS_STORE_NOT_FOUND);
        return false;
    }

    // set up lookup pointers and size words
    uint16_t truststore_size = *((uint16_t *)truststore_var);
    if (truststore_size < TRUSTSTORE_SIG_LEN + TLS_SPKI_HEADER_LEN + 2)
    {
        tls_truststore_set_status(TLS_STORE_SIZE_INVALID);
        return false;
    }

    struct tls_truststore_header *header = (struct tls_truststore_header *)((uint8_t *)truststore_var + 2 + TRUSTSTORE_SIG_LEN);
    if (header->version != TLS_TRUSTSTORE_VERSION)
    {
        tls_truststore_set_status(TLS_STORE_VERSION_MISMATCH);
        return false;
    }
    uint8_t *spki_db_start = (uint8_t *)header + TLS_SPKI_HEADER_LEN;
    uint16_t spki_db_len = truststore_size - 2 - TRUSTSTORE_SIG_LEN - TLS_SPKI_HEADER_LEN;

    // the db length not being a multiple of struct size at this point
    // means something is wrong
    if (spki_db_len % sizeof(struct tls_spki_entry))
    {
        tls_truststore_set_status(TLS_STORE_SIZE_INVALID);
        return false;
    }
    uint16_t spki_count = spki_db_len / sizeof(struct tls_spki_entry);
    if (header->entry_count != spki_count)
    {
        tls_truststore_set_status(TLS_STORE_ENTRY_MISMATCH);
        return false;
    }
    if (truststore_size != tls_ctx.truststore.size ||
        header->entry_count != tls_ctx.truststore.entry_count ||
        header->version != tls_ctx.truststore.version ||
        header->created_timestamp != tls_ctx.truststore.created_timestamp)
    {
        tls_truststore_set_status(TLS_STORE_ENTRY_MISMATCH);
        return false;
    }

    uint32_t now = 0;
    if (check_dates && !tls_truststore_get_utc(&now))
    {
        tls_truststore_set_status(TLS_STORE_TIME_INVALID);
        return false;
    }

    for (uint16_t i = 0; i < spki_count; i++)
    {
        struct tls_spki_entry *entry = &((struct tls_spki_entry *)spki_db_start)[i];
        if (tls_bytes_compare(recvd_hash, entry->hash, TLS_SHA256_DIGEST_LEN))
        {
            if (check_dates)
            {
                if (now < entry->not_before || now > entry->not_after)
                {
                    tls_truststore_set_status(TLS_STORE_TIME_INVALID);
                    return false;
                }
            }
            if (check_owner)
            {
                if (!tls_truststore_match_id(entry->owner_id, owner_id) ||
                    !tls_truststore_match_id(entry->issuer_id, issuer_id))
                {
                    tls_truststore_set_status(TLS_STORE_ENTRY_MISMATCH);
                    return false;
                }
            }
            // if match
            if (result)
                memcpy(result, entry, sizeof(*result));
            return true;
        }
    }
    return false;
}

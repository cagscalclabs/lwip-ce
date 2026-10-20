#ifndef LWIP_WIRELESS_CRYPTO_H
#define LWIP_WIRELESS_CRYPTO_H

/* Crypto offload to the Wi-Fi bridge.
 *
 * Every operation is asynchronous, because TLS runs inside USB receive
 * callbacks and cannot wait there for a reply. A start call returns a job
 * handle, or 0 when the caller must do the work itself: offload is off, there
 * is no bridge, the bridge lacks the operation, or every job slot is busy.
 * When a job finishes, altcp_tls_ce_offload_ready() runs from the timer
 * context so waiting handshakes can collect it. A job the bridge never answers
 * finishes as LWIP_CRYPTO_FAILED, and the caller falls back to local code. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct pbuf;

typedef uint16_t lwip_crypto_job_t;

typedef enum
{
    LWIP_CRYPTO_PENDING,
    LWIP_CRYPTO_OK,
    LWIP_CRYPTO_REJECTED, /* bad signature, or an all-zero X25519 result */
    LWIP_CRYPTO_FAILED    /* no answer: do the work locally */
} lwip_crypto_status_t;

/* out = X25519(scalar, point); point NULL means the base point (a public key).
 * out is written when the reply arrives, so it must outlive the job: cancel
 * the job before freeing it. */
lwip_crypto_job_t lwip_crypto_x25519(const uint8_t scalar[32], const uint8_t *point,
                                     uint8_t out[32]);

/* RSA signature check over a SHA-256 digest. alg is CTL_RSA_*; the signature
 * is exactly mod_len bytes. */
lwip_crypto_job_t lwip_crypto_rsa_verify(uint8_t alg, const uint8_t digest[32],
                                         const uint8_t *modulus, size_t mod_len,
                                         const uint8_t *exponent, size_t exp_len,
                                         const uint8_t *sig);

/* len (at most CTL_RANDOM_MAX) bytes from the bridge TRNG into out. */
lwip_crypto_job_t lwip_crypto_random(uint8_t *out, uint8_t len);

/* CTL_CAP_* the bridge offers and the settings allow; 0 before it answers. */
uint8_t lwip_crypto_caps(void);

/* Anything but PENDING releases the job. */
lwip_crypto_status_t lwip_crypto_take(lwip_crypto_job_t job);

void lwip_crypto_cancel(lwip_crypto_job_t job);

/* Asks for fresh reseed input when the bridge TRNG is the entropy source. */
void lwip_crypto_reseed(void);

/* Link edges of the bridge netif. */
void lwip_crypto_link(bool up);

/* Forgets jobs and capabilities left behind by an earlier program. */
void lwip_crypto_reset(void);

/* Consumes a crypto reply; false when the frame is not one. */
bool lwip_crypto_reply(const uint8_t *header, struct pbuf *p);

#endif

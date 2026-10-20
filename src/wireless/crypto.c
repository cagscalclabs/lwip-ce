#include <string.h>

#include "lwip/app_config.h"
#include "lwip/pbuf.h"
#include "lwip/sys.h"
#include "lwip/timeouts.h"
#include "apps/altcp_tls/altcp_tls_ce.h"
#include "../tls/includes/bytes.h"
#include "../tls/includes/random.h"
#include "wireless/crypto.h"
#include "wireless/wifi_hook.h"
#include "wireless/wifi_proto.h"

#define CRYPTO_JOBS 8
#define CRYPTO_TIMEOUT_MS 2000
#define CRYPTO_TICK_MS 250
#define CRYPTO_INSTANTIATE_BYTES 64
#define CRYPTO_RESEED_BYTES 32

enum
{
    JOB_FREE,
    JOB_SENT,
    JOB_DONE
};

typedef struct
{
    lwip_crypto_job_t id;
    uint8_t state;
    uint8_t op;
    uint8_t seq;
    uint8_t status;
    uint32_t sent;
    uint8_t *out; /* result; the owner cancels the job before freeing it */
    uint8_t out_len;
} job_t;

static job_t g_jobs[CRYPTO_JOBS];
static lwip_crypto_job_t g_next_id;
static uint8_t g_caps;
static uint8_t g_info_seq;
static uint8_t g_random_seq;
static uint8_t g_random_len;
static bool g_trng;
static bool g_tick_armed;
static bool g_ready_armed;

static void ready(void *arg)
{
    (void)arg;
    g_ready_armed = false;
    altcp_tls_ce_offload_ready();
}

static void finish(job_t *job, uint8_t status)
{
    job->status = status;
    job->state = JOB_DONE;
    if (!g_ready_armed)
    {
        g_ready_armed = true;
        sys_timeout(0, ready, NULL);
    }
}

static void tick(void *arg)
{
    bool waiting = false;

    (void)arg;
    g_tick_armed = false;
    for (uint8_t i = 0; i < CRYPTO_JOBS; i++)
    {
        if (g_jobs[i].state != JOB_SENT)
            continue;
        if (sys_now() - g_jobs[i].sent >= CRYPTO_TIMEOUT_MS)
            finish(&g_jobs[i], LWIP_CRYPTO_FAILED);
        else
            waiting = true;
    }
    if (waiting)
    {
        g_tick_armed = true;
        sys_timeout(CRYPTO_TICK_MS, tick, NULL);
    }
}

/* Claims a slot and a frame; the caller fills the body and calls send(). */
static job_t *start(uint8_t cap, uint8_t op, uint16_t body_len, struct pbuf **p)
{
    if (!(g_caps & cap))
        return NULL;
    for (uint8_t i = 0; i < CRYPTO_JOBS; i++)
    {
        job_t *job = &g_jobs[i];

        if (job->state != JOB_FREE)
            continue;
        *p = lwip_wifi_frame(op, body_len, &job->seq);
        if (!*p)
            return NULL;
        if (++g_next_id == 0)
            g_next_id = 1;
        job->id = g_next_id;
        job->op = op;
        return job;
    }
    return NULL;
}

static lwip_crypto_job_t send(job_t *job, struct pbuf *p)
{
    if (lwip_wifi_frame_send(p) != ERR_OK)
        return 0;
    job->state = JOB_SENT;
    job->sent = sys_now();
    if (!g_tick_armed)
    {
        g_tick_armed = true;
        sys_timeout(CRYPTO_TICK_MS, tick, NULL);
    }
    return job->id;
}

static job_t *find(lwip_crypto_job_t id)
{
    for (uint8_t i = 0; id && i < CRYPTO_JOBS; i++)
    {
        if (g_jobs[i].state != JOB_FREE && g_jobs[i].id == id)
            return &g_jobs[i];
    }
    return NULL;
}

static void release(job_t *job)
{
    tls_secure_memzero(job, sizeof *job);
}

lwip_crypto_job_t lwip_crypto_x25519(const uint8_t scalar[32], const uint8_t *point, uint8_t out[32])
{
    struct pbuf *p;
    job_t *job = start(CTL_CAP_X25519, CTL_OP_X25519, 64, &p);
    uint8_t *body;

    if (!job)
        return 0;
    job->out = out;
    job->out_len = 32;
    body = (uint8_t *)p->payload + CTL_HEADER;
    memcpy(body, scalar, 32);
    if (point)
    {
        memcpy(body + 32, point, 32);
    }
    else
    {
        memset(body + 32, 0, 32);
        body[32] = 9;
    }
    return send(job, p);
}

lwip_crypto_job_t lwip_crypto_rsa_verify(uint8_t alg, const uint8_t digest[32],
                                         const uint8_t *modulus, size_t mod_len,
                                         const uint8_t *exponent, size_t exp_len,
                                         const uint8_t *sig)
{
    struct pbuf *p;
    job_t *job;
    uint8_t *body;

    if (mod_len > 512 || exp_len > 255)
        return 0;
    job = start(CTL_CAP_RSA, CTL_OP_RSA_VERIFY, (uint16_t)(36 + 2 * mod_len + exp_len), &p);
    if (!job)
        return 0;
    job->out = NULL;
    job->out_len = 0;
    body = (uint8_t *)p->payload + CTL_HEADER;
    body[0] = alg;
    memcpy(body + 1, digest, 32);
    body[33] = (uint8_t)mod_len;
    body[34] = (uint8_t)(mod_len >> 8);
    body[35] = (uint8_t)exp_len;
    memcpy(body + 36, modulus, mod_len);
    memcpy(body + 36 + mod_len, exponent, exp_len);
    memcpy(body + 36 + mod_len + exp_len, sig, mod_len);
    return send(job, p);
}

lwip_crypto_job_t lwip_crypto_random(uint8_t *out, uint8_t len)
{
    struct pbuf *p;
    job_t *job;

    if (len == 0 || len > CTL_RANDOM_MAX)
        return 0;
    job = start(CTL_CAP_RANDOM, CTL_OP_RANDOM, 1, &p);
    if (!job)
        return 0;
    job->out = out;
    job->out_len = len;
    ((uint8_t *)p->payload)[CTL_HEADER] = len;
    return send(job, p);
}

uint8_t lwip_crypto_caps(void)
{
    return g_caps;
}

lwip_crypto_status_t lwip_crypto_take(lwip_crypto_job_t id)
{
    job_t *job = find(id);
    lwip_crypto_status_t status;

    if (!job)
        return LWIP_CRYPTO_FAILED;
    if (job->state == JOB_SENT)
        return LWIP_CRYPTO_PENDING;
    status = (lwip_crypto_status_t)job->status;
    release(job);
    return status;
}

void lwip_crypto_cancel(lwip_crypto_job_t id)
{
    job_t *job = find(id);

    if (job)
        release(job);
}

static void request_random(uint8_t count)
{
    struct pbuf *p = lwip_wifi_frame(CTL_OP_RANDOM, 1, &g_random_seq);

    if (!p)
        return;
    ((uint8_t *)p->payload)[CTL_HEADER] = count;
    g_random_len = count;
    if (lwip_wifi_frame_send(p) != ERR_OK)
        g_random_len = 0;
}

void lwip_crypto_reseed(void)
{
    if (g_trng)
        request_random(CRYPTO_RESEED_BYTES);
}

static void on_info(const uint8_t *header, struct pbuf *p)
{
    const lwip_app_config_t *cfg = lwip_app_config_get();
    uint8_t caps = 0;
    uint8_t wanted = 0;

    if (header[16] != g_info_seq || header[17] != CTL_ST_OK ||
        pbuf_copy_partial(p, &caps, 1, CTL_HEADER) != 1)
        return;
    if (cfg->crypto_offload)
        wanted |= CTL_CAP_X25519 | CTL_CAP_RSA;
    if (cfg->bridge_rng)
        wanted |= CTL_CAP_RANDOM;
    g_caps = caps & wanted;
    if (g_caps & CTL_CAP_RANDOM)
        request_random(CRYPTO_INSTANTIATE_BYTES);
}

/* The first answer replaces the DRBG state outright, so from then on every
 * random byte derives from the bridge TRNG; later answers reseed it. */
static void on_random(const uint8_t *header, struct pbuf *p)
{
    uint8_t bytes[CTL_RANDOM_MAX];
    uint8_t len = g_random_len;

    if (header[17] != CTL_ST_OK || !(g_caps & CTL_CAP_RANDOM) ||
        pbuf_copy_partial(p, bytes, len, CTL_HEADER) != len)
        return;
    g_random_len = 0;
    if (tls_random_add_entropy(bytes, len) && len == CRYPTO_INSTANTIATE_BYTES)
    {
        g_trng = true;
        tls_random_set_external(true);
    }
    tls_secure_memzero(bytes, sizeof bytes);
}

bool lwip_crypto_reply(const uint8_t *header, struct pbuf *p)
{
    uint8_t op = header[15] & (uint8_t)~CTL_REPLY;

    if (header[14] != CTL_VERSION || !(header[15] & CTL_REPLY) || op < CTL_OP_INFO ||
        op > CTL_OP_RANDOM)
        return false;

    if (op == CTL_OP_INFO)
    {
        on_info(header, p);
        return true;
    }
    /* The DRBG's own requests; a program's go through the job table. */
    if (op == CTL_OP_RANDOM && g_random_len && header[16] == g_random_seq)
    {
        on_random(header, p);
        return true;
    }
    for (uint8_t i = 0; i < CRYPTO_JOBS; i++)
    {
        job_t *job = &g_jobs[i];

        if (job->state != JOB_SENT || job->op != op || job->seq != header[16])
            continue;
        if (header[17] == CTL_ST_REJECTED)
            finish(job, LWIP_CRYPTO_REJECTED);
        else if (header[17] != CTL_ST_OK ||
                 (job->out && pbuf_copy_partial(p, job->out, job->out_len, CTL_HEADER) != job->out_len))
            finish(job, LWIP_CRYPTO_FAILED);
        else
            finish(job, LWIP_CRYPTO_OK);
        break;
    }
    return true;
}

static void forget(void)
{
    g_caps = 0;
    g_random_len = 0;
    if (g_trng)
        tls_random_set_external(false);
    g_trng = false;
}

void lwip_crypto_link(bool up)
{
    const lwip_app_config_t *cfg = lwip_app_config_get();
    struct pbuf *p;

    forget();
    for (uint8_t i = 0; i < CRYPTO_JOBS; i++)
    {
        if (g_jobs[i].state == JOB_SENT)
            finish(&g_jobs[i], LWIP_CRYPTO_FAILED);
    }
    if (up && (cfg->crypto_offload || cfg->bridge_rng) &&
        (p = lwip_wifi_frame(CTL_OP_INFO, 0, &g_info_seq)) != NULL)
        lwip_wifi_frame_send(p);
}

void lwip_crypto_reset(void)
{
    forget();
    tls_secure_memzero(g_jobs, sizeof g_jobs);
    g_tick_armed = false;
    g_ready_armed = false;
}

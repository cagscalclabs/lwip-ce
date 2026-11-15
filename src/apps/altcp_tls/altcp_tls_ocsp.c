#include "lwip/opt.h"

#if LWIP_ALTCP

#include "lwip/altcp.h"
#include "lwip/altcp_tcp.h"
#include "lwip/dispatch.h"
#include "lwip/dns.h"
#include "lwip/mem.h"
#include "lwip/pbuf.h"
#include "lwip/sntp_time.h"
#include "lwip/sys.h"

#include "altcp_tls_ocsp.h"
#include "../../tls/includes/ocsp.h"
#include "../../tls/includes/x509.h"

#include <stdio.h>
#include <string.h>

#define LWIP_DBG_FILE_ID LWIP_FILE_ALTCP_TLS_CE
#define LWIP_DBG_MODULE  LWIP_DBG_MOD_TLS
#include "lwip/logging.h"

#define OCSP_HTTP_TIMEOUT_MS 10000u
#define OCSP_HTTP_TICK_MS 100u
#define OCSP_HTTP_HEADER_MAX 1024u
#define OCSP_HTTP_HOST_MAX 128u
#define OCSP_HTTP_PATH_MAX 256u
#define OCSP_HTTP_PORT 80u

enum ocsp_http_state {
    OCSP_HTTP_DNS,
    OCSP_HTTP_DNS_ABANDONED,
    OCSP_HTTP_CONNECTING,
    OCSP_HTTP_SENDING,
    OCSP_HTTP_RECEIVING,
    OCSP_HTTP_RESPONSE_READY,
    OCSP_HTTP_FAILED,
    OCSP_HTTP_DONE
};

struct ocsp_http_job {
    struct ocsp_http_job *next;
    struct tls_ocsp_query *query;
    struct altcp_pcb *tcp;
    void *owner;
    altcp_tls_ocsp_done_fn done;
    void *done_arg;
    enum ocsp_http_state state;
    uint32_t deadline_ms;
    char host[OCSP_HTTP_HOST_MAX];
    char path[OCSP_HTTP_PATH_MAX];
    uint16_t port;
    uint8_t *request;
    size_t request_len;
    size_t request_sent;
    uint8_t *response;
    size_t response_len;
    size_t response_cap;
    struct pbuf *response_pbuf;
    size_t response_pbuf_len;
    size_t content_length;
};

static struct ocsp_http_job *ocsp_jobs;

static bool ocsp_expired(uint32_t now, uint32_t deadline)
{
    return (int32_t)(now - deadline) >= 0;
}

static void ocsp_job_unlink(struct ocsp_http_job *job)
{
    struct ocsp_http_job **link = &ocsp_jobs;
    while (*link && *link != job)
        link = &(*link)->next;
    if (*link == job)
        *link = job->next;
}

static void ocsp_job_release_payload(struct ocsp_http_job *job)
{
    if (!job)
        return;
    tls_ocsp_query_free(job->query);
    job->query = NULL;
    mem_free(job->request);
    job->request = NULL;
    mem_free(job->response);
    job->response = NULL;
    job->response_len = job->response_cap = 0;
    if (job->response_pbuf)
        pbuf_free(job->response_pbuf);
    job->response_pbuf = NULL;
    job->response_pbuf_len = 0;
}

static void ocsp_job_close_tcp(struct ocsp_http_job *job)
{
    if (!job || !job->tcp)
        return;
    altcp_arg(job->tcp, NULL);
    altcp_recv(job->tcp, NULL);
    altcp_sent(job->tcp, NULL);
    altcp_err(job->tcp, NULL);
    altcp_abort(job->tcp);
    job->tcp = NULL;
}

static void ocsp_job_free(struct ocsp_http_job *job)
{
    if (!job)
        return;
    ocsp_job_close_tcp(job);
    ocsp_job_release_payload(job);
    mem_free(job);
}

static void ocsp_job_finish(struct ocsp_http_job *job,
                            tls_ocsp_status_t status)
{
    altcp_tls_ocsp_done_fn done;
    void *done_arg;

    if (!job || job->state == OCSP_HTTP_DONE)
        return;
    job->state = OCSP_HTTP_DONE;
    done = job->done;
    done_arg = job->done_arg;
    ocsp_job_unlink(job);
    ocsp_job_free(job);
    if (done)
        done(done_arg, status);
}

static bool ocsp_parse_url(struct ocsp_http_job *job, const char *url)
{
    const char *authority, *path, *colon = NULL;
    size_t authority_len, host_len, path_len;
    unsigned long port = OCSP_HTTP_PORT;

    if (!job || !url || strncmp(url, "http://", 7) != 0)
        return false;
    authority = url + 7;
    path = strchr(authority, '/');
    authority_len = path ? (size_t)(path - authority) : strlen(authority);
    if (authority_len == 0)
        return false;
    for (size_t i = 0; i < authority_len; i++)
    {
        if (authority[i] == ':')
            colon = authority + i;
        else if (authority[i] == '@' || authority[i] == '[' ||
                 authority[i] == ']')
            return false;
    }
    host_len = colon ? (size_t)(colon - authority) : authority_len;
    if (host_len == 0 || host_len >= sizeof(job->host))
        return false;
    if (colon)
    {
        const char *p = colon + 1;
        port = 0;
        if (p == authority + authority_len)
            return false;
        while (p < authority + authority_len)
        {
            if (*p < '0' || *p > '9')
                return false;
            port = port * 10u + (unsigned)(*p++ - '0');
            if (port > 65535u)
                return false;
        }
        if (port == 0)
            return false;
    }
    path_len = path ? strlen(path) : 1u;
    if (path_len >= sizeof(job->path))
        return false;
    memcpy(job->host, authority, host_len);
    job->host[host_len] = '\0';
    if (path)
        memcpy(job->path, path, path_len + 1u);
    else
        memcpy(job->path, "/", 2u);
    job->port = (uint16_t)port;
    return true;
}

static size_t ocsp_decimal_digits(unsigned value)
{
    size_t digits = 1;
    while (value >= 10u)
    {
        value /= 10u;
        digits++;
    }
    return digits;
}

static bool ocsp_build_request(struct ocsp_http_job *job)
{
    static const char fmt[] =
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: application/ocsp-request\r\n"
        "Accept: application/ocsp-response\r\n"
        "Content-Length: %u\r\n"
        "Connection: close\r\n\r\n";
    static const char fmt_port[] =
        "POST %s HTTP/1.1\r\n"
        "Host: %s:%u\r\n"
        "Content-Type: application/ocsp-request\r\n"
        "Accept: application/ocsp-response\r\n"
        "Content-Length: %u\r\n"
        "Connection: close\r\n\r\n";
    uint8_t *body = NULL;
    size_t body_len = 0;
    size_t header_len;
    int written;

    if (!tls_ocsp_build_request(job->query->serial,
                                job->query->serial_len,
                                job->query->issuer_name_hash,
                                job->query->issuer_key_hash,
                                &body, &body_len))
        return false;
    if (job->port == OCSP_HTTP_PORT)
        header_len = (sizeof(fmt) - 1u - 6u) + strlen(job->path) +
                     strlen(job->host) + ocsp_decimal_digits((unsigned)body_len);
    else
        header_len = (sizeof(fmt_port) - 1u - 8u) + strlen(job->path) +
                     strlen(job->host) + ocsp_decimal_digits((unsigned)job->port) +
                     ocsp_decimal_digits((unsigned)body_len);
    if (header_len == 0 || header_len > OCSP_HTTP_HEADER_MAX ||
        body_len > SIZE_MAX - header_len)
    {
        tls_ocsp_free(body);
        return false;
    }
    job->request_len = header_len + body_len;
    job->request = (uint8_t *)mem_malloc(job->request_len);
    if (!job->request)
    {
        tls_ocsp_free(body);
        return false;
    }
    if (job->port == OCSP_HTTP_PORT)
        written = snprintf((char *)job->request, header_len + 1u, fmt,
                           job->path, job->host, (unsigned)body_len);
    else
        written = snprintf((char *)job->request, header_len + 1u,
                           fmt_port, job->path, job->host,
                           (unsigned)job->port, (unsigned)body_len);
    if (written < 0 || (size_t)written != header_len)
    {
        tls_ocsp_free(body);
        mem_free(job->request);
        job->request = NULL;
        job->request_len = 0;
        return false;
    }
    memcpy(job->request + header_len, body, body_len);
    tls_ocsp_free(body);
    return true;
}

static bool ocsp_ascii_equal(const uint8_t *value, size_t value_len,
                             const char *expected)
{
    size_t expected_len = strlen(expected);
    if (value_len != expected_len)
        return false;
    for (size_t i = 0; i < value_len; i++)
    {
        uint8_t a = value[i];
        uint8_t b = (uint8_t)expected[i];
        if (a >= 'A' && a <= 'Z') a = (uint8_t)(a + ('a' - 'A'));
        if (b >= 'A' && b <= 'Z') b = (uint8_t)(b + ('a' - 'A'));
        if (a != b) return false;
    }
    return true;
}

static bool ocsp_parse_headers(struct ocsp_http_job *job, size_t header_len)
{
    const uint8_t *buf = job->response;
    size_t pos = 0;
    bool have_length = false, have_type = false;

    if (header_len < 13u || header_len > OCSP_HTTP_HEADER_MAX ||
        memcmp(buf, "HTTP/1.", 7) != 0 ||
        (buf[7] != '0' && buf[7] != '1') || buf[8] != ' ' ||
        memcmp(buf + 9, "200", 3) != 0 || buf[12] != ' ')
        return false;
    while (pos + 1u < header_len &&
           !(buf[pos] == '\r' && buf[pos + 1u] == '\n'))
        pos++;
    if (pos + 1u >= header_len)
        return false;
    pos += 2u;
    while (pos + 2u < header_len)
    {
        size_t line_start = pos, colon;
        if (buf[pos] == '\r' && buf[pos + 1u] == '\n')
            break;
        while (pos + 1u < header_len &&
               !(buf[pos] == '\r' && buf[pos + 1u] == '\n'))
            pos++;
        if (pos + 1u >= header_len)
            return false;
        colon = line_start;
        while (colon < pos && buf[colon] != ':')
            colon++;
        if (colon == pos)
            return false;
        size_t value = colon + 1u;
        while (value < pos && (buf[value] == ' ' || buf[value] == '\t'))
            value++;
        size_t value_end = pos;
        while (value_end > value &&
               (buf[value_end - 1u] == ' ' || buf[value_end - 1u] == '\t'))
            value_end--;
        if (ocsp_ascii_equal(buf + line_start, colon - line_start,
                             "content-length"))
        {
            size_t length = 0;
            if (have_length || value == value_end)
                return false;
            for (size_t i = value; i < value_end; i++)
            {
                if (buf[i] < '0' || buf[i] > '9')
                    return false;
                length = length * 10u + (size_t)(buf[i] - '0');
                if (length > OCSP_RESP_MAX)
                    return false;
            }
            job->content_length = length;
            have_length = true;
        }
        else if (ocsp_ascii_equal(buf + line_start, colon - line_start,
                                  "content-type"))
        {
            size_t semicolon = value;
            if (have_type)
                return false;
            while (semicolon < value_end && buf[semicolon] != ';')
                semicolon++;
            while (semicolon > value &&
                   (buf[semicolon - 1u] == ' ' || buf[semicolon - 1u] == '\t'))
                semicolon--;
            if (!ocsp_ascii_equal(buf + value, semicolon - value,
                                  "application/ocsp-response"))
                return false;
            have_type = true;
        }
        else if (ocsp_ascii_equal(buf + line_start, colon - line_start,
                                  "transfer-encoding"))
            return false;
        pos += 2u;
    }
    return have_length && have_type && job->content_length > 0;
}

static __attribute__((noinline)) bool
ocsp_response_grow(struct ocsp_http_job *job, size_t add)
{
    size_t need, cap;
    uint8_t *next;

    if (add > SIZE_MAX - job->response_len)
        return false;
    need = job->response_len + add;
    if (need > OCSP_HTTP_HEADER_MAX + OCSP_RESP_MAX)
        return false;
    if (need <= job->response_cap)
        return true;
    cap = job->response_cap ? job->response_cap : 256u;
    while (cap < need)
    {
        if (cap > (OCSP_HTTP_HEADER_MAX + OCSP_RESP_MAX) / 2u)
        {
            cap = OCSP_HTTP_HEADER_MAX + OCSP_RESP_MAX;
            break;
        }
        cap *= 2u;
    }
    next = (uint8_t *)mem_malloc(cap);
    if (!next)
        return false;
    if (job->response_len)
        memcpy(next, job->response, job->response_len);
    mem_free(job->response);
    job->response = next;
    job->response_cap = cap;
    return true;
}

static tls_ocsp_status_t ocsp_parse_response(const struct ocsp_http_job *job)
{
    return tls_ocsp_parse_response(
        job->response, job->response_len,
        job->query->serial, job->query->serial_len,
        job->query->issuer_name_hash, job->query->issuer_key_hash,
        &job->query->issuer, lwip_sntp_get_unix_time());
}

static bool ocsp_drain_response_pbuf(struct ocsp_http_job *job)
{
    size_t copied, queued_len;

    if (!job || !job->response_pbuf)
        return true;
    queued_len = job->response_pbuf_len;
    if (!ocsp_response_grow(job, queued_len))
        return false;
    copied = pbuf_copy_partial(job->response_pbuf,
                               job->response + job->response_len,
                               queued_len, 0);
    if (copied == queued_len && job->tcp)
        altcp_recved(job->tcp, (u16_t)copied);
    pbuf_free(job->response_pbuf);
    job->response_pbuf = NULL;
    job->response_pbuf_len = 0;
    if (copied != queued_len)
        return false;
    job->response_len += copied;
    return true;
}

static tls_ocsp_status_t ocsp_process_http_response(struct ocsp_http_job *job)
{
    size_t body_at = 0;

    if (!job || !job->response)
        return OCSP_PARSE_ERROR;
    for (size_t i = 3; i < job->response_len; i++)
    {
        if (job->response[i - 3] == '\r' &&
            job->response[i - 2] == '\n' &&
            job->response[i - 1] == '\r' && job->response[i] == '\n')
        {
            body_at = i + 1u;
            break;
        }
    }
    if (!body_at || body_at > OCSP_HTTP_HEADER_MAX ||
        !ocsp_parse_headers(job, body_at) ||
        job->response_len - body_at != job->content_length)
        return OCSP_PARSE_ERROR;
    job->response_len -= body_at;
    memmove(job->response, job->response + body_at, job->response_len);
    return ocsp_parse_response(job);
}

/* TCP callbacks are queue producers only: append transport bytes or publish a
 * terminal state.  HTTP/ASN.1 parsing, TLS continuation, and object teardown
 * belong to ocsp_dispatch(), outside lwIP's input callback stack. */
static err_t ocsp_recv(void *arg, struct altcp_pcb *tcp,
                       struct pbuf *p, err_t err)
{
    struct ocsp_http_job *job = (struct ocsp_http_job *)arg;

    (void)tcp;

    if (!job || job->state == OCSP_HTTP_DONE ||
        job->state == OCSP_HTTP_RESPONSE_READY ||
        job->state == OCSP_HTTP_FAILED)
    {
        if (p) pbuf_free(p);
        return ERR_OK;
    }
    if (!p)
    {
        job->state = job->state == OCSP_HTTP_RECEIVING
            ? OCSP_HTTP_RESPONSE_READY : OCSP_HTTP_FAILED;
        return ERR_OK;
    }
    if (err != ERR_OK || job->state != OCSP_HTTP_RECEIVING ||
        job->response_len > OCSP_HTTP_HEADER_MAX + OCSP_RESP_MAX ||
        job->response_pbuf_len > OCSP_HTTP_HEADER_MAX + OCSP_RESP_MAX -
                                  job->response_len ||
        p->tot_len > OCSP_HTTP_HEADER_MAX + OCSP_RESP_MAX -
                     job->response_len - job->response_pbuf_len)
    {
        pbuf_free(p);
        job->state = OCSP_HTTP_FAILED;
        return ERR_OK;
    }
    job->response_pbuf_len += p->tot_len;
    if (job->response_pbuf)
        pbuf_cat(job->response_pbuf, p);
    else
        job->response_pbuf = p;
    return ERR_OK;
}

static err_t ocsp_sent(void *arg, struct altcp_pcb *tcp, u16_t len)
{
    struct ocsp_http_job *job = (struct ocsp_http_job *)arg;
    size_t left, chunk;
    err_t err;
    (void)len;

    if (!job || job->state != OCSP_HTTP_SENDING)
        return ERR_OK;
    left = job->request_len - job->request_sent;
    if (!left)
    {
        job->state = OCSP_HTTP_RECEIVING;
        return ERR_OK;
    }
    chunk = left > UINT16_MAX ? UINT16_MAX : left;
    /* Keep the request buffer owned by the job until the private PCB is
     * closed. Zero-copy avoids competing for another payload pbuf while the
     * server certificate flight is deliberately retained by the TLS client. */
    err = altcp_write(tcp, job->request + job->request_sent,
                      (u16_t)chunk, 0);
    if (err == ERR_OK)
    {
        job->request_sent += chunk;
        (void)altcp_output(tcp);
        if (job->request_sent == job->request_len)
            job->state = OCSP_HTTP_RECEIVING;
    }
    else if (err != ERR_MEM)
    {
        ocsp_job_finish(job, OCSP_PARSE_ERROR);
        return ERR_ABRT;
    }
    return ERR_OK;
}

static err_t ocsp_connected(void *arg, struct altcp_pcb *tcp, err_t err)
{
    struct ocsp_http_job *job = (struct ocsp_http_job *)arg;

    (void)tcp;

    if (!job || err != ERR_OK)
    {
        if (job) ocsp_job_finish(job, OCSP_PARSE_ERROR);
        return ERR_ABRT;
    }
    /* Leave the connect callback before allocating/queuing the request.  On
     * the calculator this callback is already nested under the TCP input path
     * (and, for OCSP, under a suspended TLS handshake).  The dispatcher both
     * keeps that stack bounded and supplies the retry point required when
     * tcp_write() temporarily returns ERR_MEM. */
    job->state = OCSP_HTTP_SENDING;
    return ERR_OK;
}

static void ocsp_tcp_err(void *arg, err_t err)
{
    struct ocsp_http_job *job = (struct ocsp_http_job *)arg;
    (void)err;
    if (!job || job->state == OCSP_HTTP_DONE)
        return;
    job->tcp = NULL;
    job->state = OCSP_HTTP_FAILED;
}

static void ocsp_dns_found(const char *name, const ip_addr_t *addr, void *arg)
{
    struct ocsp_http_job *job = (struct ocsp_http_job *)arg;
    (void)name;

    if (!job)
        return;
    if (job->state == OCSP_HTTP_DNS_ABANDONED)
    {
        ocsp_job_unlink(job);
        ocsp_job_free(job);
        return;
    }
    if (job->state != OCSP_HTTP_DNS || !addr)
    {
        ocsp_job_finish(job, OCSP_PARSE_ERROR);
        return;
    }
    job->tcp = altcp_tcp_new_ip_type(IP_GET_TYPE(addr));
    if (!job->tcp)
    {
        ocsp_job_finish(job, OCSP_PARSE_ERROR);
        return;
    }
    altcp_arg(job->tcp, job);
    altcp_recv(job->tcp, ocsp_recv);
    altcp_sent(job->tcp, ocsp_sent);
    altcp_err(job->tcp, ocsp_tcp_err);
    job->state = OCSP_HTTP_CONNECTING;
    if (altcp_connect(job->tcp, addr, job->port, ocsp_connected) != ERR_OK)
        ocsp_job_finish(job, OCSP_PARSE_ERROR);
}

static void ocsp_dispatch(void)
{
    struct ocsp_http_job *job = ocsp_jobs;
    uint32_t now = sys_now();

    while (job)
    {
        struct ocsp_http_job *next = job->next;
        if ((job->state == OCSP_HTTP_RECEIVING ||
             job->state == OCSP_HTTP_RESPONSE_READY) &&
            !ocsp_drain_response_pbuf(job))
            job->state = OCSP_HTTP_FAILED;
        if (job->state == OCSP_HTTP_RESPONSE_READY)
        {
            tls_ocsp_status_t status = ocsp_process_http_response(job);
            ocsp_job_finish(job, status);
            job = next;
            continue;
        }
        if (job->state == OCSP_HTTP_FAILED)
        {
            ocsp_job_finish(job, OCSP_PARSE_ERROR);
            job = next;
            continue;
        }
        if (job->state == OCSP_HTTP_SENDING && job->tcp &&
            ocsp_sent(job, job->tcp, 0) == ERR_ABRT)
        {
            job = next;
            continue;
        }
        if (job->state != OCSP_HTTP_DONE &&
            job->state != OCSP_HTTP_DNS_ABANDONED &&
            ocsp_expired(now, job->deadline_ms))
        {
            if (job->state == OCSP_HTTP_DNS)
            {
                altcp_tls_ocsp_done_fn done = job->done;
                void *done_arg = job->done_arg;
                job->state = OCSP_HTTP_DNS_ABANDONED;
                job->owner = NULL;
                job->done = NULL;
                job->done_arg = NULL;
                ocsp_job_release_payload(job);
                if (done) done(done_arg, OCSP_PARSE_ERROR);
            }
            else
                ocsp_job_finish(job, OCSP_PARSE_ERROR);
        }
        job = next;
    }
    if (!ocsp_jobs)
        lwip_dispatch_set_period(LWIP_DISPATCH_TLS_OCSP_JOB, 0);
}

static void ocsp_arm(void)
{
    static bool attached;
    if (!attached)
    {
        lwip_dispatch_attach(LWIP_DISPATCH_TLS_OCSP_JOB, ocsp_dispatch);
        attached = true;
    }
    lwip_dispatch_set_period(LWIP_DISPATCH_TLS_OCSP_JOB,
                             lwip_dispatch_period_from_ms(OCSP_HTTP_TICK_MS));
    lwip_dispatch_start();
}

bool altcp_tls_ocsp_start(struct tls_ocsp_query *query, void *owner,
                          altcp_tls_ocsp_done_fn done, void *arg)
{
    struct ocsp_http_job *job;
    ip_addr_t addr;
    err_t err;

    if (!query || !owner || !done)
        return false;
    job = (struct ocsp_http_job *)mem_malloc(sizeof(*job));
    if (!job)
        return false;
    memset(job, 0, sizeof(*job));
    job->query = query;
    job->owner = owner;
    job->done = done;
    job->done_arg = arg;
    job->port = OCSP_HTTP_PORT;
    if (!ocsp_parse_url(job, query->url) || !ocsp_build_request(job))
    {
        job->query = NULL;
        ocsp_job_free(job);
        return false;
    }
    job->state = OCSP_HTTP_DNS;
    job->deadline_ms = sys_now() + OCSP_HTTP_TIMEOUT_MS;
    job->next = ocsp_jobs;
    ocsp_jobs = job;
    err = dns_gethostbyname(job->host, &addr, ocsp_dns_found, job);
    if (err == ERR_OK)
        ocsp_dns_found(job->host, &addr, job);
    else if (err != ERR_INPROGRESS)
    {
        ocsp_job_unlink(job);
        job->query = NULL;
        ocsp_job_free(job);
        return false;
    }
    ocsp_arm();
    return true;
}

void altcp_tls_ocsp_cancel(void *owner)
{
    struct ocsp_http_job *job = ocsp_jobs;
    while (job)
    {
        struct ocsp_http_job *next = job->next;
        if (job->owner == owner)
        {
            if (job->state == OCSP_HTTP_DNS)
            {
                job->state = OCSP_HTTP_DNS_ABANDONED;
                job->owner = NULL;
                job->done = NULL;
                job->done_arg = NULL;
                ocsp_job_release_payload(job);
            }
            else
            {
                ocsp_job_unlink(job);
                job->done = NULL;
                ocsp_job_free(job);
            }
        }
        job = next;
    }
    if (!ocsp_jobs)
        lwip_dispatch_set_period(LWIP_DISPATCH_TLS_OCSP_JOB, 0);
}

#endif

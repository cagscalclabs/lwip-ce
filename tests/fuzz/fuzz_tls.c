#include "tls_unit.c"

static void walk_certificate(const uint8_t *data, size_t size, size_t chunk)
{
    struct tls_handshake_context ctx;
    struct tls_cert_walker *w;
    size_t off = 0;

    if (!tls_handshake_init(&ctx, NULL, NULL)) return;
    ctx.hostname = "example.test";
    ctx.state = TLS_STATE_ENCRYPTED_EXTENSIONS_RECEIVED;
    w = tls_cert_walker_new(&ctx);
    ctx.cert_walker = w;
    while (w && off < size && w->state != CW_DONE && w->state != CW_ERROR)
    {
        size_t n = size - off < chunk ? size - off : chunk;
        if (!tls_cert_walker_feed(w, data + off, n)) break;
        off += n;
    }
    if (w && w->state == CW_DONE && tls_recv_certificate_streamed(&ctx, w))
        while (tls_cert_jobs_pending(&ctx) && tls_cert_jobs_step(&ctx))
            ;
    tls_handshake_cleanup(&ctx);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct tls_handshake_context ctx;
    size_t msg_len;

    if (size < 2) return 0;
    switch (data[0] & 3)
    {
    case 0:
        memset(&ctx, 0, sizeof(ctx));
        ctx.state = TLS_STATE_HANDSHAKE_KEYS_DERIVED;
        tls_recv_encrypted_extensions(&ctx, data + 1, size - 1);
        break;
    case 1:
        memset(&ctx, 0, sizeof(ctx));
        ctx.state = TLS_STATE_ENCRYPTED_EXTENSIONS_RECEIVED;
        tls_recv_certificate_request(&ctx, data + 1, size - 1);
        break;
    case 2:
        walk_certificate(data + 2, size - 2, (size_t)data[1] + 1);
        break;
    default:
        tls_parse_handshake_header(data + 2, size - 2, data[1], &msg_len);
        break;
    }
    return 0;
}

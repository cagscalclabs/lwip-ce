static void algorithm(const uint8_t *der, size_t n, bool expected, tls_alg_t scheme)
{
    struct tls_asn1_cursor c;
    struct tls_asn1_tlv item;
    tls_alg_t actual;
    assert(tls_asn1_cursor_init(&c, der, n) && tls_asn1_next(&c, &item));
    assert(tls_x509_signature_algorithm(&item, &actual) == expected);
    assert(actual == (expected ? scheme : TLS_ALG_UNKNOWN));
}
#define ALG(v, ok, scheme) algorithm(v, sizeof(v), ok, scheme)

static unsigned be16(const uint8_t *p) { return (unsigned)p[0] * 256 + p[1]; }
static void hello(bool psk, const char *hostname, bool offer_alpn)
{
    static const uint8_t protocols[] = {
        8, 'h', 't', 't', 'p', '/', '1', '.', '1',
        2, 'h', '2'
    };
    struct tls_handshake_context ctx;
    assert(tls_handshake_init(&ctx, NULL, NULL));
    ctx.psk_mode = psk;
    ctx.hostname = hostname;
    if (offer_alpn)
    {
        ctx.alpn_protocols = protocols;
        ctx.alpn_protocols_len = sizeof(protocols);
    }
    ctx.psk_identity.identity_len = 1;
    uint8_t buf[512]; size_t n, again, required;
    assert(tls_send_client_hello(&ctx, NULL, 0, &required));
    assert(tls_send_client_hello(&ctx, buf, sizeof(buf), &n));
    assert(n == required);
    ctx.state = TLS_STATE_INIT; /* Each serialization starts a fresh flight. */
    assert(tls_send_client_hello(&ctx, buf, n, &again) && n == again);
    ctx.state = TLS_STATE_INIT;
    assert(!tls_send_client_hello(&ctx, buf, n-1, &again));
    assert(buf[0] == TLS_HANDSHAKE_CLIENT_HELLO);
    assert((((unsigned)buf[1] << 16) | ((unsigned)buf[2] << 8) | buf[3]) == n-4);
    assert(buf[4] == 3 && buf[5] == 3);
    assert(memcmp(buf + 6, ctx.client_random, 32) == 0);
    static const uint8_t fixed_body[] = {
        0, 0, 4, 0x13, 0x01, 0x13, 0x04, 1, 0
    };
    assert(memcmp(buf + 38, fixed_body, sizeof(fixed_body)) == 0);
    assert(be16(buf+47) == n-49);
    unsigned versions = 0, groups = 0, key_share = 0, record_size_limit = 0;
    unsigned signatures = 0, alpn = 0, sni = 0, psk_modes = 0, psk_ext = 0;
    for (size_t off = 49; off < n; )
    {
        unsigned type = be16(buf+off), len = be16(buf+off+2);
        assert(off + 4 + len <= n);
        if (type == 43)
        {
            static const uint8_t expected[] = {2, 3, 4};
            assert(len == sizeof(expected) && memcmp(buf+off+4, expected, len) == 0);
            versions++;
        }
        if (type == 10)
        {
            static const uint8_t expected[] = {0, 4, 0, 0x1d, 0, 0x17};
            assert(len == sizeof(expected) && memcmp(buf+off+4, expected, len) == 0);
            groups++;
        }
        if (type == 51)
        {
            static const uint8_t expected_header[] = {0, 0x24, 0, 0x1d, 0, 0x20};
            assert(len == 38 &&
                   memcmp(buf+off+4, expected_header, sizeof(expected_header)) == 0);
            assert(memcmp(buf+off+10, ctx.ecdhe_public, 32) == 0);
            key_share++;
        }
        if (type == TLS_EXT_RECORD_SIZE_LIMIT)
        {
            assert(len == 2 && buf[off+4] == TLS_RECORD_SIZE_LIMIT_4096_HI &&
                   buf[off+5] == TLS_RECORD_SIZE_LIMIT_4096_LO);
            record_size_limit++;
        }
        if (type == 0)
        {
            sni++;
            assert(hostname && len == strlen(hostname) + 5);
            assert(memcmp(buf + off + 9, hostname, strlen(hostname)) == 0);
        }
        if (type == 13)
        {
            assert(len == 6 && be16(buf+off+4) == 4 &&
                   be16(buf+off+6) == 0x0804 && be16(buf+off+8) == 0x0403);
            signatures++;
        }
        if (type == 50)
        {
            assert(len == 8 && be16(buf+off+4) == 6);
            assert(be16(buf+off+6) == 0x0401 && be16(buf+off+8) == 0x0804 &&
                   be16(buf+off+10) == 0x0403);
            signatures++;
        }
        if (type == 16)
        {
            static const uint8_t expected[] = {
                0, 12, 8, 'h', 't', 't', 'p', '/', '1', '.', '1',
                2, 'h', '2'
            };
            assert(len == sizeof(expected) && memcmp(buf+off+4, expected, len) == 0);
            alpn++;
        }
        if (type == 45)
        {
            assert(len == 2 && buf[off+4] == 1 && buf[off+5] == 1);
            psk_modes++;
        }
        if (type == 41)
        {
            assert(off + 4 + len == n); /* pre_shared_key must be last */
            psk_ext++;
        }
        off += 4 + len;
    }
    assert(versions == 1 && groups == 1 && key_share == 1);
    assert(record_size_limit == 1);
    assert(signatures == 2 && alpn == (unsigned)offer_alpn);
    assert(sni == (unsigned)(hostname && !strcmp(hostname, "example.test")));
    assert(psk_modes == (unsigned)psk && psk_ext == (unsigned)psk);

    /* A P-256 HRR changes ClientHello2's key_share to exactly one P-256
     * entry while leaving both groups advertised in the same order. */
    ctx.state = TLS_STATE_HRR_RECEIVED;
    ctx.hrr_requested_group = TLS_NAMED_GROUP_SECP256R1;
    ctx.keyshare_ready |= TLS_KEYSHARE_P256_READY;
    assert(tls_send_client_hello(&ctx, NULL, 0, &required));
    assert(tls_send_client_hello(&ctx, buf, sizeof(buf), &n));
    assert(n == required);
    unsigned p256_share = 0;
    for (size_t off = 49; off < n; )
    {
        unsigned type = be16(buf + off), len = be16(buf + off + 2);
        assert(off + 4 + len <= n);
        if (type == TLS_EXT_KEY_SHARE)
        {
            static const uint8_t expected_header[] = {
                0, 0x45, 0, 0x17, 0, 0x41
            };
            assert(len == 71);
            assert(memcmp(buf + off + 4, expected_header,
                          sizeof(expected_header)) == 0);
            assert(memcmp(buf + off + 10, ctx.p256_public, 65) == 0);
            p256_share++;
        }
        off += 4 + len;
    }
    assert(p256_share == 1);
    tls_handshake_cleanup(&ctx);
}

static void hrr_keyshare_tests(void)
{
    static const uint8_t hrr_p256[] = {
        TLS_HANDSHAKE_SERVER_HELLO, 0, 0, 52,
        3, 3,
        0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
        0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
        0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
        0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
        0,                    /* legacy_session_id */
        0x13, 0x01,           /* TLS_AES_128_GCM_SHA256 */
        0,                    /* legacy_compression_method */
        0, 12,                /* extensions length */
        0, 43, 0, 2, 3, 4,   /* supported_versions: TLS 1.3 */
        0, 51, 0, 2, 0, 0x17 /* key_share: secp256r1 */
    };
    struct tls_handshake_context ctx;
    uint8_t client_hello[512];
    size_t written;

    assert(tls_handshake_keyshares_begin(&ctx, NULL, NULL));
    assert(tls_handshake_keyshares_step(&ctx) == 1);
    assert(tls_send_client_hello(&ctx, client_hello,
                                 sizeof(client_hello), &written));
    assert(tls_recv_server_hello(&ctx, hrr_p256, sizeof(hrr_p256)));
    assert(ctx.state == TLS_STATE_HRR_RECEIVED);
    assert(ctx.hrr_done);
    assert(ctx.hrr_requested_group == TLS_NAMED_GROUP_SECP256R1);
    assert(tls_handshake_p256_step(&ctx, true) == 1);
    assert(tls_send_client_hello(&ctx, client_hello,
                                 sizeof(client_hello), &written));
    uint8_t server_hello[123] = {0};
    server_hello[0] = TLS_HANDSHAKE_SERVER_HELLO;
    server_hello[3] = 119;
    server_hello[4] = 3;
    server_hello[5] = 3;
    memset(server_hello + 6, 0x11, 32); /* ordinary ServerHello.random */
    server_hello[38] = 0;              /* legacy_session_id */
    server_hello[39] = 0x13;
    server_hello[40] = 0x01;
    server_hello[41] = 0;              /* legacy_compression_method */
    server_hello[42] = 0;
    server_hello[43] = 79;             /* extensions length */
    server_hello[44] = 0;
    server_hello[45] = 43;
    server_hello[46] = 0;
    server_hello[47] = 2;
    server_hello[48] = 3;
    server_hello[49] = 4;
    server_hello[50] = 0;
    server_hello[51] = 51;
    server_hello[52] = 0;
    server_hello[53] = 69;
    server_hello[54] = 0;
    server_hello[55] = 0x17;
    server_hello[56] = 0;
    server_hello[57] = 65;
    server_hello[58] = 0x04;
    memset(server_hello + 59, 0x22, 64);
    assert(tls_recv_server_hello(&ctx, server_hello, sizeof(server_hello)));
    assert(ctx.state == TLS_STATE_SERVER_HELLO_RECEIVED);
    assert(ctx.ecdhe_negotiated);
    tls_handshake_cleanup(&ctx);

    /* Requesting X25519 is illegal because ClientHello1 already sent it. */
    uint8_t hrr_x25519[sizeof(hrr_p256)];
    memcpy(hrr_x25519, hrr_p256, sizeof(hrr_p256));
    hrr_x25519[sizeof(hrr_x25519) - 1] = 0x1d;
    assert(tls_handshake_keyshares_begin(&ctx, NULL, NULL));
    assert(tls_handshake_keyshares_step(&ctx) == 1);
    assert(tls_send_client_hello(&ctx, client_hello,
                                 sizeof(client_hello), &written));
    last_alert = 0;
    assert(!tls_recv_server_hello(&ctx, hrr_x25519, sizeof(hrr_x25519)));
    assert(last_alert == TLS_ALERT_ILLEGAL_PARAMETER);
    tls_handshake_cleanup(&ctx);
}


/* The client's mTLS flight: Certificate + CertificateVerify as produced by
 * tls_send_client_certificate(). Exercised here rather than over the network
 * because a test server cannot be trusted by the calculator (the trust store
 * is a signed AppVar and there is no override), so an end-to-end client mTLS
 * handshake cannot get past server certificate verification in the harness. */

/* parse_cert_chain() turns an AppVar of PEM into the configured chain. Fed with
 * an exactly-sized, non-NUL-terminated buffer, the shape read_appvar_pem()
 * allocates, so ASan reports any overread past the PEM text. */
static void parse_cert_chain_tests(void)
{
    size_t n = 0;

    struct tls_x509_object **chain =
        parse_cert_chain((const char *)chain_pem, sizeof(chain_pem), &n);
    assert(chain != NULL);
    assert(n == 2);
    assert(chain[0] && chain[1]);
    assert(chain[0]->der_len == CERT_EC_DER_LEN);
    assert(chain[1]->der_len == CERT_MISMATCH_DER_LEN);
    assert(memcmp(chain[0]->der, cert_ec, CERT_EC_DER_LEN) == 0);
    assert(memcmp(chain[1]->der, cert_mismatch, CERT_MISMATCH_DER_LEN) == 0);
    for (size_t i = 0; i < n; i++)
        tls_x509_object_free(chain[i]);
    mem_free(chain);

    /* A single certificate is the self-signed case. */
    n = 0;
    chain = parse_cert_chain((const char *)single_pem, sizeof(single_pem), &n);
    assert(chain != NULL && n == 1);
    assert(chain[0]->der_len == CERT_EC_DER_LEN);
    tls_x509_object_free(chain[0]);
    mem_free(chain);

    /* No banner at all: refused, not a partial chain. */
    static const char junk[] = "not a certificate";
    n = 123;
    assert(parse_cert_chain(junk, sizeof(junk) - 1, &n) == NULL);

    /* Banner with a truncated body: the import fails and nothing leaks. */
    static const char broken[] =
        "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
    n = 123;
    assert(parse_cert_chain(broken, sizeof(broken) - 1, &n) == NULL);
}

static void client_certificate_flight_tests(void)
{
    static const uint8_t der_a[] = {0x30, 0x03, 0x02, 0x01, 0x01};
    static const uint8_t der_b[] = {0x30, 0x05, 0x02, 0x03, 0x02, 0x03, 0x04};
    /* tls_x509_object has a flexible DER array, so instances are sized to
     * their certificate. */
    struct tls_x509_object *a = calloc(1, sizeof(*a) + sizeof(der_a));
    struct tls_x509_object *b = calloc(1, sizeof(*b) + sizeof(der_b));
    struct tls_x509_object *chain[] = {a, b};
    struct tls_key key;
    struct tls_handshake_context ctx;
    struct tls_hash_context transcript;
    uint8_t out[256];
    size_t written = 0;

    assert(a && b);
    memcpy(a->der, der_a, sizeof(der_a)); a->der_len = sizeof(der_a);
    memcpy(b->der, der_b, sizeof(der_b)); b->der_len = sizeof(der_b);
    static const uint8_t dummy_priv[32] = {1, 2, 3};
    memset(&key, 0, sizeof(key));
    key.type = TLS_KEY_TYPE_EC_P256;
    key.ec.priv = dummy_priv;   /* the stubbed signer ignores it */

    test_p256_sign_ok = true;
    memset(&ctx, 0, sizeof(ctx));
    assert(transcript_hash_init(&transcript));
    ctx.transcript_hash = &transcript;
    ctx.state = TLS_STATE_SERVER_FINISHED_RECEIVED;
    ctx.client_certificate_requested = true;
    ctx.client_certificate_compatible = true;
    ctx.client_key = &key;
    ctx.client_chain = chain;
    ctx.client_chain_len = 2;

    /* Certificate, then CertificateVerify: one message per call. */
    assert(tls_send_client_certificate(&ctx, out, sizeof(out), &written));

    /* Certificate: type, 24-bit body length, empty request context, list. */
    size_t list_len = (3u + sizeof(der_a) + 2u) + (3u + sizeof(der_b) + 2u);
    size_t cert_msg = 4u + 1u + 3u + list_len;
    assert(out[0] == 0x0b);
    assert(((size_t)out[1] << 16 | (size_t)out[2] << 8 | out[3]) == 1u + 3u + list_len);
    assert(out[4] == 0x00);
    assert(((size_t)out[5] << 16 | (size_t)out[6] << 8 | out[7]) == list_len);
    size_t p = 8;
    assert(((size_t)out[p] << 16 | (size_t)out[p + 1] << 8 | out[p + 2]) == sizeof(der_a));
    p += 3;
    assert(memcmp(out + p, der_a, sizeof(der_a)) == 0);
    p += sizeof(der_a);
    assert(out[p] == 0 && out[p + 1] == 0);   /* CertificateEntry extensions */
    p += 2;
    assert(((size_t)out[p] << 16 | (size_t)out[p + 1] << 8 | out[p + 2]) == sizeof(der_b));
    p += 3;
    assert(memcmp(out + p, der_b, sizeof(der_b)) == 0);
    p += sizeof(der_b);
    assert(out[p] == 0 && out[p + 1] == 0);
    p += 2;
    assert(p == cert_msg);
    assert(written == cert_msg);

    /* CertificateVerify: type, scheme, signature length, DER SEQUENCE{r,s}. */
    memset(out, 0, sizeof(out));
    assert(tls_send_client_certificate(&ctx, out, sizeof(out), &written));
    assert(out[0] == 0x0f);
    assert(out[4] == 0x04 && out[5] == 0x03);           /* ecdsa_secp256r1_sha256 */
    size_t sig_len = (size_t)out[6] << 8 | out[7];
    assert(((size_t)out[1] << 16 | (size_t)out[2] << 8 | out[3]) == 4u + sig_len);
    assert(written == 8u + sig_len);
    assert(out[8] == 0x30);
    assert((size_t)out[9] + 2u == sig_len);
    /* r starts with 0x80, so it must be encoded as 0x00-prefixed INTEGER 32. */
    assert(out[10] == 0x02 && out[11] == 0x21 && out[12] == 0x00);
    assert(memcmp(out + 13, test_p256_sign_rs, 32) == 0);
    /* s starts with 0x00 then 0x21, so it is a minimal INTEGER 31. */
    size_t s_off = 13 + 32;
    assert(out[s_off] == 0x02 && out[s_off + 1] == 0x1f);
    assert(memcmp(out + s_off + 2, test_p256_sign_rs + 33, 31) == 0);

    /* Flight complete: a further call reports nothing left. */
    assert(tls_send_client_certificate(&ctx, out, sizeof(out), &written));
    assert(written == 0);

    /* Incompatible request: empty certificate list once, then nothing (no
     * CertificateVerify). */
    memset(&ctx, 0, sizeof(ctx));
    assert(transcript_hash_init(&transcript));
    ctx.transcript_hash = &transcript;
    ctx.state = TLS_STATE_SERVER_FINISHED_RECEIVED;
    ctx.client_certificate_requested = true;
    ctx.client_certificate_compatible = false;
    ctx.client_key = &key;
    ctx.client_chain = chain;
    ctx.client_chain_len = 2;
    memset(out, 0xAA, sizeof(out));
    assert(tls_send_client_certificate(&ctx, out, sizeof(out), &written));
    assert(written == 8);
    assert(out[0] == 0x0b && out[3] == 0x04 && out[7] == 0x00);
    assert(tls_send_client_certificate(&ctx, out, sizeof(out), &written));
    assert(written == 0);

    /* Compatible but no identity configured: same empty list. */
    memset(&ctx, 0, sizeof(ctx));
    assert(transcript_hash_init(&transcript));
    ctx.transcript_hash = &transcript;
    ctx.state = TLS_STATE_SERVER_FINISHED_RECEIVED;
    ctx.client_certificate_requested = true;
    ctx.client_certificate_compatible = true;
    ctx.client_key = NULL;
    ctx.client_chain = chain;
    ctx.client_chain_len = 2;
    assert(tls_send_client_certificate(&ctx, out, sizeof(out), &written));
    assert(written == 8);

    /* Signing failure must not emit a half-built CertificateVerify. */
    memset(&ctx, 0, sizeof(ctx));
    assert(transcript_hash_init(&transcript));
    ctx.transcript_hash = &transcript;
    ctx.state = TLS_STATE_SERVER_FINISHED_RECEIVED;
    ctx.client_certificate_requested = true;
    ctx.client_certificate_compatible = true;
    ctx.client_key = &key;
    ctx.client_chain = chain;
    ctx.client_chain_len = 2;
    assert(tls_send_client_certificate(&ctx, out, sizeof(out), &written));
    assert(written == cert_msg);
    test_p256_sign_ok = false;
    assert(!tls_send_client_certificate(&ctx, out, sizeof(out), &written));
    test_p256_sign_ok = true;

    /* Too small a buffer is refused rather than truncated. */
    memset(&ctx, 0, sizeof(ctx));
    assert(transcript_hash_init(&transcript));
    ctx.transcript_hash = &transcript;
    ctx.state = TLS_STATE_SERVER_FINISHED_RECEIVED;
    ctx.client_certificate_requested = true;
    ctx.client_certificate_compatible = true;
    ctx.client_key = &key;
    ctx.client_chain = chain;
    ctx.client_chain_len = 2;
    assert(!tls_send_client_certificate(&ctx, out, cert_msg - 1u, &written));

    free(a);
    free(b);
}

static void handshake_extension_tests(void)
{
    static const uint8_t offered[] = {
        8, 'h', 't', 't', 'p', '/', '1', '.', '1',
        2, 'h', '2'
    };
    static const uint8_t ee_h2[] = {
        TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS, 0, 0, 11,
        0, 9, TLS_EXT_ALPN >> 8, TLS_EXT_ALPN & 0xff, 0, 5,
        0, 3, 2, 'h', '2'
    };
    static const uint8_t ee_unoffered[] = {
        TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS, 0, 0, 17,
        0, 15, TLS_EXT_ALPN >> 8, TLS_EXT_ALPN & 0xff, 0, 11,
        0, 9, 8, 'h', 't', 't', 'p', '/', '1', '.', '0'
    };
    static const uint8_t ee_supported_groups[] = {
        TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS, 0, 0, 24,
        0, 22, TLS_EXT_SUPPORTED_GROUPS >> 8,
        TLS_EXT_SUPPORTED_GROUPS & 0xff, 0, 18,
        0, 16, 0x11, 0xec, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x1e,
        0x00, 0x18, 0x00, 0x19, 0x01, 0x00, 0x01, 0x01
    };
    static const uint8_t ee_duplicate_group[] = {
        TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS, 0, 0, 12,
        0, 10, TLS_EXT_SUPPORTED_GROUPS >> 8,
        TLS_EXT_SUPPORTED_GROUPS & 0xff, 0, 6,
        0, 4, 0, 0x1d, 0, 0x1d
    };
    static const uint8_t ee_rsl_4096[] = {
        TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS, 0, 0, 8,
        0, 6, 0, TLS_EXT_RECORD_SIZE_LIMIT, 0, 2,
        TLS_RECORD_SIZE_LIMIT_4096_HI, TLS_RECORD_SIZE_LIMIT_4096_LO
    };
    static const uint8_t ee_rsl_wrong[] = {
        TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS, 0, 0, 8,
        0, 6, 0, TLS_EXT_RECORD_SIZE_LIMIT, 0, 2, 0x40, 0x01
    };
    static const uint8_t ee_rsl_duplicate[] = {
        TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS, 0, 0, 14,
        0, 12,
        0, TLS_EXT_RECORD_SIZE_LIMIT, 0, 2,
        TLS_RECORD_SIZE_LIMIT_4096_HI, TLS_RECORD_SIZE_LIMIT_4096_LO,
        0, TLS_EXT_RECORD_SIZE_LIMIT, 0, 2,
        TLS_RECORD_SIZE_LIMIT_4096_HI, TLS_RECORD_SIZE_LIMIT_4096_LO
    };
    static const uint8_t cert_request[] = {
        TLS_HANDSHAKE_CERTIFICATE_REQUEST, 0, 0, 11,
        0, 0, 8,
        TLS_EXT_SIGNATURE_ALGORITHMS >> 8,
        TLS_EXT_SIGNATURE_ALGORITHMS & 0xff, 0, 4,
        0, 2, 0x08, 0x04
    };
    static const uint8_t cert_request_ecdsa[] = {
        TLS_HANDSHAKE_CERTIFICATE_REQUEST, 0, 0, 11,
        0, 0, 8,
        TLS_EXT_SIGNATURE_ALGORITHMS >> 8,
        TLS_EXT_SIGNATURE_ALGORITHMS & 0xff, 0, 4,
        0, 2, 0x04, 0x03
    };
    static const uint8_t requested_ca[] = {0x30, 0x01, 0x42};
    static const uint8_t cert_request_ecdsa_ca[] = {
        TLS_HANDSHAKE_CERTIFICATE_REQUEST, 0, 0, 22,
        0, 0, 19,
        TLS_EXT_SIGNATURE_ALGORITHMS >> 8,
        TLS_EXT_SIGNATURE_ALGORITHMS & 0xff, 0, 4,
        0, 2, 0x04, 0x03,
        TLS_EXT_CERTIFICATE_AUTHORITIES >> 8,
        TLS_EXT_CERTIFICATE_AUTHORITIES & 0xff, 0, 7,
        0, 5, 0, 3, 0x30, 0x01, 0x42
    };
    static const uint8_t cert_request_no_sig[] = {
        TLS_HANDSHAKE_CERTIFICATE_REQUEST, 0, 0, 3, 0, 0, 0
    };
    static const uint8_t cert_request_context[] = {
        TLS_HANDSHAKE_CERTIFICATE_REQUEST, 0, 0, 4, 1, 0x42, 0, 0
    };
    static const uint8_t cert_request_duplicate[] = {
        TLS_HANDSHAKE_CERTIFICATE_REQUEST, 0, 0, 19,
        0, 0, 16,
        0, TLS_EXT_SIGNATURE_ALGORITHMS, 0, 4, 0, 2, 0x08, 0x04,
        0, TLS_EXT_SIGNATURE_ALGORITHMS, 0, 4, 0, 2, 0x08, 0x04
    };
    struct tls_handshake_context ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.state = TLS_STATE_HANDSHAKE_KEYS_DERIVED;
    ctx.alpn_protocols = offered;
    ctx.alpn_protocols_len = sizeof(offered);
    assert(tls_recv_encrypted_extensions(&ctx, ee_h2, sizeof(ee_h2)));
    assert(ctx.negotiated_alpn_len == 2);
    assert(memcmp(ctx.negotiated_alpn, "h2", 2) == 0);

    memset(&ctx, 0, sizeof(ctx));
    ctx.state = TLS_STATE_HANDSHAKE_KEYS_DERIVED;
    ctx.alpn_protocols = offered;
    ctx.alpn_protocols_len = sizeof(offered);
    last_alert = 0;
    assert(!tls_recv_encrypted_extensions(&ctx, ee_unoffered,
                                          sizeof(ee_unoffered)));
    assert(last_alert == TLS_ALERT_ILLEGAL_PARAMETER);

    memset(&ctx, 0, sizeof(ctx));
    ctx.state = TLS_STATE_HANDSHAKE_KEYS_DERIVED;
    last_alert = 0;
    assert(!tls_recv_encrypted_extensions(&ctx, ee_h2, sizeof(ee_h2)));
    assert(last_alert == TLS_ALERT_UNSUPPORTED_EXTENSION);

    memset(&ctx, 0, sizeof(ctx));
    ctx.state = TLS_STATE_HANDSHAKE_KEYS_DERIVED;
    assert(tls_recv_encrypted_extensions(&ctx, ee_supported_groups,
                                          sizeof(ee_supported_groups)));
    memset(&ctx, 0, sizeof(ctx));
    ctx.state = TLS_STATE_HANDSHAKE_KEYS_DERIVED;
    assert(!tls_recv_encrypted_extensions(&ctx, ee_duplicate_group,
                                          sizeof(ee_duplicate_group)));

    memset(&ctx, 0, sizeof(ctx));
    ctx.state = TLS_STATE_HANDSHAKE_KEYS_DERIVED;
    assert(tls_recv_encrypted_extensions(&ctx, ee_rsl_4096,
                                          sizeof(ee_rsl_4096)));
    memset(&ctx, 0, sizeof(ctx));
    ctx.state = TLS_STATE_HANDSHAKE_KEYS_DERIVED;
    last_alert = 0;
    assert(!tls_recv_encrypted_extensions(&ctx, ee_rsl_wrong,
                                           sizeof(ee_rsl_wrong)));
    assert(last_alert == TLS_ALERT_ILLEGAL_PARAMETER);
    memset(&ctx, 0, sizeof(ctx));
    ctx.state = TLS_STATE_HANDSHAKE_KEYS_DERIVED;
    assert(!tls_recv_encrypted_extensions(&ctx, ee_rsl_duplicate,
                                           sizeof(ee_rsl_duplicate)));

    memset(&ctx, 0, sizeof(ctx));
    ctx.state = TLS_STATE_ENCRYPTED_EXTENSIONS_RECEIVED;
    assert(tls_recv_certificate_request(&ctx, cert_request,
                                        sizeof(cert_request)));
    assert(ctx.client_certificate_requested);
    assert(!ctx.client_certificate_compatible);

    struct tls_key client_key;
    struct tls_x509_object client_cert;
    struct tls_x509_object *client_chain[] = {&client_cert};
    memset(&client_key, 0, sizeof(client_key));
    memset(&client_cert, 0, sizeof(client_cert));
    client_cert.issuer_name = requested_ca;
    client_cert.issuer_name_len = sizeof(requested_ca);
    memset(&ctx, 0, sizeof(ctx));
    ctx.state = TLS_STATE_ENCRYPTED_EXTENSIONS_RECEIVED;
    ctx.client_key = &client_key;
    ctx.client_chain = client_chain;
    ctx.client_chain_len = 1;
    assert(tls_recv_certificate_request(&ctx, cert_request_ecdsa,
                                        sizeof(cert_request_ecdsa)));
    assert(ctx.client_certificate_compatible);

    memset(&ctx, 0, sizeof(ctx));
    ctx.state = TLS_STATE_ENCRYPTED_EXTENSIONS_RECEIVED;
    ctx.client_key = &client_key;
    ctx.client_chain = client_chain;
    ctx.client_chain_len = 1;
    assert(tls_recv_certificate_request(&ctx, cert_request_ecdsa_ca,
                                        sizeof(cert_request_ecdsa_ca)));
    assert(ctx.client_certificate_compatible);

    /* A CA list that does not name our issuer is advisory: the identity is
     * still presented (RFC 8446 section 4.4.2.2). */
    client_cert.issuer_name = (const uint8_t *)"mismatch";
    client_cert.issuer_name_len = 8;
    memset(&ctx, 0, sizeof(ctx));
    ctx.state = TLS_STATE_ENCRYPTED_EXTENSIONS_RECEIVED;
    ctx.client_key = &client_key;
    ctx.client_chain = client_chain;
    ctx.client_chain_len = 1;
    assert(tls_recv_certificate_request(&ctx, cert_request_ecdsa_ca,
                                        sizeof(cert_request_ecdsa_ca)));
    assert(ctx.client_certificate_compatible);

    /* No client identity configured: present nothing. */
    memset(&ctx, 0, sizeof(ctx));
    ctx.state = TLS_STATE_ENCRYPTED_EXTENSIONS_RECEIVED;
    assert(tls_recv_certificate_request(&ctx, cert_request_ecdsa,
                                        sizeof(cert_request_ecdsa)));
    assert(!ctx.client_certificate_compatible);

    memset(&ctx, 0, sizeof(ctx));
    ctx.state = TLS_STATE_ENCRYPTED_EXTENSIONS_RECEIVED;
    ctx.psk_mode = true;
    last_alert = 0;
    assert(!tls_recv_certificate_request(&ctx, cert_request,
                                         sizeof(cert_request)));
    assert(last_alert == TLS_ALERT_UNEXPECTED_MESSAGE);

    memset(&ctx, 0, sizeof(ctx));
    ctx.state = TLS_STATE_ENCRYPTED_EXTENSIONS_RECEIVED;
    assert(!tls_recv_certificate_request(&ctx, cert_request_no_sig,
                                         sizeof(cert_request_no_sig)));
    memset(&ctx, 0, sizeof(ctx));
    ctx.state = TLS_STATE_ENCRYPTED_EXTENSIONS_RECEIVED;
    assert(!tls_recv_certificate_request(&ctx, cert_request_context,
                                         sizeof(cert_request_context)));
    memset(&ctx, 0, sizeof(ctx));
    ctx.state = TLS_STATE_ENCRYPTED_EXTENSIONS_RECEIVED;
    assert(!tls_recv_certificate_request(&ctx, cert_request_duplicate,
                                         sizeof(cert_request_duplicate)));
}

/* Run every queued certificate job; false as soon as one fails. */
static bool drain_jobs(struct tls_handshake_context *ctx)
{
    while (tls_cert_jobs_pending(ctx))
    {
        if (!tls_cert_jobs_step(ctx))
            return false;
    }
    return true;
}

static void chain(const uint8_t *der, size_t n, tls_alg_t expected)
{
    struct tls_handshake_context ctx;
    memset(&ctx, 0xa5, sizeof(ctx));
    assert(tls_handshake_init(&ctx, NULL, NULL));
    assert(ctx.leaf_pubkey.type == TLS_KEY_TYPE_UNKNOWN);
    ctx.hostname = "example.test";
    struct tls_cert_walker *w = tls_cert_walker_new(&ctx);
    ctx.cert_walker = w;
    w->cert_buf = malloc(n);
    memcpy(w->cert_buf, der, n);
    w->cert_buf_len = w->cert_buf_cap = n;
    mem_stats_tls_direct_add(n, n);
    assert(tls_cert_walker_validate_one(w));
    assert(w->pending_sig_alg == expected);
    assert(ctx.leaf_pubkey.allocated && ctx.leaf_pubkey.rsa.mod_len == 256);
    assert(ctx.leaf_pubkey.rsa.exponent[0] == 1);
    // One imported/captured RSA key, two independent signature operations.
    uint8_t operation_sig[256];
    memset(operation_sig, 0x11, sizeof(operation_sig));
    assert(tls_key_verify((const uint8_t *)"message", 7, operation_sig, sizeof(operation_sig),
                         &ctx.leaf_pubkey, TLS_ALG_RSA_PKCS1_SHA256) == TLS_KEY_OP_OK);
    assert(tls_key_verify((const uint8_t *)"message", 7, operation_sig, sizeof(operation_sig),
                         &ctx.leaf_pubkey, TLS_ALG_RSA_PSS_RSAE_SHA256) == TLS_KEY_OP_INVALID);
    memset(operation_sig, 0x22, sizeof(operation_sig));
    assert(tls_key_verify((const uint8_t *)"message", 7, operation_sig, sizeof(operation_sig),
                         &ctx.leaf_pubkey, TLS_ALG_RSA_PSS_RSAE_SHA256) == TLS_KEY_OP_OK);
    assert(ctx.leaf_pubkey.type == TLS_KEY_TYPE_RSA);
    w->cert_index = 1;
    assert(tls_cert_walker_validate_one(w)); // adjacent link uses stored scheme
    // The link signature check is queued, not run inline.
    assert(tls_cert_jobs_pending(&ctx) && ctx.cert_jobs_count == 1);
    w->state = CW_DONE;

    // Root metadata deliberately differs from the child's signature scheme.
    root_entry = calloc(1, sizeof(*root_entry) + 259);
    root_entry->len = sizeof(*root_entry) + 259;
    root_entry->alg_id = expected == TLS_ALG_RSA_PKCS1_SHA256
        ? TLS_CERT_SIG_RSA_PSS_SHA256 : TLS_CERT_SIG_RSA_PKCS1_SHA256;
    memcpy(root_entry->subject, w->pending_issuer_name_digest,
           TLS_TRUSTSTORE_SUBJECT_LEN);
    root_entry->key[0] = root_entry->key[2] = 1;
    memset(root_entry->key + 3, 0x81, 256);
    struct tls_truststore_entry *wrong_root = calloc(1, sizeof(*wrong_root) + 259);
    wrong_root->len = sizeof(*wrong_root) + 259;
    wrong_root->alg_id = root_entry->alg_id;
    memcpy(wrong_root->subject, w->pending_issuer_name_digest,
           TLS_TRUSTSTORE_SUBJECT_LEN);
    wrong_root->key[0] = wrong_root->key[2] = 1;
    memset(wrong_root->key + 3, 0x82, 256);
    root_candidates[0] = wrong_root;
    root_candidates[1] = root_entry;
    root_candidate_count = 2;
    if (w->topmost_authority_key_id_present)
    {
        uint8_t alert = 0;
        root_entry->subject[0] ^= 1;
        assert(!tls_cert_anchor_root(w, &alert));
        assert(alert == TLS_ALERT_UNKNOWN_CA);
        root_entry->subject[0] ^= 1;
    }
    ctx.state = TLS_STATE_ENCRYPTED_EXTENSIONS_RECEIVED;
    assert(tls_recv_certificate_streamed(&ctx, w));
    assert(ctx.cert_jobs_count == 2); // link + root, nothing verified yet
    // Held-back handshake bytes are replayed only after the queue drains.
    assert(tls_hs_defer_bytes(&ctx, (const uint8_t *)"abc", 3));
    assert(tls_hs_defer_bytes(&ctx, (const uint8_t *)"de", 2));
    assert(ctx.hs_deferred_len == 5);
    replayed_bytes = 0;
    assert(tls_cert_jobs_step(&ctx));      // link job
    assert(ctx.cert_jobs_count == 1 && replayed_bytes == 0);
    assert(tls_cert_jobs_step(&ctx));      // root job; queue drained
    assert(!tls_cert_jobs_pending(&ctx) && replayed_bytes == 5);
    assert(ctx.hs_deferred == NULL && ctx.hs_deferred_len == 0);
    // A failing replayed message is fatal too.
    assert(tls_hs_defer_bytes(&ctx, (const uint8_t *)"xy", 2));
    assert(tls_cert_job_enqueue(w, &ctx.leaf_pubkey));
    replay_result = false;
    assert(!drain_jobs(&ctx));
    replay_result = true;
    assert(!tls_cert_jobs_pending(&ctx) && ctx.hs_deferred == NULL);
    root_candidate_count = 0;
    free(wrong_root);
    // The root job took the walker's signature; give it a fresh valid one.
    assert(w->pending_sig == NULL && w->pending_link);
    w->pending_sig = malloc(256);
    mem_stats_tls_direct_add(256, 256);
    memset(w->pending_sig, expected == TLS_ALG_RSA_PKCS1_SHA256 ? 0x11 : 0x22, 256);
    w->pending_sig_len = 256;
    w->pending_sig[0] ^= 1;
    ctx.state = TLS_STATE_ENCRYPTED_EXTENSIONS_RECEIVED;
    ctx.fatal_alert_sent = false; /* synthetic second connection phase */
    last_alert = 0;
    root_candidates[0] = root_entry;
    root_candidate_count = 1;
    // A bad signature is caught when the job runs: fatal alert, state ERROR,
    // queue and held bytes discarded.
    assert(tls_recv_certificate_streamed(&ctx, w));
    assert(tls_hs_defer_bytes(&ctx, (const uint8_t *)"zz", 2));
    assert(!drain_jobs(&ctx));
    assert(last_alert == TLS_ALERT_BAD_CERTIFICATE && ctx.state == TLS_STATE_ERROR);
    assert(!tls_cert_jobs_pending(&ctx) && ctx.hs_deferred == NULL);
    // The pending signature moved to the (failed) root job, so this adjacent
    // link has no signature left to check and is rejected when it runs.
    assert(tls_cert_walker_validate_one(w));
    assert(!drain_jobs(&ctx));
    assert(!tls_cert_jobs_pending(&ctx));
    // Queue bound: a full queue runs the oldest job inline.
    for (int i = 0; i < 6; i++)
    {
        ctx.state = TLS_STATE_ENCRYPTED_EXTENSIONS_RECEIVED;
        root_candidate_count = 0;
        assert(tls_cert_walker_validate_one(w) || true);
        assert(ctx.cert_jobs_count <= TLS_CERT_JOB_MAX);
        (void)drain_jobs(&ctx);
    }
    // Cleanup frees whatever is still queued (accounting checked below).
    assert(tls_cert_walker_validate_one(w) || true);
    assert(tls_hs_defer_bytes(&ctx, (const uint8_t *)"q", 1));

    uint8_t sig[256]; memset(sig, 0x22, sizeof(sig));
    assert(tls_certverify_rsa_pss_sha256(&ctx, sig, sizeof(sig)));
    assert(!tls_certverify_rsa_pss_sha256(&ctx, sig, sizeof(sig)-1));
    tls_handshake_cleanup(&ctx);
    assert(ctx.leaf_pubkey.type == TLS_KEY_TYPE_UNKNOWN && !ctx.leaf_pubkey.allocated);
    tls_handshake_cleanup(&ctx); // cleanup is idempotent
    assert(allocated == 0);
    free(root_entry); root_entry = NULL;
}

static void time_tests(void)
{
    uint32_t t = 1;
    /* RFC 5280 4.1.2.5: 9999-12-31T23:59:59Z means "no expiry"; saturate. */
    assert(tls_x509_time_to_unix((const uint8_t *)"99991231235959Z", 15,
                                 ASN1_GENERALIZEDTIME, &t) && t == UINT32_MAX);
    /* A pre-1970 instant saturates to 0 (UTCTime pivot: 50 -> 1950). */
    assert(tls_x509_time_to_unix((const uint8_t *)"500101000000Z", 13,
                                 ASN1_UTCTIME, &t) && t == 0);
    /* Calendar validity: leap day only in leap years, no Feb 30 / Apr 31. */
    assert(tls_x509_time_to_unix((const uint8_t *)"20240229000000Z", 15,
                                 ASN1_GENERALIZEDTIME, &t));
    assert(!tls_x509_time_to_unix((const uint8_t *)"20230229000000Z", 15,
                                  ASN1_GENERALIZEDTIME, &t));
    assert(!tls_x509_time_to_unix((const uint8_t *)"21000229000000Z", 15,
                                  ASN1_GENERALIZEDTIME, &t));
    assert(tls_x509_time_to_unix((const uint8_t *)"20000229000000Z", 15,
                                 ASN1_GENERALIZEDTIME, &t));
    assert(!tls_x509_time_to_unix((const uint8_t *)"20260431000000Z", 15,
                                  ASN1_GENERALIZEDTIME, &t));
}

static void walker_set_certificate(struct tls_cert_walker *w,
                                   const uint8_t *der, size_t der_len)
{
    if (w->cert_buf)
    {
        mem_stats_tls_direct_release(w->cert_buf_cap, w->cert_buf_cap);
        mem_buffer_custom_free(w->cert_buf);
    }
    w->cert_buf = mem_buffer_custom_malloc(der_len);
    assert(w->cert_buf);
    memcpy(w->cert_buf, der, der_len);
    w->cert_buf_len = w->cert_buf_cap = der_len;
    mem_stats_tls_direct_add(der_len, der_len);
}

static void unset_clock_test(void)
{
    struct tls_handshake_context ctx;
    assert(tls_handshake_init(&ctx, NULL, NULL));
    ctx.hostname = "example.test";
    struct tls_cert_walker *w = tls_cert_walker_new(&ctx);
    assert(w);
    ctx.cert_walker = w;
    walker_set_certificate(w, cert_epoch_spanning,
                           sizeof(cert_epoch_spanning));

    mock_unix_time = 0;
    assert(!tls_cert_walker_validate_one(w));
    assert(w->fail_alert == TLS_ALERT_CERTIFICATE_EXPIRED);
    mock_unix_time = 1700000000;

    tls_handshake_cleanup(&ctx);
    assert(allocated == 0);
}

static void path_len_tests(void)
{
    struct tls_handshake_context ctx;
    struct tls_cert_walker *w;

    /* A normal subordinate CA consumes one unit, so its pathLen=0 parent
     * must reject it. */
    assert(tls_handshake_init(&ctx, NULL, NULL));
    w = tls_cert_walker_new(&ctx);
    assert(w);
    ctx.cert_walker = w;
    w->cert_index = 1;
    walker_set_certificate(w, cert_ca_ordinary, sizeof(cert_ca_ordinary));
    assert(tls_cert_walker_validate_one(w));
    assert(w->non_self_issued_ca_count == 1);
    w->cert_index = 2;
    walker_set_certificate(w, cert_ca_ordinary_parent,
                           sizeof(cert_ca_ordinary_parent));
    assert(!tls_cert_walker_validate_one(w));
    tls_handshake_cleanup(&ctx);
    assert(allocated == 0);

    /* A self-issued rollover CA does not consume path length, so a pathLen=0
     * parent with the same subject Name remains valid. */
    assert(tls_handshake_init(&ctx, NULL, NULL));
    w = tls_cert_walker_new(&ctx);
    assert(w);
    ctx.cert_walker = w;
    w->cert_index = 1;
    walker_set_certificate(w, cert_ca_self_issued,
                           sizeof(cert_ca_self_issued));
    assert(tls_cert_walker_validate_one(w));
    assert(w->non_self_issued_ca_count == 0);
    w->cert_index = 2;
    walker_set_certificate(w, cert_ca_rollover_parent,
                           sizeof(cert_ca_rollover_parent));
    assert(tls_cert_walker_validate_one(w));
    tls_handshake_cleanup(&ctx);
    assert(allocated == 0);
}

static bool name_constraint_chain(const uint8_t *leaf, size_t leaf_len,
                                  const char *hostname,
                                  const uint8_t *issuer, size_t issuer_len)
{
    struct tls_handshake_context ctx;
    struct tls_cert_walker *w;
    bool ok;

    assert(tls_handshake_init(&ctx, NULL, NULL));
    ctx.hostname = hostname;
    w = tls_cert_walker_new(&ctx);
    assert(w);
    ctx.cert_walker = w;
    walker_set_certificate(w, leaf, leaf_len);
    assert(tls_cert_walker_validate_one(w));
    w->cert_index = 1;
    walker_set_certificate(w, issuer, issuer_len);
    ok = tls_cert_walker_validate_one(w);
    tls_handshake_cleanup(&ctx);
    assert(allocated == 0);
    return ok;
}

static void name_constraint_tests(void)
{
    struct tls_x509_object cert;

    /* Every dNSName is checked, case-insensitively, rather than only the
     * connection hostname. */
    assert(name_constraint_chain(cert_nc_leaf_good,
                                 sizeof(cert_nc_leaf_good),
                                 "www.example.test", cert_nc_ca_dns,
                                 sizeof(cert_nc_ca_dns)));
    assert(!name_constraint_chain(cert_nc_leaf_extra,
                                  sizeof(cert_nc_leaf_extra),
                                  "www.example.test", cert_nc_ca_dns,
                                  sizeof(cert_nc_ca_dns)));
    assert(!name_constraint_chain(cert_nc_leaf_good,
                                  sizeof(cert_nc_leaf_good),
                                  "www.example.test", cert_nc_ca_excluded,
                                  sizeof(cert_nc_ca_excluded)));

    /* A permitted dNSName subtree is irrelevant when the subordinate has no
     * dNSName; its iPAddress identity remains acceptable. */
    assert(name_constraint_chain(cert_nc_leaf_ip,
                                 sizeof(cert_nc_leaf_ip), "192.0.2.1",
                                 cert_nc_ca_dns, sizeof(cert_nc_ca_dns)));

    /* Mandatory directoryName processing accepts a subject whose leading
     * RDN sequence is the permitted subtree. */
    assert(name_constraint_chain(cert_nc_leaf_good,
                                 sizeof(cert_nc_leaf_good),
                                 "www.example.test", cert_nc_ca_directory,
                                 sizeof(cert_nc_ca_directory)));

    assert(tls_x509_parse_certificate(cert_nc_ca_noncritical,
                                      sizeof(cert_nc_ca_noncritical), &cert));
    assert(!tls_x509_validate_path_extensions(&cert, true, 0));
    assert(tls_x509_parse_certificate(cert_nc_ca_bad_minimum,
                                      sizeof(cert_nc_ca_bad_minimum), &cert));
    assert(!tls_x509_validate_path_extensions(&cert, true, 0));
    assert(tls_x509_parse_certificate(cert_nc_ca_empty,
                                      sizeof(cert_nc_ca_empty), &cert));
    assert(!tls_x509_validate_path_extensions(&cert, true, 0));
    assert(tls_x509_parse_certificate(cert_nc_ca_unsupported,
                                      sizeof(cert_nc_ca_unsupported), &cert));
    assert(!tls_x509_validate_path_extensions(&cert, true, 0));
    assert(tls_x509_parse_certificate(cert_nc_ca_duplicate,
                                      sizeof(cert_nc_ca_duplicate), &cert));
    assert(!tls_x509_validate_path_extensions(&cert, true, 0));
    assert(tls_x509_parse_certificate(cert_nc_leaf_has_nc,
                                      sizeof(cert_nc_leaf_has_nc), &cert));
    assert(!tls_x509_validate_path_extensions(&cert, false, 0));
}

static bool certificate_extensions_valid(const uint8_t *der, size_t der_len,
                                         bool is_ca)
{
    struct tls_x509_object cert;
    assert(tls_x509_parse_certificate(der, der_len, &cert));
    return tls_x509_validate_path_extensions(&cert, is_ca, 0);
}

static void extended_key_usage_tests(void)
{
    /* serverAuth, anyExtendedKeyUsage, and an absent EKU all authorize the
     * TLS server purpose; RFC 5280 permits critical or non-critical EKU. */
    assert(certificate_extensions_valid(cert_pkcs, sizeof(cert_pkcs), false));
    assert(certificate_extensions_valid(cert_eku_any,
                                        sizeof(cert_eku_any), false));
    assert(certificate_extensions_valid(cert_eku_absent,
                                        sizeof(cert_eku_absent), false));
    assert(certificate_extensions_valid(cert_eku_critical,
                                        sizeof(cert_eku_critical), false));

    /* The project also applies an issuer EKU as a server-auth path policy. */
    assert(certificate_extensions_valid(cert_pkcs, sizeof(cert_pkcs), true));
    assert(certificate_extensions_valid(cert_eku_any,
                                        sizeof(cert_eku_any), true));
    assert(certificate_extensions_valid(cert_eku_absent,
                                        sizeof(cert_eku_absent), true));

    assert(!certificate_extensions_valid(cert_eku_client,
                                         sizeof(cert_eku_client), false));
    assert(!certificate_extensions_valid(cert_eku_client,
                                         sizeof(cert_eku_client), true));
    assert(!certificate_extensions_valid(cert_eku_empty,
                                         sizeof(cert_eku_empty), false));
    assert(!certificate_extensions_valid(cert_eku_malformed_oid,
                                         sizeof(cert_eku_malformed_oid), false));
}

int main(void)
{
    client_certificate_flight_tests();
    parse_cert_chain_tests();
    /* Staged client setup gates ClientHello1 on X25519 only. P-256's blocking
     * software fallback is deferred until an HRR requests it. */
    {
        struct tls_handshake_context staged;
        x25519_public_calls = 0;
        p256_public_calls = 0;
        assert(tls_handshake_keyshares_begin(&staged, NULL, NULL));
        assert(staged.keyshare_state == TLS_KEYSHARE_STATE_GENERATING);
        assert(staged.keyshare_ready == 0);
        assert(tls_handshake_keyshares_step(&staged) == 1);
        assert(x25519_public_calls == 1 && p256_public_calls == 0);
        assert(staged.keyshare_ready == TLS_KEYSHARE_X25519_READY);
        assert(staged.keyshare_state == TLS_KEYSHARE_STATE_READY);
        assert(tls_handshake_p256_step(&staged, true) == 1);
        assert(x25519_public_calls == 1 && p256_public_calls == 1);
        assert(staged.keyshare_ready == TLS_KEYSHARE_BOTH_READY);
        tls_handshake_cleanup(&staged);
    }

    time_tests();
    unset_clock_test();
    path_len_tests();
    name_constraint_tests();
    extended_key_usage_tests();
    ALG(alg_pkcs, true, TLS_ALG_RSA_PKCS1_SHA256);
    ALG(alg_pss, true, TLS_ALG_RSA_PSS_RSAE_SHA256);
    ALG(alg_pss_trailer, true, TLS_ALG_RSA_PSS_RSAE_SHA256);
    ALG(alg_ec, true, TLS_ALG_ECDSA_SECP256R1_SHA256);
    ALG(bad_default, false, 0); ALG(bad_absent, false, 0);
    ALG(bad_salt, false, 0); ALG(bad_hash, false, 0);
    ALG(bad_mgf_hash, false, 0); ALG(bad_duplicate, false, 0);
    ALG(bad_trailer, false, 0); ALG(bad_key_oid, false, 0);
    hello(false, NULL, false); hello(true, NULL, false);
    hrr_keyshare_tests();
    hello(false, "example.test", true); hello(true, "example.test", true);
    hello(false, "192.168.2.10", false); hello(true, "192.168.2.10", false);
    hello(false, "2001:db8::1", false); hello(true, "2001:db8::1", false);
    handshake_extension_tests();
    identity_tests();
    chain(cert_pkcs, sizeof(cert_pkcs), TLS_ALG_RSA_PKCS1_SHA256);
    chain(cert_pss, sizeof(cert_pss), TLS_ALG_RSA_PSS_RSAE_SHA256);
    chain(cert_aki, sizeof(cert_aki), TLS_ALG_RSA_PKCS1_SHA256);
    assert(ski_lookup_calls != 0);
    assert(pkcs_calls && pss_calls);

    struct tls_x509_object with_aki;
    assert(tls_x509_parse_certificate(cert_aki, sizeof(cert_aki), &with_aki));
    assert(with_aki.authority_key_id_len == 20 &&
           with_aki.authority_key_id[0] == 0xa0 &&
           with_aki.authority_key_id[19] == 0xb3);
    assert(!tls_x509_parse_certificate(cert_duplicate_aki,
                                       sizeof(cert_duplicate_aki), &with_aki));
    assert(!tls_x509_parse_certificate(cert_bad_aki,
                                       sizeof(cert_bad_aki), &with_aki));

    struct tls_x509_object nonminimal_ku;
    assert(tls_x509_parse_certificate(cert_nonminimal_ku,
                                      sizeof(cert_nonminimal_ku), &nonminimal_ku));
    assert(!tls_x509_validate_path_extensions(&nonminimal_ku, true, 0));

    struct tls_x509_object ec;
    assert(tls_x509_parse_certificate(cert_ec, sizeof(cert_ec), &ec));
    assert(ec.pubkey.type == TLS_KEY_TYPE_EC_P256 && ec.pubkey.ec.len == 65);
    uint8_t digest[32], sig[128]; memset(digest, 0x42, 32); memset(sig, 0x22, 128);
    assert(tls_cert_verify_digest(NULL, TLS_ALG_ECDSA_SECP256R1_SHA256, &ec.pubkey,
                                  digest, sig, 128) == TLS_KEY_OP_INVALID);
    assert(tls_cert_verify_digest(NULL, TLS_ALG_RSA_PSS_RSAE_SHA256, &ec.pubkey, digest, sig, 128) == TLS_KEY_OP_INVALID);

    /* RSA offload must enforce the same full-width modulus policy as the
     * local verifier instead of relying on the accelerator's import policy. */
    {
        struct tls_handshake_context offload_ctx = {0};
        uint8_t modulus[RSA_MODULUS_MAX_SUPPORTED];
        uint8_t exponent[] = {0x01, 0x00, 0x01};
        uint8_t rsa_sig[RSA_MODULUS_MAX_SUPPORTED] = {0};
        const size_t widths[] = {
            RSA_MODULUS_MIN_SUPPORTED,
            RSA_MODULUS_MAX_SUPPORTED,
        };
        struct tls_key rsa_key = {
            .type = TLS_KEY_TYPE_RSA,
            .rsa = {
                .exp_len = sizeof(exponent),
                .exponent = exponent,
                .modulus = modulus,
            },
        };
        unsigned before_offload = rsa_offload_calls;

        for (size_t i = 0; i < sizeof(widths) / sizeof(widths[0]); i++)
        {
            rsa_key.rsa.mod_len = widths[i];
            memset(modulus, 0x81, widths[i]);
            modulus[0] = 0x41;
            assert(!tls_verify_deferred(&offload_ctx, TLS_ALG_RSA_PSS_RSAE_SHA256,
                                        &rsa_key, digest, rsa_sig, widths[i],
                                        TLS_ALERT_BAD_CERTIFICATE));
            assert(rsa_offload_calls == before_offload + i);

            modulus[0] = 0x81;
            assert(!tls_verify_deferred(&offload_ctx, TLS_ALG_RSA_PSS_RSAE_SHA256,
                                        &rsa_key, digest, rsa_sig, widths[i],
                                        TLS_ALERT_BAD_CERTIFICATE));
            assert(rsa_offload_calls == before_offload + i + 1);
        }
    }

    /* Chain-policy distinction: a correctly-sized signature under an RSA key
     * wider than the platform cap is unsupported, while a width mismatch is
     * invalid and must remain fail-closed. */
    struct tls_cert_walker pending = {0};
    uint8_t rsa_oversize_modulus[RSA_MODULUS_MAX_SUPPORTED + 1] = {0};
    uint8_t rsa_exponent[] = {1, 0, 1};
    struct tls_key rsa_oversize = {
        .type = TLS_KEY_TYPE_RSA,
        .rsa = {
            .exp_len = sizeof(rsa_exponent),
            .exponent = rsa_exponent,
            .mod_len = sizeof(rsa_oversize_modulus),
            .modulus = rsa_oversize_modulus,
        },
    };
    pending.pending_link = true;
    pending.pending_sig_omitted = true;
    pending.pending_sig_alg = TLS_ALG_RSA_PKCS1_SHA256;
    pending.pending_sig_len = sizeof(rsa_oversize_modulus);
    assert(tls_cert_verify_pending_link(&pending, &rsa_oversize, false) ==
           TLS_KEY_OP_UNSUPPORTED);
    pending.pending_sig_len = 256;
    assert(tls_cert_verify_pending_link(&pending, &rsa_oversize, false) ==
           TLS_KEY_OP_INVALID);

    /* A structurally accepted but unknown signature OID follows the same
     * temporary unsupported-operation policy without retaining its bytes. */
    pending.pending_sig_alg = TLS_ALG_UNKNOWN;
    pending.pending_sig_len = 384;
    assert(tls_cert_verify_pending_link(&pending, &rsa_oversize, false) ==
           TLS_KEY_OP_UNSUPPORTED);

    struct tls_handshake_context ctx;
    assert(tls_handshake_init(&ctx, NULL, NULL));
    ctx.leaf_pubkey = ec.pubkey;
    assert(!tls_certverify_rsa_pss_sha256(&ctx, sig, 128));
    tls_handshake_cleanup(&ctx);
    // EC leaf capture/free must use the EC member of the key union.
    assert(tls_handshake_init(&ctx, NULL, NULL));
    ctx.hostname = "example.test";
    struct tls_cert_walker *w = tls_cert_walker_new(&ctx);
    ctx.cert_walker = w;
    w->cert_buf = malloc(sizeof(cert_ec));
    memcpy(w->cert_buf, cert_ec, sizeof(cert_ec));
    w->cert_buf_len = w->cert_buf_cap = sizeof(cert_ec);
    mem_stats_tls_direct_add(sizeof(cert_ec), sizeof(cert_ec));
    assert(tls_cert_walker_validate_one(w));
    assert(ctx.leaf_pubkey.allocated && ctx.leaf_pubkey.ec.len == 65);
    tls_handshake_cleanup(&ctx);
    assert(allocated == 0);

    const uint8_t *tbs, *signature; size_t tbs_len, sig_len; tls_alg_t scheme;
    assert(!tls_cert_extract_sig_material(cert_mismatch, sizeof(cert_mismatch), &tbs, &tbs_len, &scheme, &signature, &sig_len));
    // Oversized modulus must not overrun the fixed PSS scratch during cleanup.
    struct tls_key bad = {.type = TLS_KEY_TYPE_RSA, .rsa = {.mod_len = 4096}};
    assert(tls_x509_signature_verify_digest(digest, sig, 128, &bad, TLS_ALG_RSA_PSS_RSAE_SHA256) == TLS_KEY_OP_INVALID);
    assert(tls_x509_signature_verify(digest, 32, sig, 128, &bad, TLS_ALG_RSA_PSS_RSAE_SHA256) == TLS_KEY_OP_INVALID);

    uint8_t secret[32] = {0};
    struct tls_key aes = {.type = TLS_KEY_TYPE_AES, .aes = {16, secret}};
    tls_alg_t ciphers[] = {TLS_ALG_AES_128_GCM, TLS_ALG_AES_128_CCM, TLS_ALG_AES_128_CBC};
    for (size_t i = 0; i < 3; i++)
    {
        uint8_t *blob = tls_cipher_encrypt(&aes, ciphers[i], digest, 32);
        assert(blob != NULL);
        assert(last_cipher == ciphers[i] && aes.type == TLS_KEY_TYPE_AES);
        tls_cipher_blob_free(blob);
    }
    unsigned before = cipher_calls;
    assert(!tls_cipher_encrypt(&aes, TLS_ALG_AES_256_GCM, digest, 32));
    assert(!tls_cipher_encrypt(&ec.pubkey, TLS_ALG_AES_128_GCM, digest, 32));
    assert(!tls_cipher_encrypt(&aes, TLS_ALG_RSA_OAEP_SHA256, digest, 32));
    assert(cipher_calls == before);
    aes.aes.len = 32;
    {
        uint8_t *blob = tls_cipher_encrypt_aad(&aes, TLS_ALG_AES_256_GCM, NULL, 0, digest, 32);
        assert(blob != NULL);
        assert(last_cipher == TLS_ALG_AES_256_GCM);
        tls_cipher_blob_free(blob);
    }
    assert(tls_key_verify(digest, 32, sig, 128, &aes, TLS_ALG_RSA_PKCS1_SHA256) == TLS_KEY_OP_INVALID);
    assert(tls_key_verify(digest, 32, sig, 128, &aes, TLS_ALG_UNKNOWN) == TLS_KEY_OP_UNKNOWN);
    size_t signature_len = 0;
    assert(tls_key_sign(digest, 32, sig, &signature_len, &aes, TLS_ALG_RSA_PKCS1_SHA256) == TLS_KEY_OP_INVALID);
    assert(tls_key_sign(digest, 32, sig, &signature_len, &ec.pubkey, TLS_ALG_ECDSA_SECP256R1_SHA256) == TLS_KEY_OP_INVALID);
    puts("TLS signature dispatch/lifecycle regressions passed");
    return 0;
}

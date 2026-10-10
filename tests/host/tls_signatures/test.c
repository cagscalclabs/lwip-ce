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
    static const uint8_t fixed_body[] = {0, 0, 2, 0x13, 1, 1, 0};
    assert(memcmp(buf + 38, fixed_body, sizeof(fixed_body)) == 0);
    assert(be16(buf+45) == n-47);
    unsigned versions = 0, groups = 0, key_share = 0;
    unsigned signatures = 0, alpn = 0, sni = 0, psk_modes = 0, psk_ext = 0;
    for (size_t off = 47; off < n; )
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
            static const uint8_t expected[] = {0, 2, 0, 0x1d};
            assert(len == sizeof(expected) && memcmp(buf+off+4, expected, len) == 0);
            groups++;
        }
        if (type == 51)
        {
            static const uint8_t expected_header[] = {0, 0x24, 0, 0x1d, 0, 0x20};
            assert(len == 38 && memcmp(buf+off+4, expected_header, sizeof(expected_header)) == 0);
            assert(memcmp(buf+off+10, ctx.ecdhe_public, 32) == 0);
            key_share++;
        }
        if (type == 0)
        {
            sni++;
            assert(hostname && len == strlen(hostname) + 5);
            assert(memcmp(buf + off + 9, hostname, strlen(hostname)) == 0);
        }
        if (type == 13)
        {
            assert(len == 4 && be16(buf+off+4) == 2 && be16(buf+off+6) == 0x0804);
            signatures++;
        }
        if (type == 50)
        {
            assert(len == 6 && be16(buf+off+4) == 4);
            assert(be16(buf+off+6) == 0x0401 && be16(buf+off+8) == 0x0804);
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
    assert(signatures == 2 && alpn == (unsigned)offer_alpn);
    assert(sni == (unsigned)(hostname && !strcmp(hostname, "example.test")));
    assert(psk_modes == (unsigned)psk && psk_ext == (unsigned)psk);
    tls_handshake_cleanup(&ctx);
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
    static const uint8_t cert_request[] = {
        TLS_HANDSHAKE_CERTIFICATE_REQUEST, 0, 0, 11,
        0, 0, 8,
        TLS_EXT_SIGNATURE_ALGORITHMS >> 8,
        TLS_EXT_SIGNATURE_ALGORITHMS & 0xff, 0, 4,
        0, 2, 0x08, 0x04
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
    uint8_t shared[32] = {0};

    assert(!tls_x25519_shared_is_nonzero(shared));
    shared[31] = 1;
    assert(tls_x25519_shared_is_nonzero(shared));

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
    ctx.state = TLS_STATE_ENCRYPTED_EXTENSIONS_RECEIVED;
    assert(tls_recv_certificate_request(&ctx, cert_request,
                                        sizeof(cert_request)));
    assert(ctx.client_certificate_requested);

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
    assert(ctx.leaf_pubkey.allocated && ctx.leaf_pubkey.rsa.mod_len == 128);
    assert(ctx.leaf_pubkey.rsa.exponent[0] == 1);
    // One imported/captured RSA key, two independent signature operations.
    uint8_t operation_sig[128];
    memset(operation_sig, 0x11, sizeof(operation_sig));
    assert(tls_key_verify((const uint8_t *)"message", 7, operation_sig, 128,
                         &ctx.leaf_pubkey, TLS_ALG_RSA_PKCS1_SHA256) == TLS_KEY_OP_OK);
    assert(tls_key_verify((const uint8_t *)"message", 7, operation_sig, 128,
                         &ctx.leaf_pubkey, TLS_ALG_RSA_PSS_RSAE_SHA256) == TLS_KEY_OP_INVALID);
    memset(operation_sig, 0x22, sizeof(operation_sig));
    assert(tls_key_verify((const uint8_t *)"message", 7, operation_sig, 128,
                         &ctx.leaf_pubkey, TLS_ALG_RSA_PSS_RSAE_SHA256) == TLS_KEY_OP_OK);
    assert(ctx.leaf_pubkey.type == TLS_KEY_TYPE_RSA);
    w->cert_index = 1;
    assert(tls_cert_walker_validate_one(w)); // adjacent link uses stored scheme
    w->state = CW_DONE;

    // Root metadata deliberately differs from the child's signature scheme.
    root_entry = calloc(1, sizeof(*root_entry) + 131);
    root_entry->len = sizeof(*root_entry) + 131;
    root_entry->alg_id = expected == TLS_ALG_RSA_PKCS1_SHA256
        ? TLS_CERT_SIG_RSA_PSS_SHA256 : TLS_CERT_SIG_RSA_PKCS1_SHA256;
    root_entry->key[0] = root_entry->key[2] = 1;
    memset(root_entry->key + 3, 0x81, 128);
    ctx.state = TLS_STATE_ENCRYPTED_EXTENSIONS_RECEIVED;
    assert(tls_recv_certificate_streamed(&ctx, w));
    w->pending_sig[0] ^= 1;
    ctx.state = TLS_STATE_ENCRYPTED_EXTENSIONS_RECEIVED;
    assert(!tls_recv_certificate_streamed(&ctx, w));
    assert(!tls_cert_walker_validate_one(w)); // invalid adjacent link too

    uint8_t sig[128]; memset(sig, 0x22, sizeof(sig));
    assert(tls_certverify_rsa_pss_sha256(&ctx, sig, sizeof(sig)));
    assert(!tls_certverify_rsa_pss_sha256(&ctx, sig, sizeof(sig)-1));
    tls_handshake_cleanup(&ctx);
    assert(ctx.leaf_pubkey.type == TLS_KEY_TYPE_UNKNOWN && !ctx.leaf_pubkey.allocated);
    tls_handshake_cleanup(&ctx); // cleanup is idempotent
    assert(allocated == 0);
    free(root_entry); root_entry = NULL;
}

int main(void)
{
    ALG(alg_pkcs, true, TLS_ALG_RSA_PKCS1_SHA256);
    ALG(alg_pss, true, TLS_ALG_RSA_PSS_RSAE_SHA256);
    ALG(alg_pss_trailer, true, TLS_ALG_RSA_PSS_RSAE_SHA256);
    ALG(alg_ec, true, TLS_ALG_ECDSA_SECP256R1_SHA256);
    ALG(bad_default, false, 0); ALG(bad_absent, false, 0);
    ALG(bad_salt, false, 0); ALG(bad_hash, false, 0);
    ALG(bad_mgf_hash, false, 0); ALG(bad_duplicate, false, 0);
    ALG(bad_trailer, false, 0); ALG(bad_key_oid, false, 0);
    hello(false, NULL, false); hello(true, NULL, false);
    hello(false, "example.test", true); hello(true, "example.test", true);
    hello(false, "192.168.2.10", false); hello(true, "192.168.2.10", false);
    hello(false, "2001:db8::1", false); hello(true, "2001:db8::1", false);
    handshake_extension_tests();
    identity_tests();
    chain(cert_pkcs, sizeof(cert_pkcs), TLS_ALG_RSA_PKCS1_SHA256);
    chain(cert_pss, sizeof(cert_pss), TLS_ALG_RSA_PSS_RSAE_SHA256);
    assert(pkcs_calls && pss_calls);

    struct tls_x509_object ec;
    assert(tls_x509_parse_certificate(cert_ec, sizeof(cert_ec), &ec));
    assert(ec.pubkey.type == TLS_KEY_TYPE_EC_P256 && ec.pubkey.ec.len == 65);
    uint8_t digest[32], sig[128]; memset(digest, 0x42, 32); memset(sig, 0x22, 128);
    assert(tls_cert_verify_digest(TLS_ALG_ECDSA_SECP256R1_SHA256, &ec.pubkey, digest, sig, 128) == TLS_KEY_OP_UNSUPPORTED);
    assert(tls_cert_verify_digest(TLS_ALG_RSA_PSS_RSAE_SHA256, &ec.pubkey, digest, sig, 128) == TLS_KEY_OP_INVALID);

    /* Chain-policy distinction: a correctly-sized signature under an RSA key
     * wider than the platform cap is unsupported, while a width mismatch is
     * invalid and must remain fail-closed. */
    struct tls_cert_walker pending = {0};
    uint8_t rsa4096_modulus[512] = {0};
    uint8_t rsa_exponent[] = {1, 0, 1};
    struct tls_key rsa4096 = {
        .type = TLS_KEY_TYPE_RSA,
        .rsa = {
            .exp_len = sizeof(rsa_exponent),
            .exponent = rsa_exponent,
            .mod_len = sizeof(rsa4096_modulus),
            .modulus = rsa4096_modulus,
        },
    };
    pending.pending_link = true;
    pending.pending_sig_omitted = true;
    pending.pending_sig_alg = TLS_ALG_RSA_PKCS1_SHA256;
    pending.pending_sig_len = sizeof(rsa4096_modulus);
    assert(tls_cert_verify_pending_link(&pending, &rsa4096) ==
           TLS_KEY_OP_UNSUPPORTED);
    pending.pending_sig_len = 256;
    assert(tls_cert_verify_pending_link(&pending, &rsa4096) ==
           TLS_KEY_OP_INVALID);

    /* A structurally accepted but unknown signature OID follows the same
     * temporary unsupported-operation policy without retaining its bytes. */
    pending.pending_sig_alg = TLS_ALG_UNKNOWN;
    pending.pending_sig_len = 384;
    assert(tls_cert_verify_pending_link(&pending, &rsa4096) ==
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
    assert(tls_key_sign(digest, 32, sig, &signature_len, &ec.pubkey, TLS_ALG_ECDSA_SECP256R1_SHA256) == TLS_KEY_OP_UNSUPPORTED);
    puts("TLS signature dispatch/lifecycle regressions passed");
    return 0;
}

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
static void hello(bool psk, const char *hostname)
{
    struct tls_handshake_context ctx;
    assert(tls_handshake_init(&ctx, NULL, NULL));
    ctx.psk_mode = psk;
    ctx.hostname = hostname;
    ctx.psk_identity.identity_len = 1;
    uint8_t buf[512]; size_t n, again;
    assert(tls_send_client_hello(&ctx, buf, sizeof(buf), &n));
    ctx.state = TLS_STATE_INIT; /* Each serialization starts a fresh flight. */
    assert(tls_send_client_hello(&ctx, buf, n, &again) && n == again);
    ctx.state = TLS_STATE_INIT;
    assert(!tls_send_client_hello(&ctx, buf, n-1, &again));
    assert(be16(buf+45) == n-47);
    unsigned found = 0, sni = 0;
    for (size_t off = 47; off < n; )
    {
        unsigned type = be16(buf+off), len = be16(buf+off+2);
        assert(off + 4 + len <= n);
        if (type == 0)
        {
            sni++;
            assert(hostname && len == strlen(hostname) + 5);
            assert(memcmp(buf + off + 9, hostname, strlen(hostname)) == 0);
        }
        if (type == 13)
        {
            assert(len == 4 && be16(buf+off+4) == 2 && be16(buf+off+6) == 0x0804);
            found++;
        }
        if (type == 50)
        {
            assert(len == 6 && be16(buf+off+4) == 4);
            assert(be16(buf+off+6) == 0x0401 && be16(buf+off+8) == 0x0804);
            found++;
        }
        off += 4 + len;
    }
    assert(found == 2);
    assert(sni == (unsigned)(hostname && !strcmp(hostname, "example.test")));
    tls_handshake_cleanup(&ctx);
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
    hello(false, NULL); hello(true, NULL);
    hello(false, "example.test"); hello(true, "example.test");
    hello(false, "192.168.2.10"); hello(true, "192.168.2.10");
    hello(false, "2001:db8::1"); hello(true, "2001:db8::1");
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

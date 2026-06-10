#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ti/getkey.h>
#include <ti/screen.h>

#include <lwip/core.h>
#include <lwip/cryptography/hash.h>
#include <lwip/cryptography/rsa.h>

void *os_FindAppStart(const char *name);

static const char rsa_pubkey_hex[] =
    "a8f037966fd8f3e402fa02a1c564b6dab0a957162085aa90bf02763a97a8e700"
    "4c61e34504e1a7164c53c0da6d186db2dc3875ecef833e9f17df7efec064ecee"
    "5c3168ec0a8b3ae73c309ccfe9787dd98cdb7423ec9a8ae85999ed78eeb52893"
    "5a38cc239650f6068d5ac11fc969221fd266957c57c5d8a7935b08d75f8f4487"
    "8e9264ec08159b8c6829ab759093c1f42c4703363817bb72af9aaf219a578135"
    "bc5ed9d3f9e48098542eebdc735b60d62dbf384f484c823d3c69dc100e7c87a6"
    "9c28f26c4a1eccf466785fb1234c57f54dfd8227194558e6a13baa63cef69a92"
    "cb10e5123be856fdb7cd30434a7370e1dcb8bf8760f9a254722cdb1a97a54491";

static const char rsa_sig_hex[] =
    "87d54d3a79a00946304bf97a81dd4a16b1dfd937565bc223748c5f858546210e"
    "8f7136acb861a74e5dee4fd3e185d3248dc24504da5f1898b3012abdceb16037"
    "99e382fd328a6ed60eef500e1d89240023ee30978ed616362b4c25ca4299f151"
    "e5333d29021b77e58dfc64f9eac47f23291263df72bfddf2a54745dc4a5bdfa2"
    "1c49c2df87efd2570d5f97031cc1ef5e6651e42077f792ac3b9a58ab827045f5"
    "88e9296e7c900a6dfa5fd8dcb0e07e336a8c52e37778634384b99c2537e0b547"
    "ebf5d89a2c3f3c0be14943fa2affcb786a5f98382c04724a07ecaf2ec51b7ec1"
    "586166738a3d2c3d617552fb7ad69e74beee413c3bd9d291c291f95fe8254f3f";

static void show_wait(const char *line1, const char *line2)
{
    os_ClrHome();
    printf("%s", line1);
    if (line2)
    {
        printf("\n%s", line2);
    }
    os_GetKey();
}

static uint8_t hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return (uint8_t)(c - '0');
    if (c >= 'a' && c <= 'f') return (uint8_t)(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return (uint8_t)(c - 'A' + 10);
    return 0xff;
}

static bool decode_hex(uint8_t *out, size_t out_len, const char *hex)
{
    size_t hex_len = strlen(hex);
    if (!out || !hex || hex_len != out_len * 2)
    {
        return false;
    }

    for (size_t i = 0; i < out_len; i++)
    {
        uint8_t hi = hex_nibble(hex[i * 2]);
        uint8_t lo = hex_nibble(hex[i * 2 + 1]);
        if (hi > 0x0f || lo > 0x0f)
        {
            return false;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

static bool hash_message(uint8_t out[TLS_SHA256_DIGEST_LEN])
{
    static const uint8_t msg[] = "hello world";
    struct tls_hash_context hash_ctx;

    show_wait("rsa probe", "pre hash");
    if (!tls_hash_context_init(&hash_ctx, TLS_HASH_SHA256))
    {
        return false;
    }
    tls_hash_update(&hash_ctx, msg, sizeof(msg) - 1);
    tls_hash_digest(&hash_ctx, out);
    show_wait("rsa probe", "post hash");
    return true;
}

int main(void)
{
    uint8_t mhash[TLS_SHA256_DIGEST_LEN];
    uint8_t *pubkey = NULL;
    uint8_t *sig = NULL;
    uint8_t *decoded = NULL;
    bool ok = false;

    if (!os_FindAppStart("lwIP"))
    {
        show_wait("rsa probe failed", "app missing");
        return 1;
    }

    show_wait("rsa probe", "pre runtime");
    if (!lwip_init_runtime())
    {
        char buf[24];
        snprintf(buf, sizeof(buf), "runtime %u",
                 (unsigned)lwip_runtime_last_error());
        show_wait("rsa probe failed", buf);
        return 1;
    }
    show_wait("rsa probe", "post runtime");

    show_wait("rsa probe", "pre lwip_init");
    if (lwip_init() != ERR_OK)
    {
        show_wait("rsa probe failed", "lwip init");
        return 1;
    }
    show_wait("rsa probe", "post lwip_init");

    pubkey = (uint8_t *)mem_malloc(RSA_MODULUS_MAX_SUPPORTED);
    sig = (uint8_t *)mem_malloc(RSA_MODULUS_MAX_SUPPORTED);
    decoded = (uint8_t *)mem_malloc(RSA_MODULUS_MAX_SUPPORTED);
    if (!pubkey || !sig || !decoded)
    {
        show_wait("rsa probe failed", "mem_malloc");
        goto cleanup;
    }

    if (!decode_hex(pubkey, RSA_MODULUS_MAX_SUPPORTED, rsa_pubkey_hex) ||
        !decode_hex(sig, RSA_MODULUS_MAX_SUPPORTED, rsa_sig_hex))
    {
        show_wait("rsa probe failed", "hex decode");
        goto cleanup;
    }

    if (!hash_message(mhash))
    {
        show_wait("rsa probe failed", "hash");
        goto cleanup;
    }

    show_wait("rsa probe", "pre rsa decrypt");
    if (!tls_rsa_decrypt_signature(sig, RSA_MODULUS_MAX_SUPPORTED,
                                   decoded, pubkey,
                                   RSA_MODULUS_MAX_SUPPORTED))
    {
        show_wait("rsa probe failed", "rsa decrypt");
        goto cleanup;
    }
    show_wait("rsa probe", "post rsa decrypt");

    show_wait("rsa probe", "pre pss verify");
    ok = tls_rsa_pss_verify(decoded, RSA_MODULUS_MAX_SUPPORTED,
                            mhash, sizeof(mhash), TLS_HASH_SHA256);
    show_wait(ok ? "rsa probe OK" : "rsa probe failed",
              ok ? "pss verified" : "pss verify");

cleanup:
    if (decoded) mem_free(decoded);
    if (sig) mem_free(sig);
    if (pubkey) mem_free(pubkey);
    return ok ? 0 : 1;
}

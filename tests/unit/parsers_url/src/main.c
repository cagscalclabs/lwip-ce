#include <ti/screen.h>
#include <ti/getkey.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "../../../../src/parsers/url.h"
#include <lwip.h>

static void show_result(bool ok)
{
    if (ok)
        printf("success");
    else
        printf("failed");
    os_GetKey();
    os_ClrHome();
}

/* 1: encode unreserved chars pass through unchanged (RFC 3986 §2.3) */
static bool test_encode_unreserved(void)
{
    char buf[64];
    size_t n = url_encode(buf, sizeof(buf), "hello-world_1.0~");
    return n != URL_ERR && strcmp(buf, "hello-world_1.0~") == 0;
}

/* 2: encode a realistic OAuth POST body field value */
static bool test_encode_oauth_value(void)
{
    char buf[128];
    /* client secret that contains special chars a real server might issue */
    size_t n = url_encode(buf, sizeof(buf), "s3cr3t+k3y/v1=abc&xyz");
    if (n == URL_ERR) return false;
    if (strcmp(buf, "s3cr3t%2Bk3y%2Fv1%3Dabc%26xyz") != 0) return false;
    return url_encode(buf, 4, "hello") == URL_ERR;
}

/* 3: decode the same string back to original */
static bool test_decode_roundtrip(void)
{
    const char *encoded = "s3cr3t%2Bk3y%2Fv1%3Dabc%26xyz";
    char buf[64];
    size_t n = url_decode(buf, sizeof(buf), encoded);
    if (n == URL_ERR) return false;
    if (strcmp(buf, "s3cr3t+k3y/v1=abc&xyz") != 0) return false;
    return url_decode(buf, sizeof(buf), "bad%2X") == URL_ERR;
}

/* 4: decode plain string (no percent sequences) is a passthrough */
static bool test_decode_plain(void)
{
    char buf[64];
    size_t n = url_decode(buf, sizeof(buf), "hello");
    return n != URL_ERR && strcmp(buf, "hello") == 0;
}

/* 5: url_build_query — real OAuth 2.0 client_credentials request body */
static bool test_query_oauth(void)
{
    char buf[256];
    const char *keys[]   = {"grant_type", "client_id", "client_secret", "scope"};
    const char *values[] = {"client_credentials", "myapp", "s3cr3t+k3y", "read write"};
    size_t n = url_build_query(buf, sizeof(buf), keys, values, 4);
    if (n == URL_ERR) return false;
    return strcmp(buf,
        "grant_type=client_credentials"
        "&client_id=myapp"
        "&client_secret=s3cr3t%2Bk3y"
        "&scope=read%20write") == 0;
}

/* 6: encode→decode roundtrip preserves arbitrary byte values */
static bool test_encode_decode_roundtrip(void)
{
    const char original[] = "user@example.com?foo=bar&baz=qux#anchor";
    char encoded[256];
    char decoded[256];
    size_t n = url_encode(encoded, sizeof(encoded), original);
    if (n == URL_ERR) return false;
    n = url_decode(decoded, sizeof(decoded), encoded);
    if (n == URL_ERR) return false;
    return strcmp(decoded, original) == 0;
}

int main(void)
{
    if (!lwip_start()) return 1;
    os_ClrHome();

    show_result(test_encode_unreserved());
    show_result(test_encode_oauth_value());
    show_result(test_decode_roundtrip());
    show_result(test_decode_plain());
    show_result(test_query_oauth());
    show_result(test_encode_decode_roundtrip());

    return 0;
}

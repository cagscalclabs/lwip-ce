#include <ti/screen.h>
#include <ti/getkey.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "tls/includes/x509.h"
#include "lwip/mem.h"
#include "drivers/mem.h"

#define TLS_TEST_STATIC_ARENA (32u * 1024u)
static uint8_t tls_test_arena[TLS_TEST_STATIC_ARENA];

static bool tls_test_mem_init(void)
{
    if (!mem_init_static(tls_test_arena, sizeof(tls_test_arena)))
    {
        return false;
    }
    return true;
}

static void draw_line(const char *msg, int *y)
{
    os_FontDrawText(msg, 2, *y);
    *y += 12;
}

static void draw_result_line(const char *name, bool pass, int *y)
{
    char line[96];
    snprintf(line, sizeof(line), "%s: %s", name, pass ? "pass" : "fail");
    draw_line(line, y);
}

static const char *asn1_class_name(uint8_t tag)
{
    switch (tls_asn1_tag_class(tag))
    {
    case ASN1_UNIVERSAL:
        return "U";
    case ASN1_APPLICATION:
        return "A";
    case ASN1_CONTEXTSPEC:
        return "C";
    case ASN1_PRIVATE:
        return "P";
    default:
        return "?";
    }
}

static void asn1_preview_hex(const struct tls_asn1_tlv *tlv, char *out, size_t out_sz)
{
    size_t pos = 0;
    size_t n = tlv->len < 6 ? tlv->len : 6;
    if (out_sz == 0)
    {
        return;
    }
    out[0] = '\0';
    for (size_t i = 0; i < n; i++)
    {
        int w = snprintf(out + pos, out_sz - pos, "%02X", tlv->value[i]);
        if (w < 0 || (size_t)w >= out_sz - pos)
        {
            break;
        }
        pos += (size_t)w;
        if (i + 1 < n && pos + 1 < out_sz)
        {
            out[pos++] = ' ';
            out[pos] = '\0';
        }
    }
    if (tlv->len > n && pos + 4 < out_sz)
    {
        snprintf(out + pos, out_sz - pos, " ...");
    }
}

static void dump_asn1_tree_rec(const uint8_t *base,
                               size_t base_len,
                               int depth,
                               int *y,
                               int *nodes_left)
{
    struct tls_asn1_cursor cur;
    struct tls_asn1_tlv tlv;

    if (*nodes_left <= 0 || depth > 8)
    {
        return;
    }
    if (!tls_asn1_cursor_init(&cur, base, base_len))
    {
        return;
    }

    while (*nodes_left > 0 && tls_asn1_next(&cur, &tlv))
    {
        char line[96];
        char bytes[32];
        char indent[20];
        size_t ind = (size_t)(depth * 2);
        if (ind > sizeof(indent) - 2)
        {
            ind = sizeof(indent) - 2;
        }
        memset(indent, ' ', ind);
        indent[ind] = '\0';

        asn1_preview_hex(&tlv, bytes, sizeof(bytes));
        snprintf(line, sizeof(line), "%s%s c=%u,tag=%u,len=%u] %s",
                 indent,
                 asn1_class_name(tlv.tag),
                 tls_asn1_tag_constructed(tlv.tag) ? 1u : 0u,
                 (unsigned)tls_asn1_tag_number(tlv.tag),
                 (unsigned)tlv.len,
                 bytes);
        draw_line(line, y);
        (*nodes_left)--;
        if (*nodes_left <= 0)
        {
            draw_line("... tree truncated ...", y);
            return;
        }

        if (tls_asn1_tag_constructed(tlv.tag))
        {
            dump_asn1_tree_rec(tlv.value, tlv.len, depth + 1, y, nodes_left);
            if (*nodes_left <= 0)
            {
                return;
            }
        }
    }
}

static void dump_asn1_tree(const struct tls_x509_object *x, int *y)
{
    struct tls_asn1_cursor c;
    struct tls_asn1_tlv root;
    int nodes_left = 14;

    if (!x)
    {
        return;
    }
    if (!tls_asn1_cursor_init(&c, x->der, x->der_len) || !tls_asn1_next(&c, &root))
    {
        draw_line("  (unable to parse root)", y);
        return;
    }
    dump_asn1_tree_rec(root.tlv, root.header_len + root.len, 0, y, &nodes_left);
}

static bool show_parse_result(const char *name, bool pass, const struct tls_x509_object *x)
{
    int y = 30;
    os_ClrHome();
    os_FontSelect(os_SmallFont);
    draw_result_line(name, pass, &y);
    dump_asn1_tree(x, &y);
    os_GetKey();
    return pass;
}

static bool show_result(const char *name, bool pass)
{
    int y = 30;
    os_ClrHome();
    os_FontSelect(os_SmallFont);
    draw_result_line(name, pass, &y);
    os_GetKey();
    return pass;
}

static bool tls_patch_basic_constraints_ca_false(uint8_t *der, size_t der_len)
{
    size_t i;
    if (!der || der_len < 5)
    {
        return false;
    }

    for (i = 0; i + 5 <= der_len; i++)
    {
        if (der[i] == 0x30 && der[i + 1] == 0x03 &&
            der[i + 2] == 0x01 && der[i + 3] == 0x01 &&
            der[i + 4] == 0xFF)
        {
            der[i + 4] = 0x00;
            return true;
        }
    }

    return false;
}

static const char cert_pem[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDnzCCAoegAwIBAgIUHE/g0NoguFZkQL9VBbXbIm/7WDswDQYJKoZIhvcNAQEL\n"
    "BQAwXzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5ZMQswCQYDVQQHDAJOWTERMA8G\n"
    "A1UECgwIY2Fnc3RlY2gxETAPBgNVBAsMCGNhZ3N0ZWNoMRAwDgYDVQQDDAdBbnRo\n"
    "b255MB4XDTI0MDkwODA1NDc1M1oXDTI1MDkwODA1NDc1M1owXzELMAkGA1UEBhMC\n"
    "VVMxCzAJBgNVBAgMAk5ZMQswCQYDVQQHDAJOWTERMA8GA1UECgwIY2Fnc3RlY2gx\n"
    "ETAPBgNVBAsMCGNhZ3N0ZWNoMRAwDgYDVQQDDAdBbnRob255MIIBIjANBgkqhkiG\n"
    "9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8q4s1a+ReNvXPOhFhdpNGwCwfR6WHzRoksko\n"
    "2SJCqwhO9b9+0cUM6WQxCPDtAxba8g6FgJTc2m9x/I1gybyn7++ZrtNaMXgICIFz\n"
    "a5rh5pBNbtHiL+5v1fy7wIkKo34jK3VryRNQTbb5VJqfGD33OJYUp3BfpShRkIwg\n"
    "xocloqXqwB9UOzUF99icUvC3wDy85y4zolIpNEM8zQqEuQSJIISUQuevo0DlvMtB\n"
    "/DMeGQP64pE5/HDz89+agFka1sDWguGyp3TbzvXxiEoigxsj2208unqozsNIYTRG\n"
    "xPF5deNJ/x+3kW4ivBVzpC01/3ETpiMYotxaEARoO0maBDpKzQIDAQABo1MwUTAd\n"
    "BgNVHQ4EFgQUrv2AiZkx1XiN7qY3wGkpiJ5GCjMwHwYDVR0jBBgwFoAUrv2AiZkx\n"
    "1XiN7qY3wGkpiJ5GCjMwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC\n"
    "AQEA6YccSZu9vRgEZ3oHSpB7LRxYF5FxwH2WCUtnxz3uIafzbjnyP7tLkTL845Je\n"
    "VFgAi/ZHpJGKLOxXIqIffGnUe6wuaYFr2M2QdzkKIRvr0/Mi5XFRX0PI7/dAFZhj\n"
    "5DFtdM9avzdczka4r8AB8nHZwcmlQbxdbs/hv1nVsr6mfh5FntuPY3cNulkLwOhq\n"
    "UCKEFl1CoCpz68ejKhszhTrYWVLTfNrm3HwQlMRqXvmv1jWsh9X8sm/IM1psUPmm\n"
    "95VY+2OxBwJRHh1hYVlBn8RxnCM4EGTAqowTv/r8sktY2gW2HulwdMSzxOlApL5f\n"
    "5yiwKkSmPVU7SIUuC5UVOujblw==\n"
    "-----END CERTIFICATE-----\n";

static const char cert2_pem[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDaDCCAlCgAwIBAgIJAIqzf9vicn6WMA0GCSqGSIb3DQEBCwUAMGExCzAJBgNV\n"
    "BAYTAlVTMQswCQYDVQQIDAJDQTELMAkGA1UEBwwCU0YxEDAOBgNVBAoMB2x3aXAt\n"
    "Y2UxDTALBgNVBAsMBHRlc3QxFzAVBgNVBAMMDlVuaXQgVGVzdCBDQSAyMB4XDTI2\n"
    "MDIyNDIxNDY1MloXDTI3MDIyNDIxNDY1MlowYTELMAkGA1UEBhMCVVMxCzAJBgNV\n"
    "BAgMAkNBMQswCQYDVQQHDAJTRjEQMA4GA1UECgwHbHdpcC1jZTENMAsGA1UECwwE\n"
    "dGVzdDEXMBUGA1UEAwwOVW5pdCBUZXN0IENBIDIwggEiMA0GCSqGSIb3DQEBAQUA\n"
    "A4IBDwAwggEKAoIBAQCvMr+ZGl5LYfJEZqTED05rtfSwS1sIpjfw3G6Dnn9kV+i+\n"
    "F5N71JkR+V8t4K7/pHWQYRHETnLkyc1smtbPUcwBmVXIO19nSR6ri5wGeXKZQyuR\n"
    "Mxsf49Cehb/nvqBWbMzcZbALuTR3H5/ny8bGR9n/6TQwZIxyYkx6cxM0nn9bX49P\n"
    "VvcUPjjK3bmDksFjK5LW5LWnemi8irz7WLyDxZYcoqragv7ypCZTv6oWsgeP1OI6\n"
    "XxKgTj6LgtNHBtRQvIfPtVVNnqNMN1l9yg/IY2XAixvuVF9hFV0+izqIFBSqhg6T\n"
    "iQjlwVm3+Vic+p2d+HiOMoHSV14k9rw4Ef3A4j+tAgMBAAGjIzAhMA8GA1UdEwEB\n"
    "/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3DQEBCwUAA4IBAQCLN3lC\n"
    "Dd0XzcKgSaPnEGnHUVl811si5HbKsOzmLBiZcPppdL30lKZXCKtcDtaz1Qs/GaZg\n"
    "00KWKSpNtv7ibO272gu/TrBhEv95vs1MfFwvb6ROpNuK3nS0m9ziDddZTx8b/K4C\n"
    "FRg2ZGJO89HsjTuGtNvp0dmxc2Zaz3WHFiLNdZCcj716c3j+ynsdtI4NDPwNosmm\n"
    "wR8XNmTGxPnNmQS1T+Bwk8fggCVw+49pCzvw45AfUJlzxWHzOO2ZhejPiT5q7wSE\n"
    "E8fx/679lHkVgb/0lMhc/hl3+BY9OBrjgCg74HxjNDD//xcPg7rxUURbMIMjTxbP\n"
    "i7P5ofHug8rThiTS\n"
    "-----END CERTIFICATE-----\n";

int main(void)
{
    uint8_t der_patched[1800];
    struct tls_x509_object *obj1 = NULL;
    struct tls_x509_object *obj2 = NULL;
    bool ok = true;
    bool pass = false;

    os_ClrHome();
    os_FontSelect(os_SmallFont);
    if (!tls_test_mem_init())
    {
        int y = 30;
        draw_line("mem init failed", &y);
        os_GetKey();
        return 1;
    }

    obj1 = tls_x509_import_certificate(cert_pem, strlen(cert_pem));
    obj2 = tls_x509_import_certificate(cert2_pem, strlen(cert2_pem));

    pass =
        obj1 &&
        obj1->parsed.issuer_cn && obj1->parsed.issuer_cn->data &&
        obj1->parsed.subject_cn && obj1->parsed.subject_cn->data &&
        obj1->parsed.spki_raw && obj1->parsed.spki_raw->data && obj1->parsed.spki_raw->len > 0 &&
        obj1->parsed.extensions && obj1->parsed.extensions->data && obj1->parsed.extensions->len > 0;
    ok &= show_parse_result("cert1 parse", pass, obj1);

    pass =
        obj1 &&
        tls_x509_has_valid_constraints(obj1->parsed.extensions->data, obj1->parsed.extensions->len) &&
        tls_x509_has_required_ca_constraints(obj1->der, obj1->der_len);
    ok &= show_result("cert1 constraints", pass);

    {
        pass = false;
        if (obj1 && obj1->der_len <= sizeof(der_patched))
        {
            memcpy(der_patched, obj1->der, obj1->der_len);
            if (tls_patch_basic_constraints_ca_false(der_patched, obj1->der_len))
            {
                pass = !tls_x509_has_required_ca_constraints(der_patched, obj1->der_len);
            }
        }
        ok &= show_result("cert1 patched reject", pass);
    }

    pass =
        obj2 &&
        obj2->parsed.issuer_cn && obj2->parsed.issuer_cn->data &&
        obj2->parsed.subject_cn && obj2->parsed.subject_cn->data &&
        obj2->parsed.spki_raw && obj2->parsed.spki_raw->data && obj2->parsed.spki_raw->len > 0 &&
        obj2->parsed.extensions && obj2->parsed.extensions->data && obj2->parsed.extensions->len > 0;
    ok &= show_parse_result("cert2 parse", pass, obj2);

    pass =
        obj2 &&
        tls_x509_has_valid_constraints(obj2->parsed.extensions->data, obj2->parsed.extensions->len) &&
        tls_x509_has_required_ca_constraints(obj2->der, obj2->der_len);
    ok &= show_result("cert2 constraints", pass);

    {
        pass = false;
        if (obj2 && obj2->der_len <= sizeof(der_patched))
        {
            memcpy(der_patched, obj2->der, obj2->der_len);
            if (tls_patch_basic_constraints_ca_false(der_patched, obj2->der_len))
            {
                pass = !tls_x509_has_required_ca_constraints(der_patched, obj2->der_len);
            }
        }
        ok &= show_result("cert2 patched reject", pass);
    }

    os_ClrHome();
    tls_x509_object_destroy(obj1);
    tls_x509_object_destroy(obj2);
    return ok ? 0 : 1;
}

#include <ti/screen.h>
#include <ti/getkey.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <lwip/parsers/json.h>
#include <lwip.h>

/* Real-world OAuth 2.0 token response payload */
static const char oauth_response[] =
    "{"
    "\"access_token\":\"eyJhbGciOiJSUzI1NiJ9.payload.sig\","
    "\"token_type\":\"Bearer\","
    "\"expires_in\":3600,"
    "\"scope\":\"read write\","
    "\"refresh_token\":null"
    "}";

/* Real-world JSON array payload (e.g. a sensor reading list) */
static const char array_payload[] =
    "[{\"id\":1,\"val\":\"23.5\"},{\"id\":2,\"val\":\"19.0\"}]";

static void show_result(bool ok)
{
    if (ok)
        printf("success");
    else
        printf("failed");
    os_GetKey();
    os_ClrHome();
}

/* 1: pull walk of oauth_response — confirm all keys/types present */
static bool test_pull_walk(void)
{
    json_parser_t root, obj;
    json_token_t tok;
    json_init(&root, oauth_response, sizeof(oauth_response) - 1);

    /* root token is the object itself */
    if (json_next(&root, &tok) != JSON_OK || tok.type != JSON_TOK_OBJECT) return false;
    json_enter(&obj, &tok);

    /* access_token */
    if (json_next(&obj, &tok) != JSON_OK || tok.type != JSON_TOK_KEY) return false;
    if (json_next(&obj, &tok) != JSON_OK || tok.type != JSON_TOK_STRING) return false;
    /* token_type */
    if (json_next(&obj, &tok) != JSON_OK || tok.type != JSON_TOK_KEY) return false;
    if (json_next(&obj, &tok) != JSON_OK || tok.type != JSON_TOK_STRING) return false;
    /* expires_in */
    if (json_next(&obj, &tok) != JSON_OK || tok.type != JSON_TOK_KEY) return false;
    if (json_next(&obj, &tok) != JSON_OK || tok.type != JSON_TOK_NUMBER) return false;
    /* scope */
    if (json_next(&obj, &tok) != JSON_OK || tok.type != JSON_TOK_KEY) return false;
    if (json_next(&obj, &tok) != JSON_OK || tok.type != JSON_TOK_STRING) return false;
    /* refresh_token: null */
    if (json_next(&obj, &tok) != JSON_OK || tok.type != JSON_TOK_KEY) return false;
    if (json_next(&obj, &tok) != JSON_OK || tok.type != JSON_TOK_NULL) return false;
    /* exhausted */
    if (json_next(&obj, &tok) != JSON_ERR_DONE) return false;
    return true;
}

/* 2: json_get_string extracts token_type = "Bearer" */
static bool test_get_string(void)
{
    json_parser_t root, obj;
    json_token_t tok;
    char buf[32];
    json_init(&root, oauth_response, sizeof(oauth_response) - 1);
    if (json_next(&root, &tok) != JSON_OK || tok.type != JSON_TOK_OBJECT) return false;
    json_enter(&obj, &tok);
    if (json_get_string(&obj, "token_type", buf, sizeof(buf)) != JSON_OK) return false;
    return strcmp(buf, "Bearer") == 0;
}

/* 3: json_get_number extracts expires_in = 3600 */
static bool test_get_number(void)
{
    json_parser_t root, obj;
    json_token_t tok;
    long val;
    json_init(&root, oauth_response, sizeof(oauth_response) - 1);
    if (json_next(&root, &tok) != JSON_OK || tok.type != JSON_TOK_OBJECT) return false;
    json_enter(&obj, &tok);
    if (json_get_number(&obj, "expires_in", &val) != JSON_OK) return false;
    return val == 3600;
}

/* 4: json_get_key_value targeted — refresh_token value is JSON_TOK_NULL */
static bool test_get_key_value_null(void)
{
    json_parser_t root, obj;
    json_token_t tok, key, value;
    json_init(&root, oauth_response, sizeof(oauth_response) - 1);
    if (json_next(&root, &tok) != JSON_OK || tok.type != JSON_TOK_OBJECT) return false;
    json_enter(&obj, &tok);
    if (json_get_key_value(&obj, "refresh_token", &key, &value) != JSON_OK) return false;
    if (key.type != JSON_TOK_KEY) return false;
    if (key.value.len != 13 || memcmp(key.value.str, "refresh_token", 13) != 0) return false;
    return value.type == JSON_TOK_NULL;
}

/* 5: json_enter into array elements, use json_enter on second object */
static bool test_skip_in_array(void)
{
    json_parser_t root, arr, obj;
    json_token_t tok;
    char buf[16];
    json_init(&root, array_payload, sizeof(array_payload) - 1);

    /* root is the array */
    if (json_next(&root, &tok) != JSON_OK || tok.type != JSON_TOK_ARRAY) return false;
    json_enter(&arr, &tok);

    /* first element — get its OBJECT token but don't enter (skip by not calling json_enter) */
    if (json_next(&arr, &tok) != JSON_OK || tok.type != JSON_TOK_OBJECT) return false;

    /* second element — enter and search */
    if (json_next(&arr, &tok) != JSON_OK || tok.type != JSON_TOK_OBJECT) return false;
    json_enter(&obj, &tok);
    if (json_get_string(&obj, "val", buf, sizeof(buf)) != JSON_OK) return false;
    return strcmp(buf, "19.0") == 0;
}

/* 6: json_get_key_value iterator (NULL key_name) — walks all pairs */
static bool test_iterate_pairs(void)
{
    const char input[] = "{\"a\":\"1\",\"b\":\"2\",\"c\":\"3\"}";
    json_parser_t root, obj;
    json_token_t tok, key, value;
    char keybuf[8], valbuf[8];
    const char *exp_keys[] = {"a", "b", "c"};
    const char *exp_vals[] = {"1", "2", "3"};
    json_init(&root, input, sizeof(input) - 1);
    if (json_next(&root, &tok) != JSON_OK || tok.type != JSON_TOK_OBJECT) return false;
    json_enter(&obj, &tok);
    for (int i = 0; i < 3; i++) {
        if (json_get_key_value(&obj, NULL, &key, &value) != JSON_OK) return false;
        if (!json_slice_copy(keybuf, sizeof(keybuf), &key.value)) return false;
        if (!json_slice_copy(valbuf, sizeof(valbuf), &value.value)) return false;
        if (strcmp(keybuf, exp_keys[i]) != 0) return false;
        if (strcmp(valbuf, exp_vals[i]) != 0) return false;
    }
    /* exhausted */
    return json_get_key_value(&obj, NULL, &key, &value) == JSON_ERR_DONE;
}

int main(void)
{
    if (!lwip_start()) return 1;
    os_ClrHome();

    show_result(test_pull_walk());
    show_result(test_get_string());
    show_result(test_get_number());
    show_result(test_get_key_value_null());
    show_result(test_skip_in_array());
    show_result(test_iterate_pairs());

    return 0;
}

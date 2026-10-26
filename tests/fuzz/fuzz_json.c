#include <stddef.h>
#include <stdint.h>

#include "parsers/json.h"

static void walk(json_parser_t *p, unsigned depth)
{
    json_token_t tok;
    char buf[32];
    long number;
    json_parser_t probe = *p;

    json_get_string(&probe, "a", buf, sizeof(buf));
    probe = *p;
    json_get_number(&probe, "n", &number);
    while (json_next(p, &tok) == JSON_OK)
    {
        json_slice_copy(buf, sizeof(buf), &tok.value);
        if (depth < 64 && (tok.type == JSON_TOK_OBJECT || tok.type == JSON_TOK_ARRAY))
        {
            json_parser_t child;
            json_enter(&child, &tok);
            walk(&child, depth + 1);
        }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    json_parser_t p;
    json_init(&p, (const char *)data, size);
    walk(&p, 0);
    return 0;
}

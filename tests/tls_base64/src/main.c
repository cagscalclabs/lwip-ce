#include <ti/screen.h>
#include <ti/getkey.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "base64.h"

// test vectors
const char *test1 = "Science7!";
const char *test2 = "Cemetech12?";
const char *test3 = "Leading the way to the future!";

const char *encoded1 = "U2NpZW5jZTch";
const char *encoded2 = "Q2VtZXRlY2gxMj8=";
const char *encoded3 = "TGVhZGluZyB0aGUgd2F5IHRvIHRoZSBmdXR1cmUh";

const char *decoded1 = "Science7!";
const char *decoded2 = "Cemetech12?";
const char *decoded3 = "Leading the way to the future!";


static void show_result(bool ok)
{
    if (ok)
        printf("success");
    else
        printf("failed");
    os_GetKey();
    os_ClrHome();
}

/* Main function, called first */
int main(void)
{
    os_ClrHome();

    char buf[50];
    size_t olen;
    bool ok;

    // test 1: encode
    memset(buf, 0, sizeof buf);
    olen = tls_base64_encode(test1, strlen(test1), buf);
    ok = (strncmp(buf, encoded1, olen) == 0) && (olen == strlen(encoded1));
    show_result(ok);

    // test 2: encode
    memset(buf, 0, sizeof buf);
    olen = tls_base64_encode(test2, strlen(test2), buf);
    ok = (strncmp(buf, encoded2, olen) == 0) && (olen == strlen(encoded2));
    show_result(ok);

    // test 3: encode
    memset(buf, 0, sizeof buf);
    olen = tls_base64_encode(test3, strlen(test3), buf);
    ok = (strncmp(buf, encoded3, olen) == 0) && (olen == strlen(encoded3));
    show_result(ok);

    // test 4: decode
    memset(buf, 0, sizeof buf);
    olen = tls_base64_decode(encoded1, strlen(encoded1), buf);
    ok = (strncmp(buf, decoded1, olen) == 0) && (olen == strlen(decoded1));
    show_result(ok);

    // test 5: decode
    memset(buf, 0, sizeof buf);
    olen = tls_base64_decode(encoded2, strlen(encoded2), buf);
    ok = (strncmp(buf, decoded2, olen) == 0) && (olen == strlen(decoded2));
    show_result(ok);

    // test 6: decode
    memset(buf, 0, sizeof buf);
    olen = tls_base64_decode(encoded3, strlen(encoded3), buf);
    ok = (strncmp(buf, decoded3, olen) == 0) && (olen == strlen(decoded3));
    show_result(ok);

    return 0;
}

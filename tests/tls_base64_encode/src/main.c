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

const char *expected1 = "U2NpZW5jZTch";
const char *expected2 = "Q2VtZXRlY2gxMj8=";
const char *expected3 = "TGVhZGluZyB0aGUgd2F5IHRvIHRoZSBmdXR1cmUh";


/* Main function, called first */
int main(void)
{
    /* Clear the homescreen */
    os_ClrHome();
    
    char buf[50];
    size_t olen;
    
    // test 1
    memset(buf, 0, sizeof buf);
    olen = tls_base64_encode(test1, strlen(test1), buf);
    
    if((strncmp(buf, expected1, olen)==0) &&
       (olen == strlen(expected1)))
        printf("success");
    else printf("failed");
    os_GetKey();
    os_ClrHome();
    
    // test 2
    memset(buf, 0, sizeof buf);
    olen = tls_base64_encode(test2, strlen(test2), buf);
    
    if((strncmp(buf, expected2, olen)==0) &&
       (olen == strlen(expected2)))
        printf("success");
    else printf("failed");
    os_GetKey();
    os_ClrHome();
    
    // test 3
    memset(buf, 0, sizeof buf);
    olen = tls_base64_encode(test3, strlen(test3), buf);
    
    if((strncmp(buf, expected3, olen)==0) &&
       (olen == strlen(expected3)))
        printf("success");
    else printf("failed");
    os_GetKey();
    os_ClrHome();
    return 0;
}

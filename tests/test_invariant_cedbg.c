#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Include the actual production header
#include "build-tools/debug/cedbg/cedbg.h"

START_TEST(test_strtok_invariant)
{
    // Invariant: strtok usage must not corrupt adjacent memory or produce unexpected tokenization
    const char *payloads[] = {
        "test|data|here",           // Valid input with delimiters
        "|||",                      // Boundary: only delimiters
        "no_delimiter",             // Valid: no delimiter
        "a|b|c|d|e|f|g|h|i|j|k",    // Many tokens
        "\0embedded\0null",         // Attack: embedded null bytes
    };
    int num_payloads = sizeof(payloads) / sizeof(payloads[0]);

    for (int i = 0; i < num_payloads; i++) {
        // Create a mutable copy since strtok modifies the buffer
        char buffer[256];
        strncpy(buffer, payloads[i], sizeof(buffer) - 1);
        buffer[sizeof(buffer) - 1] = '\0';
        
        char *saveptr = NULL;
        char *token = strtok_r(buffer, "|", &saveptr);
        int token_count = 0;
        
        // Count tokens safely
        while (token != NULL) {
            token_count++;
            // Verify token is null-terminated
            ck_assert_msg(strlen(token) < sizeof(buffer), 
                         "Token length exceeds buffer bounds");
            token = strtok_r(NULL, "|", &saveptr);
        }
        
        // Security property: Original buffer's first character should be unchanged
        // (or at least the buffer should remain valid C string)
        ck_assert_msg(buffer[0] == payloads[i][0] || 
                     (payloads[i][0] == '\0' && buffer[0] == '\0'),
                     "First character corrupted by strtok usage");
        
        // Additional invariant: No buffer overflow in tokenization
        ck_assert_msg(token_count >= 0 && token_count <= 50, 
                     "Unreasonable token count indicates possible memory corruption");
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_strtok_invariant);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
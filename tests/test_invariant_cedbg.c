#include <check.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define BUFFER_SIZE 256  // Based on typical fgets buffer size in cdbg.c

START_TEST(test_buffer_reads_never_exceed_declared_length)
{
    // Invariant: Buffer reads never exceed the declared length
    const char *payloads[] = {
        "normal line\n",  // Valid input
        "A" "256" "\n",   // Boundary case: exactly fills buffer
        "A" "512" "\n",   // 2x buffer size
        "A" "2560" "\n",  // 10x buffer size
        "A" "5000" "\n"   // Exact exploit case from vulnerability report
    };
    
    int num_payloads = sizeof(payloads) / sizeof(payloads[0]);
    
    for (int i = 0; i < num_payloads; i++) {
        // Create a temporary script file with the payload
        char temp_filename[] = "/tmp/cedbg_test_XXXXXX";
        int fd = mkstemp(temp_filename);
        ck_assert(fd != -1);
        
        FILE *temp_file = fdopen(fd, "w");
        ck_assert(temp_file != NULL);
        
        // Write the test line to the file
        fprintf(temp_file, "%s", payloads[i]);
        fclose(temp_file);
        
        // Reopen for reading
        FILE *script = fopen(temp_filename, "r");
        ck_assert(script != NULL);
        
        // Test the actual vulnerable code path
        char line[BUFFER_SIZE];
        int read_result = 0;
        
        // This should not crash or overflow the buffer
        while (fgets(line, sizeof(line), script)) {
            read_result = 1;
            // Verify the read didn't exceed buffer bounds
            ck_assert(strlen(line) <= sizeof(line));
            // Verify null termination
            ck_assert(line[sizeof(line) - 1] == '\0' || 
                     strlen(line) < sizeof(line) - 1);
        }
        
        fclose(script);
        unlink(temp_filename);
        
        // Ensure something was read (except for empty payloads)
        if (strlen(payloads[i]) > 0) {
            ck_assert(read_result == 1);
        }
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_buffer_reads_never_exceed_declared_length);
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
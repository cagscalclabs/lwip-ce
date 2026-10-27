#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "x509.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct tls_x509_object cert;
    struct tls_x509_object *imported;
    uint32_t secs;
    char *pem;

    if (tls_x509_parse_certificate(data, size, &cert))
    {
        tls_x509_hostname_matches(cert.extensions, cert.extensions_len,
                                  cert.subject_cn, cert.subject_cn_len, "www.example.com");
        tls_x509_hostname_matches(cert.extensions, cert.extensions_len,
                                  cert.subject_cn, cert.subject_cn_len, "192.168.84.1");
        tls_x509_validate_path_extensions(&cert, false, 0);
        tls_x509_validate_path_extensions(&cert, true, 2);
        tls_x509_time_in_validity(&cert, 1790000000u);
        tls_x509_has_valid_constraints(cert.extensions, cert.extensions_len);
    }
    tls_x509_has_required_ca_constraints(data, size);
    tls_x509_has_valid_constraints(data, size);
    tls_x509_hostname_matches(data, size, data, size, "*.example.com");
    if (size)
    {
        tls_x509_time_to_unix(data + 1, size - 1, data[0], &secs);
        tls_x509_oid_to_sig_alg(data, size);
    }
    pem = malloc(size + 1);
    memcpy(pem, data, size);
    pem[size] = '\0';
    imported = tls_x509_import_certificate(pem, size);
    tls_x509_object_free(imported);
    free(pem);
    return 0;
}

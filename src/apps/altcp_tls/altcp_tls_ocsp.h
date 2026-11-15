#ifndef ALTCP_TLS_OCSP_H
#define ALTCP_TLS_OCSP_H

#include <stdbool.h>

#include "../../tls/includes/handshake.h"
#include "../../tls/includes/ocsp.h"

typedef void (*altcp_tls_ocsp_done_fn)(void *arg, tls_ocsp_status_t status);

/* Takes ownership of query on success. */
bool altcp_tls_ocsp_start(struct tls_ocsp_query *query, void *owner,
                          altcp_tls_ocsp_done_fn done, void *arg);

/* Cancel every lookup owned by owner. DNS callbacks retain only an inert
 * shell until lwIP reports completion, avoiding callback-argument UAF. */
void altcp_tls_ocsp_cancel(void *owner);

#endif

/**
 * @file tls-alpn.h
 * @brief Registered ALPN protocol identifiers commonly used over TLS/TCP.
 *
 * Values are the protocol-name strings from the IANA ALPN registry.  This
 * header intentionally omits protocols that cannot run over this TLS/TCP
 * transport (for example HTTP/3 and the cleartext-only h2c identifier).
 */

#ifndef TLS_ALPN_H
#define TLS_ALPN_H

/* Web protocols. */
#define TLS_ALPN_HTTP_1_0 "http/1.0"
#define TLS_ALPN_HTTP_1_1 "http/1.1"
#define TLS_ALPN_HTTP_2   "h2"

/* Messaging and mail protocols. */
#define TLS_ALPN_MQTT        "mqtt"
#define TLS_ALPN_IMAP        "imap"
#define TLS_ALPN_POP3        "pop3"
#define TLS_ALPN_MANAGESIEVE "managesieve"
#define TLS_ALPN_XMPP_CLIENT "xmpp-client"
#define TLS_ALPN_XMPP_SERVER "xmpp-server"

/* Infrastructure protocols. */
#define TLS_ALPN_ACME_TLS_1 "acme-tls/1"
#define TLS_ALPN_COAP       "coap"
#define TLS_ALPN_DNS_OVER_TLS "dot"
#define TLS_ALPN_NTSKE_1    "ntske/1"

/* An ALPN ProtocolName is an opaque, non-empty uint8 vector. */
#define TLS_ALPN_PROTOCOL_NAME_MAX 255u

#endif /* TLS_ALPN_H */

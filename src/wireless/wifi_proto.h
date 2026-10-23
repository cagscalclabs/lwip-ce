#ifndef LWIP_WIRELESS_WIFI_PROTO_H
#define LWIP_WIRELESS_WIFI_PROTO_H

/* Control protocol between lwIP and the Wi-Fi bridge. Shared by the calculator
 * build and the bridge firmware (wifi_bridge/), so keep it plain C.
 *
 * Every message is one Ethernet frame:
 *   [0..5]   destination MAC
 *   [6..11]  source MAC
 *   [12..13] CTL_ETHERTYPE
 *   [14]     CTL_VERSION
 *   [15]     op, with CTL_REPLY set in replies
 *   [16]     sequence number, echoed in the reply
 *   [17]     status (CTL_ST_*), replies only
 *   [18..]   body
 */

#include "wifi.h"

#define CTL_ETHERTYPE 0x88B5
#define CTL_VERSION 1
#define CTL_HEADER 18
#define CTL_REPLY 0x80

enum
{
    CTL_OP_STATUS = 1,
    CTL_OP_LIST,
    CTL_OP_SCAN,
    CTL_OP_SAVE,
    CTL_OP_FORGET,
    CTL_OP_ENABLE,
    CTL_OP_PREFER,
    CTL_OP_CONNECT,
    CTL_OP_DISCONNECT,
    CTL_OP_INFO,
    CTL_OP_X25519,
    CTL_OP_RSA_VERIFY,
    CTL_OP_RANDOM,
    CTL_OP_P256,
    CTL_OP_ECDSA_VERIFY,
    CTL_OP_EVENT = 0x40,
};

enum
{
    CTL_ST_OK,
    CTL_ST_BAD_REQUEST,
    CTL_ST_NOT_FOUND,
    CTL_ST_FULL,
    CTL_ST_BUSY,
    CTL_ST_REJECTED,
};

/* Crypto offload. These requests may overlap: each reply is matched by op
 * and sequence number, not just the most recent request.
 *
 *   CTL_OP_INFO        -> caps (CTL_CAP_*)
 *   CTL_OP_X25519      scalar[32] point[32] -> X25519(scalar, point)[32];
 *                      CTL_ST_REJECTED for an all-zero result
 *   CTL_OP_RSA_VERIFY  alg digest[32] mod_len[2, little-endian] exp_len
 *                      modulus exponent signature[mod_len] (numbers big-endian)
 *                      -> CTL_ST_OK or CTL_ST_REJECTED
 *   CTL_OP_RANDOM      count -> count bytes from the bridge TRNG
 *   CTL_OP_P256        scalar[32] -> uncompressed public key[65], or
 *                      scalar[32] point[65] -> shared secret x-coordinate[32]
 *   CTL_OP_ECDSA_VERIFY digest[32] public key[65] r[32] s[32]
 *                      -> CTL_ST_OK or CTL_ST_REJECTED
 */
#define CTL_CAP_X25519 LWIP_WIFI_CAP_X25519
#define CTL_CAP_RSA LWIP_WIFI_CAP_RSA
#define CTL_CAP_RANDOM LWIP_WIFI_CAP_RANDOM
#define CTL_CAP_P256 LWIP_WIFI_CAP_P256

#define CTL_RSA_PKCS1_SHA256 1
#define CTL_RSA_PSS_SHA256 2

#define CTL_RANDOM_MAX LWIP_WIFI_RANDOM_MAX

#endif

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
    CTL_OP_EVENT = 0x40,
};

enum
{
    CTL_ST_OK,
    CTL_ST_BAD_REQUEST,
    CTL_ST_NOT_FOUND,
    CTL_ST_FULL,
    CTL_ST_BUSY,
};

#endif

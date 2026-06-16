#include <lwip.h>

#include "../../common/lwip_chat_client.h"

#ifndef CHAT_HOST
#define CHAT_HOST "192.168.2.1"
#endif

#define CHAT_PORT 4242

int main(void)
{
    return lwip_chat_run(LWIP_SOCKET_TCP, "== TCP Chat ==",
                         CHAT_HOST, CHAT_PORT, false);
}

#ifndef LWIP_APP_WIFI_SCREEN_H
#define LWIP_APP_WIFI_SCREEN_H

#include <stdbool.h>
#include <stdint.h>

void app_net_begin(void);
void app_net_stop(void);
bool app_net_idle(void);
const char *app_wifi_summary(uint8_t *color);
void app_wifi_screen(void);

#endif

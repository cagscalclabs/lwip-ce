idf_component_register(SRCS "main.c" "bridge.c" "control.c" "wifi.c" "profiles.c"
                       INCLUDE_DIRS "."
                       REQUIRES usb usb_host_cdc_acm esp_event esp_wifi nvs_flash)

### lwIP NTP Example

Starts lwIP with DHCP and SNTP service flags, then waits for the lwIP SNTP clock to be set.

This uses the public release API. DHCP-provided NTP servers are used when available; otherwise the resident stack falls back to the configured DNS NTP server.

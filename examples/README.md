# lwIP-CE examples

The examples are intentionally small and cover the three useful starting
points for an application:

- `pcb/` uses lwIP's native TCP PCB callbacks to run a plain-text echo server.
  It prints its DHCP address and listens on port 8080; connect with a TCP
  client such as `nc CALCULATOR_IP 8080`.
- `socket/` uses the higher-level lwIP-CE socket API to make an HTTPS request
  to `example.com`. Certificate mode requires the current `lwIPCERT` truststore
  AppVar on the calculator.
- `template/` contains only the stack lifecycle and empty application hooks.
  Press Clear to leave the PCB, socket, or template examples.
- `wifi_api/` exercises bridge discovery, scanning, and saved-profile
  management, and writes the complete result to the `WIFILOG` AppVar.

Build every example with `make -C examples`, or build one directory directly.
Each program requires the lwIP-CE AppVar and an installed network adapter.


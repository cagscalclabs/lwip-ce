# Networked integration suite

`NETTEST` exercises lwIP-CE over a real network path: CEmu-lwIP-CE emulates
the calc's USB CDC-ECM Ethernet adapter and bridges it to a TAP interface,
and `run.py` serves the endpoints the calc talks to on that interface.

| Check | Endpoint |
| --- | --- |
| DHCP lease, gateway, DNS service | CEmu's built-in DHCP server |
| TCP / ALTCP echo (8 KiB / 4 KiB) | host `:7001` |
| UDP echo, 8 datagrams | host `:7002` |
| Listening server, 3 clients | calc `:7003`, host connects |
| WebSocket echo (`/echo`) | host `:7004` |
| Untrusted TLS rejected with an alert | host `:7005`, self-signed cert |
| 256 KiB bulk download | host `:7006` |
| 16 connect/close/abort cycles | host `:7001` |
| Refused port, NXDOMAIN | host `:7999`, `*.invalid` |
| HTTPS HEAD / GET with full body | `tls13.akamai.io`, `raw.githubusercontent.com` |

The calc logs every check to the `NETLOG` appvar and ends on a solid green
or red screen; `run.py` saves the appvar and fails unless every check passed.

## Running

CI runs it in `.github/workflows/net.yml` after `alessiodam/cemu-net-action`
sets up the TAP interface. Locally, after `make dylib` and with `clibs.8xg`
and `lwIPCERT.8xv` in `tests/common`:

```sh
make -C tests/net
# a private network namespace gives the TAP interface without root
unshare -rn sh -c '
  ip link set lo up
  ip tuntap add dev cemu0 mode tap user 0
  ip addr add 192.168.84.1/24 dev cemu0
  ip link set cemu0 up
  AUTOTESTER_ROM=/path/to/ce.rom python3 tests/net/run.py \
    --autotester /path/to/CEmu-lwIP-CE/tests/autotester/autotester \
    --usb "usb|eth,cemu0,dhcp=192.168.84.2/24,gw=192.168.84.1,dns=192.168.84.1"'
```

Without NAT the namespace has no internet, so the DNS, SNTP-dependent TLS and
HTTPS checks fail there; everything served by `run.py` still runs.

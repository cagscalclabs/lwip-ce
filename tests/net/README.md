# Networked suites

These suites run lwIP-CE over a real network path. CEmu-lwIP-CE emulates the calc's USB CDC-ECM Ethernet adapter and
bridges it to a TAP interface. [`run.py`](run.py) serves every endpoint the calc talks to on that interface,
answers control requests the calc sends on UDP 7000 (start an openssl peer, send an IPv6 router advertisement,
connect to the calc, report what it saw on the wire), and grades the `NETLOG` appvar each suite saves.

Each suite logs `PASS`/`FAIL` lines plus `METRIC name value unit` lines and ends on a solid green or red screen.
Shared calc code lives in [`common/`](common).

| Suite | Program | What it covers |
| --- | --- | --- |
| [`sockets`](sockets/src/main.c) | `NETTEST` | `lwip_socket_*`: TCP/ALTCP/WS/UDP echo, 256 KiB download, listen/accept, connect/close/abort churn, half-close, peer FIN and RST, rx-ring backpressure with `create_ex`/`resize_rx_max`, event callbacks, loopback netif, concurrent sockets, API contract errors, refused/NXDOMAIN/untrusted-TLS/connect-timeout failures, heap leak check |
| [`raw`](raw/src/main.c) | `NETRAW` | lwIP's own APIs: address/checksum/string helpers, netif lookup, pbuf chains, `sys_timeout` ordering, raw ICMP echo, host pings and ICMP port unreachable, raw TCP client/server/abort/poll, raw UDP, broadcast, IPv4 fragmentation and reassembly (and its bound), loopback UDP, DNS A/AAAA/cache/NXDOMAIN, ARP, IGMP join/leave on the wire, IPv6 link-local, SLAAC from a router advertisement, TCP over IPv6, IPv6 fragmentation, MLD, ACD probe and conflict, SNTP, DHCP renew/release/restart |
| [`tls`](tls/src/main.c) | `NETTLS` | External-PSK TLS 1.3 against `openssl s_server`: AES-128-GCM and AES-128-CCM with X25519, wrong key, unknown identity, unsupported cipher and groups, KeyUpdate with update_requested, 128 KiB download, raw altcp TLS API, ALPN, session tickets and resumption. Before public HTTPS/WSS checks, the host runner probes ordered endpoint pools and supplies the first healthy equivalent; chain-specific fallbacks preserve the same CA and key type. Certificate validation covers RSA-2048, ECDSA P-256 and the Starfield cross-chain; Amazon Root CA 4 verifies P-384 rejection. A controlled OpenSSL peer covers TLS 1.2 rejection. Certificate-policy negatives use deterministic unit fixtures. |
| [`records`](records/src/main.c) | `NETREC` | 128 KiB over TLS in maximum-size (16 KiB) records with GCM and CCM |
| [`server`](server/src/main.c) | `NETSRV` | lwIP-CE as a TLS 1.3 PSK server: `openssl s_client` echo with GCM and CCM, wrong-PSK rejection, listener close |
| [`perf`](perf/src/main.c) | `NETPERF` | Throughput (TCP down/up via sockets and the raw API, UDP, WebSocket, loopback, TLS GCM/CCM down and up), latency (TCP connect, TCP/UDP/WS round trips, TLS handshake), heap at idle and peak per workload |

Positive external-HTTPS failures remain failures unless the GitHub runner
immediately reproduces a compatible DNS, transport, TLS, HTTP, or timeout
failure against the same endpoint. Such cases are reported as `SKIP` with
both symptoms in the job summary and `endpoint-probes.json`. Local tests,
negative certificate tests, and failures for which the host probe succeeds
are never waived.

Metrics are measured on the calc's clock (emulated eZ80 time). `run.py` writes them to `metrics.json` and, in CI,
to the job summary.

## Notes

- `records` covers TLS records at the RFC 8446 maximum. OpenSSL ignores `record_size_limit` (RFC 8449), so it sends
  16 KiB records even though lwIP-CE asks for 4 KiB. This suite found two bugs, both now fixed. The socket API
  refused plaintext larger than its rx ring, and the TLS and WebSocket layers then returned that refusal to TCP for
  pbufs they had already freed (a double free).
- `server` checks lwIP-CE as a TLS 1.3 server with an external PSK (psk_dhe_ke over X25519). `openssl s_client`
  echoes a line through the calc with AES-128-GCM and AES-128-CCM, a client with the wrong PSK is refused, and the
  listener closes cleanly.

## Running

CI runs one job per suite in `.github/workflows/net.yml`, after `alessiodam/cemu-net-action` sets up the TAP
interface. Locally, after `make dylib`, with `clibs.8xg` and `lwIPCERT.8xv` in `tests/common` and scapy installed:

```sh
make -C tests/net
# a private network namespace gives a TAP interface and root without sudo
unshare -rn sh -c '
  ip link set lo up
  ip tuntap add dev cemu0 mode tap user 0
  ip addr add 192.168.84.1/24 dev cemu0
  ip link set cemu0 up
  AUTOTESTER_ROM=/path/to/ce.rom python3 tests/net/run.py --suite sockets \
    --autotester /path/to/CEmu-lwIP-CE/tests/autotester/autotester \
    --usb "usb|eth,cemu0,dhcp=192.168.84.2/24,gw=192.168.84.1,dns=192.168.84.1"'
```

The namespace has no internet, so DNS, SNTP and the certificate checks against real hosts need a local resolver and
time server there or fail. `--pcap file` captures the TAP interface for Wireshark.

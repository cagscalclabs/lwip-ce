# Networked suites

These suites run lwIP-CE over a real network path. CEmu-lwIP-CE emulates the calc's USB CDC-ECM Ethernet adapter and
bridges it to a TAP interface. [`run.py`](run.py) serves every endpoint the calc talks to on that interface,
answers control requests the calc sends on UDP 7000 (start an openssl peer, send an IPv6 router advertisement,
connect to the calc, report what it saw on the wire), and grades the `NETLOG` appvar each suite saves.

Each suite logs `PASS`/`FAIL` lines plus `METRIC name value unit` lines and ends on a solid green or red screen.
Shared calc code lives in [`common/`](common).

| Suite | Program | What it covers |
| --- | --- | --- |
| [`sockets`](sockets/src/main.c) | `NETTEST` | `lwip_socket_*`: TCP/ALTCP/WS/UDP echo, 256 KiB download, plain and TLS listen/accept (external PSK and P-256 certificate modes), connect/close/abort churn, half-close, peer FIN and RST, rx-ring backpressure with `create_ex`/`resize_rx_max`, event callbacks, loopback netif, concurrent sockets, API contract errors, refused/NXDOMAIN/untrusted-TLS/connect-timeout failures, heap leak check |
| [`raw`](raw/src/main.c) | `NETRAW` | lwIP's own APIs: address/checksum/string helpers, netif lookup, pbuf chains, `sys_timeout` ordering, raw ICMP echo, host pings and ICMP port unreachable, raw TCP client/server/abort/poll, raw UDP, broadcast, IPv4 fragmentation and reassembly (and its bound), loopback UDP, DNS A/AAAA/cache/NXDOMAIN, ARP, IGMP join/leave on the wire, IPv6 link-local, SLAAC from a router advertisement, TCP over IPv6, IPv6 fragmentation, MLD, ACD probe and conflict, SNTP, DHCP renew/release/restart |
| [`tls`](tls/src/main.c) | `NETTLS` | Runner-local TLS 1.3 against `openssl s_server`: external PSK with AES-128-GCM/CCM and X25519/P-256, rejection cases, KeyUpdate, bulk records, raw altcp, ALPN, tickets and resumption. Certificate mode uses an ephemeral RSA test CA and RSA-2048/ECDSA-P-256 leaves across AES-128-GCM, AES-128-CCM and AES-256-GCM. A runner-local HTTP OCSP responder verifies that a good certificate connects with checking both off and on, while a revoked certificate is rejected when checking is on, both with the CA in the chain and with the leaf alone (issuer taken from the truststore root). CI adds the CA to a v4 test truststore signed by the normal `TRUSTSTORE_SIGNER`, exercising the complete production verification path without a public server. A controlled local peer covers TLS 1.2 rejection. Public HTTPS/WSS probes are optional, non-gating observations. |
| [`records`](records/src/main.c) | `NETREC` | 128 KiB over TLS in maximum-size (16 KiB) records with GCM and CCM |
| [`server`](server/src/main.c) | `NETSRV` | lwIP-CE as a TLS 1.3 server: `openssl s_client` echo through external-PSK mode (GCM and CCM, including wrong-PSK rejection) and P-256 certificate-chain mode, plus listener close |
| [`perf`](perf/src/main.c) | `NETPERF` | Throughput (TCP down/up via sockets and the raw API, UDP, WebSocket, loopback, TLS GCM/CCM down and up), latency (TCP connect, TCP/UDP/WS round trips, TLS handshake), heap at idle and peak per workload, and an upstream rate ramp (see below) |

Public HTTPS/WSS probes are disabled by default. Passing `--external-info`
boots the TLS program a second time with the unchanged production `lwIPCERT`
and runs them as `INFO PASS`/`INFO FAIL` observations with timing metrics.
That second run never affects the suite verdict. The gating run receives only
the ephemeral test CA, and all of its TLS traffic stays on the runner-local
TAP network.

Metrics are measured on the calc's clock (emulated eZ80 time). `run.py` writes them to `metrics.json` and attaches each one to the check logged just before it, so throughput, timings, heap and rate-ramp results appear beside their checks in the CI job summary.

## Notes

- `records` covers TLS records at the RFC 8446 maximum. OpenSSL ignores `record_size_limit` (RFC 8449), so it sends
  16 KiB records even though lwIP-CE asks for 4 KiB. This suite found two bugs, both now fixed. The socket API
  refused plaintext larger than its rx ring, and the TLS and WebSocket layers then returned that refusal to TCP for
  pbufs they had already freed (a double free).
- `server` checks lwIP-CE as a TLS 1.3 server with an external PSK (psk_dhe_ke over X25519). `openssl s_client`
  echoes a line through the calc with AES-128-GCM and AES-128-CCM, a client with the wrong PSK is refused, and the
  listener closes cleanly.

## Rate ramp

The last `perf` phase opens UDP, raw IP, TCP, ALTCP, ALTCP_TLS (PSK), WS and WSS
sessions in turn. Each one sends upstream at a paced rate that starts at 64 kbit/s and rises by 64 kbit/s
every 2 s window, up to 1024 kbit/s. The bounds are the `RAMP_*` defines in [`perf/src/main.c`](perf/src/main.c).

`run.py` sniffs the calc's traffic to count what arrives:

- **UDP and raw:** each datagram carries its window number in its first byte, so it is counted against the right
  window even if it arrives late. The drop rate is the scheduled datagrams that never arrived, including ones the
  calc could not queue.
- **TCP-based sockets:** windows are split at the `ramp-mark` sent when each window starts. The drop rate is
  retransmitted segments as a share of all data segments.

The calc reads every window's result once, after its last window (`ramp-result`). The autotester's suite timeout
counts emulated time, which runs far ahead of wall time while the calc waits on the host, so per-window host
waits would use up the budget.

Each socket's result takes one of three forms:

```text
RAMP udp stable till 821 kbps, loss from 896 kbps
   832 kbps => 0.00% drop (sent 821 kbps)
   896 kbps => 38.58% drop (sent 870 kbps)
   ...
RAMP tcp no loss; sender-limited at 299 kbps
RAMP raw no loss through 1024 kbps
```

- **Loss:** the stable rate is the highest rate actually delivered before the first loss. The drop rate is listed
  for every window from the first loss through the cap.
- **Sender-limited:** the socket never lost anything but could not reach the target rate.
- **No loss through the cap:** the socket kept up with every window.

The metrics `ramp_<socket>_stable`, `ramp_<socket>_limited` (kbps) and `ramp_<socket>_<rate>k_drop` (hundredths of
a percent) carry the same results into the CI job summary, and `ramp_total` records the emulated seconds the ramp
used. Only session setup is graded. The ramp needs scapy and root for the sniffer, and it is skipped without them.
WSS uses certificate authentication only, so it runs only when `--truststore-signer` is given. In that case `perf`
receives the same runner-local CA truststore as `tls`.

## Running

CI uses `.github/scripts/run_nettests.py` to build and run all seven suites
concurrently. Each unchanged `run.py` process gets its own Linux network
namespace and private `cemu0`, so the suites can retain the fixed calculator
addresses and service ports without interfering with one another. The runner
emits the same nested module/unit/test JSON schema as the dyload unit runner,
plus the existing flat rows, metrics, endpoint probes, pcaps, and `NETLOG`
artifacts.

Locally, after `make dylib`, with `lwIPCERT.8xv` in `tests/common`, a prepared
CEmu state, and scapy installed:

```sh
make -C tests/net
# a private network namespace gives a TAP interface and root without sudo
unshare -rn sh -c '
  ip link set lo up
  ip tuntap add dev cemu0 mode tap user 0
  ip addr add 192.168.84.1/24 dev cemu0
  ip link set cemu0 up
  AUTOTESTER_IMAGE=/path/to/ce-patched.ce python3 tests/net/run.py --suite sockets \
    --autotester /path/to/CEmu-lwIP-CE/tests/autotester/autotester \
    --usb "usb|eth,cemu0,dhcp=192.168.84.2/24,gw=192.168.84.1,dns=192.168.84.1"'
```

The `tls` suite additionally requires `--truststore-signer /secure/path/to/key.pem`.
The key is used only to sign the compact temporary v4 `lwIPCERT` profile
containing the ephemeral local CA; it is never copied to the calculator.
The released truststore is not modified. With `--external-info`, the local
gating boot receives that CA-only profile and a separate informational boot
receives the production profile from `tests/common`. `--pcap file` captures
the TAP interface for Wireshark.

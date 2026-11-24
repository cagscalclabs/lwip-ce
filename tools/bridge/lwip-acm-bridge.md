# lwip-acm-bridge: CDC-ACM internet bridge

`lwip-acm-bridge.py` gives a TI-84 Plus CE running lwIP-CE in USB device mode
outbound IPv4 access through a macOS or Linux computer. It carries Ethernet
frames over the calculator's CDC-ACM serial interface. The calculator is the
network client and the computer is its router and NAT gateway. The bridge
opens no network listener and no remote command interface.

In a release, the script is in `tools/`. In the source tree, it is in
`tools/bridge/`.

## Requirements

- Python 3.8 or later.
- **macOS:** root (`sudo`).
- **Linux:** `pyusb` (`dnf install python3-pyusb`, `apt install
  python3-usb`, or `pip install pyusb`), plus `iproute2` and `nftables`.
  Root is needed unless you do the one-time setup in
  [Linux without root](#linux-without-root).
- **Optional:** Python's `cryptography` package, only for
  `--accelerate-crypto`.

## Run

```sh
# macOS
sudo python3 lwip-acm-bridge.py

# Linux, as root
sudo python3 lwip-acm-bridge.py

# Linux, unprivileged, after the one-time setup below
python3 lwip-acm-bridge.py --tap lwipce0
```

The bridge waits for the calculator (USB VID:PID `16c0:05e1`), connects, and
runs until Ctrl+C. After a disconnect it waits for the calculator again;
`--once` exits instead. `--seconds N` stops after N seconds.

### Options

| Option | Effect |
|---|---|
| `--odevice IFACE` (or `--uplink`) | Outbound interface to NAT through. Default: the interface that carries the default route. |
| `--host-ip IP` | The computer's address on the link. Default `10.84.0.1`. |
| `--client-ip IP` | The address DHCP gives the calculator. Default `10.84.0.10`. |
| `--dns IP` | DNS server advertised by DHCP. Default `1.1.1.1`. |
| `--ntp IP` | NTP server advertised by DHCP. Default `162.159.200.1`. |
| `--accelerate-crypto` | Answer the calculator's crypto offload requests locally. |
| `--quiet` | Print a periodic counter instead of every packet. |
| `--tls` | Decode TLS records: ClientHello contents and server alerts. |
| `--debug` | Also report how each connection ended and why. Implies `--tls`. |
| `--save-hello PATH` | Write the calculator's raw ClientHello record to PATH. |
| `--port PATH` | macOS only: serial port to use. Default: auto-detected. |
| `--tap IFACE` | Linux only: TAP interface to use. See below. |
| `--print-setup` | Linux only: print the one-time setup commands and exit. |

## How it works

Frames on the USB link carry a two-byte big-endian length prefix, so serial
read and write boundaries do not affect frame boundaries. The bridge answers
DHCP for the calculator and passes everything else to the host kernel, which
routes it and translates its addresses (NAT) out of the uplink. IPv6 is not
forwarded. The bridge also lowers the MSS in the calculator's TCP SYNs to
360 so that inbound frames stay under 512 bytes. Larger frames can be split
across USB transfers, and the calculator would lose them.

### macOS

The bridge opens the calculator's `/dev/cu.usbmodem*` port and asserts DTR.
It creates a point-to-point `utun` interface (host `10.84.0.1`, calculator
`10.84.0.10`) and ensures the host route to the calculator uses it. A `utun`
is layer 3, so the bridge answers ARP itself, strips the Ethernet header from
outbound packets, and adds one to replies.

Host changes, all undone on exit:

- **IP forwarding.** `net.inet.ip.forwarding` is set to `1` only if it was
  `0`, and restored only if the bridge changed it.
- **PF NAT.** A rule such as `nat on en0 from 10.84.0.10 to any -> (en0)`
  is loaded into the `com.apple/lwip-ce-bridge` anchor, or into an existing
  legacy `lwip-ce-bridge` anchor. The bridge refuses to replace the main PF
  ruleset if neither anchor point is active. PF is enabled with a reference
  token (`pfctl -E`) and only that reference is released (`pfctl -X`), so
  other PF users are unaffected.

### Linux

The bridge talks to the calculator directly over libusb. It detaches the
`cdc_acm` kernel driver while it runs and reattaches it on exit. Frames go
through a TAP interface, which is layer 2, so the kernel handles ARP itself.

**As root**, the bridge creates a temporary TAP interface `lwipceN`, and
then:

- enables IPv4 forwarding on that interface and on the uplink only, not the
  global `ip_forward` switch. The uplink's original value is restored on
  exit.
- adds an nftables table `lwip_ce_bridge` with a masquerade rule for the
  calculator's address on the uplink.
- if firewalld is running, adds the interface to the `trusted` zone (runtime
  only).

All of these are undone on exit. Without firewalld, the bridge warns if any
forward chain has a drop policy, because that chain can still discard the
calculator's traffic. Docker installs such a chain.

#### Linux without root

`--print-setup` prints the root commands that set up a persistent TAP
interface owned by your user, its address, forwarding, the NAT rule, and a
udev rule that grants USB access to the logged-in user:

```sh
python3 lwip-acm-bridge.py --print-setup   # review, then run the commands as root
python3 lwip-acm-bridge.py --tap lwipce0
```

The network part of the setup lasts until reboot. The udev rule is
permanent. With `--tap` pointing at an existing interface, the bridge uses
it as configured and changes nothing on the host. It warns if the
interface's address does not match `--host-ip` or if the interface is down.
The printed output includes the commands to undo the setup.

## Cleanup caveat

On both platforms, cleanup runs on normal exit, Ctrl+C, and bridge errors.
A forced kill (`SIGKILL`) or power loss skips it. To recover:

- **macOS:** run `sudo pfctl -a com.apple/lwip-ce-bridge -F all` and, if
  needed, `sudo sysctl -w net.inet.ip.forwarding=0`.
- **Linux:** run `sudo nft delete table ip lwip_ce_bridge` and
  `sudo ip link delete lwipce0`. On the next run as root, the bridge also
  replaces any leftover nftables table.

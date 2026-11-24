# lwip-acm-bridge: CDC-ACM internet bridge

`lwip-acm-bridge.py` gives a TI-84 Plus CE running lwIP-CE in USB device mode
outbound IPv4 access through a macOS or Linux computer. It carries Ethernet
frames over the calculator's CDC-ACM serial interface. The calculator is the
network client and the computer is its router and NAT gateway. The bridge
opens no network listener and no remote command interface.

In a release, the script is in `tools/`. In the source tree, it is in
`tools/bridge/`.

## Requirements

- Python 3.10 or later.
- **macOS:** `sudo` access for interface and PF changes.
- **Linux:** `pyusb` (`dnf install python3-pyusb`, `apt install
  python3-usb`, or `pip install pyusb`), plus `iproute2` and `nftables`.
  `sudo` access is needed for temporary TAP and firewall setup unless you
  do the one-time setup in [Linux without root](#linux-without-root). If USB
  access is not already granted by udev, `getfacl` and `setfacl` are needed
  for a temporary device ACL.
- **Optional:** Python's `cryptography` package, only for
  `--accelerate-crypto`.

## Run

```sh
# macOS
python3 lwip-acm-bridge.py

# Linux, temporary TAP
python3 lwip-acm-bridge.py

# Linux, unprivileged, after the one-time setup below
python3 lwip-acm-bridge.py --tap lwipce0
```

The bridge waits for the calculator (USB VID:PID `16c0:05e1`), connects, and
runs until Ctrl+C. After a disconnect it waits for the calculator again;
`--once` exits instead. `--seconds N` stops after N seconds.
The script runs as your user and prompts through `sudo` only for host
networking commands. Invoke it without `sudo`; starting it with `sudo`
exits immediately so the packet loop cannot run as root or trigger a second
authentication after dropping privileges. It writes a timestamped, levelled log to
the platform's per-user log directory by default:
`~/Library/Logs/lwip-acm-bridge/bridge.log` on macOS (visible in
Console.app), and `$XDG_STATE_HOME/lwip-acm-bridge/bridge.log` on Linux,
which falls back to `~/.local/state` when the variable is unset. The log contains
settings changes, restoration results, errors and counters. `--debug` adds
frame directions and byte counts; packet bytes and decoded packet contents
are never logged. Files are user-owned, mode `0600`, and rotate at 10 MiB
with three backups. `--log-file /var/log/lwip-acm-bridge.log` is available
when your user has write access there.

### Options

| Option | Effect |
|---|---|
| `--odevice IFACE` (or `--uplink`) | Outbound interface to NAT through. Default: the interface that carries the default route. |
| `--host-ip IP` | The computer's address on the link. Default `10.84.0.1`. |
| `--client-ip IP` | The address DHCP gives the calculator. Default `10.84.0.10`. |
| `--dns IP` | DNS server advertised by DHCP. Default `1.1.1.1`. |
| `--ntp IP` | NTP server advertised by DHCP. Default `162.159.200.1`. |
| `--accelerate-crypto` | Answer the calculator's crypto offload requests locally. See [Crypto offload and secrets](#crypto-offload-and-secrets). |
| `--quiet` | Suppress periodic packet counters. |
| `--debug` | Log frame directions and byte counts, without packet contents. |
| `--log-file PATH` | Write the log to PATH instead of the default user log path. |
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
  is loaded into a unique anchor under `com.apple/*`. The bridge refuses to
  replace the main PF ruleset if that anchor point is unavailable. PF is enabled with a reference
  token (`pfctl -E`) and only that reference is released (`pfctl -X`), so
  other PF users are unaffected.

### Linux

The bridge talks to the calculator directly over libusb. It detaches the
`cdc_acm` kernel driver while it runs and reattaches it on exit. Frames go
through a TAP interface, which is layer 2, so the kernel handles ARP itself.
If udev has not granted USB access, it asks `sudo` to grant the invoking user
access to this USB device node for the session and removes that ACL on close.

The bridge asks `sudo` to create a temporary TAP interface `lwipceN` owned
by your user, then asks `sudo` for these setup changes:

- enables IPv4 forwarding on that interface and on the uplink only, not the
  global `ip_forward` switch. The uplink's original value is restored on
  exit.
- adds a uniquely named nftables table with a masquerade rule for the
  calculator's address on the uplink.
- if firewalld is running, adds a runtime forwarding rule limited to the
  calculator's source address, TAP and uplink.

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

The network part of the manual setup lasts until reboot. The udev rule is
permanent. With `--tap` pointing at an existing interface, the bridge uses
it as configured and changes nothing on the host. It warns if the
interface's address does not match `--host-ip` or if the interface is down.
The printed output includes the commands to undo the setup.

## Crypto offload and secrets

> **Warning:** `--accelerate-crypto` routes X25519 and P-256 operations
> through the host. Ephemeral private scalars and shared secrets pass through
> host process memory and are not guaranteed to be wiped (Python's immutable
> bytes/int objects and the interpreter's copying prevent this). Core dumps
> are disabled while the flag is active, but swap and a privileged local
> attacker are not mitigated. If your threat model includes a compromised or
> untrusted host, leave this flag off.

These values are never logged, written to disk, or forwarded to the network.
Without the flag, crypto control frames are dropped.

What the bridge does to limit exposure:

- zeroes its receive buffer once each frame has been taken out of it.
- on Linux, marks itself non-dumpable, so crash handlers such as
  `systemd-coredump` can't capture its memory and other processes running as
  your user can't attach a debugger or read it.
- relies on `python3-cryptography` to clear the key material it holds
  itself. That doesn't cover the copies Python makes before the key reaches
  it.

Leaving the flag off keeps all key operations on the calculator. The Wi-Fi
bridge firmware is the alternative when you want offload without these
host-side limits.

## Cleanup caveat

On both platforms, cleanup runs on normal exit, Ctrl+C, and bridge errors.
A forced kill (`SIGKILL`) or power loss skips it. To recover:

- **macOS:** inspect `sudo pfctl -s Anchors` for a stale
  `com.apple/lwip-ce-bridge-*` anchor, flush only that anchor, then restore
  `net.inet.ip.forwarding` to its recorded prior value.
- **Linux:** inspect `sudo nft list tables` for a stale
  `lwip_ce_bridge_*` table, delete only that table, remove the corresponding
  TAP, and restore uplink forwarding to its recorded prior value. Remove any
  matching runtime firewalld direct rule.

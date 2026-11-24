#!/usr/bin/env python3
"""Bridge the calculator's CDC-ACM link to a real network.

The calculator in USB device mode presents a CDC-ACM interface carrying raw
Ethernet frames -- one per USB bulk transfer, no header, no length prefix, no
escaping. The ESP32 Wi-Fi bridge firmware reads those frames and forwards them
over Wi-Fi; this does the same job on a computer. The approach is Alessio
Dam's; this is an independent implementation against the same wire format.

    --listen    decode and print frames; no privileges, nothing written
    --serve     answer DHCP and ARP in-process, so the calculator gets an
                address and can reach this host. No TAP driver needed.
    --tap       forward frames to a TAP interface (Linux). The real bridge:
                the calculator becomes a host on your network.
    --accelerate-crypto  answer the existing crypto offload requests with
                python3-cryptography. Requires Crypto offload enabled on the
                calculator and a build with the P-256 request-length hint.

On macOS, use the serial port macOS already provides. A tty is a byte stream
and loses the USB transfer boundaries that are this protocol's only framing,
so frames are recovered by parsing their headers -- see frame_length(). That
works for IPv4, IPv6, ARP, 802.3-length and crypto control frames.

On Linux, prefer PyUSB: detach_kernel_driver() releases cdc_acm and bulk
reads preserve transfer boundaries exactly, so no header parsing is needed.
"""

from __future__ import annotations

import argparse
import glob
import os
import platform
import select
import socket
import struct
import sys
import termios
import time

VID, PID = 0x16C0, 0x05E1

ETH_HDR = 14
ETH_MAX = 1514
USB_MPS = 64     # bulk max packet size

# The Wi-Fi bridge's control protocol, from src/wireless/wifi_proto.h. The
# calculator sends these unprompted when it is looking for a bridge, so a
# host-side bridge that does not know the type loses frame sync the first
# time one arrives: there is no length field to recover from, so the parser
# starts discarding bytes and never realigns.
CTL_ETHERTYPE = 0x88B5
CTL_HEADER = 18          # dst/src/type(14) + version, opcode, id, status
CTL_VERSION = 1
CTL_REPLY = 0x80
CTL_ST_OK = 0
CTL_ST_BAD_REQUEST = 1
CTL_ST_REJECTED = 5
CTL_CAP_X25519 = 0x01
CTL_CAP_RSA = 0x02
CTL_CAP_RANDOM = 0x04
CTL_CAP_P256 = 0x08
CTL_CRYPTO_CAPS = (CTL_CAP_X25519 | CTL_CAP_RSA |
                   CTL_CAP_RANDOM | CTL_CAP_P256)
CTL_OP_NAMES = {
    1: "STATUS", 2: "LIST", 3: "SCAN", 4: "SAVE", 5: "FORGET",
    6: "ENABLE", 7: "PREFER", 8: "CONNECT", 9: "DISCONNECT", 10: "INFO",
    11: "X25519", 12: "RSA_VERIFY", 13: "RANDOM", 14: "P256",
    15: "ECDSA_VERIFY",
}


class MissingP256LengthHint(ValueError):
    """The calculator uses the old ambiguous P-256 byte-stream format."""


def zlp_needed(length: int) -> bool:
    """True if a frame needs a terminating zero-length packet.

    A transfer that is an exact multiple of the max packet size is not
    self-terminating -- the receiver cannot tell it ended. The ESP32 firmware
    appends a pad byte instead; a ZLP is cleaner and the device takes either,
    since it reads whatever the transfer delivers.
    """
    return length % USB_MPS == 0


def frame_length(buf: bytes) -> int | None:
    """Total frame length from the headers.

    None when more bytes are needed, 0 when the buffer does not start with
    something parseable (the caller resyncs).

    Only needed when USB transfer boundaries were lost, i.e. reading a tty.
    The PyUSB path gets exact lengths from the transfer itself.
    """
    if len(buf) < ETH_HDR:
        return None
    et = (buf[12] << 8) | buf[13]

    if et == 0x0800:                      # IPv4
        if len(buf) < 18:
            return None
        if (buf[14] >> 4) != 4:
            return 0
        total = (buf[16] << 8) | buf[17]
        return ETH_HDR + total if total >= 20 else 0
    if et == 0x0806:                      # ARP over ethernet/IPv4
        return ETH_HDR + 28
    if et == 0x86DD:                      # IPv6
        if len(buf) < 20:
            return None
        return ETH_HDR + 40 + ((buf[18] << 8) | buf[19])
    if et == CTL_ETHERTYPE:
        if len(buf) < CTL_HEADER:
            return None
        if buf[14] != CTL_VERSION or buf[15] & CTL_REPLY:
            return 0
        op = buf[15]
        if op == 11:                # X25519: scalar + point
            return CTL_HEADER + 64
        if op == 12:                # RSA: variable modulus and exponent
            if len(buf) < CTL_HEADER + 36:
                return None
            modulus = buf[CTL_HEADER + 33] | (buf[CTL_HEADER + 34] << 8)
            exponent = buf[CTL_HEADER + 35]
            if not 1 <= modulus <= 512 or not 1 <= exponent <= 255:
                return 0
            return CTL_HEADER + 36 + 2 * modulus + exponent
        if op == 13:                # random: count
            return CTL_HEADER + 1
        if op == 14:                # P-256: request length hint in byte 17
            if buf[17] not in (32, 97):
                raise MissingP256LengthHint(
                    f"P-256 request has invalid length hint {buf[17]}; "
                    "rebuild the calculator with the updated "
                    "src/wireless/crypto.c")
            return CTL_HEADER + buf[17]
        if op == 15:                # ECDSA P-256 verify
            return CTL_HEADER + 161
        return CTL_HEADER
    # 802.3 length rather than an EtherType. A zero or tiny length is not a
    # real frame -- it is almost always a misaligned read, and treating it as
    # a valid 14-byte frame makes the parser consume garbage forever instead
    # of resyncing (observed: a desync produced an endless run of "0x0000
    # 14B" lines).
    if 46 <= et <= 1500:
        return ETH_HDR + et
    return 0


class FrameReassembler:
    """Recover frame boundaries from a byte stream that lost them (legacy mode).

    Consumes exactly the header-derived length. An earlier version rounded up
    to the 60-byte Ethernet minimum on the assumption that short frames are
    padded; the calculator does not pad, so that ate the first bytes of the
    next frame and showed up as resyncs on live traffic.

    resync_bytes counts bytes discarded to regain sync, so callers can tell
    whether reassembly is actually holding rather than assume it.
    """

    def __init__(self) -> None:
        self.buf = bytearray()
        self.frames = 0
        self.resync_bytes = 0

    def feed(self, chunk: bytes):
        self.buf += chunk
        while self.buf:
            n = frame_length(bytes(self.buf))
            if n is None:
                return
            if n == 0 or n > ETH_MAX or n < ETH_HDR:
                del self.buf[0]
                self.resync_bytes += 1
                continue
            if len(self.buf) < n:
                return
            frame = bytes(self.buf[:n])
            del self.buf[:n]
            self.frames += 1
            yield frame


class LengthPrefixReassembler:
    """Recover frames from a 2-byte big-endian length-prefixed byte stream.

    Wire format: [len_hi][len_lo][payload...].  Works regardless of how the
    OS chunks USB transfers -- required for macOS ACM tty.
    """

    def __init__(self) -> None:
        self.buf = bytearray()
        self.frames = 0

    def feed(self, chunk: bytes):
        self.buf += chunk
        while len(self.buf) >= 2:
            n = (self.buf[0] << 8) | self.buf[1]
            if n < ETH_HDR or n > ETH_MAX:
                del self.buf[0]
                continue
            if len(self.buf) < 2 + n:
                return
            frame = bytes(self.buf[2:2 + n])
            del self.buf[:2 + n]
            self.frames += 1
            yield frame


def mac_str(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def describe_frame(f: bytes) -> str:
    et = (f[12] << 8) | f[13]
    kind = {0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6"}.get(et, f"0x{et:04x}")
    extra = ""
    if et == 0x0800 and len(f) >= 34:
        proto = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(f[23], str(f[23]))
        src = ".".join(str(x) for x in f[26:30])
        dst = ".".join(str(x) for x in f[30:34])
        extra = f"  {proto} {src}->{dst}"
        if f[23] == 17 and len(f) >= 38:
            sp, dp = (f[34] << 8) | f[35], (f[36] << 8) | f[37]
            extra += f" :{sp}->{dp}"
            if dp in (67, 68) or sp in (67, 68):
                extra += "  [DHCP]"
    elif et == 0x0806 and len(f) >= 42:
        extra = "  who-has " + ".".join(str(x) for x in f[38:42])
    elif et == CTL_ETHERTYPE and len(f) >= CTL_HEADER:
        op = f[15]
        name = CTL_OP_NAMES.get(op & ~CTL_REPLY, str(op))
        extra = (f"  CTL v{f[14]} {name}"
                 f"{' reply' if op & CTL_REPLY else ''} id={f[16]}")
        kind = "CTL"
    return f"{kind:>6} {len(f):>5}B  {mac_str(f[6:12])} -> {mac_str(f[0:6])}{extra}"


def find_calculator_tty() -> str | None:
    """The serial port belonging to our VID/PID, or None if not attached.

    Matching on hardware identity rather than taking the first usbmodem*:
    other CDC devices create ports too, and writing Ethernet frames into
    somebody's modem would be rude. On macOS the IORegistry carries the
    idVendor/idProduct next to the port name; elsewhere fall back to the
    by-id symlinks, which encode the same thing.
    """
    if platform.system() == "Darwin":
        import subprocess
        try:
            out = subprocess.run(
                ["ioreg", "-r", "-c", "IOUSBHostDevice", "-l"],
                capture_output=True, text=True, timeout=10).stdout
        except Exception:
            out = ""
        # Walk the device's subtree: the dialin device appears under the
        # ACM data interface, after the matching idVendor/idProduct.
        want_v, want_p = f'"idVendor" = {VID}', f'"idProduct" = {PID}'
        in_device = False
        for line in out.splitlines():
            if want_v in line:
                in_device = True
            elif '"idVendor" =' in line and want_v not in line:
                in_device = False
            if in_device and "IODialinDevice" in line:
                part = line.split('"IODialinDevice"', 1)[1]
                if '"' in part:
                    return part.split('"')[1]
        # The registry walk can miss it depending on nesting; fall back to
        # the glob only when exactly one candidate exists.
        found = sorted(glob.glob("/dev/cu.usbmodem*"))
        return found[0] if len(found) == 1 else None

    for pattern in (f"/dev/serial/by-id/*{VID:04x}*{PID:04x}*",
                    f"/dev/serial/by-id/*{VID:04X}*{PID:04X}*"):
        found = sorted(glob.glob(pattern))
        if found:
            return found[0]
    found = sorted(glob.glob("/dev/ttyACM*"))
    return found[0] if len(found) == 1 else None


def wait_for_calculator(port: str | None, quiet: bool = False) -> str:
    """Block until the calculator's port exists, then return it.

    The bridge should be startable before the calculator is plugged in or
    lwIP is launched, and should survive a replug -- the device disappears
    and comes back whenever lwIP restarts.
    """
    if port:
        while not os.path.exists(port):
            if not quiet:
                print(f"waiting for {port} ...", end="\r", flush=True)
            time.sleep(0.5)
        return port

    announced = False
    while True:
        found = find_calculator_tty()
        if found:
            if announced:
                print(" " * 60, end="\r")
            return found
        if not announced and not quiet:
            print(f"waiting for the calculator "
                  f"({VID:04X}:{PID:04X}) ...", end="\r", flush=True)
            announced = True
        time.sleep(0.5)


def open_tty(port: str):
    """Open the serial port raw, and assert DTR.

    Raw mode matters: any line discipline would mangle binary frames. DTR is
    how the device is told the link is up -- device_apply_dtr() raises the
    netif link on SET_CONTROL_LINE_STATE, and without it nothing is sent.
    """
    import fcntl

    fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    attrs = termios.tcgetattr(fd)
    attrs[0] = attrs[1] = attrs[3] = 0
    attrs[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
    attrs[6][termios.VMIN] = 0
    attrs[6][termios.VTIME] = 0
    termios.tcsetattr(fd, termios.TCSANOW, attrs)
    fcntl.ioctl(fd, 0x8004746C, struct.pack("I", 0x002))   # TIOCMBIS, TIOCM_DTR
    return fd


class SerialFrameWriteError(Exception):
    """A frame could not be sent as one complete serial write."""


def write_frame(fd: int, frame: bytes) -> None:
    """Send a whole frame and drain it before queuing the next frame.

    Prepends a 2-byte big-endian length prefix; pads to avoid a ZLP if the
    total wire length is an exact MPS multiple.
    """
    n = len(frame)
    prefix = bytes([n >> 8, n & 0xFF])
    wire = prefix + frame
    if zlp_needed(len(wire)):
        wire += b"\x00"

    deadline = time.monotonic() + 2.0
    while True:
        try:
            written = os.write(fd, wire)
            break
        except BlockingIOError:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SerialFrameWriteError(
                    f"serial output stayed full for 2s while sending "
                    f"a {n}-byte frame") from None
            select.select([], [fd], [], min(remaining, 0.2))
    if written != len(wire):
        raise SerialFrameWriteError(
            f"short serial write: {written}/{len(wire)} bytes; "
            "the calculator may have received a partial Ethernet frame")
    termios.tcdrain(fd)


class CryptoResponder:
    """Answer the calculator's existing Wi-Fi crypto control operations."""

    VERSION = b"pyca-bridge"

    def __init__(self) -> None:
        # Keep cryptography optional for the ordinary network bridge.
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils, x25519

        self.InvalidSignature = InvalidSignature
        self.hashes = hashes
        self.serialization = serialization
        self.ec = ec
        self.padding = padding
        self.rsa = rsa
        self.utils = utils
        self.x25519 = x25519

    def _compute(self, op: int, body: bytes) -> tuple[int, bytes]:
        if op == 10:  # INFO
            if body:
                return CTL_ST_BAD_REQUEST, b""
            return CTL_ST_OK, bytes((CTL_CRYPTO_CAPS, len(self.VERSION))) + self.VERSION

        if op == 11:  # X25519
            if len(body) != 64:
                return CTL_ST_BAD_REQUEST, b""
            try:
                private = self.x25519.X25519PrivateKey.from_private_bytes(body[:32])
                public = self.x25519.X25519PublicKey.from_public_bytes(body[32:])
                return CTL_ST_OK, private.exchange(public)
            except ValueError:  # invalid peer point, including all-zero output
                return CTL_ST_REJECTED, b""

        if op == 12:  # RSA PKCS#1 v1.5 or PSS, SHA-256 prehash
            if len(body) < 36 or body[0] not in (1, 2):
                return CTL_ST_BAD_REQUEST, b""
            mod_len = body[33] | (body[34] << 8)
            exp_len = body[35]
            if not 1 <= mod_len <= 512 or not 1 <= exp_len <= 255 or \
                    len(body) != 36 + 2 * mod_len + exp_len:
                return CTL_ST_BAD_REQUEST, b""
            modulus = int.from_bytes(body[36:36 + mod_len], "big")
            exponent = int.from_bytes(body[36 + mod_len:36 + mod_len + exp_len], "big")
            signature = body[36 + mod_len + exp_len:]
            scheme = (self.padding.PKCS1v15() if body[0] == 1 else
                      self.padding.PSS(mgf=self.padding.MGF1(self.hashes.SHA256()),
                                       salt_length=32))
            try:
                key = self.rsa.RSAPublicNumbers(exponent, modulus).public_key()
                key.verify(signature, body[1:33], scheme,
                           self.utils.Prehashed(self.hashes.SHA256()))
            except self.InvalidSignature:
                return CTL_ST_REJECTED, b""
            except ValueError:
                return CTL_ST_BAD_REQUEST, b""
            return CTL_ST_OK, b""

        if op == 13:  # random bytes from the host CSPRNG
            if len(body) != 1 or not 1 <= body[0] <= 64:
                return CTL_ST_BAD_REQUEST, b""
            return CTL_ST_OK, os.urandom(body[0])

        if op == 14:  # P-256 public key or ECDH x-coordinate
            if len(body) not in (32, 97):
                return CTL_ST_BAD_REQUEST, b""
            try:
                private = self.ec.derive_private_key(int.from_bytes(body[:32], "big"),
                                                     self.ec.SECP256R1())
                if len(body) == 32:
                    return CTL_ST_OK, private.public_key().public_bytes(
                        self.serialization.Encoding.X962,
                        self.serialization.PublicFormat.UncompressedPoint)
                peer = self.ec.EllipticCurvePublicKey.from_encoded_point(
                    self.ec.SECP256R1(), body[32:])
                return CTL_ST_OK, private.exchange(self.ec.ECDH(), peer)
            except ValueError:
                return CTL_ST_BAD_REQUEST, b""

        if op == 15:  # ECDSA P-256 verify, SHA-256 prehash, raw r||s
            if len(body) != 161:
                return CTL_ST_BAD_REQUEST, b""
            try:
                public = self.ec.EllipticCurvePublicKey.from_encoded_point(
                    self.ec.SECP256R1(), body[32:97])
                signature = self.utils.encode_dss_signature(
                    int.from_bytes(body[97:129], "big"),
                    int.from_bytes(body[129:161], "big"))
                public.verify(signature, body[:32],
                              self.ec.ECDSA(self.utils.Prehashed(self.hashes.SHA256())))
            except self.InvalidSignature:
                return CTL_ST_REJECTED, b""
            except ValueError:
                return CTL_ST_BAD_REQUEST, b""
            return CTL_ST_OK, b""

        return CTL_ST_BAD_REQUEST, b""

    def handle(self, frame: bytes, host_mac: bytes) -> bytes | None:
        if (len(frame) < CTL_HEADER or frame[12:14] != b"\x88\xb5" or
                frame[14] != CTL_VERSION or frame[15] & CTL_REPLY or
                frame[15] not in (10, 11, 12, 13, 14, 15)):
            return None
        status, body = self._compute(frame[15], frame[CTL_HEADER:])
        header = bytes((CTL_VERSION, frame[15] | CTL_REPLY, frame[16], status))
        return frame[6:12] + host_mac + frame[12:14] + header + body


# ---------------------------------------------------------------------------
# DHCP + ARP responder: enough of a network for the calculator to come up,
# without needing a TAP driver (macOS has none built in).
# ---------------------------------------------------------------------------

class MiniNet:
    """Answers ARP and DHCP so the calculator gets an address.

    Deliberately minimal: one lease, no renewal bookkeeping, no relaying. It
    exists to prove the link end to end and to give something to ping, not to
    be a DHCP server.
    """

    def __init__(self, host_ip="10.84.0.1", client_ip="10.84.0.10",
                 netmask="255.255.255.0", dns_ip=None, ntp_ip=None):
        self.host_ip = bytes(int(x) for x in host_ip.split("."))
        self.client_ip = bytes(int(x) for x in client_ip.split("."))
        self.netmask = bytes(int(x) for x in netmask.split("."))
        # Defaults are public resolvers so --bridge works out of the box.
        # In --serve mode nothing routes anyway, so these go unanswered
        # either way; the lease itself is what that mode is proving.
        self.dns_ip = bytes(int(x) for x in (dns_ip or "1.1.1.1").split("."))
        self.ntp_ip = bytes(int(x) for x in (ntp_ip or "162.159.200.1").split("."))
        self.host_mac = bytes.fromhex("02cece000001")
        self.leased_to: bytes | None = None
        self.echo_port = 7
        self.echoed = 0
        self.tcp: dict | None = None
        # In --bridge mode the kernel answers ICMP and TCP for real, so the
        # built-in responders must stand down: a local echo would make the
        # calculator look connected while it reached nothing.
        self.answer_icmp = True
        self.answer_tcp = True

    def handle(self, f: bytes) -> bytes | None:
        et = (f[12] << 8) | f[13]
        if et == 0x0806:
            return self._arp(f)
        if et != 0x0800 or len(f) < 34:
            return None
        proto = f[23]
        if proto == 17 and len(f) >= 42:
            dport = (f[36] << 8) | f[37]
            if dport == 67:
                return self._dhcp(f)
        elif proto == 1 and self.answer_icmp:
            return self._icmp(f)
        elif proto == 6 and self.answer_tcp:
            return self._tcp_echo(f)
        return None

    # -- helpers shared by the IP responders --------------------------------

    @staticmethod
    def _ip_checksum(hdr: bytes) -> int:
        s = 0
        for j in range(0, len(hdr), 2):
            s += (hdr[j] << 8) | hdr[j + 1]
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)
        return ~s & 0xFFFF

    def _ip_frame(self, dst_mac, dst_ip, proto, payload) -> bytes:
        total = 20 + len(payload)
        hdr = bytearray(struct.pack(">BBHHHBBH", 0x45, 0, total, 0, 0,
                                    64, proto, 0))
        hdr += self.host_ip + dst_ip
        hdr[10:12] = struct.pack(">H", self._ip_checksum(bytes(hdr)))
        return dst_mac + self.host_mac + b"\x08\x00" + bytes(hdr) + payload

    @staticmethod
    def _l4_checksum(src_ip, dst_ip, proto, body) -> int:
        pseudo = src_ip + dst_ip + bytes([0, proto]) + struct.pack(">H", len(body))
        data = pseudo + body
        if len(data) % 2:
            data += b"\x00"
        s = 0
        for j in range(0, len(data), 2):
            s += (data[j] << 8) | data[j + 1]
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)
        return ~s & 0xFFFF

    def _icmp(self, f: bytes) -> bytes | None:
        """Answer echo requests, so the link can be pinged from the calc."""
        ihl = (f[14] & 0x0F) * 4
        icmp = f[14 + ihl:]
        if len(icmp) < 8 or icmp[0] != 8:       # echo request only
            return None
        body = bytearray(icmp)
        body[0] = 0                              # echo reply
        body[2:4] = b"\x00\x00"
        ck = self._ip_checksum(bytes(body) + (b"\x00" if len(body) % 2 else b""))
        body[2:4] = struct.pack(">H", ck)
        return self._ip_frame(f[6:12], f[26:30], 1, bytes(body))

    def _tcp_echo(self, f: bytes) -> bytes | None:
        """A single-connection TCP echo server, enough to ping-pong on.

        Not a TCP stack: it answers SYN with SYN-ACK, echoes payload back in
        an ACK, and closes on FIN. One connection at a time, no
        retransmission, no window management. It exists so the calculator's
        echo client has a peer without needing a TAP interface or a real
        server on the host.
        """
        ihl = (f[14] & 0x0F) * 4
        ip_off = 14
        tcp_off = ip_off + ihl
        if len(f) < tcp_off + 20:
            return None
        src_ip, dst_ip = f[26:30], f[30:34]
        if dst_ip != self.host_ip:
            return None
        sport = (f[tcp_off] << 8) | f[tcp_off + 1]
        dport = (f[tcp_off + 2] << 8) | f[tcp_off + 3]
        if dport != self.echo_port:
            return None
        seq = struct.unpack(">I", f[tcp_off + 4:tcp_off + 8])[0]
        ack = struct.unpack(">I", f[tcp_off + 8:tcp_off + 12])[0]
        doff = (f[tcp_off + 12] >> 4) * 4
        flags = f[tcp_off + 13]
        payload = f[tcp_off + doff:]
        # Trim any Ethernet padding the sender added.
        ip_total = (f[ip_off + 2] << 8) | f[ip_off + 3]
        payload = payload[:max(0, ip_total - ihl - doff)]

        SYN, ACK_F, FIN, RST, PSH = 0x02, 0x10, 0x01, 0x04, 0x08

        def seg(flags_out, seq_out, ack_out, body=b""):
            t = bytearray(struct.pack(">HHIIBBHHH", self.echo_port, sport,
                                      seq_out, ack_out, 5 << 4, flags_out,
                                      4096, 0, 0))
            t += body
            ck = self._l4_checksum(self.host_ip, src_ip, 6, bytes(t))
            t[16:18] = struct.pack(">H", ck)
            return self._ip_frame(f[6:12], src_ip, 6, bytes(t))

        if flags & RST:
            self.tcp = None
            return None
        if flags & SYN and not (flags & ACK_F):
            self.tcp = {"peer": (src_ip, sport), "our_seq": 0x1000,
                        "their_seq": seq + 1}
            return seg(SYN | ACK_F, self.tcp["our_seq"], seq + 1)
        if not self.tcp or self.tcp["peer"] != (src_ip, sport):
            return None
        if flags & FIN:
            self.tcp = None
            return seg(FIN | ACK_F, self.tcp_final_seq(ack), seq + 1)
        if payload:
            self.echoed += len(payload)
            our_seq = ack if ack else self.tcp["our_seq"] + 1
            return seg(ACK_F | PSH, our_seq, seq + len(payload), payload)
        return None

    def tcp_final_seq(self, ack: int) -> int:
        return ack

    def _arp(self, f: bytes) -> bytes | None:
        if len(f) < 42 or f[20:22] != b"\x00\x01":      # request only
            return None
        target = f[38:42]
        if target != self.host_ip:
            return None
        sender_mac, sender_ip = f[22:28], f[28:32]
        return (sender_mac + self.host_mac + b"\x08\x06"
                + bytes.fromhex("0001080006040002")
                + self.host_mac + self.host_ip
                + sender_mac + sender_ip)

    def _dhcp(self, f: bytes) -> bytes | None:
        payload = f[42:]
        if len(payload) < 240 or payload[236:240] != b"\x63\x82\x53\x63":
            return None
        xid = payload[4:8]
        chaddr = payload[28:34]

        msg_type = None
        i = 240
        while i < len(payload):
            opt = payload[i]
            if opt == 255:
                break
            if opt == 0:
                i += 1
                continue
            if i + 1 >= len(payload):
                break
            ln = payload[i + 1]
            if opt == 53 and ln >= 1:
                msg_type = payload[i + 2]
            i += 2 + ln

        if msg_type == 1:        # DISCOVER -> OFFER
            reply_type = 2
        elif msg_type == 3:      # REQUEST  -> ACK
            reply_type = 5
            self.leased_to = chaddr
        else:
            return None

        bootp = bytearray(240)
        bootp[0] = 2                      # BOOTREPLY
        bootp[1] = 1                      # ethernet
        bootp[2] = 6                      # hwaddr len
        bootp[4:8] = xid
        bootp[16:20] = self.client_ip     # yiaddr
        bootp[20:24] = self.host_ip       # siaddr
        bootp[28:34] = chaddr
        bootp[236:240] = b"\x63\x82\x53\x63"

        opts = bytearray()
        opts += bytes([53, 1, reply_type])
        opts += bytes([54, 4]) + self.host_ip        # server id
        opts += bytes([51, 4]) + struct.pack(">I", 3600)
        opts += bytes([1, 4]) + self.netmask
        opts += bytes([3, 4]) + self.host_ip         # router
        # DNS and NTP must be reachable, not just advertised. Pointing them
        # at ourselves only works if something here answers, and nothing
        # does -- in --bridge mode the kernel routes these out like any other
        # traffic, so they have to be real servers.
        #
        # lwIP needs both for TLS: socket_required_services() demands SNTP
        # for ALTCP_TLS (certificate validity needs a clock) and DNS for any
        # hostname. With SNTP_GET_SERVERS_FROM_DHCP=1 it reads option 42
        # here; without it, it falls back to "pool.ntp.org", which itself
        # needs DNS.
        opts += bytes([6, 4]) + self.dns_ip          # option 6: DNS
        opts += bytes([42, 4]) + self.ntp_ip         # option 42: NTP
        opts += bytes([255])
        body = bytes(bootp) + bytes(opts)

        udp_len = 8 + len(body)
        udp = struct.pack(">HHHH", 67, 68, udp_len, 0) + body
        total = 20 + udp_len
        ip = bytearray(struct.pack(">BBHHHBBH", 0x45, 0, total, 0, 0, 64, 17, 0))
        ip += self.host_ip + b"\xff\xff\xff\xff"
        cks = 0
        for j in range(0, 20, 2):
            cks += (ip[j] << 8) | ip[j + 1]
        cks = (cks & 0xFFFF) + (cks >> 16)
        ip[10:12] = struct.pack(">H", ~cks & 0xFFFF)

        return (b"\xff" * 6 + self.host_mac + b"\x08\x00" + bytes(ip) + udp)


# ---------------------------------------------------------------------------
# Real bridging: hand IP to the kernel and let it route, NAT and resolve.
# ---------------------------------------------------------------------------

def active_uplinks() -> list[str]:
    """Interfaces that could carry the calculator's traffic outward.

    The one holding the default route comes first, since that is what the
    host itself uses; any other up-and-addressed interface follows, so
    --odevice has something meaningful to choose from. Loopback, the utun we
    create, and virtual bridges are skipped.
    """
    import subprocess

    found: list[str] = []

    try:
        out = subprocess.run(["route", "-n", "get", "default"],
                             capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            if "interface:" in line:
                found.append(line.split(":", 1)[1].strip())
                break
    except Exception:
        pass

    # Everything else that is up and has an IPv4 address.
    try:
        out = subprocess.run(["ifconfig"], capture_output=True,
                             text=True, timeout=5).stdout
        name = None
        for line in out.splitlines():
            if line and not line[0].isspace():
                name = line.split(":", 1)[0]
                continue
            if (name and "inet " in line and name not in found
                    and not name.startswith(("lo", "utun", "gif", "stf",
                                             "awdl", "llw", "bridge"))):
                found.append(name)
    except Exception:
        pass

    return found or ["en0"]


def default_uplink() -> str:
    return active_uplinks()[0]


def route_interface(destination: str) -> str | None:
    """Interface macOS currently uses to reach one IPv4 destination."""
    import subprocess

    result = subprocess.run(["route", "-n", "get", "-host", destination],
                            capture_output=True, text=True, timeout=5)
    if result.returncode != 0:
        return None
    for line in result.stdout.splitlines():
        if line.strip().startswith("interface:"):
            return line.split(":", 1)[1].strip()
    return None


def open_utun():
    """Create a utun interface and return (socket, name).

    macOS has no TAP device, so there is no Ethernet-level interface to hand
    frames to. utun is layer 3 and built in: strip the Ethernet header on the
    way out, put one back on the way in, and the kernel does the rest. That
    keeps TCP, routing, NAT and DNS in the kernel where they belong, instead
    of in a hand-rolled stack here.

    Needs root. Creating network interfaces is privileged on every OS.
    """
    import fcntl

    AF_SYSTEM, SYSPROTO_CONTROL = 32, 2
    AF_SYS_CONTROL = 2
    CTLIOCGINFO = 0xC0644E03
    UTUN_OPT_IFNAME = 2

    s = socket.socket(AF_SYSTEM, socket.SOCK_DGRAM, SYSPROTO_CONTROL)
    info = struct.pack("<I96s", 0, b"com.apple.net.utun_control")
    ctl_id = struct.unpack("<I96s", fcntl.ioctl(s, CTLIOCGINFO, info))[0]
    s.connect((ctl_id, 0))          # unit 0: kernel picks the next free utun
    name = s.getsockopt(SYSPROTO_CONTROL, UTUN_OPT_IFNAME, 32)
    name = name.split(b"\x00")[0].decode()
    s.setblocking(False)
    return s, name


def utun_write(sock, ip_packet: bytes) -> None:
    """Send an IP packet to the kernel. utun prefixes a 4-byte address family."""
    af = socket.AF_INET6 if (ip_packet[0] >> 4) == 6 else socket.AF_INET
    sock.send(struct.pack(">I", af) + ip_packet)


def utun_read(sock) -> bytes | None:
    try:
        data = sock.recv(4096)
    except BlockingIOError:
        return None
    return data[4:] if len(data) > 4 else None


ACM_SAFE_MSS = 360


def clamp_tcp_mss(frame: bytes, limit: int = ACM_SAFE_MSS) -> tuple[bytes, int | None]:
    """Limit the calculator's SYN MSS so inbound ACM frames stay below 512 B.

    macOS's serial driver may split a larger write into USB transfers. The
    calculator currently treats each completed transfer as one Ethernet
    frame, so a server's 512-byte TCP payload (566-byte Ethernet frame) can
    be lost at this link. A 360-byte MSS leaves room even for maximal IPv4
    and TCP option headers within a 512-byte Ethernet frame.
    """
    if len(frame) < 14 + 20 + 20 or frame[12:14] != b"\x08\x00" or \
            frame[14] >> 4 != 4 or frame[23] != 6:
        return frame, None
    ihl = (frame[14] & 15) * 4
    total = (frame[16] << 8) | frame[17]
    tcp_at = 14 + ihl
    if (ihl < 20 or total < ihl + 20 or len(frame) < 14 + total or
            frame[20] & 0x3f or frame[21] or len(frame) < tcp_at + 20 or
            not frame[tcp_at + 13] & 0x02):
        return frame, None
    tcp_header = (frame[tcp_at + 12] >> 4) * 4
    if tcp_header < 20 or tcp_header > total - ihl:
        return frame, None

    pos = tcp_at + 20
    end = tcp_at + tcp_header
    while pos < end:
        kind = frame[pos]
        if kind == 0:              # end of options
            break
        if kind == 1:              # NOP
            pos += 1
            continue
        if pos + 2 > end:
            break
        length = frame[pos + 1]
        if length < 2 or pos + length > end:
            break
        if kind == 2 and length == 4:
            old = (frame[pos + 2] << 8) | frame[pos + 3]
            if old <= limit:
                return frame, None
            changed = bytearray(frame)
            changed[pos + 2:pos + 4] = limit.to_bytes(2, "big")
            changed[tcp_at + 16:tcp_at + 18] = b"\x00\x00"
            checksum = MiniNet._l4_checksum(changed[26:30], changed[30:34], 6,
                                            changed[tcp_at:14 + total])
            changed[tcp_at + 16:tcp_at + 18] = checksum.to_bytes(2, "big")
            return bytes(changed), old
        pos += length
    return frame, None


TLS_HANDSHAKE_TYPES = {
    1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket",
    8: "EncryptedExtensions", 11: "Certificate", 13: "CertificateRequest",
    15: "CertificateVerify", 20: "Finished",
}
TLS_ALERTS = {
    0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac",
    40: "handshake_failure", 42: "bad_certificate", 43: "unsupported_certificate",
    44: "certificate_revoked", 45: "certificate_expired", 46: "certificate_unknown",
    47: "illegal_parameter", 48: "unknown_ca", 49: "access_denied",
    50: "decode_error", 51: "decrypt_error", 70: "protocol_version",
    71: "insufficient_security", 80: "internal_error", 86: "inappropriate_fallback",
    109: "missing_extension", 112: "unrecognized_name",
    116: "certificate_required", 120: "no_application_protocol",
}


def describe_tls(frame: bytes, direction: str,
                 save_to: str | None = None) -> None:
    """Decode a TLS record carried in this frame, if there is one.

    A server that closes immediately after the ClientHello has read it and
    rejected it, so what we actually put on the wire is the evidence -- not
    what the code intends to send. Prints the ClientHello's version, cipher
    suites and extension ids, and decodes any alert the server sends back.
    """
    ihl = (frame[14] & 0x0F) * 4
    off = 14 + ihl
    if len(frame) < off + 20 or frame[23] != 6:        # TCP only
        return
    doff = (frame[off + 12] >> 4) * 4
    payload = frame[off + doff:]
    ip_total = (frame[16] << 8) | frame[17]
    payload = payload[:max(0, ip_total - ihl - doff)]
    if len(payload) < 6:
        return

    ctype, ver_hi, ver_lo = payload[0], payload[1], payload[2]
    rec_len = (payload[3] << 8) | payload[4]

    if ctype == 21 and len(payload) >= 7:              # alert, plaintext
        level, desc = payload[5], payload[6]
        name = TLS_ALERTS.get(desc, str(desc))
        print(f"  !! TLS alert from {direction}: level={level} {name}")
        return
    if ctype != 22:                                    # handshake only
        return

    body = payload[5:5 + rec_len]
    if len(body) < 4:
        return
    htype = body[0]
    hname = TLS_HANDSHAKE_TYPES.get(htype, f"type {htype}")
    print(f"  ** TLS {hname} ({direction}): record ver 0x{ver_hi:02x}{ver_lo:02x}, "
          f"{rec_len} bytes")

    if htype != 1 or len(body) < 39:
        return

    # ClientHello: legacy_version, random[32], session_id, cipher_suites,
    # compression, extensions.
    p = 4
    legacy = (body[p] << 8) | body[p + 1]
    p += 2 + 32
    sid_len = body[p]; p += 1 + sid_len
    if p + 2 > len(body):
        return
    cs_len = (body[p] << 8) | body[p + 1]; p += 2
    suites = [(body[p + i] << 8) | body[p + i + 1] for i in range(0, cs_len, 2)
              if p + i + 1 < len(body)]
    p += cs_len
    if p >= len(body):
        return
    comp_len = body[p]; p += 1 + comp_len
    print(f"     legacy_version 0x{legacy:04x}, session_id {sid_len}B, "
          f"suites {['0x%04x' % s for s in suites]}")
    if p + 2 > len(body):
        print("     no extensions")
        return
    ext_total = (body[p] << 8) | body[p + 1]; p += 2
    end = min(len(body), p + ext_total)
    exts = []
    while p + 4 <= end:
        eid = (body[p] << 8) | body[p + 1]
        elen = (body[p + 2] << 8) | body[p + 3]
        exts.append(f"{eid}({elen}B)")
        p += 4 + elen
    print(f"     extensions: {', '.join(exts)}")
    if p != end:
        print(f"     *** extension block does not add up: stopped at {p}, "
              f"expected {end} -- MALFORMED")

    # A server that closes without an alert gives no reason, so the only way
    # to find out what it objected to is to replay the exact bytes at it and
    # bisect. Saving them is opt-in and names the path: a tool running as
    # root should not drop files in the user's working directory uninvited.
    if save_to:
        try:
            with open(save_to, "wb") as fh:
                fh.write(payload[:5 + rec_len])
            print(f"     saved {5 + rec_len} bytes to {save_to}")
        except OSError as e:
            print(f"     (could not save: {e})")


class ConnectionWatch:
    """Notices how connections end, and says why in plain terms.

    A handshake that fails is usually diagnosed from the last thing that
    happened before the close, and that evidence is on the wire: a TLS alert
    naming the reason, a bare RST, or a FIN with nothing sent at all. The
    calculator's own log records the state it reached, which cannot
    distinguish "the server objected" from "the server vanished".
    """

    def __init__(self, trace: bool = False):
        # keyed by (src_ip, sport, dst_ip, dport) seen from the calculator
        self.flows: dict = {}
        # trace prints every TCP segment's flags, which is what distinguishes
        # "we never sent it" from "we sent it and it was discarded".
        self.trace = trace

    @staticmethod
    def _key(f):
        ihl = (f[14] & 0x0F) * 4
        off = 14 + ihl
        sport = (f[off] << 8) | f[off + 1]
        dport = (f[off + 2] << 8) | f[off + 3]
        return (bytes(f[26:30]), sport, bytes(f[30:34]), dport)

    def observe(self, frame: bytes, outbound: bool) -> None:
        if len(frame) < 34 or (frame[12] << 8) | frame[13] != 0x0800:
            return
        if frame[23] != 6:                      # TCP only
            return
        ihl = (frame[14] & 0x0F) * 4
        off = 14 + ihl
        if len(frame) < off + 20:
            return
        flags = frame[off + 13]
        doff = (frame[off + 12] >> 4) * 4
        ip_total = (frame[16] << 8) | frame[17]
        plen = max(0, ip_total - ihl - doff)
        payload = frame[off + doff:off + doff + plen]

        key = self._key(frame)
        if not outbound:                        # normalise direction
            key = (key[2], key[3], key[0], key[1])
        st = self.flows.setdefault(key, {
            "sent": 0, "recvd": 0, "alert": None,
            "tls_out": 0, "tls_in": 0, "opened": time.time(),
        })

        if outbound:
            st["sent"] += plen
        else:
            st["recvd"] += plen

        # Remember any TLS record seen, and any alert in particular.
        if plen >= 6 and payload[0] in (20, 21, 22, 23):
            if outbound:
                st["tls_out"] += 1
            else:
                st["tls_in"] += 1
            if payload[0] == 21 and plen >= 7:
                st["alert"] = (payload[5], payload[6], outbound)

        SYN, ACK, FIN, RST, PSH = 0x02, 0x10, 0x01, 0x04, 0x08
        if self.trace:
            names = [n for bit, n in ((SYN, "SYN"), (ACK, "ACK"), (FIN, "FIN"),
                                      (RST, "RST"), (PSH, "PSH"))
                     if flags & bit]
            arrow = "calc->" if outbound else "  ->calc"
            seq = struct.unpack(">I", frame[off + 4:off + 8])[0]
            ack_n = struct.unpack(">I", frame[off + 8:off + 12])[0]
            print(f"     tcp {arrow} [{','.join(names) or 'none'}] "
                  f"seq={seq} ack={ack_n} len={plen}")

        if flags & (FIN | RST):
            who = "calculator" if outbound else "server"
            how = "RST" if flags & RST else "FIN"
            dest = ".".join(str(b) for b in key[2])
            age = time.time() - st["opened"]
            print(f"\n  == connection to {dest}:{key[3]} closed by {who} "
                  f"({how}) after {age:.1f}s ==")
            print(f"     bytes: {st['sent']} sent, {st['recvd']} received; "
                  f"TLS records: {st['tls_out']} out, {st['tls_in']} in")

            if st["alert"]:
                level, desc, from_calc = st["alert"]
                name = TLS_ALERTS.get(desc, f"unknown({desc})")
                lvl = {1: "warning", 2: "fatal"}.get(level, str(level))
                src = "calculator" if from_calc else "server"
                print(f"     REASON: {src} sent a {lvl} TLS alert: {name}")
            elif st["tls_out"] and not st["tls_in"]:
                how_long = "reset" if flags & RST else "closed"
                print(f"     REASON: we sent TLS records and the peer never "
                      f"replied with one -- it {how_long} the connection "
                      f"instead of sending an alert.")
                print("             Usual causes: missing or wrong SNI, no "
                      "acceptable cipher suite or group, or a malformed "
                      "hello. Re-run with --tls to see what we sent.")
            elif not st["sent"]:
                print("     REASON: the connection was opened but we never "
                      "sent anything before it closed.")
            elif flags & RST:
                print("     REASON: reset without an alert -- the peer "
                      "abandoned the connection at the TCP layer.")
            del self.flows[key]


def cmd_bridge(fd: int, net: "MiniNet", uplink: str, seconds: float,
               verbose: bool = True, tls_dump: bool = False,
               watch: "ConnectionWatch | None" = None,
               crypto: "CryptoResponder | None" = None) -> int:
    """Bridge the calculator onto the real network via utun + pf NAT.

    The bridge itself does almost nothing: DHCP and ARP (the kernel will not
    serve those on a point-to-point utun), plus Ethernet header removal and
    reattachment. Every protocol that matters is handled by the kernel.
    """
    import subprocess

    tun, tun_name = open_utun()
    host_ip = ".".join(str(b) for b in net.host_ip)
    client_ip = ".".join(str(b) for b in net.client_ip)

    netmask = ".".join(str(b) for b in net.netmask)
    # Without an explicit netmask ifconfig defaults a 10.x utun to /8, which
    # makes the kernel treat all of 10.0.0.0/8 as on-link.
    subprocess.run(["ifconfig", tun_name, host_ip, client_ip,
                    "netmask", netmask, "up"], check=True)
    # ifconfig normally installs the point-to-point host route itself. An
    # unconditional `route add` printed "File exists" even when routing was
    # correct, and a stale route to an old utun could silently steal replies.
    current_route = route_interface(client_ip)
    if current_route != tun_name:
        subprocess.run(["route", "-q", "-n", "delete", "-host", client_ip],
                       capture_output=True, check=False)
        subprocess.run(["route", "-q", "-n", "add", "-host", client_ip,
                        "-interface", tun_name], check=True)
        current_route = route_interface(client_ip)
    if current_route != tun_name:
        tun.close()
        raise RuntimeError(f"route to {client_ip} uses {current_route or 'no interface'}, "
                           f"expected {tun_name}")

    anchor = "lwip-ce-bridge"
    rule = f"nat on {uplink} from {client_ip} to any -> ({uplink})\n"
    print(f"\ninterface : {tun_name}  {host_ip} -> {client_ip}")
    print(f"route     : {client_ip} via {current_route}")
    print(f"uplink    : {uplink}")
    print(f"pf rule   : {rule.strip()}")

    # IP forwarding must be on or the kernel drops anything not addressed to
    # itself, which looks exactly like a NAT failure.
    fwd = subprocess.run(["sysctl", "-n", "net.inet.ip.forwarding"],
                         capture_output=True, text=True).stdout.strip()
    if fwd != "1":
        subprocess.run(["sysctl", "-w", "net.inet.ip.forwarding=1"],
                       capture_output=True)
        print("forwarding: enabled (was off)")

    # An anchor alone does nothing unless the main ruleset references it, and
    # nothing at all unless pf is enabled. Both are easy to get silently
    # wrong: pfctl -a <anchor> -f succeeds against a disabled firewall.
    pf_was_enabled = "Status: Enabled" in subprocess.run(
        ["pfctl", "-s", "info"], capture_output=True, text=True).stdout

    pf_loaded = False
    try:
        main_rules = subprocess.run(
            ["pfctl", "-sn"], capture_output=True, text=True).stdout
        if anchor not in main_rules:
            # Load a minimal ruleset that includes our anchor. pf on macOS
            # ships with an empty nat ruleset, so this adds rather than
            # replaces anything the user had.
            combined = (f'nat-anchor "{anchor}"\n'
                        f'rdr-anchor "{anchor}"\n')
            subprocess.run(["pfctl", "-f", "-"], input=combined, text=True,
                           capture_output=True)

        subprocess.run(["pfctl", "-a", anchor, "-f", "-"],
                       input=rule, text=True, check=True, capture_output=True)

        en = subprocess.run(["pfctl", "-e"], capture_output=True, text=True)
        status = subprocess.run(["pfctl", "-s", "info"],
                                capture_output=True, text=True).stdout
        if "Status: Enabled" not in status:
            print(f"pf        : NOT ENABLED -- NAT will not happen "
                  f"({en.stderr.strip()})")
        else:
            pf_loaded = True
            print("pf        : enabled, NAT anchor loaded")
        # Show what pf thinks it has, so a silent mismatch is visible.
        shown = subprocess.run(["pfctl", "-a", anchor, "-s", "nat"],
                               capture_output=True, text=True).stdout.strip()
        print(f"pf rules  : {shown or '(none -- NAT is not active)'}\n")
    except subprocess.CalledProcessError as e:
        print(f"pf        : could not load NAT ({e.stderr.strip()})")
        print("            outbound traffic will not be translated\n")

    asm = LengthPrefixReassembler()
    start = time.time()
    last_tick = start
    tx = rx = 0
    if verbose:
        print("  out = calculator -> internet, in = internet -> calculator\n")
    try:
        while seconds <= 0 or time.time() - start < seconds:
            moved = False

            # calculator -> kernel
            try:
                chunk = os.read(fd, 4096)
            except BlockingIOError:
                chunk = b""
            if chunk:
                moved = True
                for frame in asm.feed(chunk):
                    et = (frame[12] << 8) | frame[13]
                    if crypto and (reply := crypto.handle(frame, net.host_mac)):
                        write_frame(fd, reply)
                        if verbose:
                            print("  <- " + describe_frame(frame))
                            print("  -> " + describe_frame(reply))
                        continue
                    reply = net.handle(frame)      # DHCP + ARP only now
                    if reply:
                        if verbose:
                            print("  <- " + describe_frame(frame))
                            print("  -> " + describe_frame(reply))
                        write_frame(fd, reply)
                        continue
                    if et == 0x0800:
                        if tls_dump:
                            describe_tls(frame, "calc->net", save_to=save_hello)
                        if watch:
                            watch.observe(frame, outbound=True)
                        wire_frame, old_mss = clamp_tcp_mss(frame)
                        if old_mss is not None:
                            print(f"     tcp MSS {old_mss} -> {ACM_SAFE_MSS} (ACM receive limit)")
                        utun_write(tun, wire_frame[14:])
                        tx += 1
                        if verbose:
                            print(f"  out {describe_frame(frame)}")
                    elif verbose:
                        # Not forwarded: utun is IPv4 here, and the control
                        # protocol is for the Wi-Fi bridge, not the network.
                        print(f"  --  {describe_frame(frame)}  (not forwarded)")

            # kernel -> calculator
            pkt = utun_read(tun)
            if pkt:
                moved = True
                dst_mac = net.leased_to or (b"\xff" * 6)
                frame = dst_mac + net.host_mac + b"\x08\x00" + pkt
                if tls_dump:
                    describe_tls(frame, "net->calc")
                if watch:
                    watch.observe(frame, outbound=False)
                write_frame(fd, frame)
                rx += 1
                if verbose:
                    print(f"  in  {describe_frame(frame)}")

            if not moved:
                time.sleep(0.005)

            # A silent terminal should still show whether anything is moving.
            if not verbose and time.time() - last_tick >= 2.0:
                last_tick = time.time()
                print(f"  out {tx}  in {rx}", end="\r", flush=True)
    except KeyboardInterrupt:
        print("\ninterrupted")
    finally:
        if pf_loaded:
            subprocess.run(["pfctl", "-a", anchor, "-F", "all"],
                           capture_output=True)
            if not pf_was_enabled:
                # Leave the firewall as we found it.
                subprocess.run(["pfctl", "-d"], capture_output=True)
                print("pf        : NAT anchor flushed, pf disabled again")
            else:
                print("pf        : NAT anchor flushed")
        tun.close()

    print(f"\nforwarded {tx} packets out, {rx} in")
    return 0


def cmd_listen(fd: int, seconds: float) -> int:
    asm = LengthPrefixReassembler()
    total = 0
    start = time.time()
    try:
        while time.time() - start < seconds:
            try:
                chunk = os.read(fd, 4096)
            except BlockingIOError:
                time.sleep(0.01)
                continue
            if not chunk:
                time.sleep(0.01)
                continue
            total += len(chunk)
            for frame in asm.feed(chunk):
                print("  " + describe_frame(frame))
    except KeyboardInterrupt:
        print("\ninterrupted")
    print(f"\nbytes {total}  frames {asm.frames}  "
          f"resync {asm.resync_bytes}  buffered {len(asm.buf)}")
    if asm.frames and not asm.resync_bytes:
        print("Clean: every byte accounted for.")
    elif asm.resync_bytes:
        print(f"{asm.resync_bytes} bytes needed resync -- reassembly imperfect "
              "on this traffic.")
    return 0


def cmd_serve(fd: int, seconds: float, net: MiniNet,
              crypto: "CryptoResponder | None" = None) -> int:
    asm = LengthPrefixReassembler()
    start = time.time()
    print(f"serving: host {'.'.join(str(b) for b in net.host_ip)}, "
          f"offering {'.'.join(str(b) for b in net.client_ip)}\n")
    try:
        while seconds <= 0 or time.time() - start < seconds:
            try:
                chunk = os.read(fd, 4096)
            except BlockingIOError:
                time.sleep(0.01)
                continue
            if not chunk:
                time.sleep(0.01)
                continue
            for frame in asm.feed(chunk):
                print("  rx " + describe_frame(frame))
                reply = crypto.handle(frame, net.host_mac) if crypto else None
                if reply is None:
                    reply = net.handle(frame)
                if reply:
                    write_frame(fd, reply)
                    print("  tx " + describe_frame(reply))
    except KeyboardInterrupt:
        print("\ninterrupted")
    if net.leased_to:
        print(f"\nLeased {'.'.join(str(b) for b in net.client_ip)} to "
              f"{mac_str(net.leased_to)} -- the link works end to end.")
    else:
        print("\nNo lease completed.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Bridge the calculator's CDC-ACM link to a real network.")
    ap.add_argument("--odevice", "--uplink", dest="odevice", metavar="IFACE",
                    help="outbound interface to NAT through "
                         "(default: whichever carries the host's default route)")
    ap.add_argument("--port",
                    help="serial port "
                         f"(default: auto-detect VID={VID:04X}:{PID:04X})")
    ap.add_argument("--seconds", type=float, default=0.0,
                    help="how long to run; 0 means until interrupted (default)")
    ap.add_argument("--once", action="store_true",
                    help="exit on disconnect instead of waiting for reconnect")
    ap.add_argument("--save-hello", metavar="PATH",
                    help="write the calculator's raw ClientHello record to PATH")
    ap.add_argument("--debug", action="store_true",
                    help="report how each connection ended and why (implies --tls)")
    ap.add_argument("--tls", action="store_true",
                    help="decode TLS records: ClientHello contents and server alerts")
    ap.add_argument("--quiet", action="store_true",
                    help="print only a periodic counter instead of every packet")
    ap.add_argument("--accelerate-crypto", action="store_true",
                    help="answer the calculator's crypto offload requests with "
                         "python3-cryptography")
    ap.add_argument("--host-ip", default="10.84.0.1")
    ap.add_argument("--client-ip", default="10.84.0.10")
    ap.add_argument("--dns", default=None, metavar="IP",
                    help="DNS server to advertise via DHCP (default 1.1.1.1)")
    ap.add_argument("--ntp", default=None, metavar="IP",
                    help="NTP server to advertise via DHCP (default 162.159.200.1)")
    args = ap.parse_args()

    try:
        crypto = CryptoResponder() if args.accelerate_crypto else None
    except ImportError as e:
        ap.error(f"--accelerate-crypto needs python3-cryptography: {e}")

    if platform.system() not in ("Darwin", "Linux"):
        print(f"unsupported platform: {platform.system()}", file=sys.stderr)
        return 2

    if os.geteuid() != 0:
        print("needs root (creates a utun interface and loads a pf NAT rule)\n"
              "Re-run with sudo.", file=sys.stderr)
        return 2

    candidates = active_uplinks()
    if not candidates:
        print("no active network interface found", file=sys.stderr)
        return 2
    uplink = args.odevice or candidates[0]
    if args.odevice and args.odevice not in candidates:
        print(f"warning: {args.odevice} not among active interfaces {candidates}",
              file=sys.stderr)
    elif not args.odevice and len(candidates) > 1:
        print(f"outbound : {uplink} (also available: "
              f"{', '.join(candidates[1:])}; pick with --odevice)")

    net = MiniNet(args.host_ip, args.client_ip, dns_ip=args.dns, ntp_ip=args.ntp)
    # The kernel handles ICMP and TCP once the utun is up.
    net.answer_icmp = net.answer_tcp = False

    try:
        while True:
            port = wait_for_calculator(args.port)
            fd = open_tty(port)
            print(f"port: {port}  (DTR asserted)")
            try:
                cmd_bridge(fd, net, uplink, args.seconds,
                           verbose=not args.quiet,
                           tls_dump=args.tls or args.debug,
                           watch=ConnectionWatch(trace=args.debug) if args.debug else None,
                           crypto=crypto)
            except BlockingIOError as e:
                print(f"\nbridge I/O would block: {e}", file=sys.stderr)
                return 2
            except OSError as e:
                print(f"\ndevice went away ({e.strerror}); waiting for it "
                      f"to come back")
            except SerialFrameWriteError as e:
                print(f"\nserial frame write failed: {e}", file=sys.stderr)
                return 2
            except MissingP256LengthHint as e:
                print(f"\n{e}", file=sys.stderr)
                return 2
            finally:
                try:
                    os.close(fd)
                except OSError:
                    pass
            if args.seconds > 0 or args.once:
                return 0
    except KeyboardInterrupt:
        print("\ninterrupted")
        return 0


if __name__ == "__main__":
    sys.exit(main())

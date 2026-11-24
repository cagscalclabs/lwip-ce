#!/usr/bin/env python3
"""Bridge lwIP-CE's length-prefixed CDC-ACM frames to the internet.

The calculator is the network client. This local program answers DHCP (and
the Wi-Fi bridge's crypto offload, if asked) and hands everything else to the
host kernel, which routes and NATs it out of the selected uplink.

macOS
    Talks to the calculator through the cu.usbmodem serial port, forwards
    IPv4 through a utun interface, answers ARP itself, and loads a PF NAT
    anchor. Needs root.

Linux
    Talks to the calculator directly over libusb (pyusb), detaching cdc_acm
    for the duration, and forwards ARP and IPv4 through a TAP interface, so
    the kernel does ARP as well. Needs pyusb. Two ways to run:

    * as root: creates a temporary TAP interface, enables IPv4 forwarding on
      it and the uplink, adds an nftables masquerade table, and (if firewalld
      is running) puts the interface in the trusted zone. All of it is undone
      on exit.
    * unprivileged: point --tap at a persistent TAP interface you own that
      is already addressed and NATed, and grant USB access with a udev rule.
      --print-setup prints the one-time root commands for that.
"""

from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager
import glob
import os
import platform
import re
import select
import socket
import struct
import subprocess
import sys
import termios
import time

VID, PID = 0x16C0, 0x05E1

ETH_HDR = 14
ETH_MAX = 1514
USB_MPS = 64     # bulk max packet size

# The Wi-Fi bridge's control protocol, from src/wireless/wifi_proto.h. The
# calculator sends these unprompted when it is looking for a bridge; the
# bridge answers the crypto operations (--accelerate-crypto) and ignores the
# rest.
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


def zlp_needed(length: int) -> bool:
    """True if a frame needs a terminating zero-length packet.

    A transfer that is an exact multiple of the max packet size is not
    self-terminating -- the receiver cannot tell it ended. The ESP32 firmware
    appends a pad byte instead; a ZLP is cleaner and the device takes either,
    since it reads whatever the transfer delivers.
    """
    return length % USB_MPS == 0


class LengthPrefixReassembler:
    """Recover frames from a 2-byte big-endian length-prefixed byte stream.

    Wire format: [len_hi][len_lo][payload...]. Works regardless of how the
    OS or USB stack chunks the bytes.
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
    """macOS: the serial port belonging to our VID/PID, or None.

    Matching on hardware identity rather than taking the first usbmodem*:
    other CDC devices create ports too, and writing Ethernet frames into
    somebody's modem would be rude. The IORegistry carries the
    idVendor/idProduct next to the port name.
    """
    import subprocess
    try:
        out = subprocess.run(
            ["ioreg", "-r", "-c", "IOUSBHostDevice", "-l"],
            capture_output=True, text=True, timeout=10).stdout
    except Exception:
        out = ""
    # Walk the device's subtree: the dialin device appears under the
    # ACM data interface, after the matching idVendor/idProduct.
    want_v = f'"idVendor" = {VID}'
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


def find_calculator_usb():
    """Linux: the calculator's pyusb device, or None if not attached."""
    import usb.core
    return usb.core.find(idVendor=VID, idProduct=PID)


def wait_for(finder, what: str, quiet: bool = False):
    """Block until finder() returns something, then return it.

    The bridge should be startable before the calculator is plugged in or
    lwIP is launched, and should survive a replug -- the device disappears
    and comes back whenever lwIP restarts.
    """
    announced = False
    while True:
        found = finder()
        if found:
            if announced:
                print(" " * 60, end="\r")
            return found
        if not announced and not quiet:
            print(f"waiting for {what} ...", end="\r", flush=True)
            announced = True
        time.sleep(0.5)


def wait_for_calculator(port: str | None, quiet: bool = False) -> str:
    """macOS: block until the calculator's serial port exists."""
    if port:
        return wait_for(lambda: port if os.path.exists(port) else None,
                        port, quiet)
    return wait_for(find_calculator_tty,
                    f"the calculator ({VID:04X}:{PID:04X})", quiet)


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


def frame_wire(frame: bytes) -> bytes:
    """A frame as it goes on the wire: 2-byte big-endian length prefix, and a
    pad byte if the total would be an exact MPS multiple (see zlp_needed)."""
    n = len(frame)
    wire = bytes([n >> 8, n & 0xFF]) + frame
    if zlp_needed(len(wire)):
        wire += b"\x00"
    return wire


def write_frame(fd: int, frame: bytes) -> None:
    """Send a whole frame and drain it before queuing the next frame."""
    wire = frame_wire(frame)
    n = len(frame)

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


class TtyLink:
    """macOS: the calculator's CDC-ACM serial port."""

    def __init__(self, port: str) -> None:
        self.name = port
        self.fd = open_tty(port)

    def read(self) -> bytes:
        """Whatever bytes are waiting, without blocking."""
        try:
            return os.read(self.fd, 4096)
        except BlockingIOError:
            return b""

    def write_frame(self, frame: bytes) -> None:
        write_frame(self.fd, frame)

    def close(self) -> None:
        try:
            os.close(self.fd)
        except OSError:
            pass


class UsbLink:
    """Linux: the calculator's CDC-ACM interfaces, driven over libusb.

    Going around the tty keeps cdc_acm's line discipline, buffering and
    write splitting out of the path entirely; the bridge sees the same
    length-prefixed byte stream either way, so the framing code is shared.

    Reads run on a thread with a short timeout and land in a queue, so the
    bridge loop can poll without blocking. A timed-out bulk read does not
    lose data: pyusb (1.2+) returns what libusb transferred before the
    timeout instead of raising.
    """

    COMM_CLASS, DATA_CLASS = 0x02, 0x0A
    SET_CONTROL_LINE_STATE = 0x22
    DTR = 0x0001

    def __init__(self, dev) -> None:
        import queue
        import threading
        import usb.core
        import usb.util

        self.usb = usb
        self.dev = dev
        self.name = (f"usb {dev.bus:03d}:{dev.address:03d} "
                     f"({VID:04X}:{PID:04X})")
        self.detached: list[int] = []
        self.claimed: list[int] = []
        self.queue: queue.Queue = queue.Queue()
        self.error: BaseException | None = None
        self.closing = False

        try:
            cfg = dev.get_active_configuration()
        except usb.core.USBError:
            dev.set_configuration()
            cfg = dev.get_active_configuration()

        comm = data = None
        for intf in cfg:
            if intf.bAlternateSetting:
                continue
            if intf.bInterfaceClass == self.COMM_CLASS and comm is None:
                comm = intf
            elif intf.bInterfaceClass == self.DATA_CLASS and data is None:
                data = intf
        if comm is None or data is None:
            raise RuntimeError("calculator does not expose CDC-ACM "
                               "communication and data interfaces")

        def bulk(direction):
            return usb.util.find_descriptor(
                data, custom_match=lambda e:
                usb.util.endpoint_direction(e.bEndpointAddress) == direction
                and usb.util.endpoint_type(e.bmAttributes)
                == usb.util.ENDPOINT_TYPE_BULK)

        self.ep_in = bulk(usb.util.ENDPOINT_IN)
        self.ep_out = bulk(usb.util.ENDPOINT_OUT)
        if self.ep_in is None or self.ep_out is None:
            raise RuntimeError("calculator's CDC data interface has no "
                               "bulk endpoint pair")

        try:
            # cdc_acm owns both interfaces; take them for the session and
            # hand them back in close() so /dev/ttyACM* returns afterwards.
            for n in (comm.bInterfaceNumber, data.bInterfaceNumber):
                if dev.is_kernel_driver_active(n):
                    dev.detach_kernel_driver(n)
                    self.detached.append(n)
                usb.util.claim_interface(dev, n)
                self.claimed.append(n)
            # DTR raises the calculator's netif link (device_apply_dtr).
            dev.ctrl_transfer(0x21, self.SET_CONTROL_LINE_STATE, self.DTR,
                              comm.bInterfaceNumber, None, timeout=1000)
        except BaseException:
            self.close()
            raise

        self.thread = threading.Thread(target=self._reader, daemon=True,
                                       name="usb-reader")
        self.thread.start()

    def _reader(self) -> None:
        size = self.ep_in.wMaxPacketSize * 32
        while not self.closing:
            try:
                data = self.ep_in.read(size, timeout=200)
            except self.usb.core.USBTimeoutError:
                continue
            except BaseException as e:
                if not self.closing:
                    self.queue.put(e)
                return
            if data:
                self.queue.put(bytes(data))

    def read(self) -> bytes:
        """Whatever bytes the reader thread has collected, without blocking.

        A reader failure (normally the device going away) is raised as the
        OSError pyusb reported, after any bytes that arrived before it.
        """
        import queue

        if self.error is not None:
            raise self.error
        chunks = []
        while True:
            try:
                item = self.queue.get_nowait()
            except queue.Empty:
                break
            if isinstance(item, BaseException):
                self.error = item
                break
            chunks.append(item)
        if not chunks and self.error is not None:
            raise self.error
        return b"".join(chunks)

    STALL_LIMIT = 30.0          # seconds with no bytes accepted

    def write_frame(self, frame: bytes) -> None:
        """Send a whole frame, waiting out the calculator's busy spells.

        The calculator only takes OUT packets while its software services
        the USB controller, so it NAKs for as long as it is busy elsewhere
        (a TLS handshake's crypto takes seconds). That is flow control, not
        failure: a timed-out write reports the bytes that did go through, and
        the rest follows as another transfer -- the device reassembles from
        the length prefix, not from transfer boundaries. This matches the
        macOS path, where tcdrain() waits for as long as it takes.

        The remainder can never be an exact MPS multiple (frame_wire avoids
        that for the whole, and a partial write is whole packets), so every
        transfer still ends in a short packet.
        """
        wire = frame_wire(frame)
        sent = 0
        last_progress = time.monotonic()
        while sent < len(wire):
            try:
                n = self.ep_out.write(wire[sent:], timeout=1000)
            except self.usb.core.USBTimeoutError:
                n = 0                    # timed out before any byte went out
            if n:
                sent += n
                last_progress = time.monotonic()
            elif time.monotonic() - last_progress > self.STALL_LIMIT:
                raise SerialFrameWriteError(
                    f"calculator accepted no data for {self.STALL_LIMIT:.0f}s "
                    f"({sent}/{len(wire)} bytes of a {len(frame)}-byte frame "
                    "sent); it is likely hung")

    def close(self) -> None:
        self.closing = True
        thread = getattr(self, "thread", None)
        if thread is not None:
            thread.join(timeout=1.0)
        for n in self.claimed:
            try:
                self.usb.util.release_interface(self.dev, n)
            except Exception:
                pass
        for n in self.detached:
            try:
                self.dev.attach_kernel_driver(n)
            except Exception:
                pass
        self.claimed.clear()
        self.detached.clear()
        try:
            self.usb.util.dispose_resources(self.dev)
        except Exception:
            pass


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

    Deliberately minimal: one lease, no renewal bookkeeping, no relaying.
    Everything past getting an address is the host kernel's job.
    """

    def __init__(self, host_ip="10.84.0.1", client_ip="10.84.0.10",
                 netmask="255.255.255.0", dns_ip=None, ntp_ip=None):
        self.host_ip = bytes(int(x) for x in host_ip.split("."))
        self.client_ip = bytes(int(x) for x in client_ip.split("."))
        self.netmask = bytes(int(x) for x in netmask.split("."))
        # Defaults are public servers so the bridge works out of the box.
        self.dns_ip = bytes(int(x) for x in (dns_ip or "1.1.1.1").split("."))
        self.ntp_ip = bytes(int(x) for x in (ntp_ip or "162.159.200.1").split("."))
        self.host_mac = bytes.fromhex("02cece000001")
        self.leased_to: bytes | None = None
        # On Linux the TAP interface is Ethernet, so the kernel answers ARP
        # for its own address; answering here too would be redundant.
        self.answer_arp = True

    def handle(self, f: bytes) -> bytes | None:
        et = (f[12] << 8) | f[13]
        if et == 0x0806:
            return self._arp(f) if self.answer_arp else None
        if et != 0x0800 or len(f) < 34:
            return None
        proto = f[23]
        if proto == 17 and len(f) >= 42:
            dport = (f[36] << 8) | f[37]
            if dport == 67:
                return self._dhcp(f)
        return None

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
    --odevice has something meaningful to choose from. Loopback, the
    interface we create, and virtual bridges are skipped.
    """
    if platform.system() == "Linux":
        return TapHost.uplinks()
    return macos_uplinks()


def macos_uplinks() -> list[str]:
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


@contextmanager
def temporary_ipv4_forwarding():
    """Enable forwarding for a bridge run, then restore its prior value."""
    import subprocess

    original = subprocess.run(
        ["sysctl", "-n", "net.inet.ip.forwarding"], check=True,
        capture_output=True, text=True).stdout.strip()
    if original not in ("0", "1"):
        raise RuntimeError(f"unexpected net.inet.ip.forwarding value: {original!r}")

    changed = original == "0"
    try:
        if changed:
            subprocess.run(["sysctl", "-w", "net.inet.ip.forwarding=1"],
                           check=True, capture_output=True, text=True)
            print("forwarding: enabled for this bridge run")
        yield
    finally:
        if changed:
            subprocess.run(["sysctl", "-w", "net.inet.ip.forwarding=0"],
                           check=True, capture_output=True, text=True)
            print("forwarding: restored to 0")


def select_pf_nat_anchor(main_rules: str) -> str:
    """Use an existing NAT anchor point without replacing the main ruleset."""
    anchors = [line.strip() for line in main_rules.splitlines()
               if line.strip().startswith("nat-anchor ")]
    if any('"com.apple/*"' in line for line in anchors):
        return "com.apple/lwip-ce-bridge"
    if any('"lwip-ce-bridge"' in line for line in anchors):
        return "lwip-ce-bridge"  # main rules left by an older bridge run
    raise RuntimeError("PF has no usable NAT anchor; refusing to replace "
                       "the main PF ruleset. Load a ruleset with "
                       "nat-anchor \"com.apple/*\" before starting the bridge")


def pf_enable_token(output: str) -> str:
    match = re.search(r"\bToken\s*:\s*(\d+)\b", output)
    if not match:
        raise RuntimeError(f"pfctl -E did not return an enable token: {output.strip()}")
    return match.group(1)


class UtunHost:
    """macOS: the calculator's IPv4 goes through a utun and PF NAT.

    The bridge itself does almost nothing: DHCP and ARP (the kernel will not
    serve those on a point-to-point utun), plus Ethernet header removal and
    reattachment. Every protocol that matters is handled by the kernel.
    """

    forwards = (0x0800,)        # utun is layer 3, IPv4 only here

    def __init__(self, net: "MiniNet", uplink: str) -> None:
        self.net = net
        self.uplink = uplink
        self.stack = ExitStack()

    def __enter__(self) -> "UtunHost":
        try:
            self.stack.enter_context(temporary_ipv4_forwarding())
            self._setup()
        except BaseException:
            self.stack.close()
            raise
        return self

    def __exit__(self, *exc) -> None:
        self.stack.close()

    def _setup(self) -> None:
        import subprocess

        net, uplink = self.net, self.uplink
        main_rules = subprocess.run(["pfctl", "-sn"], check=True,
                                    capture_output=True, text=True).stdout
        anchor = select_pf_nat_anchor(main_rules)
        self.tun, tun_name = open_utun()
        self.stack.callback(self.tun.close)
        host_ip = ".".join(str(b) for b in net.host_ip)
        client_ip = ".".join(str(b) for b in net.client_ip)

        netmask = ".".join(str(b) for b in net.netmask)
        # Without an explicit netmask ifconfig defaults a 10.x utun to /8,
        # which makes the kernel treat all of 10.0.0.0/8 as on-link.
        subprocess.run(["ifconfig", tun_name, host_ip, client_ip,
                        "netmask", netmask, "up"], check=True)
        # ifconfig normally installs the point-to-point host route itself.
        # An unconditional `route add` printed "File exists" even when
        # routing was correct, and a stale route to an old utun could
        # silently steal replies.
        current_route = route_interface(client_ip)
        if current_route != tun_name:
            subprocess.run(["route", "-q", "-n", "delete", "-host", client_ip],
                           capture_output=True, check=False)
            subprocess.run(["route", "-q", "-n", "add", "-host", client_ip,
                            "-interface", tun_name], check=True)
            current_route = route_interface(client_ip)
        if current_route != tun_name:
            raise RuntimeError(f"route to {client_ip} uses "
                               f"{current_route or 'no interface'}, "
                               f"expected {tun_name}")

        rule = f"nat on {uplink} from {client_ip} to any -> ({uplink})\n"
        print(f"\ninterface : {tun_name}  {host_ip} -> {client_ip}")
        print(f"route     : {client_ip} via {current_route}")
        print(f"uplink    : {uplink}")
        print(f"pf rule   : {rule.strip()}")

        # The anchor needs an active NAT anchor point and a PF enable
        # reference. -E/-X avoids globally disabling PF if another service
        # starts using it.
        subprocess.run(["pfctl", "-a", anchor, "-f", "-"],
                       input=rule, text=True, check=True, capture_output=True)

        def flush_anchor():
            subprocess.run(["pfctl", "-a", anchor, "-F", "all"],
                           capture_output=True)
            print("pf        : NAT anchor flushed")
        self.stack.callback(flush_anchor)

        en = subprocess.run(["pfctl", "-E"], check=True,
                            capture_output=True, text=True)
        pf_token = pf_enable_token(en.stdout + en.stderr)

        def release_pf():
            subprocess.run(["pfctl", "-X", pf_token], capture_output=True)
            print("pf        : enable reference released")
        self.stack.callback(release_pf)

        status = subprocess.run(["pfctl", "-s", "info"],
                                check=True, capture_output=True, text=True).stdout
        if "Status: Enabled" not in status:
            raise RuntimeError("PF did not enable after pfctl -E")
        print(f"pf        : enabled, NAT anchor {anchor} loaded")
        # Show what pf thinks it has, so a silent mismatch is visible.
        shown = subprocess.run(["pfctl", "-a", anchor, "-s", "nat"],
                               check=True, capture_output=True, text=True).stdout.strip()
        print(f"pf rules  : {shown or '(none -- NAT is not active)'}\n")

    def send(self, frame: bytes) -> None:
        utun_write(self.tun, frame[14:])

    def recv(self) -> bytes | None:
        pkt = utun_read(self.tun)
        if not pkt:
            return None
        dst_mac = self.net.leased_to or (b"\xff" * 6)
        return dst_mac + self.net.host_mac + b"\x08\x00" + pkt


# -- Linux ------------------------------------------------------------------

TAP_PREFIX = "lwipce"
NFT_TABLE = "lwip_ce_bridge"


def netmask_prefix(mask: bytes) -> int:
    return bin(int.from_bytes(mask, "big")).count("1")


class TapHost:
    """Linux: the calculator's Ethernet frames go through a TAP interface.

    Two modes:

    * created (needs root): a fresh TAP is addressed, IPv6 is disabled on it
      (nothing NATs v6, and the kernel's multicast chatter would only cost
      USB bandwidth), IPv4 forwarding is enabled on it and on the uplink,
      an nftables table masquerades the calculator's address out of the
      uplink, and firewalld (if running) gets the TAP in its trusted zone so
      its forward chain does not reject the traffic. Each step is undone on
      exit, in reverse.
    * preconfigured: --tap names an interface that already exists (typically
      a persistent TAP owned by the user, see --print-setup). Nothing on the
      host is changed; the bridge only checks the address and adopts the
      interface's MAC for its DHCP replies.
    """

    forwards = (0x0800, 0x0806)

    def __init__(self, net: "MiniNet", uplink: str | None,
                 name: str | None = None) -> None:
        self.net = net
        self.uplink = uplink
        self.name = name
        self.stack = ExitStack()
        self.fd = -1

    SKIP_UPLINKS = ("lo", "lwipce", "docker", "veth", "virbr", "br-")

    @staticmethod
    def interface_ipv4(name: str) -> str | None:
        """Linux: the IPv4 address on an interface (SIOCGIFADDR), or None."""
        import fcntl

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            try:
                res = fcntl.ioctl(s, 0x8915, struct.pack("256s", name.encode()[:15]))
            except OSError:
                return None
        return socket.inet_ntoa(res[20:24])

    @staticmethod
    def uplinks() -> list[str]:
        """Default-route interfaces by metric, then others with IPv4."""
        found: list[str] = []
        # Default routes, lowest metric first.
        defaults = []
        try:
            with open("/proc/net/route") as fh:
                next(fh)
                for line in fh:
                    f = line.split()
                    if (len(f) >= 8 and f[1] == "00000000" and f[7] == "00000000"
                            and int(f[3], 16) & 1):          # RTF_UP
                        defaults.append((int(f[6]), f[0]))
        except OSError:
            pass
        for _, name in sorted(defaults):
            if name not in found:
                found.append(name)
        for _, name in socket.if_nameindex():
            if (name not in found and not name.startswith(TapHost.SKIP_UPLINKS)
                    and TapHost.interface_ipv4(name)):
                found.append(name)
        return found

    @staticmethod
    def open_tap(name: str) -> tuple[int, str]:
        """Open (creating if root and absent) a TAP interface; return (fd, name).

        TAP rather than TUN: Linux has it, it carries Ethernet, and the
        calculator speaks Ethernet -- so frames pass through untouched and the
        kernel does ARP on its side like on any LAN. A non-persistent TAP
        created here disappears, with its address and routes, when the fd
        closes, which makes cleanup after a crash automatic.
        """
        import fcntl

        TUNSETIFF = 0x400454CA
        IFF_TAP, IFF_NO_PI = 0x0002, 0x1000
        fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
        try:
            ifr = struct.pack("16sH22x", name.encode(), IFF_TAP | IFF_NO_PI)
            res = fcntl.ioctl(fd, TUNSETIFF, ifr)
        except BaseException:
            os.close(fd)
            raise
        return fd, res[:16].split(b"\x00")[0].decode()

    @staticmethod
    def route_interface(destination: str) -> str | None:
        import subprocess

        out = subprocess.run(["ip", "-o", "-4", "route", "get", destination],
                             capture_output=True, text=True).stdout
        m = re.search(r"\bdev (\S+)", out)
        return m.group(1) if m else None

    @staticmethod
    def write_sysctl(path: str, value: str) -> str:
        """Write a /proc/sys value and return the one it replaced."""
        with open(path) as fh:
            old = fh.read().strip()
        with open(path, "w") as fh:
            fh.write(value)
        return old

    @staticmethod
    def firewalld_running() -> bool:
        import shutil
        import subprocess

        if not shutil.which("firewall-cmd"):
            return False
        return subprocess.run(["firewall-cmd", "--state"],
                              capture_output=True).returncode == 0

    @staticmethod
    def print_setup(args, uplink: str | None) -> None:
        """The one-time root commands for running the bridge unprivileged."""
        import getpass

        tap = args.tap or f"{TAP_PREFIX}0"
        up = uplink or "UPLINK"
        prefix = netmask_prefix(MiniNet().netmask)
        import textwrap

        print(textwrap.dedent(f"""\
    # One-time setup, as root, so the bridge can run as {getpass.getuser()}.
    # The network part lasts until reboot; the udev rule is permanent.

    ip tuntap add dev {tap} mode tap user {getpass.getuser()}
    ip link set dev {tap} address 02:ce:ce:00:00:01
    sysctl -w net.ipv6.conf.{tap}.disable_ipv6=1
    ip addr add {args.host_ip}/{prefix} dev {tap}
    ip link set dev {tap} up
    sysctl -w net.ipv4.conf.{tap}.forwarding=1 net.ipv4.conf.{up}.forwarding=1
    nft add table ip {NFT_TABLE}
    nft 'add chain ip {NFT_TABLE} postrouting {{ type nat hook postrouting priority srcnat; }}'
    nft add rule ip {NFT_TABLE} postrouting ip saddr {args.client_ip} oifname '"{up}"' masquerade
    firewall-cmd --zone=trusted --add-interface={tap}     # only if firewalld runs

    # USB access for the logged-in user (also lets the bridge detach cdc_acm):
    echo 'SUBSYSTEM=="usb", ATTR{{idVendor}}=="{VID:04x}", ATTR{{idProduct}}=="{PID:04x}", TAG+="uaccess"' \\
        > /etc/udev/rules.d/70-lwip-ce.rules
    udevadm control --reload && udevadm trigger

    # Then, unprivileged:
    #   python3 {sys.argv[0]} --tap {tap}
    #
    # To undo the network part:
    #   nft delete table ip {NFT_TABLE}; ip link delete {tap}"""))


    def __enter__(self) -> "TapHost":
        try:
            if self.name and os.path.exists(f"/sys/class/net/{self.name}"):
                self._attach_existing()
            else:
                self._create()
        except BaseException:
            self.stack.close()
            raise
        return self

    def __exit__(self, *exc) -> None:
        self.stack.close()

    def _open(self, name: str) -> None:
        try:
            self.fd, self.name = self.open_tap(name)
        except PermissionError:
            raise RuntimeError(
                f"cannot attach to TAP interface {name}: it is not owned by "
                "this user. Recreate it with `ip tuntap add ... user "
                f"{os.environ.get('USER', '$USER')}` (see --print-setup) "
                "or run as root.") from None
        except FileNotFoundError:
            raise RuntimeError("/dev/net/tun is missing; load the tun "
                               "module (modprobe tun)") from None
        fd = self.fd
        self.stack.callback(lambda: os.close(fd))

    def _attach_existing(self) -> None:
        self._open(self.name)
        sysfs = f"/sys/class/net/{self.name}"
        with open(f"{sysfs}/address") as fh:
            self.net.host_mac = bytes.fromhex(fh.read().strip().replace(":", ""))
        host_ip = ".".join(str(b) for b in self.net.host_ip)
        have = self.interface_ipv4(self.name)
        print(f"\ninterface : {self.name} (preconfigured; host left unchanged)")
        print(f"address   : {have or 'none'}  mac {mac_str(self.net.host_mac)}")
        if have != host_ip:
            print(f"warning   : {self.name} has {have or 'no IPv4 address'}, "
                  f"but DHCP will name {host_ip} as the router; pass "
                  f"--host-ip {have} or fix the interface", file=sys.stderr)
        with open(f"{sysfs}/flags") as fh:
            if not int(fh.read(), 16) & 0x1:                # IFF_UP
                print(f"warning   : {self.name} is down "
                      f"(ip link set dev {self.name} up)", file=sys.stderr)
        print()

    def _create(self) -> None:
        import shutil
        import subprocess

        if os.geteuid() != 0:
            hint = (f"{self.name} does not exist; " if self.name else "")
            raise RuntimeError(
                f"{hint}creating and configuring a TAP interface needs root. "
                "Re-run with sudo, or set up a persistent interface once "
                "(--print-setup) and pass it with --tap.")
        for tool in ("ip", "nft"):
            if not shutil.which(tool):
                raise RuntimeError(f"`{tool}` not found; install "
                                   f"{'iproute' if tool == 'ip' else 'nftables'}")
        if not self.uplink:
            raise RuntimeError("no outbound interface found; pass --odevice")

        def run(*cmd: str) -> None:
            subprocess.run(cmd, check=True, capture_output=True, text=True)

        net, uplink = self.net, self.uplink
        self._open(self.name or f"{TAP_PREFIX}%d")
        tap = self.name
        host_ip = ".".join(str(b) for b in net.host_ip)
        client_ip = ".".join(str(b) for b in net.client_ip)
        prefix = netmask_prefix(net.netmask)

        run("ip", "link", "set", "dev", tap, "address", mac_str(net.host_mac))
        try:
            self.write_sysctl(f"/proc/sys/net/ipv6/conf/{tap}/disable_ipv6", "1")
        except OSError:
            pass                             # IPv6 not built in: nothing to do
        run("ip", "addr", "add", f"{host_ip}/{prefix}", "dev", tap)
        run("ip", "link", "set", "dev", tap, "up")
        current_route = self.route_interface(client_ip)
        if current_route != tap:
            raise RuntimeError(f"route to {client_ip} uses "
                               f"{current_route or 'no interface'}, expected "
                               f"{tap}; is {host_ip}/{prefix} already in use "
                               "on another interface?")

        # Per-interface forwarding rather than the global ip_forward switch:
        # Linux decides on the ingress interface, so these two are all the
        # path needs, and nothing else on the host starts routing.
        self.write_sysctl(f"/proc/sys/net/ipv4/conf/{tap}/forwarding", "1")
        up_path = f"/proc/sys/net/ipv4/conf/{uplink}/forwarding"
        old = self.write_sysctl(up_path, "1")
        if old != "1":
            def restore_forwarding():
                self.write_sysctl(up_path, old)
                print(f"forwarding: restored to {old} on {uplink}")
            self.stack.callback(restore_forwarding)
            print(f"forwarding: enabled on {uplink} for this bridge run")

        rule = (f"ip saddr {client_ip} oifname \"{uplink}\" masquerade")
        ruleset = (f"table ip {NFT_TABLE} {{\n"
                   f"  chain postrouting {{\n"
                   f"    type nat hook postrouting priority srcnat; policy accept;\n"
                   f"    {rule}\n"
                   f"  }}\n"
                   f"}}\n")
        # A table left by a run that was killed would make `add` merge into
        # it; replace it instead.
        subprocess.run(["nft", "delete", "table", "ip", NFT_TABLE],
                       capture_output=True)
        subprocess.run(["nft", "-f", "-"], input=ruleset, text=True,
                       check=True, capture_output=True)

        def drop_table():
            subprocess.run(["nft", "delete", "table", "ip", NFT_TABLE],
                           capture_output=True)
            print(f"nft       : table {NFT_TABLE} removed")
        self.stack.callback(drop_table)

        print(f"\ninterface : {tap}  {host_ip}/{prefix}  mac {mac_str(net.host_mac)}")
        print(f"route     : {client_ip} via {current_route}")
        print(f"uplink    : {uplink}")
        print(f"nft rule  : {rule}")

        if self.firewalld_running():
            run("firewall-cmd", "--zone=trusted", f"--add-interface={tap}")

            def leave_zone():
                subprocess.run(["firewall-cmd", "--zone=trusted",
                                f"--remove-interface={tap}"],
                               capture_output=True)
                print(f"firewalld : {tap} removed from the trusted zone")
            self.stack.callback(leave_zone)
            print(f"firewalld : {tap} in the trusted zone (runtime only)")
        else:
            # Without firewalld, a drop policy on some other forward chain
            # (Docker installs one) still discards the traffic, and an accept
            # here cannot override it.
            rules = subprocess.run(["nft", "list", "ruleset"],
                                   capture_output=True, text=True).stdout
            if re.search(r"hook forward[^\n]*policy drop", rules):
                print("warning   : a forward chain has policy drop; the "
                      "calculator's traffic may be discarded unless that "
                      f"chain accepts {tap} -> {uplink}", file=sys.stderr)
        print()

    def send(self, frame: bytes) -> None:
        os.write(self.fd, frame)

    def recv(self) -> bytes | None:
        try:
            frame = os.read(self.fd, ETH_MAX + 4)
        except BlockingIOError:
            return None
        if len(frame) < ETH_HDR:
            return None
        # Only what the calculator needs: frames addressed to it, and
        # broadcasts (the kernel's ARP requests). Multicast such as mDNS
        # would just use up the USB link.
        if frame[0] & 1 and frame[0:6] != b"\xff" * 6:
            return None
        if ((frame[12] << 8) | frame[13]) not in self.forwards:
            return None
        return frame


# -- the bridge loop ---------------------------------------------------------

def run_bridge(link, net: "MiniNet", host, seconds: float,
               verbose: bool = True, tls_dump: bool = False,
               watch: "ConnectionWatch | None" = None,
               crypto: "CryptoResponder | None" = None,
               save_hello: str | None = None) -> int:
    """Move frames between the calculator and the host network.

    host is a UtunHost or TapHost already entered; it decides which
    EtherTypes go to the kernel and how frames come back.
    """
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
            chunk = link.read()
            if chunk:
                moved = True
                for frame in asm.feed(chunk):
                    et = (frame[12] << 8) | frame[13]
                    if crypto and (reply := crypto.handle(frame, net.host_mac)):
                        link.write_frame(reply)
                        if verbose:
                            print("  <- " + describe_frame(frame))
                            print("  -> " + describe_frame(reply))
                        continue
                    reply = net.handle(frame)      # DHCP (+ ARP on macOS)
                    if reply:
                        if verbose:
                            print("  <- " + describe_frame(frame))
                            print("  -> " + describe_frame(reply))
                        link.write_frame(reply)
                        continue
                    if et in host.forwards:
                        if et == 0x0800:
                            if tls_dump:
                                describe_tls(frame, "calc->net", save_to=save_hello)
                            if watch:
                                watch.observe(frame, outbound=True)
                            frame, old_mss = clamp_tcp_mss(frame)
                            if old_mss is not None:
                                print(f"     tcp MSS {old_mss} -> {ACM_SAFE_MSS} "
                                      "(ACM receive limit)")
                        host.send(frame)
                        tx += 1
                        if verbose:
                            print(f"  out {describe_frame(frame)}")
                    elif verbose:
                        # Not forwarded: only IPv4 is NATed, and the control
                        # protocol is for the Wi-Fi bridge, not the network.
                        print(f"  --  {describe_frame(frame)}  (not forwarded)")

            # kernel -> calculator
            frame = host.recv()
            if frame:
                moved = True
                if frame[12:14] == b"\x08\x00":
                    if tls_dump:
                        describe_tls(frame, "net->calc")
                    if watch:
                        watch.observe(frame, outbound=False)
                link.write_frame(frame)
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

    print(f"\nforwarded {tx} packets out, {rx} in")
    return 0


def open_link(args, system: str):
    """Wait for the calculator, then open it the platform's way."""
    if system == "Darwin":
        port = wait_for_calculator(args.port, quiet=args.quiet)
        link = TtyLink(port)
        print(f"port: {port}  (DTR asserted)")
        return link
    import usb.core

    dev = wait_for(find_calculator_usb,
                   f"the calculator ({VID:04X}:{PID:04X})", args.quiet)
    try:
        link = UsbLink(dev)
    except usb.core.USBError as e:
        if e.errno == 13:                                  # EACCES
            raise RuntimeError(
                "no permission to open the calculator's USB device; run as "
                "root, or install the udev rule from --print-setup") from None
        raise
    print(f"device: {link.name}  (DTR asserted)")
    return link


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Bridge the calculator's CDC-ACM link to a real network.")
    ap.add_argument("--odevice", "--uplink", dest="odevice", metavar="IFACE",
                    help="outbound interface to NAT through "
                         "(default: whichever carries the host's default route)")
    ap.add_argument("--port",
                    help="macOS: serial port "
                         f"(default: auto-detect VID={VID:04X}:{PID:04X})")
    ap.add_argument("--tap", metavar="IFACE",
                    help="Linux: TAP interface to use. If it exists it is "
                         "used as configured (no root needed if you own it); "
                         f"otherwise it is created (default name {TAP_PREFIX}N)")
    ap.add_argument("--print-setup", action="store_true",
                    help="Linux: print the one-time root commands for "
                         "running unprivileged, then exit")
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

    system = platform.system()
    if system not in ("Darwin", "Linux"):
        print("this bridge supports macOS (utun + PF) and Linux "
              "(libusb + TAP + nftables)", file=sys.stderr)
        return 2
    if system == "Darwin" and (args.tap or args.print_setup):
        ap.error("--tap and --print-setup are for Linux")
    if system == "Linux" and args.port:
        ap.error("--port is for macOS; on Linux the calculator is opened "
                 "over libusb")

    candidates = active_uplinks()
    if args.print_setup:
        TapHost.print_setup(args, args.odevice or (candidates[0] if candidates else None))
        return 0

    try:
        crypto = CryptoResponder() if args.accelerate_crypto else None
    except ImportError as e:
        ap.error(f"--accelerate-crypto needs python3-cryptography: {e}")

    if system == "Darwin" and os.geteuid() != 0:
        print("needs root (creates a utun interface and loads a pf NAT rule)\n"
              "Re-run with sudo.", file=sys.stderr)
        return 2
    if system == "Linux":
        try:
            import usb.core
            import usb.backend.libusb1
        except ImportError:
            print("needs pyusb: dnf install python3-pyusb "
                  "(or pip install pyusb)", file=sys.stderr)
            return 2
        if usb.backend.libusb1.get_backend() is None:
            print("pyusb cannot find libusb-1.0: dnf install libusb1",
                  file=sys.stderr)
            return 2

    preconfigured = (system == "Linux" and args.tap
                     and os.path.exists(f"/sys/class/net/{args.tap}"))
    uplink = args.odevice or (candidates[0] if candidates else None)
    if not uplink and not preconfigured:
        print("no active network interface found", file=sys.stderr)
        return 2
    if not preconfigured:
        if args.odevice and args.odevice not in candidates:
            print(f"warning: {args.odevice} not among active interfaces "
                  f"{candidates}", file=sys.stderr)
        elif not args.odevice and len(candidates) > 1:
            print(f"outbound : {uplink} (also available: "
                  f"{', '.join(candidates[1:])}; pick with --odevice)")

    net = MiniNet(args.host_ip, args.client_ip, dns_ip=args.dns, ntp_ip=args.ntp)
    # On Linux the kernel also answers ARP, since the TAP interface is
    # Ethernet.
    if system == "Linux":
        net.answer_arp = False

    try:
        while True:
            try:
                link = open_link(args, system)
            except RuntimeError as e:
                print(f"\n{e}", file=sys.stderr)
                return 2
            try:
                host = (UtunHost(net, uplink) if system == "Darwin"
                        else TapHost(net, uplink, args.tap))
                with host:
                    run_bridge(link, net, host, args.seconds,
                               verbose=not args.quiet,
                               tls_dump=args.tls or args.debug or bool(args.save_hello),
                               watch=ConnectionWatch(trace=args.debug) if args.debug else None,
                               crypto=crypto, save_hello=args.save_hello)
            except RuntimeError as e:
                print(f"\n{e}", file=sys.stderr)
                return 2
            except subprocess.CalledProcessError as e:
                detail = (e.stderr or "").strip()
                print(f"\n`{' '.join(e.cmd)}` failed (exit {e.returncode})"
                      f"{': ' + detail if detail else ''}", file=sys.stderr)
                return 2
            except BlockingIOError as e:
                print(f"\nbridge I/O would block: {e}", file=sys.stderr)
                return 2
            except OSError as e:
                print(f"\ndevice went away ({e.strerror or e}); waiting for "
                      f"it to come back")
            except SerialFrameWriteError as e:
                print(f"\nserial frame write failed: {e}", file=sys.stderr)
                return 2
            finally:
                link.close()
            if args.seconds > 0 or args.once:
                return 0
    except KeyboardInterrupt:
        print("\ninterrupted")
        return 0


if __name__ == "__main__":
    sys.exit(main())

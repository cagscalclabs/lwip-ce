#!/usr/bin/env python3
"""Bridge lwIP-CE's length-prefixed CDC-ACM frames to the internet.

The calculator is the network client. This local program answers DHCP (and
the Wi-Fi bridge's crypto offload, if asked) and hands everything else to the
host kernel, which routes and NATs it out of the selected uplink.

macOS
    Talks to the calculator through the cu.usbmodem serial port, forwards
    IPv4 through a utun interface, answers ARP itself, and loads a PF NAT
    anchor. Requests sudo only for privileged setup and cleanup.

Linux
    Talks to the calculator directly over libusb (pyusb), detaching cdc_acm
    for the duration, and forwards ARP and IPv4 through a TAP interface, so
    the kernel does ARP as well. Needs pyusb. Two ways to run:

    * temporary: creates a user-owned TAP interface, enables IPv4 forwarding on
      it and the uplink, adds an nftables masquerade table, and (if firewalld
      is running) permits only the calculator's forwarding flow. Sudo is
      requested for setup and cleanup; the bridge loop runs as the user.
    * unprivileged: point --tap at a persistent TAP interface you own that
      is already addressed and NATed, and grant USB access with a udev rule.
      --print-setup prints the one-time root commands for that.
"""

from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager
import glob
import ipaddress
import logging
from logging.handlers import RotatingFileHandler
import os
import platform
import re
import secrets
import select
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import termios
import time

VID, PID = 0x16C0, 0x05E1

ETH_HDR = 14
ETH_MAX = 1514
USB_MPS = 64     # bulk max packet size
LOG = logging.getLogger("lwip-acm-bridge")
CLEANUP_ERRORS = 0


class PrivateRotatingFileHandler(RotatingFileHandler):
    def _open(self):
        fd = os.open(self.baseFilename,
                     os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW,
                     0o600)
        os.fchmod(fd, 0o600)
        return os.fdopen(fd, "a", encoding="utf-8")


def configure_logging(path: str, debug: bool) -> None:
    """Keep the log owned by the invoking user, even when sudo is available."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), mode=0o700, exist_ok=True)
    handler = PrivateRotatingFileHandler(path, maxBytes=10 * 1024 * 1024,
                                         backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)s %(message)s"))
    LOG.addHandler(handler)
    LOG.setLevel(logging.DEBUG if debug else logging.INFO)
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    LOG.addHandler(console)


def privileged(*cmd: str, input: str | None = None,
               check: bool = True) -> subprocess.CompletedProcess:
    """Run only a specific host-networking command with elevated rights."""
    argv = list(cmd) if os.geteuid() == 0 else ["sudo", "--", *cmd]
    try:
        return subprocess.run(argv, input=input, text=True, check=check,
                              capture_output=True)
    except FileNotFoundError as exc:
        raise RuntimeError(f"required command is missing: {argv[0]}") from exc


def cleanup_command(description: str, *cmd: str) -> None:
    global CLEANUP_ERRORS
    try:
        privileged(*cmd)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        CLEANUP_ERRORS += 1
        detail = getattr(exc, "stderr", None)
        LOG.error("Failed to restore %s: %s %s", description, exc,
                  (detail or "").strip())
    else:
        LOG.info("Restored %s", description)

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
            return found
        if not announced and not quiet:
            LOG.info("Waiting for %s", what)
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
    try:
        attrs = termios.tcgetattr(fd)
        attrs[0] = attrs[1] = attrs[3] = 0
        attrs[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
        attrs[6][termios.VMIN] = 0
        attrs[6][termios.VTIME] = 0
        termios.tcsetattr(fd, termios.TCSANOW, attrs)
        fcntl.ioctl(fd, 0x8004746C,
                    struct.pack("I", 0x002))  # TIOCMBIS, TIOCM_DTR
        return fd
    except BaseException:
        os.close(fd)
        raise


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

        try:
            self.thread = threading.Thread(target=self._reader, daemon=True,
                                           name="usb-reader")
            self.thread.start()
        except BaseException:
            self.close()
            raise

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
        global CLEANUP_ERRORS
        self.closing = True
        thread = getattr(self, "thread", None)
        if thread is not None:
            thread.join(timeout=1.0)
        for n in self.claimed:
            try:
                self.usb.util.release_interface(self.dev, n)
            except Exception as exc:
                CLEANUP_ERRORS += 1
                LOG.error("Could not release USB interface %d: %s", n, exc)
        for n in self.detached:
            try:
                self.dev.attach_kernel_driver(n)
            except Exception as exc:
                CLEANUP_ERRORS += 1
                LOG.error("Could not reattach USB kernel driver %d: %s", n, exc)
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
            if i + 2 + ln > len(payload):
                return None
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

    Try this as the invoking user first; some macOS versions permit it.
    """
    import fcntl

    AF_SYSTEM, SYSPROTO_CONTROL = 32, 2
    CTLIOCGINFO = 0xC0644E03
    UTUN_OPT_IFNAME = 2

    s = socket.socket(AF_SYSTEM, socket.SOCK_DGRAM, SYSPROTO_CONTROL)
    try:
        info = struct.pack("<I96s", 0, b"com.apple.net.utun_control")
        ctl_id = struct.unpack("<I96s", fcntl.ioctl(s, CTLIOCGINFO, info))[0]
        s.connect((ctl_id, 0))      # unit 0: kernel picks the next free utun
        name = s.getsockopt(SYSPROTO_CONTROL, UTUN_OPT_IFNAME, 32)
        name = name.split(b"\x00")[0].decode()
        s.setblocking(False)
        return s, name
    except BaseException:
        s.close()
        raise


UTUN_HELPER = '''\
import fcntl, socket, struct, sys
s = socket.socket(32, socket.SOCK_DGRAM, 2)
info = struct.pack("<I96s", 0, b"com.apple.net.utun_control")
ctl_id = struct.unpack("<I96s", fcntl.ioctl(s, 0xC0644E03, info))[0]
s.connect((ctl_id, 0))
name = s.getsockopt(2, 2, 32).split(b"\\0")[0]
with socket.socket(socket.AF_UNIX) as channel:
    channel.connect(sys.argv[1])
    channel.sendmsg([name], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                             struct.pack("i", s.fileno()))])
'''


def open_privileged_utun():
    """Have a short-lived sudo helper create utun and hand back only its fd."""
    directory = tempfile.mkdtemp(prefix="lwip-acm-utun-")
    path = os.path.join(directory, "fd.sock")
    try:
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(path)
            listener.listen(1)
            process = subprocess.Popen(
                ["sudo", "--", sys.executable, "-c", UTUN_HELPER, path],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.monotonic() + 120
                while True:
                    ready, _, _ = select.select([listener], [], [], 0.5)
                    if ready:
                        break
                    if process.poll() is not None:
                        raise RuntimeError("utun helper failed: " +
                                           (process.stderr.read() or "unknown error"))
                    if time.monotonic() >= deadline:
                        process.terminate()
                        raise RuntimeError("timed out waiting for sudo utun helper")
                channel, _ = listener.accept()
                with channel:
                    data, controls, _, _ = channel.recvmsg(32, socket.CMSG_SPACE(4))
                process.wait(timeout=5)
                if process.returncode:
                    raise RuntimeError("utun helper failed: " +
                                       (process.stderr.read() or "unknown error"))
                fds = [struct.unpack("i", item[:4])[0]
                       for level, kind, item in controls
                       if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS]
                if not data or len(fds) != 1:
                    raise RuntimeError("utun helper did not pass an interface")
                # Python cannot infer the family of a macOS kernel-control
                # socket from its fd (getsockname returns EOPNOTSUPP).
                sock = socket.socket(32, socket.SOCK_DGRAM, 2, fileno=fds[0])
                sock.setblocking(False)
                return sock, data.decode()
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait()
                process.stderr.close()
    finally:
        if os.path.exists(path):
            os.unlink(path)
        os.rmdir(directory)


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


@contextmanager
def temporary_ipv4_forwarding():
    """Enable forwarding for a bridge run, then restore its prior value."""
    original = subprocess.run(
        ["sysctl", "-n", "net.inet.ip.forwarding"], check=True,
        capture_output=True, text=True).stdout.strip()
    if original not in ("0", "1"):
        raise RuntimeError(f"unexpected net.inet.ip.forwarding value: {original!r}")

    changed = original == "0"
    try:
        if changed:
            LOG.info("Setting net.inet.ip.forwarding: 0 -> 1")
            privileged("sysctl", "-w", "net.inet.ip.forwarding=1")
        yield
    finally:
        if changed:
            cleanup_command("net.inet.ip.forwarding=0", "sysctl", "-w",
                            "net.inet.ip.forwarding=0")


def select_pf_nat_anchor(main_rules: str) -> str:
    """Use an existing NAT anchor point without replacing the main ruleset."""
    anchors = [line.strip() for line in main_rules.splitlines()
               if line.strip().startswith("nat-anchor ")]
    if any('"com.apple/*"' in line for line in anchors):
        return "com.apple/lwip-ce-bridge"
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
        main_rules = privileged("pfctl", "-sn").stdout
        anchor = f"{select_pf_nat_anchor(main_rules)}-{secrets.token_hex(8)}"
        try:
            self.tun, tun_name = open_utun()
        except PermissionError:
            LOG.info("Creating utun using a short-lived sudo helper")
            self.tun, tun_name = open_privileged_utun()
        self.stack.callback(self.tun.close)
        host_ip = ".".join(str(b) for b in net.host_ip)
        client_ip = ".".join(str(b) for b in net.client_ip)

        netmask = ".".join(str(b) for b in net.netmask)
        # Without an explicit netmask ifconfig defaults a 10.x utun to /8,
        # which makes the kernel treat all of 10.0.0.0/8 as on-link.
        LOG.info("Configuring %s: %s -> %s netmask %s", tun_name,
                 host_ip, client_ip, netmask)
        privileged("ifconfig", tun_name, host_ip, client_ip,
                   "netmask", netmask, "up")
        # ifconfig normally installs the point-to-point host route itself.
        # An unconditional `route add` printed "File exists" even when
        # routing was correct, and a stale route to an old utun could
        # silently steal replies.
        current_route = route_interface(client_ip)
        if current_route is None:
            LOG.info("Adding host route for %s through %s", client_ip, tun_name)
            privileged("route", "-q", "-n", "add", "-host", client_ip,
                       "-interface", tun_name)
            self.stack.callback(lambda: cleanup_command(
                f"host route to {client_ip}", "route", "-q", "-n",
                "delete", "-host", client_ip))
            current_route = route_interface(client_ip)
        elif current_route != tun_name:
            # Keep the old route intact. A conflicting route needs operator
            # attention; deleting it would change unrelated host networking.
            raise RuntimeError(f"route to {client_ip} uses "
                               f"{current_route}, expected "
                               f"{tun_name}; choose another --client-ip")
        if current_route != tun_name:
            raise RuntimeError(f"route to {client_ip} uses "
                               f"{current_route or 'no interface'}, "
                               f"expected {tun_name}")

        rule = f"nat on {uplink} from {client_ip} to any -> ({uplink})\n"
        LOG.info("Interface %s: %s -> %s; route via %s; uplink %s",
                 tun_name, host_ip, client_ip, current_route, uplink)
        LOG.info("Loading PF NAT rule: %s", rule.strip())

        # The anchor needs an active NAT anchor point and a PF enable
        # reference. -E/-X avoids globally disabling PF if another service
        # starts using it.
        privileged("pfctl", "-a", anchor, "-f", "-", input=rule)

        def flush_anchor():
            cleanup_command(f"PF NAT anchor {anchor}", "pfctl", "-a",
                            anchor, "-F", "all")
        self.stack.callback(flush_anchor)

        LOG.info("Enabling PF with a reference token")
        en = privileged("pfctl", "-E")
        try:
            pf_token = pf_enable_token(en.stdout + en.stderr)
        except RuntimeError:
            # pfctl may have enabled PF despite an unexpected output format.
            # The token cannot be released safely; make this visible.
            LOG.error("PF enable reference may remain active; output: %s %s",
                      en.stdout.strip(), en.stderr.strip())
            raise

        def release_pf():
            cleanup_command("PF enable reference", "pfctl", "-X", pf_token)
        self.stack.callback(release_pf)

        status = privileged("pfctl", "-s", "info").stdout
        if "Status: Enabled" not in status:
            raise RuntimeError("PF did not enable after pfctl -E")
        LOG.info("PF enabled; NAT anchor %s loaded", anchor)
        # Show what pf thinks it has, so a silent mismatch is visible.
        shown = privileged("pfctl", "-a", anchor, "-s", "nat").stdout.strip()
        LOG.info("PF NAT rules: %s", shown or "(none; NAT is not active)")

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


def valid_interface(name: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", name)) and name not in (".", "..")


def netmask_prefix(mask: bytes) -> int:
    return bin(int.from_bytes(mask, "big")).count("1")


class TapHost:
    """Linux: the calculator's Ethernet frames go through a TAP interface.

    Two modes:

    * created (needs root): a fresh TAP is addressed, IPv6 is disabled on it
      (nothing NATs v6, and the kernel's multicast chatter would only cost
      USB bandwidth), IPv4 forwarding is enabled on it and on the uplink,
      an nftables table masquerades the calculator's address out of the
      uplink, and firewalld (if running) gets a scoped forwarding rule.
      Each step is undone on exit, in reverse.
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
    def write_sysctl(key: str, value: str, restore: ExitStack | None = None) -> str:
        """Use sudo only for the write; return the prior kernel value."""
        old = subprocess.run(["sysctl", "-n", key], check=True,
                             capture_output=True, text=True).stdout.strip()
        if old != value:
            if restore is not None:
                restore.callback(lambda: cleanup_command(
                    f"{key}={old}", "sysctl", "-w", f"{key}={old}"))
            LOG.info("Setting %s: %s -> %s", key, old, value)
            privileged("sysctl", "-w", f"{key}={value}")
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
        import pwd
        import shlex

        tap = args.tap or f"{TAP_PREFIX}0"
        up = uplink or "UPLINK"
        prefix = netmask_prefix(MiniNet().netmask)
        import textwrap
        user = shlex.quote(pwd.getpwuid(os.getuid()).pw_name)

        print(textwrap.dedent(f"""\
    # One-time setup, as root, so the bridge can run as {user}.
    # The network part lasts until reboot; the udev rule is permanent.
    # Record this value so it can be restored at cleanup:
    sysctl -n net.ipv4.conf.{up}.forwarding

    ip tuntap add dev {tap} mode tap user {user}
    ip link set dev {tap} address 02:ce:ce:00:00:01
    sysctl -w net.ipv6.conf.{tap}.disable_ipv6=1
    ip addr add {args.host_ip}/{prefix} dev {tap}
    ip link set dev {tap} up
    sysctl -w net.ipv4.conf.{tap}.forwarding=1 net.ipv4.conf.{up}.forwarding=1
    nft add table ip {NFT_TABLE}
    nft 'add chain ip {NFT_TABLE} postrouting {{ type nat hook postrouting priority srcnat; }}'
    nft add rule ip {NFT_TABLE} postrouting iifname '"{tap}"' ip saddr {args.client_ip} oifname '"{up}"' masquerade
    firewall-cmd --direct --add-rule ipv4 filter FORWARD 0 -i {tap} -s {args.client_ip} -o {up} -j ACCEPT  # only if firewalld runs

    # USB access for the logged-in user (also lets the bridge detach cdc_acm):
    echo 'SUBSYSTEM=="usb", ATTR{{idVendor}}=="{VID:04x}", ATTR{{idProduct}}=="{PID:04x}", TAG+="uaccess"' \\
        > /etc/udev/rules.d/70-lwip-ce.rules
    udevadm control --reload && udevadm trigger

    # Then, unprivileged:
    #   python3 {sys.argv[0]} --tap {tap}
    #
    # To undo the network part, also restore the uplink forwarding value
    # recorded before setup and remove the firewalld zone assignment:
    #   firewall-cmd --direct --remove-rule ipv4 filter FORWARD 0 -i {tap} -s {args.client_ip} -o {up} -j ACCEPT
    #   nft delete table ip {NFT_TABLE}
    #   sysctl -w net.ipv4.conf.{up}.forwarding=PRIOR_VALUE
    #   ip link delete {tap}"""))


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
                "or use the temporary TAP mode.") from None
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
        LOG.info("Using preconfigured interface %s, address %s, MAC %s",
                 self.name, have or "none", mac_str(self.net.host_mac))
        if have != host_ip:
            LOG.warning("%s has %s, but DHCP will name %s as router; "
                        "fix the interface or pass --host-ip", self.name,
                        have or "no IPv4 address", host_ip)
        with open(f"{sysfs}/flags") as fh:
            if not int(fh.read(), 16) & 0x1:                # IFF_UP
                LOG.warning("%s is down (ip link set dev %s up)",
                            self.name, self.name)

    def _create(self) -> None:
        import shutil
        import subprocess

        for tool in ("ip", "nft"):
            if not shutil.which(tool):
                raise RuntimeError(f"`{tool}` not found; install "
                                   f"{'iproute' if tool == 'ip' else 'nftables'}")
        if not self.uplink:
            raise RuntimeError("no outbound interface found; pass --odevice")

        net, uplink = self.net, self.uplink
        if self.name:
            tap = self.name
        else:
            tap = next((f"{TAP_PREFIX}{n}" for n in range(1000)
                        if not os.path.exists(f"/sys/class/net/{TAP_PREFIX}{n}")),
                       None)
            if tap is None:
                raise RuntimeError("no free lwipce TAP interface name")
        LOG.info("Creating TAP %s owned by uid %d", tap, os.getuid())
        privileged("ip", "tuntap", "add", "dev", tap, "mode", "tap",
                   "user", str(os.getuid()))
        self.stack.callback(lambda: cleanup_command(
            f"TAP {tap}", "ip", "link", "delete", "dev", tap))
        self._open(tap)
        tap = self.name
        host_ip = ".".join(str(b) for b in net.host_ip)
        client_ip = ".".join(str(b) for b in net.client_ip)
        prefix = netmask_prefix(net.netmask)

        LOG.info("Setting TAP %s MAC to %s", tap, mac_str(net.host_mac))
        privileged("ip", "link", "set", "dev", tap, "address", mac_str(net.host_mac))
        try:
            self.write_sysctl(f"net.ipv6.conf.{tap}.disable_ipv6", "1")
        except subprocess.CalledProcessError:
            pass                             # IPv6 not built in: nothing to do
        LOG.info("Addressing TAP %s with %s/%s", tap, host_ip, prefix)
        privileged("ip", "addr", "add", f"{host_ip}/{prefix}", "dev", tap)
        LOG.info("Bringing TAP %s up", tap)
        privileged("ip", "link", "set", "dev", tap, "up")
        current_route = self.route_interface(client_ip)
        if current_route != tap:
            raise RuntimeError(f"route to {client_ip} uses "
                               f"{current_route or 'no interface'}, expected "
                               f"{tap}; is {host_ip}/{prefix} already in use "
                               "on another interface?")

        # Per-interface forwarding rather than the global ip_forward switch:
        # Linux decides on the ingress interface, so these two are all the
        # path needs, and nothing else on the host starts routing.
        self.write_sysctl(f"net.ipv4.conf.{tap}.forwarding", "1")
        up_key = f"net.ipv4.conf.{uplink}.forwarding"
        self.write_sysctl(up_key, "1", restore=self.stack)

        table = f"{NFT_TABLE}_{secrets.token_hex(8)}"
        rule = (f"iifname \"{tap}\" ip saddr {client_ip} "
                f"oifname \"{uplink}\" masquerade")
        ruleset = (f"table ip {table} {{\n"
                   f"  chain postrouting {{\n"
                   f"    type nat hook postrouting priority srcnat; policy accept;\n"
                   f"    {rule}\n"
                   f"  }}\n"
                   f"}}\n")
        LOG.info("Installing nftables table %s with rule: %s", table, rule)
        privileged("nft", "-f", "-", input=ruleset)

        def drop_table():
            cleanup_command(f"nftables table {table}", "nft", "delete",
                            "table", "ip", table)
        self.stack.callback(drop_table)

        LOG.info("Interface %s %s/%s; client route via %s; uplink %s",
                 tap, host_ip, prefix, current_route, uplink)

        if self.firewalld_running():
            # A source-bound forward rule grants just this calculator's
            # outbound traffic. It does not trust traffic to host services.
            direct = (f"-i {tap} -s {client_ip} -o {uplink} -j ACCEPT")
            argv = ("firewall-cmd", "--direct", "--add-rule", "ipv4",
                    "filter", "FORWARD", "0", *direct.split())
            LOG.info("Adding firewalld forward rule: %s", direct)
            privileged(*argv)

            def leave_zone():
                cleanup_command(f"firewalld forward rule for {tap}",
                                "firewall-cmd", "--direct", "--remove-rule",
                                "ipv4", "filter", "FORWARD", "0", *direct.split())
            self.stack.callback(leave_zone)
        else:
            # Without firewalld, a drop policy on some other forward chain
            # (Docker installs one) still discards the traffic, and an accept
            # here cannot override it.
            rules = subprocess.run(["nft", "list", "ruleset"],
                                   capture_output=True, text=True).stdout
            if re.search(r"hook forward[^\n]*policy drop", rules):
                LOG.warning("A forward chain has policy drop; traffic may be "
                            "discarded unless it accepts %s -> %s", tap, uplink)

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
               quiet: bool = False, debug: bool = False,
               crypto: "CryptoResponder | None" = None) -> int:
    """Move frames between the calculator and the host network.

    host is a UtunHost or TapHost already entered; it decides which
    EtherTypes go to the kernel and how frames come back.
    """
    asm = LengthPrefixReassembler()
    start = time.time()
    last_tick = start
    tx = rx = 0
    LOG.info("Bridge started")
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
                        if debug:
                            LOG.debug("<- control frame bytes=%d", len(frame))
                        link.write_frame(reply)
                        if debug:
                            LOG.debug("-> control frame bytes=%d", len(reply))
                        continue
                    reply = net.handle(frame)      # DHCP (+ ARP on macOS)
                    if reply:
                        if debug:
                            LOG.debug("<- local frame bytes=%d", len(frame))
                        link.write_frame(reply)
                        if debug:
                            LOG.debug("-> local frame bytes=%d", len(reply))
                        continue
                    if et in host.forwards:
                        if et == 0x0800:
                            frame, _ = clamp_tcp_mss(frame)
                        host.send(frame)
                        tx += 1
                        if debug:
                            LOG.debug("out frame bytes=%d", len(frame))

            # kernel -> calculator
            frame = host.recv()
            if frame:
                moved = True
                link.write_frame(frame)
                rx += 1
                if debug:
                    LOG.debug("in frame bytes=%d", len(frame))

            if not moved:
                time.sleep(0.005)

            # A silent terminal should still show whether anything is moving.
            if not quiet and time.time() - last_tick >= 2.0:
                last_tick = time.time()
                LOG.info("Forwarded counters: out=%d in=%d", tx, rx)
    except KeyboardInterrupt:
        LOG.info("Bridge interrupted")

    LOG.info("Bridge stopped: forwarded %d packets out, %d in", tx, rx)
    return 0


def open_link(args, system: str):
    """Wait for the calculator, then open it the platform's way."""
    if system == "Darwin":
        port = wait_for_calculator(args.port, quiet=args.quiet)
        link = TtyLink(port)
        LOG.info("Port %s opened; DTR asserted", port)
        return link
    import usb.core

    dev = wait_for(find_calculator_usb,
                   f"the calculator ({VID:04X}:{PID:04X})", args.quiet)
    try:
        link = UsbLink(dev)
    except usb.core.USBError as e:
        if e.errno != 13:                                  # EACCES
            raise
        if not shutil.which("getfacl") or not shutil.which("setfacl"):
            raise RuntimeError(
                "USB access denied; install the udev rule from --print-setup "
                "or install the Linux acl tools for a temporary access grant") from None
        device_path = f"/dev/bus/usb/{dev.bus:03d}/{dev.address:03d}"
        uid = os.getuid()
        current = subprocess.run(["getfacl", "-cn", device_path],
                                 check=True, capture_output=True, text=True).stdout
        if re.search(rf"^user:{uid}:", current, re.MULTILINE):
            raise RuntimeError("USB access denied despite an existing user ACL; "
                               "check the udev rule and device permissions") from None
        LOG.info("Granting uid %d temporary USB access to %s", uid, device_path)
        try:
            privileged("setfacl", "-m", f"u:{uid}:rw", device_path)
        except BaseException:
            cleanup_command(f"USB ACL on {device_path}", "setfacl", "-x",
                            f"u:{uid}", device_path)
            raise
        try:
            link = UsbLink(dev)
        except BaseException:
            cleanup_command(f"USB ACL on {device_path}", "setfacl", "-x",
                            f"u:{uid}", device_path)
            raise
        link.usb_acl = (device_path, uid)
    LOG.info("Device %s opened; DTR asserted", link.name)
    return link


def main() -> int:
    global CLEANUP_ERRORS
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
    ap.add_argument("--debug", action="store_true",
                    help="log frame directions and byte counts (no packet data)")
    ap.add_argument("--quiet", action="store_true",
                    help="suppress periodic packet counters")
    ap.add_argument("--log-file", metavar="PATH",
                    help="log path (default: ~/.local/state/lwip-acm-bridge/bridge.log)")
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
    for name in (args.tap, args.odevice):
        if name and not valid_interface(name):
            ap.error(f"invalid interface name: {name!r}")
    for label in ("host_ip", "client_ip", "dns", "ntp"):
        value = getattr(args, label)
        if value is not None:
            try:
                ipaddress.IPv4Address(value)
            except ipaddress.AddressValueError:
                ap.error(f"invalid IPv4 address for --{label.replace('_', '-')}: {value!r}")
    if args.host_ip == args.client_ip:
        ap.error("--host-ip and --client-ip must differ")

    # A sudo invocation must not keep the packet parser running as root. It
    # also does not seed the invoking user's sudo timestamp after dropping
    # privileges, which would cause a second password prompt during setup.
    if os.geteuid() == 0:
        ap.error("run without sudo; the bridge will request it once for "
                 "privileged host networking operations")

    import pwd
    user_home = pwd.getpwuid(os.getuid()).pw_dir
    log_path = args.log_file or os.path.join(
        user_home, ".local", "state", "lwip-acm-bridge", "bridge.log")
    try:
        configure_logging(log_path, args.debug)
    except OSError as e:
        ap.error(f"cannot open log file {log_path!r}: {e}")
    LOG.info("Starting bridge; log file %s", log_path)

    candidates = active_uplinks()
    if args.print_setup:
        TapHost.print_setup(args, args.odevice or (candidates[0] if candidates else None))
        return 0

    try:
        crypto = CryptoResponder() if args.accelerate_crypto else None
    except ImportError as e:
        ap.error(f"--accelerate-crypto needs python3-cryptography: {e}")

    if system == "Linux":
        try:
            import usb.core
            import usb.backend.libusb1
        except ImportError:
            LOG.error("Needs pyusb: dnf install python3-pyusb "
                      "(or pip install pyusb)")
            return 2
        if usb.backend.libusb1.get_backend() is None:
            LOG.error("Pyusb cannot find libusb-1.0: dnf install libusb1")
            return 2

    preconfigured = (system == "Linux" and args.tap
                     and os.path.exists(f"/sys/class/net/{args.tap}"))
    uplink = args.odevice or (candidates[0] if candidates else None)
    if not uplink and not preconfigured:
        LOG.error("No active network interface found")
        return 2
    if not preconfigured:
        if args.odevice and args.odevice not in candidates:
            LOG.warning("%s not among active interfaces %s",
                        args.odevice, candidates)
        elif not args.odevice and len(candidates) > 1:
            LOG.info("Outbound interface %s (also available: %s)",
                     uplink, ", ".join(candidates[1:]))

    net = MiniNet(args.host_ip, args.client_ip, dns_ip=args.dns, ntp_ip=args.ntp)
    # On Linux the kernel also answers ARP, since the TAP interface is
    # Ethernet.
    if system == "Linux":
        net.answer_arp = False

    try:
        while True:
            cleanup_errors_before = CLEANUP_ERRORS
            try:
                link = open_link(args, system)
            except (RuntimeError, subprocess.CalledProcessError, OSError) as e:
                LOG.error("%s", e)
                return 2
            except Exception as e:
                LOG.error("Could not open device: %s", type(e).__name__)
                return 2
            try:
                host = (UtunHost(net, uplink) if system == "Darwin"
                        else TapHost(net, uplink, args.tap))
                with host:
                    try:
                        run_bridge(link, net, host, args.seconds,
                                   quiet=args.quiet, debug=args.debug,
                                   crypto=crypto)
                    except OSError as e:
                        LOG.warning("Link I/O stopped (%s); waiting for reconnect",
                                    e.strerror or type(e).__name__)
            except RuntimeError as e:
                LOG.error("%s", e)
                return 2
            except subprocess.CalledProcessError as e:
                detail = (e.stderr or "").strip()
                LOG.error("`%s` failed (exit %d)%s", " ".join(e.cmd),
                          e.returncode, f": {detail}" if detail else "")
                return 2
            except BlockingIOError as e:
                LOG.error("Bridge I/O would block: %s", e)
                return 2
            except OSError as e:
                LOG.error("Host setup or cleanup failed: %s", e)
                return 2
            except SerialFrameWriteError as e:
                LOG.error("Serial frame write failed: %s", e)
                return 2
            except Exception as e:
                LOG.error("Unhandled bridge error: %s", type(e).__name__)
                return 2
            finally:
                try:
                    link.close()
                except Exception as e:
                    CLEANUP_ERRORS += 1
                    LOG.error("Could not close device: %s", type(e).__name__)
                finally:
                    acl = getattr(link, "usb_acl", None)
                    if acl:
                        cleanup_command(f"USB ACL on {acl[0]}", "setfacl",
                                        "-x", f"u:{acl[1]}", acl[0])
            if CLEANUP_ERRORS != cleanup_errors_before:
                LOG.error("Bridge shutdown left %d host changes unconfirmed",
                          CLEANUP_ERRORS - cleanup_errors_before)
                return 2
            if args.seconds > 0 or args.once:
                return 0
    except KeyboardInterrupt:
        LOG.info("Interrupted")
        return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Host side of the networked lwIP-CE suites in tests/net.

Serves every endpoint the calc suites talk to on the TAP gateway, answers
their control requests (UDP 7000), runs each suite's program in the CEmu
autotester with the emulated USB Ethernet adapter plugged in, and grades the
NETLOG appvar each suite saves.

    sudo python3 tests/net/run.py --autotester PATH --usb 'usb|eth,cemu0,...' [--suite sockets ...]

Root is needed for the IPv6 router advertisements, multicast and ARP
sniffing (scapy) used by the raw suite. In CI the TAP interface and NAT are
set up by alessiodam/cemu-net-action.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import os
import re
import shutil
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent / "common"
SUITES = {"sockets": "NETTEST", "raw": "NETRAW", "tls": "NETTLS", "records": "NETREC",
          "server": "NETSRV", "perf": "NETPERF", "timeouts": "NETTMO"}
CALC = "192.168.84.2"
HOST = "192.168.84.1"
HOST6 = "fd00:84::1"
IFACE = "cemu0"
CONTROL = None
BULK_BYTES = 262144
# CRC-32C of a solid green / red 8bpp screen: the suites' pass and fail verdicts.
VERDICT_CRCS = ["A511C030", "22D544B5"]
# CRC-32C of the home screen after the calc reset itself (crash).
CRASH_CRC = "93BFC41E"
PSK = bytes(((i * 31) + (i >> 8)) & 0xFF for i in range(32))
PSK_IDENTITY = "lwip-ce-nettest"
CIPHERS = {"gcm": "TLS_AES_128_GCM_SHA256", "ccm": "TLS_AES_128_CCM_SHA256", "aes256": "TLS_AES_256_GCM_SHA384"}
GROUPS = {"x25519": "X25519", "p256": "P-256", "p384": "P-384"}
ENDPOINT_POOLS = {
    # Fungible smoke tests may use a different provider. Certificate-policy
    # tests only use alternatives that exercise the same CA and key type.
    "tls13": [("tls13.akamai.io", "/"), ("www.cloudflare.com", "/")],
    "rsa2048": [("valid.rootca1.demo.amazontrust.com", "/"),
                ("good.sca1a.amazontrust.com", "/")],
    "ecdsa256": [("valid.rootca3.demo.amazontrust.com", "/"),
                 ("good.sca3a.amazontrust.com", "/")],
    "body": [("raw.githubusercontent.com",
              "/lwip-tcpip/lwip/STABLE-2_2_1_RELEASE/src/core/udp.c"),
             ("www.amazontrust.com", "/")],
    "starfield": [("www.amazontrust.com", "/"),
                  ("valid.sfg2.demo.amazontrust.com", "/")],
    "p384": [("valid.rootca4.demo.amazontrust.com", "/"),
             ("good.sca4a.amazontrust.com", "/")],
    "wss": [("websocket-echo.com", "/")],
    "wss_long": [("echo.websocket.in", "/")],
}
ENDPOINT_PHASES = {
    "body": "body",
    "wss": "wss",
    "wss_long": "wss",
}
HTTPS_PATHS = {host: path for pool in ENDPOINT_POOLS.values() for host, path in pool}
HTTPS_FAILURE = re.compile(
    r"^FAIL https (?P<host>[A-Za-z0-9.-]+)(?: \([^)]*\))?"
    r"(?P<phase> answers HTTP| full body)?$"
)
SOCKET_STATUS = re.compile(r"^\s+\S+: status (\d+) err (\d+)(?: in \d+ ms)?$")


def pattern(start: int, n: int) -> bytes:
    return bytes(((i * 31) + (i >> 8)) & 0xFF for i in range(start, start + n))


def log(msg: str) -> None:
    print(f"[host] {msg}", flush=True)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

class TCP(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class TCP6(TCP):
    address_family = socket.AF_INET6


class UDP(socketserver.ThreadingUDPServer):
    allow_reuse_address = True


class UDP6(UDP):
    address_family = socket.AF_INET6


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.serve()
        except (ConnectionError, OSError):
            pass

    def recv_exact(self, n: int) -> bytes:
        data = b""
        while len(data) < n:
            chunk = self.request.recv(n - len(data))
            if not chunk:
                raise ConnectionError
            data += chunk
        return data


class Echo(Handler):
    def serve(self):
        while data := self.request.recv(4096):
            self.request.sendall(data)


class Bulk(Handler):
    def serve(self):
        for off in range(0, BULK_BYTES, 8192):
            self.request.sendall(pattern(off, 8192))


class SizedBulk(Handler):
    """Client sends a 4-byte big-endian length, gets that many pattern bytes."""
    def serve(self):
        total = struct.unpack("!I", self.recv_exact(4))[0]
        for off in range(0, total, 8192):
            self.request.sendall(pattern(off, min(8192, total - off)))


class Sink(Handler):
    """Counts bytes until the client half-closes, then replies with the count."""
    def serve(self):
        total, bad = 0, 0
        while data := self.request.recv(65536):
            if data != pattern(total, len(data)):
                bad += 1
            total += len(data)
        self.request.sendall(f"{total} {'ok' if not bad else 'corrupt'}".encode())


class Hold(Handler):
    def serve(self):
        self.request.sendall(pattern(0, 32768))
        self.request.shutdown(socket.SHUT_WR)
        self.request.recv(1)


class HalfClose(Handler):
    def serve(self):
        total = 0
        while data := self.request.recv(4096):
            total += len(data)
        self.request.sendall(f"{total} bye".encode())


class Reset(Handler):
    def serve(self):
        self.request.recv(1)
        self.request.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        self.request.close()


class Closer(Handler):
    def serve(self):
        self.request.sendall(b"bye")


class ExpectReset(Handler):
    outcomes: list[str] = []

    def serve(self):
        try:
            data = self.request.recv(64)
            self.outcomes.append("eof" if not data else "data")
        except ConnectionResetError:
            self.outcomes.append("rst")


class WebSocketEcho(Handler):
    GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    def serve(self):
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = self.request.recv(1024)
            if not chunk:
                return
            head += chunk
        key = re.search(rb"(?i)sec-websocket-key:\s*(\S+)", head)
        if not key or not head.startswith(b"GET /echo "):
            self.request.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            return
        accept = base64.b64encode(hashlib.sha1(key.group(1) + self.GUID).digest())
        self.request.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                             b"Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept + b"\r\n\r\n")
        while True:
            b0, b1 = self.recv_exact(2)
            n = b1 & 0x7F
            if n == 126:
                n = int.from_bytes(self.recv_exact(2), "big")
            elif n == 127:
                n = int.from_bytes(self.recv_exact(8), "big")
            mask = self.recv_exact(4) if b1 & 0x80 else b"\0\0\0\0"
            payload = bytes(c ^ mask[i & 3] for i, c in enumerate(self.recv_exact(n)))
            opcode = b0 & 0x0F
            if opcode == 8:
                self.request.sendall(b"\x88\x00")
                return
            if opcode == 9:
                opcode = 10
            header = bytes([0x80 | opcode]) + (bytes([n]) if n < 126 else b"\x7e" + n.to_bytes(2, "big"))
            self.request.sendall(header + payload)


class UDPEcho(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)


class UDPLength(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(str(len(data)).encode(), self.client_address)


class Broadcast(socketserver.BaseRequestHandler):
    got = ""

    def handle(self):
        data, _ = self.request
        Broadcast.got = data.decode(errors="replace")


class TLSBad(Handler):
    context = None
    outcomes: list[str] = []

    def serve(self):
        import ssl
        try:
            with self.context.wrap_socket(self.request, server_side=True) as tls:
                tls.recv(1)
                self.outcomes.append("handshake completed")
        except ssl.SSLError as e:
            self.outcomes.append(e.reason or str(e))


def self_signed_context(tmp: Path):
    import ssl
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-nodes", "-days", "2", "-subj", f"/CN={HOST}", "-addext", f"subjectAltName=IP:{HOST}",
                    "-keyout", str(tmp / "key.pem"), "-out", str(tmp / "cert.pem")],
                   check=True, capture_output=True)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(tmp / "cert.pem", tmp / "key.pem")
    return ctx


# ---------------------------------------------------------------------------
# openssl PSK peers
# ---------------------------------------------------------------------------

class OpenSSL:
    def __init__(self, args: list[str], cwd: Path, ready: str | None):
        self.output = ""
        self.proc = subprocess.Popen(["openssl", *args], cwd=cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, text=True, errors="replace", bufsize=1)
        self.ready = threading.Event()
        self.marker = ready
        threading.Thread(target=self.pump, daemon=True).start()

    def pump(self):
        for out in self.proc.stdout:
            self.output += out
            if self.marker and self.marker in out:
                self.ready.set()

    def send(self, text: str):
        try:
            self.proc.stdin.write(text)
            self.proc.stdin.flush()
        except (BrokenPipeError, ValueError):
            pass

    def stop(self):
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()


def psk_args(cipher: str, group: str, key: bytes = PSK, identity: str = PSK_IDENTITY) -> list[str]:
    return ["-tls1_3", "-psk", key.hex(), "-psk_identity", identity, "-ciphersuites", CIPHERS[cipher],
            "-groups", GROUPS[group]]


def host_mac() -> str:
    out = subprocess.run(["ip", "-o", "link", "show", "dev", IFACE], capture_output=True, text=True).stdout
    return re.search(r"link/ether ([0-9a-f:]{17})", out).group(1)


def link_local() -> str:
    out = subprocess.run(["ip", "-6", "-o", "addr", "show", "dev", IFACE, "scope", "link"],
                         capture_output=True, text=True).stdout
    m = re.search(r"inet6 (fe80::[0-9a-f:]+)/", out)
    return m.group(1) if m else "fe80::1"


# ---------------------------------------------------------------------------
# Control server
# ---------------------------------------------------------------------------

class Control:
    def __init__(self, tmp: Path):
        self.tmp = tmp
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("0.0.0.0", 7000))
        self.peer: OpenSSL | None = None
        self.connect_results: list[str] = []
        self.sniffed: list[str] = []
        self.claimed: set[str] = set()
        self.last: dict[str, str] = {}
        self.last_request = ""
        self.endpoint_selected: dict[str, tuple[str, str]] = {}
        self.last_group = "-"
        (tmp / "bulk.bin").write_bytes(pattern(0, 131072))
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        inflight: set[str] = set()
        while True:
            data, addr = self.sock.recvfrom(512)
            cmd = data.decode(errors="replace").strip()
            # Requests carry a per-run sequence number; a new run starts at "1 begin".
            if cmd.startswith("1 begin "):
                self.last.clear()
            # The calc retries requests it has no answer for yet; never run one twice.
            if cmd in self.last:
                self.sock.sendto(self.last[cmd].encode(), addr)
            elif cmd not in inflight:
                inflight.add(cmd)
                threading.Thread(target=self.answer, args=(cmd, addr, inflight), daemon=True).start()

    def answer(self, cmd: str, addr, inflight: set[str]):
        words = cmd.split()[1:]
        self.last_request = " ".join(words)
        try:
            reply = getattr(self, "cmd_" + words[0].replace("-", "_"))(*words[1:])
        except Exception as e:  # noqa: BLE001
            reply = f"ERR {type(e).__name__}: {e}"
        reply = reply if reply.startswith(("OK", "ERR")) else f"OK {reply}"
        reply = f"{cmd.split()[0]} {reply}"[:95]
        self.last[cmd] = reply
        inflight.discard(cmd)
        log(f"{cmd} -> {reply}")
        self.sock.sendto(reply.encode(), addr)

    # -- generic ------------------------------------------------------------

    def cmd_begin(self, suite: str) -> str:
        self.sniffed.clear()
        return "OK"

    def cmd_end(self) -> str:
        if self.peer:
            self.peer.stop()
        return "OK"

    def cmd_hello(self) -> str:
        return f"{link_local()} {host_mac()} {int(time.time())}"

    def cmd_time(self) -> str:
        return str(int(time.time()))

    def cmd_endpoint_pick(self, test: str) -> str:
        pool = ENDPOINT_POOLS.get(test)
        if not pool:
            return f"ERR unknown endpoint pool {test}"
        phase = ENDPOINT_PHASES.get(test, "tls")
        failures = []
        for host, path in pool:
            if phase == "wss":
                ok, issue, detail = host_wss_probe(host, path)
            else:
                ok, issue, detail = host_https_probe(host, phase, path=path)
            log(f"endpoint probe {test} {host}{path}: {detail}")
            if ok:
                self.endpoint_selected[test] = (host, path)
                return host
            failures.append(f"{host}:{issue}")
        return "ERR no healthy endpoint: " + ",".join(failures)

    def cmd_endpoint_path(self, test: str) -> str:
        selected = self.endpoint_selected.get(test)
        return selected[1] if selected else f"ERR no endpoint selected for {test}"

    def cmd_connect(self, port: str, count: str) -> str:
        self.connect_results = []
        threading.Thread(target=self.connect_to_calc, args=(int(port), int(count)), daemon=True).start()
        return "OK"

    def connect_to_calc(self, port: int, count: int):
        deadline = time.monotonic() + 60
        sent = 0
        while sent < count and time.monotonic() < deadline:
            try:
                with socket.create_connection((CALC, port), timeout=5) as s:
                    msg = f"lwip-ce-server-{sent}".encode()[:16]
                    s.sendall(msg)
                    echo = b""
                    while len(echo) < len(msg):
                        chunk = s.recv(64)
                        if not chunk:
                            break
                        echo += chunk
                    self.connect_results.append("ok" if echo == msg else repr(echo))
                    sent += 1
            except OSError:
                time.sleep(0.5)

    def cmd_connect_result(self, count: str = "3") -> str:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and len(self.connect_results) < int(count):
            time.sleep(0.2)
        return f"{self.connect_results.count('ok')}/{len(self.connect_results)}"

    def cmd_tls_bad_result(self) -> str:
        return ",".join(TLSBad.outcomes) or "none"

    def cmd_rst_result(self) -> str:
        time.sleep(1)
        return ",".join(ExpectReset.outcomes) or "none"

    def cmd_bcast_result(self) -> str:
        time.sleep(0.5)
        return Broadcast.got or "none"

    def cmd_ping(self, count: str = "3") -> str:
        r = subprocess.run(["ping", "-c", count, "-w", "20", CALC], capture_output=True, text=True)
        m = re.search(r"(\d+) received", r.stdout)
        return f"{m.group(1) if m else 0}/{count}"

    def cmd_pingburst(self, seconds: str = "10") -> str:
        """Ping the calc for a while without blocking the requesting suite.

        Used by the timeout suite: the point is that unrelated traffic is on
        the wire while a socket is expected to time out.
        """
        limit = max(1, min(30, int(seconds)))

        def racer():
            deadline = time.monotonic() + limit
            while time.monotonic() < deadline:
                subprocess.run(["ping", "-c", "1", "-W", "1", CALC],
                               capture_output=True, text=True)
                time.sleep(0.2)

        threading.Thread(target=racer, daemon=True).start()
        return "OK"

    def cmd_ping6(self, addr: str, count: str = "3") -> str:
        addr = addr.lower()
        target = f"{addr}%{IFACE}" if addr.startswith("fe80") else addr
        r = subprocess.run(["ping", "-6", "-c", count, "-w", "20", target], capture_output=True, text=True)
        m = re.search(r"(\d+) received", r.stdout)
        return f"{m.group(1) if m else 0}/{count}"

    def cmd_udp_unreach(self, port: str) -> str:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(3)
            s.connect((CALC, int(port)))
            s.send(b"anyone?")
            try:
                s.recv(16)
                return "ERR answered"
            except ConnectionRefusedError:
                return "refused"
            except socket.timeout:
                return "ERR no ICMP port unreachable"

    def cmd_frag_send(self, size: str, port: str) -> str:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(pattern(0, int(size)), (CALC, int(port)))
        return "OK"

    def cmd_frag6_send(self, addr: str, size: str, port: str) -> str:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
            s.sendto(pattern(0, int(size)), (addr, int(port), 0, socket.if_nametoindex(IFACE)))
        return "OK"

    def cmd_mcast4(self, group: str, port: str) -> str:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(HOST))
            for _ in range(3):
                s.sendto(b"lwip-ce-mcast4", (group, int(port)))
                time.sleep(0.2)
        return "OK"

    def cmd_mcast6(self, group: str, port: str) -> str:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, socket.if_nametoindex(IFACE))
            for _ in range(3):
                s.sendto(b"lwip-ce-mcast6", (group, int(port), 0, socket.if_nametoindex(IFACE)))
                time.sleep(0.2)
        return "OK"

    # -- scapy ----------------------------------------------------------------

    def start_sniffer(self):
        from scapy.all import ARP, AsyncSniffer, Ether, sendp
        from scapy.contrib.igmp import IGMP

        def record(pkt):
            if pkt.haslayer("TCP") and pkt["TCP"].sport == 7100:
                self.server_hello_group(bytes(pkt["TCP"].payload))
            elif IGMP in pkt:
                self.sniffed.append(f"igmp {pkt[IGMP].type:#x} {pkt[IGMP].gaddr}")
            elif pkt.haslayer("ICMPv6MLReport2"):
                for rec in pkt["ICMPv6MLReport2"].records:
                    self.sniffed.append(f"mld {rec.rtype} {rec.dst}")
            elif pkt.haslayer("ICMPv6MLReport"):
                self.sniffed.append(f"mld 1 {pkt['ICMPv6MLReport'].mladdr}")
            elif pkt.haslayer("ICMPv6MLDone"):
                self.sniffed.append(f"mld done {pkt['ICMPv6MLDone'].mladdr}")
            elif ARP in pkt and pkt[ARP].op == 1 and pkt[ARP].psrc == "0.0.0.0":
                self.sniffed.append(f"acd-probe {pkt[ARP].pdst}")
                if pkt[ARP].pdst in self.claimed:
                    mac = "02:84:ce:00:00:77"
                    sendp(Ether(src=mac, dst=pkt[ARP].hwsrc) /
                          ARP(op=2, hwsrc=mac, psrc=pkt[ARP].pdst, hwdst=pkt[ARP].hwsrc, pdst=pkt[ARP].pdst),
                          iface=IFACE, verbose=False)

        AsyncSniffer(iface=IFACE, prn=record, store=False, filter="igmp or ip6 or arp or tcp src port 7100").start()

    def server_hello_group(self, data: bytes):
        """Records the key_share group of a plaintext ServerHello from the PSK peer."""
        if len(data) < 44 or data[0] != 0x16 or data[5] != 0x02:
            return
        at = 9 + 2 + 32
        at += 1 + data[at]
        at += 3
        end = at + 2 + int.from_bytes(data[at:at + 2], "big")
        at += 2
        while at + 4 <= min(end, len(data)):
            kind, size = int.from_bytes(data[at:at + 2], "big"), int.from_bytes(data[at + 2:at + 4], "big")
            if kind == 0x33 and size >= 2:
                group = int.from_bytes(data[at + 4:at + 6], "big")
                self.last_group = {0x1d: "X25519", 0x17: "P-256", 0x18: "P-384"}.get(group, hex(group))
            at += 4 + size

    def cmd_sniffed(self, kind: str, what: str) -> str:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            hits = [s for s in self.sniffed if s.startswith(kind) and what in s]
            if hits:
                return hits[-1]
            time.sleep(0.2)
        return f"ERR no {kind} {what} seen ({len(self.sniffed)} captured)"

    def cmd_acd_claim(self, ip: str) -> str:
        self.claimed.add(ip)
        return "OK"

    def cmd_ra(self, prefix: str) -> str:
        from scapy.all import ICMPv6ND_RA, ICMPv6NDOptPrefixInfo, ICMPv6NDOptSrcLLAddr, IPv6, Ether, sendp
        mac = host_mac()
        ra = (Ether(src=mac, dst="33:33:00:00:00:01") / IPv6(src=link_local(), dst="ff02::1") /
              ICMPv6ND_RA(routerlifetime=1800) / ICMPv6NDOptSrcLLAddr(lladdr=mac) /
              ICMPv6NDOptPrefixInfo(prefix=prefix, prefixlen=64, L=1, A=1, validlifetime=3600,
                                    preferredlifetime=1800))
        for _ in range(3):
            sendp(ra, iface=IFACE, verbose=False)
            time.sleep(0.5)
        return "OK"

    # -- TLS peers ------------------------------------------------------------

    def cmd_tls12_server(self) -> str:
        """Start a deterministic TLS 1.2-only peer for version rejection."""
        if self.peer:
            self.peer.stop()
        args = [
            "s_server", "-accept", "7100", "-tls1_2", "-nocert", "-naccept", "1",
            "-psk", PSK.hex(), "-psk_identity", PSK_IDENTITY,
            "-cipher", "PSK-AES128-GCM-SHA256",
        ]
        self.peer = OpenSSL(args, self.tmp, "ACCEPT")
        if not self.peer.ready.wait(10):
            return f"ERR TLS 1.2 s_server did not start: {self.peer.output[-80:]}"
        return "OK"

    def cmd_psk_server(self, cipher: str, group: str, mode: str, key: str = "good", ident: str = "good",
                       naccept: str = "1") -> str:
        if self.peer:
            self.peer.stop()
        self.last_group = "-"
        args = ["s_server", "-accept", "7100", "-nocert", "-naccept", naccept]
        args += psk_args(cipher, group, PSK if key == "good" else bytes(32),
                         PSK_IDENTITY if ident == "good" else "someone-else")
        args += {"rev": ["-rev"], "www": ["-WWW"], "www4k": ["-WWW", "-max_send_frag", "4096"], "plain": [],
                 "alpn": ["-rev", "-alpn", "lwip/1,http/1.1"]}[mode]
        self.peer = OpenSSL(args, self.tmp, "ACCEPT")
        if not self.peer.ready.wait(10):
            return f"ERR s_server did not start: {self.peer.output[-80:]}"
        return "OK"

    def wait_peer_exit(self) -> str:
        """s_server buffers some of its report until it exits (-naccept reached)."""
        if not self.peer:
            return ""
        try:
            self.peer.proc.wait(5)
        except subprocess.TimeoutExpired:
            pass
        time.sleep(0.3)
        return self.peer.output

    def cmd_psk_result(self) -> str:
        out = self.wait_peer_exit()
        cipher = re.search(r"(?:CIPHER is|Ciphersuite:) (\S+)", out)
        group = re.search(r"(?:Peer Temp Key|Negotiated TLS1.3 group): ([\w-]+)", out)
        alpn = re.search(r"ALPN protocols selected: (\S+)", out)
        if cipher:
            return f"{cipher.group(1)} {group.group(1) if group else self.last_group} {alpn.group(1) if alpn else '-'}"
        errors = re.findall(r"(?:error|alert)[^\n]{0,70}", out)
        log("s_server output:\n" + out)
        return f"ERR {errors[-1] if errors else 'no handshake'}"

    def cmd_psk_send(self, text: str) -> str:
        self.peer.send(text + "\n")
        return "OK"

    def cmd_psk_seen(self, text: str) -> str:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.peer and text in self.peer.output:
                return "OK"
            time.sleep(0.2)
        return f"ERR {text!r} not received"

    def cmd_psk_count(self, char: str) -> str:
        deadline = time.monotonic() + 20
        last = -1
        while time.monotonic() < deadline:
            count = self.peer.output.count(char) if self.peer else 0
            if count == last:
                break
            last = count
            time.sleep(1)
        return str(last)

    def cmd_keyupdate(self, kind: str) -> str:
        self.peer.send("K\n" if kind == "requested" else "k\n")
        return "OK"

    def cmd_psk_client_badkey(self, port: str) -> str:
        return self.cmd_psk_client(port, "gcm", "x25519", bytes(32))

    def cmd_psk_client(self, port: str, cipher: str, group: str, key: bytes = PSK) -> str:
        peer = OpenSSL(["s_client", "-connect", f"{CALC}:{port}", *psk_args(cipher, group, key), "-quiet"],
                       self.tmp, None)
        time.sleep(2)
        peer.send("lwip-ce psk server check\n")
        deadline = time.monotonic() + 60
        while (time.monotonic() < deadline and "lwip-ce psk server check" not in peer.output
               and peer.proc.poll() is None):
            time.sleep(0.2)
        peer.stop()
        return "echo" if "lwip-ce psk server check" in peer.output else f"ERR {peer.output[-70:]!r}"

    # -- perf -----------------------------------------------------------------

    def cmd_udp_blast(self, count: str, size: str, port: str, gap_us: str) -> str:
        def blast():
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                for i in range(int(count)):
                    s.sendto(struct.pack("!I", i) + pattern(0, int(size) - 4), (CALC, int(port)))
                    time.sleep(int(gap_us) / 1e6)
        threading.Thread(target=blast, daemon=True).start()
        return "OK"


def setup_interface():
    subprocess.run(["sysctl", "-qw", f"net.ipv6.conf.{IFACE}.disable_ipv6=0"], capture_output=True)
    subprocess.run(["ip", "-6", "addr", "add", f"{HOST6}/64", "dev", IFACE, "nodad"], capture_output=True)


def serve(server, port: int, handler):
    srv = server(("::" if server in (TCP6, UDP6) else "0.0.0.0", port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# ---------------------------------------------------------------------------
# Suite runner
# ---------------------------------------------------------------------------

def write_autotest(path: Path, suite: str, usb: str, timeout_ms: int) -> None:
    program = SUITES[suite]
    files = [f"{suite}/bin/{program}.8xp"] + sorted(os.path.relpath(f, HERE) for f in COMMON.glob("*.8x*"))
    path.write_text(json.dumps({
        "description": f"lwIP-CE networked suite {program}",
        "transfer_files": files,
        "target": {"name": program, "isASM": True},
        "sequence": ["delay|20000", "key|clear", "action|launch:INSTALL", "hashWait|1", "key|left",
                     "key|enter", "delay|1000", usb, "action|launch", "hashWait|2", "delay|2000",
                     "saveVar|NETLOG", "key|enter"],
        "hashes": {
            "1": {"description": "lwIP-CE installed", "start": "vram_start", "size": "vram_16_size",
                  "expected_CRCs": ["F7C03D8D"], "timeout": 180000},
            "2": {"description": f"{program} finished", "start": "vram_start", "size": "vram_8_size",
                  "expected_CRCs": VERDICT_CRCS + [CRASH_CRC], "timeout": timeout_ms},
        },
    }, indent=2) + "\n")


def read_log(path: Path) -> str:
    data = path.read_bytes()
    length = int.from_bytes(data[0x48:0x4A], "little")
    return data[0x4A:0x4A + length].decode("latin-1")


def host_https_probe(host: str, phase: str, timeout: float = 15.0,
                     path: str | None = None) -> tuple[bool, str, str]:
    """Probe a failed public HTTPS endpoint with the runner's TLS stack."""
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    try:
        if phase == "tls":
            with socket.create_connection((host, 443), timeout=timeout) as raw:
                with context.wrap_socket(raw, server_hostname=host):
                    pass
        else:
            connection = http.client.HTTPSConnection(host, 443, timeout=timeout, context=context)
            try:
                method = "GET" if phase == "body" else "HEAD"
                connection.request(method, path or HTTPS_PATHS.get(host, "/"), headers={
                    "Host": host,
                    "Connection": "close",
                    "User-Agent": "lwip-ce-host-corroboration",
                })
                response = connection.getresponse()
                if phase == "body":
                    response.read()
            finally:
                connection.close()
        return True, "ok", "runner completed the equivalent probe"
    except socket.gaierror as exc:
        return False, "dns", f"DNS failure: {exc}"
    except (TimeoutError, socket.timeout) as exc:
        return False, "timeout", f"timeout: {exc}"
    except ConnectionResetError as exc:
        return False, "reset", f"connection reset: {exc}"
    except ssl.SSLCertVerificationError as exc:
        return False, "certificate", f"certificate verification failed: {exc.verify_message}"
    except ssl.SSLEOFError as exc:
        return False, "closed", f"TLS peer closed unexpectedly: {exc}"
    except ssl.SSLError as exc:
        return False, "tls", f"TLS failure: {exc.reason or exc}"
    except (ConnectionAbortedError, ConnectionRefusedError, BrokenPipeError, EOFError) as exc:
        return False, "closed", f"connection closed: {exc}"
    except http.client.HTTPException as exc:
        return False, "http", f"HTTP failure: {exc}"
    except OSError as exc:
        return False, "connect", f"connection failure: {exc}"


def host_wss_probe(host: str, path: str, timeout: float = 15.0) -> tuple[bool, str, str]:
    """Verify that a candidate completes a TLS 1.3 WebSocket upgrade."""
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    try:
        with socket.create_connection((host, 443), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                tls.settimeout(timeout)
                request = (
                    f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n"
                    "Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"
                    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
                )
                tls.sendall(request.encode())
                response = b""
                while b"\r\n\r\n" not in response and len(response) < 8192:
                    chunk = tls.recv(1024)
                    if not chunk:
                        break
                    response += chunk
                status = response.split(b"\r\n", 1)[0]
                if b" 101 " not in status:
                    return False, "http", f"WebSocket upgrade returned {status[:80]!r}"
        return True, "ok", "runner completed TLS 1.3 WebSocket upgrade"
    except socket.gaierror as exc:
        return False, "dns", f"DNS failure: {exc}"
    except (TimeoutError, socket.timeout) as exc:
        return False, "timeout", f"timeout: {exc}"
    except ssl.SSLCertVerificationError as exc:
        return False, "certificate", f"certificate verification failed: {exc.verify_message}"
    except ssl.SSLError as exc:
        return False, "tls", f"TLS failure: {exc.reason or exc}"
    except (ConnectionError, OSError, http.client.HTTPException) as exc:
        return False, "connect", f"connection failure: {exc}"


def cemu_failure_issue(lines: list[str], index: int, phase: str) -> str:
    if phase != "tls":
        return "http"
    for line in reversed(lines[max(0, index - 3):index]):
        match = SOCKET_STATUS.match(line)
        if not match:
            continue
        status, error = map(int, match.groups())
        if status == 7:
            return "reset"
        if status == 3 and error == 0:
            return "timeout"
        if status == 2 or error == 5:
            return "dns"
        return "connect"
    return "connect"


def similar_endpoint_issue(cemu_issue: str, host_issue: str) -> bool:
    similar = {
        "dns": {"dns"},
        "reset": {"reset", "closed"},
        "timeout": {"timeout"},
        "connect": {"reset", "closed", "timeout", "connect", "tls", "certificate"},
        "http": {"reset", "closed", "timeout", "connect", "tls", "certificate", "http"},
    }
    return host_issue in similar.get(cemu_issue, set())


def corroborate_external_https_failures(text: str, probe=host_https_probe) -> tuple[str, int, list[dict]]:
    """Turn only host-reproduced public HTTPS failures into explicit skips."""
    lines = text.splitlines()
    rendered: list[str] = []
    records: list[dict] = []
    skipped = 0
    for index, line in enumerate(lines):
        match = HTTPS_FAILURE.match(line)
        if not match:
            rendered.append(line)
            continue
        host = match.group("host")
        suffix = match.group("phase") or ""
        phase = "http" if suffix == " answers HTTP" else "body" if suffix == " full body" else "tls"
        cemu_issue = cemu_failure_issue(lines, index, phase)
        host_ok, host_issue, detail = probe(host, phase)
        corroborated = not host_ok and similar_endpoint_issue(cemu_issue, host_issue)
        records.append({
            "test": line[5:],
            "host": host,
            "phase": phase,
            "cemuIssue": cemu_issue,
            "hostIssue": host_issue,
            "hostDetail": detail,
            "skipped": corroborated,
        })
        if corroborated:
            skipped += 1
            rendered.append(
                f"SKIP {line[5:]} - endpoint issue/latency; host reproduced "
                f"{host_issue} after CEmu reported {cemu_issue}"
            )
            rendered.append(f"  host probe: {detail}")
        else:
            rendered.append(line)
            rendered.append(
                f"  host probe: {'passed; CEmu failure remains authoritative' if host_ok else detail}"
            )
    return "\n".join(rendered) + ("\n" if text.endswith("\n") else ""), skipped, records


def run_suite(suite: str, autotester: str, usb: str, timeout_ms: int) -> tuple[bool, str, dict, list[dict]]:
    autotest = HERE / f"autotest-{suite}.json"
    log_path = HERE / "NETLOG.8xv"
    log_path.unlink(missing_ok=True)
    write_autotest(autotest, suite, usb, timeout_ms)
    started = time.monotonic()
    crashed = False
    proc = subprocess.Popen([autotester, str(autotest)], cwd=HERE, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, errors="replace")
    for out in proc.stdout:
        if "transfer progress" not in out:
            print(out, end="", flush=True)
        if ("NMI reset" in out or CRASH_CRC in out) and not crashed:
            # The calc rebooted; nothing more will come from this suite.
            crashed = True
            proc.kill()
    status = proc.wait()
    wall = time.monotonic() - started
    if crashed or not log_path.exists():
        # Without NETLOG the calc never reached the end: it reset (NMI or the
        # home-screen CRC) or hung until the hash timeout.
        return False, (f"{SUITES[suite]}: calc crashed or hung after host request "
                       f"{CONTROL.last_request!r} (autotester exit {status})"), {}, []
    if False:
        return False, f"{SUITES[suite]}: NETLOG.8xv was not saved (autotester exit {status})", {}, []
    raw_text = read_log(log_path)
    log_path.replace(HERE / f"NETLOG-{suite}.8xv")
    metrics = {m.group(1): {"value": int(m.group(2)), "unit": m.group(3)}
               for m in re.finditer(r"^METRIC (\S+) (\d+) (\S+)$", raw_text, re.M)}
    metrics["host_wall_time"] = {"value": round(wall), "unit": "s"}
    done = re.search(r"DONE pass (\d+) fail (\d+)", raw_text)
    text, skipped, probes = corroborate_external_https_failures(raw_text)
    if done:
        effective_failures = max(0, int(done.group(2)) - skipped)
        text += (f"HOST-GRADE pass {done.group(1)} fail {effective_failures} "
                 f"skip {skipped}\n")
    else:
        effective_failures = 1
    metrics["host_skipped_endpoint_failures"] = {"value": skipped, "unit": "tests"}
    ok = status == 0 and bool(done) and effective_failures == 0 and int(done.group(1)) > 0
    return ok, text, metrics, probes


def build_test_rows(results: list[tuple[str, bool, str]]) -> list[dict[str, str]]:
    rows = []
    for suite, ok, text in results:
        suite_rows = 0
        last_test_row = None
        last_metric_name = None
        for line in text.splitlines():
            verdict, separator, test = line.partition(" ")
            if verdict == "METRIC" and separator and last_test_row is not None:
                parts = test.rsplit(" ", 2)
                if len(parts) == 3 and parts[2] == "ms":
                    name, value, unit = parts
                    timing = f"{value} {unit}"
                    if last_test_row.get("emulated_time"):
                        previous = last_test_row["emulated_time"]
                        if ";" not in previous:
                            previous_label = last_metric_name.removesuffix("_ms").rsplit(
                                "_", 1
                            )[-1]
                            previous = f"{previous_label}: {previous}"
                        label = name.removesuffix("_ms").rsplit("_", 1)[-1]
                        last_test_row["emulated_time"] = f"{previous}; {label}: {timing}"
                    else:
                        last_test_row["emulated_time"] = timing
                    last_metric_name = name
                continue
            if verdict not in {"PASS", "FAIL", "SKIP"} or not separator:
                continue
            last_test_row = {
                "group": "NETTEST",
                "module": "NETTEST",
                "test": f"{suite.upper()} - {test}",
                "grade": {"PASS": "Pass", "FAIL": "Fail", "SKIP": "Skipped"}[verdict],
            }
            last_metric_name = None
            rows.append(last_test_row)
            suite_rows += 1
        if not suite_rows:
            rows.append({"group": "NETTEST", "module": "NETTEST",
                         "test": f"{suite.upper()} - Suite execution",
                         "grade": "Pass" if ok else "Fail"})
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--autotester", required=True)
    ap.add_argument("--usb", required=True)
    ap.add_argument("--suite", action="append", choices=list(SUITES))
    ap.add_argument("--timeout", type=int, default=1800000)
    ap.add_argument("--metrics", default=str(HERE / "metrics.json"))
    ap.add_argument("--endpoint-probes", default=str(HERE / "endpoint-probes.json"))
    ap.add_argument("--rows", default=str(HERE / "test-rows.json"))
    ap.add_argument("--pcap", help="capture the TAP interface to this file (needs root and scapy)")
    args = ap.parse_args()

    setup_interface()
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        TLSBad.context = self_signed_context(tmp)
        for server, port, handler in [
            (TCP6, 7001, Echo), (UDP6, 7002, UDPEcho), (TCP, 7004, WebSocketEcho), (TCP, 7005, TLSBad),
            (TCP, 7006, Bulk), (TCP, 7007, Sink), (TCP, 7008, Hold), (TCP, 7009, HalfClose),
            (TCP, 7010, Reset), (TCP, 7011, Closer), (TCP, 7012, ExpectReset), (UDP, 7013, Broadcast), (UDP6, 7014, UDPLength),
            (TCP6, 7016, SizedBulk),
        ]:
            serve(server, port, handler)
        global CONTROL
        control = CONTROL = Control(tmp)
        capture = None
        if os.geteuid() == 0:
            try:
                control.start_sniffer()
                if args.pcap:
                    from scapy.all import AsyncSniffer
                    capture = AsyncSniffer(iface=IFACE)
                    capture.start()
            except ImportError:
                log("scapy missing: multicast, ACD and IPv6 router checks will fail")

        results, metrics, endpoint_probes = [], {}, []
        for suite in args.suite or list(SUITES):
            log(f"running {SUITES[suite]}")
            ok, text, values, probes = run_suite(suite, args.autotester, args.usb, args.timeout)
            metrics[suite] = values
            endpoint_probes.extend({"suite": suite, **probe} for probe in probes)
            results.append((suite, ok, text))
            print(text, flush=True)

        if capture:
            from scapy.all import wrpcap
            wrpcap(args.pcap, capture.stop())

    Path(args.metrics).write_text(json.dumps(metrics, indent=2) + "\n")
    Path(args.endpoint_probes).write_text(json.dumps(endpoint_probes, indent=2) + "\n")
    table_rows = build_test_rows(results)
    Path(args.rows).write_text(json.dumps(table_rows, indent=2) + "\n")
    for suite, ok, _ in results:
        print(f"{SUITES[suite]}: {'PASS' if ok else 'FAIL'}")
    return 0 if all(ok for _, ok, _ in results) else 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Host side of the networked lwIP-CE integration suite.

Serves the endpoints NETTEST talks to on the TAP gateway, runs NETTEST in
the CEmu autotester with the emulated USB Ethernet adapter plugged in, then
grades the NETLOG appvar the calc saved.

    python3 tests/net/run.py --autotester PATH --usb 'usb|eth,cemu0,...'

The TAP interface and NAT are set up by alessiodam/cemu-net-action in CI.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent / "common"
CALC = "192.168.84.2"
BULK_BYTES = 262144
SERVER_CLIENTS = 3
# CRC-32C of a solid green / red 8bpp screen: NETTEST's pass and fail verdicts.
VERDICT_CRCS = ["A511C030", "22D544B5"]


def pattern(start: int, n: int) -> bytes:
    return bytes(((i * 31) + (i >> 8)) & 0xFF for i in range(start, start + n))


class TCP(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            while data := self.request.recv(4096):
                self.request.sendall(data)
        except ConnectionResetError:
            pass


class Bulk(socketserver.BaseRequestHandler):
    def handle(self):
        for off in range(0, BULK_BYTES, 8192):
            self.request.sendall(pattern(off, 8192))


class WebSocketEcho(socketserver.BaseRequestHandler):
    GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    def recv_exact(self, n: int) -> bytes:
        data = b""
        while len(data) < n:
            chunk = self.request.recv(n - len(data))
            if not chunk:
                raise ConnectionError
            data += chunk
        return data

    def handle(self):
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
        try:
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
                header = bytes([0x80 | opcode])
                header += bytes([n]) if n < 126 else b"\x7e" + n.to_bytes(2, "big")
                self.request.sendall(header + payload)
        except (ConnectionError, ValueError):
            pass


class UDPEcho(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)


def self_signed_context(tmp: Path) -> ssl.SSLContext:
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-nodes", "-days", "2", "-subj", "/CN=192.168.84.1",
                    "-addext", "subjectAltName=IP:192.168.84.1",
                    "-keyout", str(tmp / "key.pem"), "-out", str(tmp / "cert.pem")],
                   check=True, capture_output=True)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(tmp / "cert.pem", tmp / "key.pem")
    return ctx


class TLSBad(socketserver.BaseRequestHandler):
    context: ssl.SSLContext
    outcomes: list[str] = []

    def handle(self):
        try:
            with self.context.wrap_socket(self.request, server_side=True) as tls:
                tls.recv(1)
                self.outcomes.append("handshake completed")
        except ssl.SSLError as e:
            self.outcomes.append(e.reason or str(e))
        except OSError as e:
            self.outcomes.append(str(e))


def connect_to_calc(port: int, stop: threading.Event, results: list[str]) -> None:
    sent = 0
    while not stop.is_set() and sent < SERVER_CLIENTS:
        try:
            with socket.create_connection((CALC, port), timeout=5) as s:
                msg = f"lwip-ce-server-{sent}".encode()
                s.sendall(msg)
                echo = b""
                while len(echo) < len(msg):
                    chunk = s.recv(64)
                    if not chunk:
                        break
                    echo += chunk
                results.append(f"server client {sent}: {'ok' if echo == msg else repr(echo)}")
                sent += 1
        except OSError:
            stop.wait(1)


def serve(cls, port: int, udp: bool = False):
    server = (socketserver.ThreadingUDPServer if udp else TCP)(("0.0.0.0", port), cls)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def autotest(out: Path, usb: str, timeout_ms: int) -> None:
    files = ["bin/NETTEST.8xp"] + sorted(os.path.relpath(f, HERE) for f in COMMON.glob("*.8x*"))
    full = {"start": "vram_start", "size": "vram_8_size"}
    out.write_text(json.dumps({
        "description": "lwIP-CE networked integration suite (DHCP, DNS, TCP, UDP, WS, TLS, server)",
        "transfer_files": files,
        "target": {"name": "NETTEST", "isASM": True},
        "sequence": ["delay|20000", "key|clear", "action|launch:INSTALL", "hashWait|1", "key|left",
                     "key|enter", "delay|1000", usb, "action|launch", "hashWait|2", "delay|2000",
                     "saveVar|NETLOG", "key|enter"],
        "hashes": {
            "1": {"description": "lwIP-CE installed", "start": "vram_start", "size": "vram_16_size",
                  "expected_CRCs": ["F7C03D8D"], "timeout": 180000},
            "2": {**full, "description": "NETTEST finished",
                  "expected_CRCs": VERDICT_CRCS,
                  "timeout": timeout_ms},
        },
    }, indent=2) + "\n")


def read_log(path: Path) -> str:
    data = path.read_bytes()
    length = int.from_bytes(data[0x48:0x4A], "little")
    return data[0x4A:0x4A + length].decode("latin-1")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--autotester", required=True)
    ap.add_argument("--usb", required=True)
    ap.add_argument("--timeout", type=int, default=1800000)
    args = ap.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        TLSBad.context = self_signed_context(Path(tmp))
        servers = [serve(Echo, 7001), serve(UDPEcho, 7002, udp=True), serve(WebSocketEcho, 7004),
                   serve(TLSBad, 7005), serve(Bulk, 7006)]
        stop = threading.Event()
        client_log: list[str] = []
        threading.Thread(target=connect_to_calc, args=(7003, stop, client_log), daemon=True).start()

        log_path = HERE / "NETLOG.8xv"
        log_path.unlink(missing_ok=True)
        autotest(HERE / "autotest.json", args.usb, args.timeout)
        started = time.monotonic()
        status = subprocess.run([args.autotester, str(HERE / "autotest.json")], cwd=HERE).returncode
        stop.set()
        for server in servers:
            server.shutdown()

    tls_alert = any("ALERT" in o for o in TLSBad.outcomes)
    client_log.append(f"self-signed TLS fixture: {', '.join(TLSBad.outcomes) or 'no connection'}")
    client_log.append(f"{'PASS' if tls_alert else 'FAIL'} calc sent a TLS alert for the untrusted certificate")
    server_ok = sum(line.endswith(": ok") for line in client_log) == SERVER_CLIENTS
    print(f"autotester exit {status} after {time.monotonic() - started:.0f}s")
    print("\n".join(client_log))
    if not log_path.exists():
        print("NETLOG.8xv was not saved")
        return 1
    log = read_log(log_path)
    print(log)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write("## NETTEST on CEmu\n\n```\n" + log + "\n" + "\n".join(client_log) + "\n```\n")
    done = re.search(r"DONE pass (\d+) fail (\d+)", log)
    passed = done and done.group(2) == "0" and int(done.group(1)) > 0
    return 0 if status == 0 and passed and tls_alert and server_ok else 1


if __name__ == "__main__":
    sys.exit(main())

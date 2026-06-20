#!/usr/bin/env python3
"""lwIP-CE DAST probe runner.

Pairs with the calc-side harness in tests/profiling/lwip_dast. The two
sides walk tests/profiling/lwip_dast/dast_tests.json in the SAME ORDER:

  - this script prepares any host-side fixture needed by the test
  - the calc enters the per-test `state`
    (idle / udp_recv / tcp_listen / tls_client)
  - this script sends the `probe` at the calc, or services a TLS fixture
  - this script grades the report against the test's `ok_responses`
  - results are written to tests/dast.json

Manual `notes` and any `grade` override you hand-edit into tests/dast.json
are carried over across runs, keyed by test id.

Usage:
    sudo ./build-tools/dast/lwip-dast.sh --ip 192.168.1.42
    python3 build-tools/dast/lwip-dast.py --gen-header   # regen calc-side C list
    python3 build-tools/dast/lwip-dast.py --ip ... --self-test  # no scapy, dry run
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST = REPO_ROOT / "tests" / "profiling" / "lwip_dast" / "dast_tests.json"
REPORT = REPO_ROOT / "tests" / "dast.json"
GEN_HEADER = REPO_ROOT / "tests" / "profiling" / "lwip_dast" / "src" / "dast_tests.h"

# Outcomes the operator can report. Anything not "ALIVE/REPLY/ACCEPT/ABORT/RST"
# (i.e. CRASH/HANG) is always a FAIL regardless of the test's ok_responses.
VALID_RESPONSES = ["ALIVE", "REPLY", "ACCEPT", "ABORT", "RST", "CRASH", "HANG", "SKIP"]
FATAL_RESPONSES = {"CRASH", "HANG"}


# ---------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------

def load_manifest() -> list[dict]:
    data = json.loads(MANIFEST.read_text())
    tests = data.get("tests", [])
    if not tests:
        die(f"no tests in {MANIFEST}")
    return tests


def die(msg: str) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------
# Calc-side C header generation
# ---------------------------------------------------------------------

STATE_ENUM = {
    "idle": "DAST_STATE_IDLE",
    "udp_recv": "DAST_STATE_UDP_RECV",
    "tcp_listen": "DAST_STATE_TCP_LISTEN",
    "tls_client": "DAST_STATE_TLS_CLIENT",
    "raw_recv": "DAST_STATE_RAW_RECV",
}


def gen_header() -> None:
    tests = load_manifest()
    lines = [
        "/* AUTO-GENERATED from tests/profiling/lwip_dast/dast_tests.json.",
        " * Do not edit by hand; run:",
        " *     python3 build-tools/dast/lwip-dast.py --gen-header",
        " * Keeps the calc-side harness in lockstep with the probe runner. */",
        "#ifndef LWIP_DAST_TESTS_H",
        "#define LWIP_DAST_TESTS_H",
        "",
        "#include <stdint.h>",
        "",
        "typedef enum {",
        "    DAST_STATE_IDLE = 0,",
        "    DAST_STATE_UDP_RECV,",
        "    DAST_STATE_TCP_LISTEN,",
        "    DAST_STATE_TLS_CLIENT,",
        "    DAST_STATE_RAW_RECV",
        "} dast_state_t;",
        "",
        "typedef struct {",
        "    const char  *id;",
        "    const char  *name;",
        "    dast_state_t state;",
        "    uint16_t     port;",
        "    const char  *intent;",
        "} dast_test_t;",
        "",
        f"#define DAST_TEST_COUNT {len(tests)}",
        "",
        "static const dast_test_t dast_tests[DAST_TEST_COUNT] = {",
    ]
    for t in tests:
        state = STATE_ENUM.get(t["state"])
        if state is None:
            die(f"test {t['id']}: unknown state {t['state']!r}")
        name = c_str(t["name"])
        intent = c_str(t["intent"])
        lines.append(
            f'    {{ {c_str(t["id"])}, {name}, {state}, '
            f'{int(t.get("port", 0))}, {intent} }},'
        )
    lines += [
        "};",
        "",
        "#endif /* LWIP_DAST_TESTS_H */",
        "",
    ]
    GEN_HEADER.parent.mkdir(parents=True, exist_ok=True)
    GEN_HEADER.write_text("\n".join(lines))
    print(f"wrote {GEN_HEADER.relative_to(REPO_ROOT)} ({len(tests)} tests)")


def c_str(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


# ---------------------------------------------------------------------
# Probes (scapy)
# ---------------------------------------------------------------------

class Probes:
    """Each method name matches a manifest `probe` key. Methods take the
    target IP (and optional port) and emit packets. Scapy is imported
    lazily so --gen-header / --self-test work without it / without root."""

    def __init__(self, ip: str, iface: str | None, dry: bool):
        self.ip = ip
        self.iface = iface
        self.dry = dry
        self._scapy = None

    @property
    def s(self):
        if self._scapy is None:
            try:
                import scapy.all as scapy  # type: ignore
            except ImportError:
                die("scapy not installed. Run: pip install scapy")
            self._scapy = scapy
        return self._scapy

    def _send(self, pkts, *, l2=False, count=1, inter=0.0):
        if self.dry:
            n = len(pkts) if isinstance(pkts, list) else 1
            print(f"    [dry-run] would send {n} packet(s)"
                  f"{' x%d' % count if count > 1 else ''}")
            return
        kw = {"verbose": False, "count": count, "inter": inter}
        if self.iface:
            kw["iface"] = self.iface
        (self.s.sendp if l2 else self.s.send)(pkts, **kw)

    # -- ICMP / liveness --------------------------------------------
    def icmp_echo_normal(self, port=0):
        s = self.s
        self._send(s.IP(dst=self.ip) / s.ICMP() / (b"lwip-dast" * 4))

    def icmp_oversize(self, port=0):
        s = self.s
        # 3000 bytes forces 2-3 IP fragments (just over one MTU) without
        # exhausting the 8KB pbuf pool. Tests the multi-fragment reassembly
        # path and drop behavior without killing the stack.
        pkts = s.fragment(s.IP(dst=self.ip) / s.ICMP() / (b"A" * 3000))
        self._send(pkts)

    def icmp_malformed(self, port=0):
        s = self.s
        # Truncated ICMP + deliberately wrong checksum.
        bad = s.IP(dst=self.ip) / s.ICMP(chksum=0xDEAD) / b"\x08\x00"
        self._send(bad)

    # -- ARP ---------------------------------------------------------
    def arp_malformed(self, port=0):
        s = self.s
        # Bogus hardware/proto length fields + truncated body.
        arp = s.ARP(op=1, pdst=self.ip, hwlen=99, plen=99)
        self._send(s.Ether(dst="ff:ff:ff:ff:ff:ff") / arp, l2=True)

    def arp_flood(self, port=0):
        s = self.s
        arp = s.Ether(dst="ff:ff:ff:ff:ff:ff") / s.ARP(op=1, pdst=self.ip)
        self._send(arp, l2=True, count=200, inter=0.002)

    # -- IP ----------------------------------------------------------
    def ip_bad_checksum(self, port=0):
        s = self.s
        self._send(s.IP(dst=self.ip, chksum=0x1234) / s.ICMP())

    def ip_frag_overlap(self, port=0):
        s = self.s
        # Two overlapping fragments of one ICMP echo (teardrop pattern).
        payload = b"B" * 80
        f1 = s.IP(dst=self.ip, id=0x4242, flags="MF", frag=0) / s.ICMP() / payload
        f2 = s.IP(dst=self.ip, id=0x4242, flags=0, frag=2) / (b"C" * 80)
        self._send([f1, f2])

    def ip_frag_bomb(self, port=0):
        s = self.s
        # Many first-fragments that are never completed -> reassembly pressure.
        pkts = [
            s.IP(dst=self.ip, id=0x5000 + i, flags="MF", frag=0)
            / s.ICMP() / (b"D" * 64)
            for i in range(64)
        ]
        self._send(pkts, inter=0.005)

    # -- UDP ---------------------------------------------------------
    def udp_normal(self, port):
        s = self.s
        self._send(s.IP(dst=self.ip) / s.UDP(dport=port, sport=40000) / b"hello")

    def udp_oversize(self, port):
        s = self.s
        # Fragment at the IP layer so the OS socket limit isn't hit.
        pkts = s.fragment(s.IP(dst=self.ip) / s.UDP(dport=port, sport=40000) / (b"E" * 9000))
        self._send(pkts)

    def udp_malformed(self, port):
        s = self.s
        # UDP length field claims more than is present + bad checksum.
        u = s.UDP(dport=port, sport=40000, len=9999, chksum=0xBEEF)
        self._send(s.IP(dst=self.ip) / u / b"short")

    # -- TCP ---------------------------------------------------------
    def tcp_syn_closed(self, port=0):
        s = self.s
        # SYN to a port the calc is not listening on -> expect RST.
        self._send(s.IP(dst=self.ip) / s.TCP(dport=65500, sport=40001, flags="S"))

    def tcp_connect_data(self, port):
        # Real handshake via a stream socket so the listen path is exercised.
        import socket
        with socket.create_connection((self.ip, port), timeout=5) as sk:
            sk.sendall(b"lwip-dast-tcp\n")
            sk.settimeout(2)
            try:
                sk.recv(64)
            except (socket.timeout, OSError):
                pass

    def tcp_flag_storm(self, port):
        s = self.s
        # NULL, FIN, XMAS, SYN+FIN, SYN+RST.
        flags = ["", "F", "FPU", "FS", "SR"]
        pkts = [s.IP(dst=self.ip) / s.TCP(dport=port, sport=40002 + i, flags=f)
                for i, f in enumerate(flags)]
        self._send(pkts)

    def tcp_tiny_window(self, port):
        s = self.s
        # SYN with window 0, then an out-of-window overlapping data segment.
        syn = s.IP(dst=self.ip) / s.TCP(dport=port, sport=40010, flags="S", window=0)
        ovl = s.IP(dst=self.ip) / s.TCP(dport=port, sport=40010, flags="PA",
                                        seq=1, window=1) / (b"F" * 200)
        self._send([syn, ovl])

    def tcp_data_overflow(self, port):
        import socket
        try:
            with socket.create_connection((self.ip, port), timeout=5) as sk:
                sk.sendall(b"G" * 65536)
        except OSError:
            pass


# ---------------------------------------------------------------------
# TLS fixtures
# ---------------------------------------------------------------------

TLS_PROBES = {
    "tls_echo_clean",
    "tls_echo_resume",
    "tls_missing_record",
    "tls_unsupported_certverify",
}

TLS_ECHO_TIMEOUT = 45.0
TLS_TEST_CERT_DIR = Path(tempfile.gettempdir()) / "lwip-ce-dast-tls"


def ensure_test_cert(kind: str) -> tuple[Path, Path]:
    TLS_TEST_CERT_DIR.mkdir(parents=True, exist_ok=True)
    cert = TLS_TEST_CERT_DIR / f"{kind}.crt"
    key = TLS_TEST_CERT_DIR / f"{kind}.key"
    if cert.is_file() and key.is_file():
        return cert, key

    import shutil
    openssl = shutil.which("openssl")
    if not openssl:
        die("openssl is required to generate DAST TLS test certificates")

    if kind == "rsa":
        cmd = [
            openssl, "req", "-x509", "-newkey", "rsa:2048",
            "-sha256", "-nodes", "-days", "1",
            "-subj", "/CN=lwip-dast-rsa",
            "-keyout", str(key), "-out", str(cert),
        ]
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
    elif kind == "ecdsa":
        subprocess.run(
            [openssl, "ecparam", "-name", "prime256v1", "-genkey",
             "-noout", "-out", str(key)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(
            [openssl, "req", "-new", "-x509", "-sha256", "-days", "1",
             "-subj", "/CN=lwip-dast-ecdsa",
             "-key", str(key), "-out", str(cert)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        die(f"unknown TLS cert kind {kind!r}")
    return cert, key


def make_tls_context(kind: str) -> ssl.SSLContext:
    cert, key = ensure_test_cert(kind)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    except ValueError:
        die("this Python ssl backend cannot serve TLS 1.3; set "
            "DAST_PYTHON to an OpenSSL-backed Python, e.g. "
            "/opt/homebrew/bin/python3.11")
    try:
        ctx.set_ciphersuites("TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384")
    except AttributeError:
        pass
    try:
        ctx.session_id_ctx = b"lwip-dast"
    except AttributeError:
        pass
    ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
    return ctx


class TlsProbeServer:
    def __init__(self, *, bind: str, port: int, probe: str, context: ssl.SSLContext | None):
        self.bind = bind
        self.port = port
        self.probe = probe
        self.context = context
        self.payload = f"lwip-dast:{probe}".encode()
        self.ready = threading.Event()
        self.done = threading.Event()
        self.ok = False
        self.response = "HANG"
        self.detail = ""
        self.session_reused = False
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self.thread.start()
        if not self.ready.wait(5.0):
            raise RuntimeError("TLS server did not start listening")
        if self.detail.startswith("listen failed"):
            raise RuntimeError(self.detail)

    def wait(self, timeout: float) -> bool:
        return self.done.wait(timeout)

    def _run(self) -> None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind((self.bind, self.port))
                srv.listen(1)
                srv.settimeout(20.0)
                self.ready.set()
                conn, peer = srv.accept()
                with conn:
                    conn.settimeout(20.0)
                    if self.probe == "tls_missing_record":
                        self._missing_record(conn, peer)
                    else:
                        self._tls_echo(conn, peer)
        except Exception as exc:  # noqa: BLE001
            if not self.ready.is_set():
                self.detail = f"listen failed: {type(exc).__name__}: {exc}"
                self.response = "HANG"
            elif self.probe.startswith("tls_") and self.probe not in (
                    "tls_echo_clean", "tls_echo_resume"):
                self.detail = f"{type(exc).__name__}: {exc}"
                self.response = "ABORT"
            else:
                self.detail = f"{type(exc).__name__}: {exc}"
                self.response = "HANG"
        finally:
            self.ready.set()
            self.done.set()

    def _missing_record(self, conn: socket.socket, peer) -> None:
        self.detail = f"accepted {peer}, closed before server TLS record"
        try:
            conn.recv(512)
        except OSError:
            pass
        self.ok = True
        self.response = "ABORT"

    def _tls_echo(self, conn: socket.socket, peer) -> None:
        if self.context is None:
            raise RuntimeError("missing TLS context")
        with self.context.wrap_socket(conn, server_side=True) as tls:
            tls.settimeout(20.0)
            reused = getattr(tls, "session_reused", False)
            self.session_reused = bool(reused)
            if self.probe == "tls_echo_resume" and not self.session_reused:
                self.detail = f"{peer} completed TLS but did not resume"
                self.response = "ABORT"
                return
            tls.sendall(self.payload)
            echoed = b""
            while len(echoed) < len(self.payload):
                chunk = tls.recv(len(self.payload) - len(echoed))
                if not chunk:
                    break
                echoed += chunk
            self.ok = echoed == self.payload
            self.response = "REPLY" if self.ok else "ABORT"
            self.detail = (f"{peer} echoed {len(echoed)} bytes"
                           f"{' with PSK resume' if self.session_reused else ''}")


class TlsFixtures:
    def __init__(self, bind: str, dry: bool):
        self.bind = bind
        self.dry = dry
        self._rsa_context: ssl.SSLContext | None = None
        self._ecdsa_context: ssl.SSLContext | None = None

    def _context(self, probe: str) -> ssl.SSLContext | None:
        if probe == "tls_missing_record":
            return None
        if probe == "tls_unsupported_certverify":
            if self._ecdsa_context is None:
                self._ecdsa_context = make_tls_context("ecdsa")
            return self._ecdsa_context
        if self._rsa_context is None:
            self._rsa_context = make_tls_context("rsa")
        return self._rsa_context

    def start(self, probe: str, port: int) -> TlsProbeServer | None:
        if self.dry:
            print(f"    [dry-run] would start TLS fixture {probe} on :{port}")
            return None
        server = TlsProbeServer(bind=self.bind, port=port, probe=probe,
                                context=self._context(probe))
        server.start()
        return server


# ---------------------------------------------------------------------
# Liveness + operator prompt + grading
# ---------------------------------------------------------------------

def ping_alive(ip: str, dry: bool) -> bool | None:
    """Best-effort ICMP liveness via the system ping. Returns None if the
    operator should decide instead (dry-run or ping unavailable)."""
    if dry:
        return None
    import shutil
    import subprocess
    ping = shutil.which("ping")
    if not ping:
        return None
    flag = "-c" if sys.platform != "win32" else "-n"
    try:
        r = subprocess.run([ping, flag, "2", "-W", "1", ip],
                           capture_output=True, timeout=8)
        return r.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def prompt_response(test: dict, ping_state: bool | None, assume: str | None) -> str:
    hint = ""
    if ping_state is True:
        hint = "  (ping: calc still responds)"
    elif ping_state is False:
        hint = "  (ping: NO response — possible crash/hang)"
    if assume:
        print(f"    [auto] response = {assume}{hint}")
        return assume
    print(f"    expect: {test['expect']}  "
          f"ok = {', '.join(test['ok_responses'])}{hint}")
    while True:
        raw = input(f"    calc response for [{test['id']}] "
                    f"({'/'.join(VALID_RESPONSES)}): ").strip().upper()
        if raw in VALID_RESPONSES:
            return raw
        print(f"    invalid — choose one of {', '.join(VALID_RESPONSES)}")


def grade(test: dict, response: str) -> str:
    if response == "SKIP":
        return "skip"
    if response in FATAL_RESPONSES:
        return "fail"
    return "ok" if response in test["ok_responses"] else "fail"


# ---------------------------------------------------------------------
# Report (with manual-note carryover)
# ---------------------------------------------------------------------

def load_prior() -> dict[str, dict]:
    if not REPORT.is_file():
        return {}
    try:
        prior = json.loads(REPORT.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return {r["id"]: r for r in prior.get("results", []) if "id" in r}


def write_report(target_ip: str, results: list[dict]) -> None:
    fails = sum(1 for r in results if r["grade"] == "fail")
    doc = {
        "tool": "lwip-dast",
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target_ip": target_ip,
        "summary": {
            "total": len(results),
            "ok": sum(1 for r in results if r["grade"] == "ok"),
            "fail": fails,
            "skip": sum(1 for r in results if r["grade"] == "skip"),
        },
        "results": results,
    }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"\nwrote {REPORT.relative_to(REPO_ROOT)}: "
          f"{doc['summary']['ok']} ok / {fails} fail / "
          f"{doc['summary']['skip']} skip")


# ---------------------------------------------------------------------
# Control channel — sends START/NEXT/DONE/ABRT to the calc's UDP port
# 9997 and, for START/NEXT, waits for a READY reply on the same port
# before returning. The calc replies to whatever peer address sent it
# the last control message, on the calc's own listening port (9997) --
# not back to the sender's ephemeral source port -- so the host must
# itself be bound to 9997 to receive it.
# ---------------------------------------------------------------------

DAST_CTRL_PORT = 9997
DAST_CTRL_READY_TIMEOUT = 10.0  # seconds to wait for READY after START/NEXT


def ctrl_send(ip: str, msg: str) -> None:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(msg.encode(), (ip, DAST_CTRL_PORT))


def ctrl_send_and_wait_ready(ip: str, msg: str,
                             timeout: float = DAST_CTRL_READY_TIMEOUT) -> bool:
    """Send a control message and block until the calc replies READY.

    Returns True on READY, False on timeout (caller decides whether that's
    fatal). Binds to DAST_CTRL_PORT locally so the calc's reply -- sent
    back to that same port on this host -- actually reaches us.
    """
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", DAST_CTRL_PORT))
        s.settimeout(timeout)
        print(f"    [ctrl] sending {msg!r} to {ip}:{DAST_CTRL_PORT} "
              f"(bound locally on {DAST_CTRL_PORT})")
        s.sendto(msg.encode(), (ip, DAST_CTRL_PORT))
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                print(f"    [ctrl] timed out waiting for READY ({timeout:.0f}s)")
                return False
            s.settimeout(remaining)
            try:
                data, peer = s.recvfrom(64)
            except socket.timeout:
                print(f"    [ctrl] timed out waiting for READY ({timeout:.0f}s)")
                return False
            print(f"    [ctrl] got {data!r} from {peer}")
            if data.strip() == b"READY":
                return True
            # Anything else (e.g. a stray NEXT echo) — keep waiting for READY
            # until the deadline.


# ---------------------------------------------------------------------
# Run loop
# ---------------------------------------------------------------------

def run(args) -> int:
    tests = load_manifest()
    prior = load_prior()
    probes = Probes(args.ip, args.iface, dry=args.self_test)
    tls_fixtures = TlsFixtures(args.tls_bind, dry=args.self_test)

    print(f"==> lwIP-CE DAST against {args.ip}"
          f"{' [self-test/dry-run]' if args.self_test else ''}")
    print()
    print(f"  {len(tests)} automated stress tests for lwIP-CE.")
    print("  Each test sends malformed, oversized, or flood traffic at the calc,")
    print("  then follows up with a ping to check if the stack is still alive.")
    print("  ALIVE/REPLY = pass. No ping response = CRASH = fail.")
    print("  You will only be prompted if liveness cannot be auto-determined.")
    print()
    print("  On the calc: launch the DAST harness and wait for an IP address.")
    print("  The script will drive the calc automatically via the control channel.")
    print("  Press [clear] on the calc at any time to abort.")
    print()
    if not args.self_test:
        input("  Is the calc currently running the DAST client and on the screen "
              "that prints the IP address? If not, please run LWDAST and ensure "
              "that it is. Then press Enter")
        print("  Sending START...")
        if not ctrl_send_and_wait_ready(args.ip, "START"):
            die("calc did not reply READY to START "
                f"(waited {DAST_CTRL_READY_TIMEOUT:.0f}s) -- is it on the IP "
                "screen and reachable?")
        print("  Calc READY, starting tests.")

    results: list[dict] = []
    for i, t in enumerate(tests, 1):
        print(f"[{i}/{len(tests)}] {t['id']} — {t['name']}")
        print(f"    state: {t['state']}"
              + (f":{t['port']}" if t.get("port") else "")
              + f"   intent: {t['intent']}")

        probe_fn = getattr(probes, t["probe"], None)
        is_tls = t["probe"] in TLS_PROBES
        tls_server = None
        if is_tls:
            print(f"    probe: {t['probe']}")
            tls_server = tls_fixtures.start(t["probe"], int(t["port"]))
        elif probe_fn is None:
            die(f"test {t['id']}: no probe method {t['probe']!r}")

        if not args.self_test:
            # START already advanced the calc into test 1 and got its READY
            # (see the START handshake above) -- sending NEXT here too would
            # double-advance it into test 2 before the host ever probes test
            # 1, putting the calc permanently one test ahead of the host for
            # the rest of the run. Only tests 2+ need an explicit NEXT to
            # leave the previous test and enter this one.
            if i > 1:
                if not ctrl_send_and_wait_ready(args.ip, "NEXT"):
                    die(f"test {t['id']}: calc did not reply READY to NEXT "
                        f"(waited {DAST_CTRL_READY_TIMEOUT:.0f}s) -- it may "
                        "have crashed or hung; see partial results")

        if is_tls:
            if args.self_test:
                response = ("REPLY" if t["probe"] in
                            ("tls_echo_clean", "tls_echo_resume") else "ABORT")
                ping_state = None
                print(f"    [dry-run] would wait for TLS fixture completion")
            else:
                assert tls_server is not None
                if not tls_server.wait(TLS_ECHO_TIMEOUT):
                    response = "HANG"
                    print("    TLS fixture timed out")
                else:
                    response = tls_server.response
                    print(f"    TLS fixture: {tls_server.detail}")
                ping_state = ping_alive(args.ip, args.self_test)
                if ping_state is False and response in ("ABORT", "ALIVE"):
                    response = "CRASH"
            hint = ("(ping: alive)" if ping_state is True
                    else "(ping: NO response)" if ping_state is False
                    else "")
            print(f"    [auto] {response}  {hint}")
        else:
            # No fixed settle needed before dispatching the probe -- the
            # READY reply already confirms the calc's listener is open.
            print(f"    probe: {t['probe']}")
            if args.self_test:
                print(f"    [dry-run] would dispatch {t['probe']}")
            else:
                try:
                    if t.get("port"):
                        probe_fn(t["port"])
                    else:
                        probe_fn()
                except Exception as exc:  # noqa: BLE001
                    print(f"    probe raised: {exc!r}")

            # Fragment/flood tests need extra settle for the reassembly reaper.
            settle = 14.0 if t["probe"] in ("ip_frag_bomb", "ip_frag_overlap",
                                             "icmp_oversize") else args.settle
            time.sleep(settle)
            ping_state = ping_alive(args.ip, args.self_test)
            assume = "ALIVE" if args.self_test else None

            if not assume:
                if ping_state is True:
                    assume = "REPLY" if t["expect"] == "reply" else "ALIVE"
                elif ping_state is False:
                    assume = "CRASH"

            if assume:
                response = assume
                hint = ("(ping: alive)" if ping_state is True
                        else "(ping: NO response)" if ping_state is False
                        else "")
                print(f"    [auto] {response}  {hint}")
            else:
                response = prompt_response(t, ping_state, None)

        g = grade(t, response)
        rec = {
            "id": t["id"],
            "name": t["name"],
            "command": f"probe={t['probe']} target={args.ip}"
                       + (f":{t['port']}" if t.get("port") else ""),
            "intent": t["intent"],
            "expect": t["expect"],
            "response": response,
            "ping_alive": ping_state,
            "grade": g,
        }
        old = prior.get(t["id"], {})
        if old.get("notes"):
            rec["notes"] = old["notes"]
        if old.get("grade_override"):
            rec["grade_override"] = old["grade_override"]
            rec["grade"] = old["grade_override"]
        print(f"    => {response}  grade={rec['grade']}\n")
        results.append(rec)

        # Tell the calc to finish. Non-final tests are advanced by the next
        # iteration's NEXT, after any host-side fixture has been prepared.
        if not args.self_test:
            is_last = (i == len(tests))
            if is_last:
                ctrl_send(args.ip, "DONE")

    if args.self_test:
        print("\n[dry-run] report not written")
    else:
        write_report(args.ip, results)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="lwIP-CE DAST probe runner")
    ap.add_argument("--ip", help="target calc IPv4 address (prompted if omitted)")
    ap.add_argument("--iface", help="network interface to send from")
    ap.add_argument("--settle", type=float, default=1.0,
                    help="seconds to wait after a probe before grading")
    ap.add_argument("--tls-bind", default="0.0.0.0",
                    help="local address for host-side TLS fixtures")
    ap.add_argument("--gen-header", action="store_true",
                    help="regenerate the calc-side C test list and exit")
    ap.add_argument("--self-test", action="store_true",
                    help="dry run: no packets, no prompts, no root needed")
    args = ap.parse_args()

    if args.gen_header:
        gen_header()
        return 0

    if not args.ip and not args.self_test:
        args.ip = input("  Enter calc IP address (shown on DAST screen): ").strip()
    if not args.ip:
        args.ip = "0.0.0.0"  # self-test placeholder

    return run(args)


if __name__ == "__main__":
    sys.exit(main())

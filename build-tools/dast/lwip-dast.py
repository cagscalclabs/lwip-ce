#!/usr/bin/env python3
"""lwIP-CE DAST probe runner.

Pairs with the calc-side harness in tests/profiling/lwip_dast. The two
sides walk tests/profiling/lwip_dast/dast_tests.json in the SAME ORDER:

  - the calc enters the per-test `state` (idle / udp_recv / tcp_listen)
  - this script sends the `probe` (scapy) at the calc
  - the operator reads what the calc did off its screen and reports it
  - this script grades the report against the test's `ok_responses`
  - results are written to tests/dast.json

Crash-vs-abort can only be judged by a human watching the calc, so the
operator is prompted after each probe. Manual `notes` and any `grade`
override you hand-edit into tests/dast.json are carried over across runs,
keyed by test id.

Usage:
    sudo ./build-tools/dast/lwip-dast.sh --ip 192.168.1.42
    python3 build-tools/dast/lwip-dast.py --gen-header   # regen calc-side C list
    python3 build-tools/dast/lwip-dast.py --ip ... --self-test  # no scapy, dry run
"""

from __future__ import annotations

import argparse
import json
import os
import sys
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
        # Large payload forcing IP fragmentation + big reassembly.
        self._send(s.IP(dst=self.ip) / s.ICMP() / (b"A" * 60000))

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
        self._send(s.IP(dst=self.ip) / s.UDP(dport=port, sport=40000) / (b"E" * 9000))

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
# Run loop
# ---------------------------------------------------------------------

def run(args) -> int:
    tests = load_manifest()
    prior = load_prior()
    probes = Probes(args.ip, args.iface, dry=args.self_test)

    print(f"==> lwIP-CE DAST against {args.ip}"
          f"{' [self-test/dry-run]' if args.self_test else ''}")
    print(f"    {len(tests)} tests. Put the calc into its DAST harness and")
    print("    advance it in lockstep: after each probe, read the calc and report.\n")

    results: list[dict] = []
    for i, t in enumerate(tests, 1):
        print(f"[{i}/{len(tests)}] {t['id']} — {t['name']}")
        print(f"    state: {t['state']}"
              + (f":{t['port']}" if t.get("port") else "")
              + f"   intent: {t['intent']}")
        if not args.self_test and t["state"] != "idle":
            input(f"    >> set calc to '{t['state']}' state for this test, "
                  "then press Enter to probe...")

        probe_fn = getattr(probes, t["probe"], None)
        if probe_fn is None:
            die(f"test {t['id']}: no probe method {t['probe']!r}")
        print(f"    probe: {t['probe']}")
        if args.self_test:
            print(f"    [dry-run] would dispatch {t['probe']}")
        else:
            try:
                if t.get("port"):
                    probe_fn(t["port"])
                else:
                    probe_fn()
            except Exception as exc:  # noqa: BLE001 — surface, don't abort the run
                print(f"    probe raised: {exc!r}")

        time.sleep(args.settle)
        ping_state = ping_alive(args.ip, args.self_test)
        assume = "ALIVE" if args.self_test else None
        response = prompt_response(t, ping_state, assume)
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
        # Carry over any hand-edited notes / grade override from the prior run.
        old = prior.get(t["id"], {})
        if old.get("notes"):
            rec["notes"] = old["notes"]
        if old.get("grade_override"):
            rec["grade_override"] = old["grade_override"]
            rec["grade"] = old["grade_override"]
        print(f"    => {response}  grade={rec['grade']}\n")
        results.append(rec)

    write_report(args.ip, results)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="lwIP-CE DAST probe runner")
    ap.add_argument("--ip", help="target calc IPv4 address")
    ap.add_argument("--iface", help="network interface to send from")
    ap.add_argument("--settle", type=float, default=1.0,
                    help="seconds to wait after a probe before grading")
    ap.add_argument("--gen-header", action="store_true",
                    help="regenerate the calc-side C test list and exit")
    ap.add_argument("--self-test", action="store_true",
                    help="dry run: no packets, no prompts, no root needed")
    args = ap.parse_args()

    if args.gen_header:
        gen_header()
        return 0
    if not args.ip:
        die("--ip is required (or use --gen-header)")
    return run(args)


if __name__ == "__main__":
    sys.exit(main())

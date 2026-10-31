#!/usr/bin/env python3
"""Build and run every network suite concurrently in isolated namespaces.

``tests/net/run.py`` remains the per-suite engine.  Each invocation gets its
own Linux network namespace and ``cemu0`` TAP, so Alessio's fixed addresses,
ports, packet capture, host-control protocol, and grading code remain intact.

The primary output uses the same nested schema as ``run_unit_tests.py``::

    [{"module": "net", "status": "pass", "units": [
        {"unit": "sockets", "status": "pass", "tests": [...]}
    ]}]
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


SUITES = ("sockets", "raw", "tls", "records", "server", "perf", "timeouts")
PROGRAMS = {
    "sockets": "NETTEST",
    "raw": "NETRAW",
    "tls": "NETTLS",
    "records": "NETREC",
    "server": "NETSRV",
    "perf": "NETPERF",
    "timeouts": "NETTMO",
}


@dataclass(frozen=True)
class NetworkNamespace:
    name: str
    root_interface: str
    peer_interface: str
    subnet: str
    host_address: str
    peer_address: str


def command(args: list[str], *, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        check=check,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
    )


def namespace_for(index: int) -> NetworkNamespace:
    token = f"{os.getpid() % 100000:05d}{index}"
    octet = 220 + index
    return NetworkNamespace(
        name=f"lwn{token}",
        root_interface=f"lwh{token}",
        peer_interface=f"lwp{token}",
        subnet=f"10.240.{octet}.0/30",
        host_address=f"10.240.{octet}.1/30",
        peer_address=f"10.240.{octet}.2/30",
    )


def setup_namespace(ns: NetworkNamespace) -> None:
    netns_etc = Path("/etc/netns") / ns.name
    netns_etc.mkdir(parents=True, exist_ok=True)
    (netns_etc / "resolv.conf").write_text("nameserver 1.1.1.1\n", encoding="ascii")
    command(["ip", "netns", "add", ns.name])
    command(["ip", "link", "add", ns.root_interface, "type", "veth", "peer", "name", ns.peer_interface])
    command(["ip", "link", "set", ns.peer_interface, "netns", ns.name])
    command(["ip", "addr", "add", ns.host_address, "dev", ns.root_interface])
    command(["ip", "link", "set", ns.root_interface, "up"])

    inside = ["ip", "netns", "exec", ns.name]
    command([*inside, "ip", "link", "set", "lo", "up"])
    command([*inside, "ip", "addr", "add", ns.peer_address, "dev", ns.peer_interface])
    command([*inside, "ip", "link", "set", ns.peer_interface, "up"])
    command([*inside, "ip", "route", "add", "default", "via", ns.host_address.split("/")[0]])
    command([*inside, "ip", "tuntap", "add", "dev", "cemu0", "mode", "tap"])
    command([*inside, "ip", "addr", "add", "192.168.84.1/24", "dev", "cemu0"])
    command([*inside, "ip", "link", "set", "cemu0", "up"])
    command([*inside, "sysctl", "-qw", "net.ipv4.ip_forward=1"])
    command([*inside, "iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "192.168.84.0/24",
             "-o", ns.peer_interface, "-j", "MASQUERADE"])
    command([*inside, "iptables", "-A", "FORWARD", "-i", "cemu0", "-j", "ACCEPT"])
    command([*inside, "iptables", "-A", "FORWARD", "-o", "cemu0", "-m", "conntrack",
             "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"])

    command(["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", ns.subnet,
             "!", "-o", ns.root_interface, "-j", "MASQUERADE"])
    command(["iptables", "-I", "FORWARD", "-i", ns.root_interface, "-j", "ACCEPT"])
    command(["iptables", "-I", "FORWARD", "-o", ns.root_interface, "-m", "conntrack",
             "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"])


def cleanup_namespace(ns: NetworkNamespace) -> None:
    commands = [
        ["iptables", "-D", "FORWARD", "-i", ns.root_interface, "-j", "ACCEPT"],
        ["iptables", "-D", "FORWARD", "-o", ns.root_interface, "-m", "conntrack",
         "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
        ["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", ns.subnet,
         "!", "-o", ns.root_interface, "-j", "MASQUERADE"],
        ["ip", "netns", "del", ns.name],
    ]
    for args in commands:
        command(args, check=False, capture=True)
    netns_etc = Path("/etc/netns") / ns.name
    (netns_etc / "resolv.conf").unlink(missing_ok=True)
    try:
        netns_etc.rmdir()
    except OSError:
        pass


def status_from_grade(grade: object) -> str:
    value = str(grade).lower()
    if value == "pass":
        return "pass"
    if value == "fail":
        return "fail"
    return "skip"


def add_heap_stats(rows: list[dict], metrics: dict) -> None:
    peak = [value["value"] for key, value in metrics.items()
            if key.endswith("_heap_peak") and isinstance(value, dict) and "value" in value]
    parts = [f"heap peak {max(peak)} B"] if peak else []
    idle = metrics.get("heap_idle", {}).get("value")
    if idle is not None:
        parts.append(f"heap idle {idle} B")
    extra = "; ".join(parts)
    if extra:
        for row in rows:
            row["stats"] = "; ".join(filter(None, (row.get("stats", ""), extra)))


def nested_unit(suite: str, returncode: int, rows: list[dict], *, build_error: bool = False) -> dict:
    tests = []
    prefix = f"{suite.upper()} - "
    for row in rows:
        name = str(row.get("test", "Suite execution"))
        if name.startswith(prefix):
            name = name[len(prefix):]
        tests.append({
            "test": name,
            "description": name,
            "status": status_from_grade(row.get("grade")),
            "stats": str(row.get("stats", "")),
        })
    if not tests:
        name = "Suite build" if build_error else "Suite execution"
        tests.append({"test": name, "description": name,
                      "status": "fail" if returncode else "pass"})

    statuses = {test["status"] for test in tests}
    if returncode or "fail" in statuses:
        status = "fail"
    elif statuses == {"skip"}:
        status = "skip"
    else:
        status = "pass"
    result = {
        "unit": suite,
        "description": f"lwIP-CE networked suite {PROGRAMS[suite]}",
        "status": status,
        "tests": tests,
    }
    if build_error:
        result["build_error"] = True
    return result


def run_suite(args: argparse.Namespace, suite: str, ns: NetworkNamespace) -> tuple[dict, list[dict], dict, list[dict]]:
    suite_dir = args.artifacts_dir / suite
    suite_dir.mkdir(parents=True, exist_ok=True)
    build = command(["make", "-C", str(args.tests_dir), suite], check=False, capture=True)
    (suite_dir / "build.log").write_text(build.stdout or "", encoding="utf-8")
    if build.returncode:
        rows = [{"group": "NETTEST", "module": "NETTEST",
                 "test": f"{suite.upper()} - Suite build", "grade": "Fail"}]
        return nested_unit(suite, build.returncode, rows, build_error=True), rows, {}, []

    rows_path = suite_dir / "test-rows.json"
    metrics_path = suite_dir / "metrics.json"
    probes_path = suite_dir / "endpoint-probes.json"
    log_path = suite_dir / "host.log"
    run_py = (args.tests_dir / "run.py").resolve()
    child = [
        "ip", "netns", "exec", ns.name,
        "env", f"AUTOTESTER_IMAGE={os.environ['AUTOTESTER_IMAGE']}",
        f"NETTEST_OUTPUT_DIR={suite_dir.resolve()}",
        sys.executable, str(run_py),
        "--suite", suite,
        "--pcap", str((suite_dir / f"{suite}.pcap").resolve()),
        "--rows", str(rows_path.resolve()),
        "--metrics", str(metrics_path.resolve()),
        "--endpoint-probes", str(probes_path.resolve()),
        "--autotester", str(args.autotester.resolve()),
        "--usb", args.usb,
        "--timeout", str(args.timeout),
    ]
    if suite == "tls":
        child.extend(["--truststore-signer", str(args.truststore_signer.resolve()),
                      "--convbin", str(args.convbin.resolve())])
        if args.external_info:
            child.append("--external-info")
    try:
        run = subprocess.run(child, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             timeout=args.process_timeout)
        output = run.stdout or ""
        returncode = run.returncode
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout or ""
        if isinstance(partial, bytes):
            partial = partial.decode(errors="replace")
        output = partial + f"\n{suite}: host process timed out\n"
        returncode = 124
    log_path.write_text(output, encoding="utf-8")

    rows = json.loads(rows_path.read_text()) if rows_path.is_file() else []
    if not rows:
        rows = [{"group": "NETTEST", "module": "NETTEST",
                 "test": f"{suite.upper()} - Suite execution",
                 "grade": "Pass" if returncode == 0 else "Fail"}]
    metrics_doc = json.loads(metrics_path.read_text()) if metrics_path.is_file() else {}
    suite_metrics = metrics_doc.get(suite, metrics_doc)
    probes = json.loads(probes_path.read_text()) if probes_path.is_file() else []
    add_heap_stats(rows, suite_metrics)
    rows_path.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    return nested_unit(suite, returncode, rows), rows, metrics_doc, probes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tests_dir", type=Path)
    parser.add_argument("--autotester", type=Path, required=True)
    parser.add_argument("--usb", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rows", type=Path, required=True)
    parser.add_argument("--metrics", type=Path, required=True)
    parser.add_argument("--endpoint-probes", type=Path, required=True)
    parser.add_argument("--artifacts-dir", type=Path, required=True)
    parser.add_argument("--suite", action="append", choices=SUITES)
    parser.add_argument("--timeout", type=int, default=1_800_000)
    parser.add_argument("--process-timeout", type=int, default=3600)
    parser.add_argument("--truststore-signer", type=Path)
    parser.add_argument("--convbin", type=Path)
    parser.add_argument("--external-info", action="store_true")
    args = parser.parse_args()

    image = os.environ.get("AUTOTESTER_IMAGE")
    if not image or not Path(image).is_file():
        parser.error("AUTOTESTER_IMAGE must point to the prepared CEmu state")
    if os.geteuid() != 0:
        parser.error("network namespace isolation requires root")
    suites = args.suite or list(SUITES)
    required_paths = [(args.autotester, "autotester")]
    if "tls" in suites:
        required_paths.extend(((args.truststore_signer, "truststore signer"),
                               (args.convbin, "convbin")))
    for path, label in required_paths:
        if path is None:
            parser.error(f"--{label.replace(' ', '-')} is required for the TLS suite")
        if not path.is_file():
            parser.error(f"{label} does not exist: {path}")
    args.artifacts_dir.mkdir(parents=True, exist_ok=True)
    command(["sysctl", "-qw", "net.ipv4.ip_forward=1"])
    namespaces: dict[str, NetworkNamespace] = {}
    try:
        for index, suite in enumerate(suites):
            ns = namespace_for(index)
            namespaces[suite] = ns
            setup_namespace(ns)

        results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(suites)) as pool:
            futures = {pool.submit(run_suite, args, suite, namespaces[suite]): suite
                       for suite in suites}
            for future in concurrent.futures.as_completed(futures):
                suite = futures[future]
                try:
                    results[suite] = future.result()
                except Exception as exc:  # noqa: BLE001
                    text = f"{type(exc).__name__}: {exc}"
                    (args.artifacts_dir / suite / "host.log").write_text(text + "\n")
                    rows = [{"group": "NETTEST", "module": "NETTEST",
                             "test": f"{suite.upper()} - Suite execution", "grade": "Fail"}]
                    results[suite] = (nested_unit(suite, 1, rows), rows, {}, [])
    finally:
        for ns in namespaces.values():
            cleanup_namespace(ns)

    units, rows, metrics, probes = [], [], {}, []
    for suite in suites:
        unit, suite_rows, suite_metrics, suite_probes = results[suite]
        units.append(unit)
        rows.extend(suite_rows)
        if suite_metrics:
            metrics.update(suite_metrics)
        else:
            metrics[suite] = {}
        probes.extend({"suite": suite, **probe} for probe in suite_probes)
        log_path = args.artifacts_dir / suite / "host.log"
        if log_path.is_file():
            print(f"\n===== {suite} =====\n{log_path.read_text()}", flush=True)

    module_status = "fail" if any(unit["status"] == "fail" for unit in units) else (
        "skip" if any(unit["status"] == "skip" for unit in units) else "pass"
    )
    report = [{
        "module": "net",
        "description": "Network subsystem tests",
        "status": module_status,
        "units": units,
    }]
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    args.rows.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    args.metrics.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    args.endpoint_probes.write_text(json.dumps(probes, indent=2) + "\n", encoding="utf-8")

    failed = sum(unit["status"] == "fail" for unit in units)
    print(f"Network tests: {len(units)} total, {len(units) - failed} non-failing, {failed} failed")
    return failed


if __name__ == "__main__":
    sys.exit(main())

"""Check the bridge's temporary host networking changes."""

import importlib.util
import io
import logging
import os
import stat
import sys
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[3] / "tools/bridge/lwip-acm-bridge.py"
spec = importlib.util.spec_from_file_location("acm_bridge", SOURCE)
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


class HostNetworkingTest(unittest.TestCase):
    def test_sudo_launch_is_rejected_before_network_setup(self):
        with patch.object(sys, "argv", ["bridge.py"]), \
                patch.object(bridge.platform, "system", return_value="Darwin"), \
                patch.object(bridge.os, "geteuid", return_value=0), \
                patch.object(bridge, "active_uplinks") as uplinks, \
                redirect_stderr(io.StringIO()), \
                self.assertRaises(SystemExit) as raised:
            bridge.main()
        self.assertEqual(raised.exception.code, 2)
        uplinks.assert_not_called()

    def test_ctrl_c_restores_forwarding_when_bridge_enabled_it(self):
        read = subprocess.CompletedProcess([], 0, stdout="0\n")
        with patch.object(subprocess, "run", return_value=read) as run, \
                patch.object(bridge, "privileged") as privileged:
            with redirect_stdout(io.StringIO()):
                with self.assertRaises(KeyboardInterrupt):
                    with bridge.temporary_ipv4_forwarding():
                        raise KeyboardInterrupt
        run.assert_called_once()
        self.assertEqual(run.call_args.args[0],
                         ["sysctl", "-n", "net.inet.ip.forwarding"])
        self.assertEqual([call.args for call in privileged.call_args_list], [
            ("sysctl", "-w", "net.inet.ip.forwarding=1"),
            ("sysctl", "-w", "net.inet.ip.forwarding=0"),
        ])

    def test_preexisting_forwarding_is_left_alone(self):
        read = subprocess.CompletedProcess([], 0, stdout="1\n")
        with patch.object(subprocess, "run", return_value=read) as run:
            with bridge.temporary_ipv4_forwarding():
                pass
        run.assert_called_once()

    def test_requires_an_existing_pf_nat_anchor(self):
        self.assertEqual(bridge.select_pf_nat_anchor(
            'nat-anchor "com.apple/*" all\n'),
            "com.apple/lwip-ce-bridge")
        with self.assertRaisesRegex(RuntimeError, "refusing to replace"):
            bridge.select_pf_nat_anchor('nat-anchor "lwip-ce-bridge" all\n')
        with self.assertRaisesRegex(RuntimeError, "refusing to replace"):
            bridge.select_pf_nat_anchor('nat on en0 from any to any -> (en0)\n')

    def test_pf_enable_token_is_parsed_for_reference_release(self):
        self.assertEqual(bridge.pf_enable_token(
            "pf enabled\nToken : 123456789\n"), "123456789")
        with self.assertRaisesRegex(RuntimeError, "did not return an enable token"):
            bridge.pf_enable_token("pf enabled\n")

    def test_malformed_dhcp_option_is_discarded(self):
        payload = bytearray(242)
        payload[236:240] = b"\x63\x82\x53\x63"
        payload[240:] = b"\x35\x01"  # type option claims a missing byte
        frame = bytearray(b"\0" * 12 + b"\x08\x00" + b"\0" * 28 + payload)
        frame[23] = 17               # UDP
        frame[36:38] = b"\0\x43"  # DHCP server port
        self.assertIsNone(bridge.MiniNet().handle(frame))

    def test_failed_cleanup_is_logged(self):
        failure = subprocess.CalledProcessError(1, ["nft", "delete"],
                                                stderr="permission denied")
        with patch.object(bridge, "privileged", side_effect=failure), \
                self.assertLogs(bridge.LOG, level="ERROR") as logs:
            bridge.cleanup_command("test table", "nft", "delete")
        self.assertIn("permission denied", logs.output[0])

    def test_linux_forwarding_restores_after_write_reports_failure(self):
        read = subprocess.CompletedProcess([], 0, stdout="0\n")
        failure = subprocess.CalledProcessError(1, ["sysctl", "-w"])
        with patch.object(subprocess, "run", return_value=read), \
                patch.object(bridge, "privileged", side_effect=[failure, None]) as run, \
                ExitStack() as stack:
            with self.assertRaises(subprocess.CalledProcessError):
                bridge.TapHost.write_sysctl("net.ipv4.conf.eth0.forwarding",
                                            "1", restore=stack)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args_list[-1].args,
                         ("sysctl", "-w", "net.ipv4.conf.eth0.forwarding=0"))

    def test_debug_log_does_not_contain_packet_bytes(self):
        frame = b"\xff" * 12 + b"\x08\x00" + b"\x45" + b"\0" * 19 + b"secret"
        wire = len(frame).to_bytes(2, "big") + frame

        class Link:
            def __init__(self):
                self.first = True

            def read(self):
                if self.first:
                    self.first = False
                    return wire
                return b""

        class Host:
            forwards = (0x0800,)

            def send(self, _frame):
                pass

            def recv(self):
                return None

        with self.assertLogs(bridge.LOG, level="DEBUG") as logs:
            bridge.run_bridge(Link(), bridge.MiniNet(), Host(), 0.01,
                              quiet=True, debug=True)
        self.assertIn("out frame bytes=40", "\n".join(logs.output))
        self.assertNotIn("secret", "\n".join(logs.output))

    def test_log_file_is_private_and_rotates(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "bridge.log")
            handler = bridge.PrivateRotatingFileHandler(
                path, maxBytes=30, backupCount=1)
            try:
                record = logging.LogRecord("bridge", logging.INFO, __file__,
                                           1, "a log entry", (), None)
                handler.emit(record)
                handler.emit(record)
                handler.emit(record)
            finally:
                handler.close()
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            self.assertTrue(os.path.exists(path + ".1"))


if __name__ == "__main__":
    unittest.main()

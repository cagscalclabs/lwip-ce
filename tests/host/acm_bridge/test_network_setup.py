"""Check the bridge's temporary host networking changes."""

import importlib.util
import io
from contextlib import redirect_stdout
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[3] / "tools/bridge/lwip-acm-bridge.py"
spec = importlib.util.spec_from_file_location("acm_bridge", SOURCE)
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


class HostNetworkingTest(unittest.TestCase):
    def test_ctrl_c_restores_forwarding_when_bridge_enabled_it(self):
        read = subprocess.CompletedProcess([], 0, stdout="0\n")
        changed = subprocess.CompletedProcess([], 0, stdout="")
        with patch.object(subprocess, "run", side_effect=[read, changed, changed]) as run:
            with redirect_stdout(io.StringIO()):
                with self.assertRaises(KeyboardInterrupt):
                    with bridge.temporary_ipv4_forwarding():
                        raise KeyboardInterrupt
        self.assertEqual([call.args[0] for call in run.call_args_list], [
            ["sysctl", "-n", "net.inet.ip.forwarding"],
            ["sysctl", "-w", "net.inet.ip.forwarding=1"],
            ["sysctl", "-w", "net.inet.ip.forwarding=0"],
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
        self.assertEqual(bridge.select_pf_nat_anchor(
            'nat-anchor "lwip-ce-bridge" all\n'),
            "lwip-ce-bridge")
        with self.assertRaisesRegex(RuntimeError, "refusing to replace"):
            bridge.select_pf_nat_anchor('nat on en0 from any to any -> (en0)\n')

    def test_pf_enable_token_is_parsed_for_reference_release(self):
        self.assertEqual(bridge.pf_enable_token(
            "pf enabled\nToken : 123456789\n"), "123456789")
        with self.assertRaisesRegex(RuntimeError, "did not return an enable token"):
            bridge.pf_enable_token("pf enabled\n")


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Unit tests for host corroboration of external HTTPS failures."""

from run import corroborate_external_https_failures


RESET_LOG = """  duckduckgo.com: status 7 err 8 in 4338 ms
FAIL https duckduckgo.com (DigiCert)
DONE pass 56 fail 1
"""


def reset_probe(host: str, phase: str):
    assert (host, phase) == ("duckduckgo.com", "tls")
    return False, "reset", "connection reset by peer"


def passing_probe(host: str, phase: str):
    return True, "ok", "runner completed the equivalent probe"


rendered, skipped, records = corroborate_external_https_failures(RESET_LOG, reset_probe)
assert skipped == 1
assert rendered.startswith("  duckduckgo.com: status 7")
assert "SKIP https duckduckgo.com (DigiCert) - endpoint issue/latency" in rendered
assert records[0]["skipped"] is True

rendered, skipped, records = corroborate_external_https_failures(RESET_LOG, passing_probe)
assert skipped == 0
assert "FAIL https duckduckgo.com (DigiCert)" in rendered
assert "CEmu failure remains authoritative" in rendered
assert records[0]["skipped"] is False

negative_test = "FAIL expired certificate rejected\nDONE pass 55 fail 1\n"
rendered, skipped, records = corroborate_external_https_failures(negative_test, reset_probe)
assert rendered == negative_test
assert skipped == 0 and records == []

http_failure = "FAIL https httpbin.dev answers HTTP\nDONE pass 56 fail 1\n"
rendered, skipped, records = corroborate_external_https_failures(
    http_failure, lambda host, phase: (False, "timeout", "timeout")
)
assert skipped == 1 and records[0]["phase"] == "http"

print("network host-corroboration self-test: PASS")

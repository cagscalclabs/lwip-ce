#!/usr/bin/env python3
"""Encrypted certificate identities must use only an application TTY callback."""

from pathlib import Path
import re


root = Path(__file__).resolve().parents[3]
header = (root / "src/lwIP.h").read_text()
altcp = (root / "src/apps/altcp_tls/altcp_tls_ce.c").read_text()
socket_api = (root / "src/lwIP.c").read_text()
key_import = (root / "src/tls/core/key.c").read_text()

assert "typedef char *(*lwip_tty_input_fn)(void);" in header
assert "void     lwip_set_tty(lwip_tty_input_fn input);" in header
assert "static lwip_tty_input_fn g_tty_input = NULL;" in altcp

setter = re.search(
    r"void lwip_set_tty\(lwip_tty_input_fn input\)\s*\{(?P<body>.*?)\n\}",
    altcp,
    re.S,
)
assert setter and "g_tty_input = input;" in setter.group("body")

loader = altcp[
    altcp.index("static bool load_cert_identity("):
    altcp.index("struct altcp_tls_ce_config *altcp_tls_ce_create_config_cert_server(")
]
assert "-----BEGIN ENCRYPTED PRIVATE KEY-----" in loader
assert "lwip_tty_input_fn input = g_tty_input;" in loader
assert "g_tty_input = NULL;" in loader
assert "if (!input || !(password = input()))" in loader
assert re.search(
    r"tls_key_import\(&key, key_pem, key_len,\s*"
    r"TLS_KEY_FORMAT_PEM, password\)",
    loader,
)
assert loader.index("g_tty_input = NULL;") < loader.index("password = input()")
assert loader.index("password = input()") < loader.index("tls_key_import(&key")
assert loader.index("tls_key_import(&key") < loader.index(
    "tls_secure_memzero(password, password_len);"
)

stop = socket_api[
    socket_api.index("void lwip_stop(void)"):
    socket_api.index("void lwip_service_events(void)")
]
assert stop.index("lwip_set_tty(NULL);") < stop.index("lwip_stack_cleanup();")
assert "if (salt.len < 8)" in key_import

print("encrypted identity TTY regression checks passed")

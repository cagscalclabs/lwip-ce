#!/usr/bin/env python3
"""
gen_p256_cavp.py — CAVP-style P-256 ECDSA test vector generator.

Generates:
  - SigVer vectors: valid + intentionally-invalid (tampered r, tampered s,
    wrong-key) test cases using python-cryptography with RFC 6979 deterministic
    signing (ECDSA/P-256/SHA-256).
  - SigGen vectors: deterministic sign vectors produced with RFC 6979; output
    is the (r, s) pair that the implementation must reproduce byte-exact.

Output: tests/profiling/p256_cavp/src/p256_cavp_vectors.h

Usage:
    python3 build-tools/scripts/gen_p256_cavp.py
    python3 build-tools/scripts/gen_p256_cavp.py --out path/to/vectors.h

Requirements:
    pip install cryptography
"""

import argparse
import hashlib
import os
import struct
import textwrap
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _int_to_bytes32(n: int) -> bytes:
    return n.to_bytes(32, "big")


def _point_to_uncompressed(pub) -> bytes:
    """Return 65-byte uncompressed point 04 || x || y."""
    pn = pub.public_numbers()
    return b"\x04" + _int_to_bytes32(pn.x) + _int_to_bytes32(pn.y)


def _c_hex_array(data: bytes, indent: int = 1) -> str:
    tab = "    " * indent
    items = ", ".join(f"0x{b:02x}" for b in data)
    # Wrap at ~80 columns of content
    out = []
    row = []
    col = 0
    for b in data:
        tok = f"0x{b:02x}"
        if col + len(tok) + 2 > 76:
            out.append(tab + ",".join(row))
            row = [tok]
            col = len(tok)
        else:
            row.append(tok)
            col += len(tok) + 2
    if row:
        out.append(tab + ",".join(row))
    return ",\n".join(out)


def _hash_message(msg: bytes) -> bytes:
    return hashlib.sha256(msg).digest()


# ---------------------------------------------------------------------------
# SigGen vectors (10+): sign message with RFC 6979, record (hash, priv, r, s)
# ---------------------------------------------------------------------------

# Fixed messages for reproducibility.
SIGGEN_MESSAGES = [
    b"sample",
    b"test",
    b"NIST P-256 test vector",
    b"The quick brown fox jumps over the lazy dog",
    b"lwIP-CE TLS 1.3 ECDSA signing test",
    b"Cryptographic Algorithm Validation Program",
    b"P-256 RFC 6979 deterministic ECDSA",
    b"CAVP vector generation via python-cryptography",
    b"eZ80 P-256 assembly implementation",
    b"TI-84 Plus CE lwIP ECDSA sign vector 10",
    b"TI-84 Plus CE lwIP ECDSA sign vector 11",
    b"TI-84 Plus CE lwIP ECDSA sign vector 12",
]

# Fixed private key seeds (32-byte big-endian integers < n).
# Key 0 is the RFC 6979 A.2.5 test key.
SIGGEN_PRIVKEYS_HEX = [
    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",  # RFC 6979 A.2.5
    "519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464",
    "0f56db78ca460b055c500064824bed999a25aaf48ebb519ac201537b85479813",
    "e283871239837e13b95f789e6a1f18be90c4693fdb03df54ebe97d35e44e4c96",
    "a3d2d3652037e057b55493ce89bdedb2c915e1955fb14b6b15a2c7f58c8c6e5b",
    "53a9aa5a4cf5bf30f99e2e31bc6e71eff7e30f4a5b84cff43cffe8a9dbc69b44",
    "e26b5b19faf9d4f1f0eb2a7f71defe90e3e6efb3e97e5c96b1c5e50e8a3b04e",
    "cf4b7f1e1f2d66bf9d3c7ff0a4e3bbd25eeaa18ddecd9c29e83fc16e1cc9dab4",
    "b34dea3f396e7f7bddc0a4f1e2a41f6dae4aec3c6dca3a5fc61b74a64b4c2c3",
    "4e72c1a4e2d3f3c7c6d1b3e9f1a6d4b8c3e7f9a1d5b7e3c9f2a4b6d8e1c3f5",  # hand-crafted < n
    "1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2",
    "2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a",
]

assert len(SIGGEN_MESSAGES) == len(SIGGEN_PRIVKEYS_HEX), "mismatch"


def _clamp_to_n(raw: int) -> int:
    """Force an arbitrary integer into [1, n-1] by modular reduction."""
    n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    v = raw % n
    return v if v != 0 else 1


def gen_siggen_vectors():
    vectors = []
    for i, (msg, priv_hex) in enumerate(zip(SIGGEN_MESSAGES, SIGGEN_PRIVKEYS_HEX)):
        priv_int = _clamp_to_n(int(priv_hex, 16))
        priv_key = ec.derive_private_key(priv_int, SECP256R1(), default_backend())
        priv_bytes = _int_to_bytes32(priv_int)

        msg_hash = _hash_message(msg)

        # Sign using RFC 6979 (default for python-cryptography)
        sig_der = priv_key.sign(msg, ec.ECDSA(hashes.SHA256()))
        r_int, s_int = decode_dss_signature(sig_der)
        r_bytes = _int_to_bytes32(r_int)
        s_bytes = _int_to_bytes32(s_int)

        vectors.append({
            "name": f"sg{i:02d}",
            "msg": msg,
            "hash": msg_hash,
            "priv": priv_bytes,
            "r": r_bytes,
            "s": s_bytes,
        })
    return vectors


# ---------------------------------------------------------------------------
# SigVer vectors (20+ including invalids): verify test cases
# ---------------------------------------------------------------------------

# Extra keys for variety — derived from SIGGEN keys, plus three fresh ones.
SIGVER_EXTRA_KEYS_HEX = [
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a139",  # too short, pad
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f",  # n-2
    "7b8f2e1a3c5d4b9e2f1a7c3b5e9d8f2a1c4b6e9d3f7a2c5b8e1d4a7c3b6e9f2",
]


def gen_sigver_vectors():
    backend = default_backend()
    vectors = []
    n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

    # ---- Valid vectors (20) ----
    messages = [
        b"sample", b"test",
        b"NIST P-256 ECDSA SigVer test 1",
        b"NIST P-256 ECDSA SigVer test 2",
        b"NIST P-256 ECDSA SigVer test 3",
        b"NIST P-256 ECDSA SigVer test 4",
        b"NIST P-256 ECDSA SigVer test 5",
        b"NIST P-256 ECDSA SigVer test 6",
        b"NIST P-256 ECDSA SigVer test 7",
        b"NIST P-256 ECDSA SigVer test 8",
        b"NIST P-256 ECDSA SigVer test 9",
        b"NIST P-256 ECDSA SigVer test 10",
        b"NIST P-256 ECDSA SigVer test 11",
        b"NIST P-256 ECDSA SigVer test 12",
        b"The quick brown fox",
        b"eZ80 P-256 assembly CAVP test",
        b"lwIP-CE TLS 1.3 ECDSA SigVer test A",
        b"lwIP-CE TLS 1.3 ECDSA SigVer test B",
        b"lwIP-CE TLS 1.3 ECDSA SigVer test C",
        b"lwIP-CE TLS 1.3 ECDSA SigVer test D",
    ]

    # Use 5 different signing keys, cycling through messages
    priv_hexes = [
        "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
        "519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464",
        "0f56db78ca460b055c500064824bed999a25aaf48ebb519ac201537b85479813",
        "e283871239837e13b95f789e6a1f18be90c4693fdb03df54ebe97d35e44e4c96",
        "a3d2d3652037e057b55493ce89bdedb2c915e1955fb14b6b15a2c7f58c8c6e5b",
    ]

    for i, msg in enumerate(messages):
        priv_int = _clamp_to_n(int(priv_hexes[i % len(priv_hexes)], 16))
        priv_key = ec.derive_private_key(priv_int, SECP256R1(), backend)
        pub_bytes = _point_to_uncompressed(priv_key.public_key())
        msg_hash = _hash_message(msg)

        sig_der = priv_key.sign(msg, ec.ECDSA(hashes.SHA256()))
        r_int, s_int = decode_dss_signature(sig_der)
        r_bytes = _int_to_bytes32(r_int)
        s_bytes = _int_to_bytes32(s_int)

        vectors.append({
            "name": f"vv{i:02d}",
            "pub": pub_bytes,
            "hash": msg_hash,
            "sig": r_bytes + s_bytes,
            "ok": True,
            "note": f"valid: {msg.decode(errors='replace')[:32]}",
        })

    # ---- Invalid vector 1: tampered r (flip one bit) ----
    _msg = b"tamper-r test"
    _priv_int = _clamp_to_n(int(priv_hexes[0], 16))
    _priv_key = ec.derive_private_key(_priv_int, SECP256R1(), backend)
    _pub_bytes = _point_to_uncompressed(_priv_key.public_key())
    _msg_hash = _hash_message(_msg)
    _sig_der = _priv_key.sign(_msg, ec.ECDSA(hashes.SHA256()))
    _r_int, _s_int = decode_dss_signature(_sig_der)
    _r_bytes_bad = bytearray(_int_to_bytes32(_r_int))
    _r_bytes_bad[5] ^= 0x10
    vectors.append({
        "name": "inv_r",
        "pub": _pub_bytes,
        "hash": _msg_hash,
        "sig": bytes(_r_bytes_bad) + _int_to_bytes32(_s_int),
        "ok": False,
        "note": "invalid: r tampered (bit flip)",
    })

    # ---- Invalid vector 2: tampered s (flip one bit) ----
    _msg = b"tamper-s test"
    _priv_int = _clamp_to_n(int(priv_hexes[1], 16))
    _priv_key = ec.derive_private_key(_priv_int, SECP256R1(), backend)
    _pub_bytes = _point_to_uncompressed(_priv_key.public_key())
    _msg_hash = _hash_message(_msg)
    _sig_der = _priv_key.sign(_msg, ec.ECDSA(hashes.SHA256()))
    _r_int, _s_int = decode_dss_signature(_sig_der)
    _s_bytes_bad = bytearray(_int_to_bytes32(_s_int))
    _s_bytes_bad[12] ^= 0x40
    vectors.append({
        "name": "inv_s",
        "pub": _pub_bytes,
        "hash": _msg_hash,
        "sig": _int_to_bytes32(_r_int) + bytes(_s_bytes_bad),
        "ok": False,
        "note": "invalid: s tampered (bit flip)",
    })

    # ---- Invalid vector 3: wrong key (different private key) ----
    _msg = b"wrong-key test"
    _priv_int = _clamp_to_n(int(priv_hexes[2], 16))
    _priv_key = ec.derive_private_key(_priv_int, SECP256R1(), backend)
    _wrong_priv_int = _clamp_to_n(int(priv_hexes[3], 16))
    _wrong_priv_key = ec.derive_private_key(_wrong_priv_int, SECP256R1(), backend)
    _wrong_pub_bytes = _point_to_uncompressed(_wrong_priv_key.public_key())
    _msg_hash = _hash_message(_msg)
    _sig_der = _priv_key.sign(_msg, ec.ECDSA(hashes.SHA256()))
    _r_int, _s_int = decode_dss_signature(_sig_der)
    vectors.append({
        "name": "inv_key",
        "pub": _wrong_pub_bytes,
        "hash": _msg_hash,
        "sig": _int_to_bytes32(_r_int) + _int_to_bytes32(_s_int),
        "ok": False,
        "note": "invalid: signature made with different key",
    })

    # ---- Invalid vector 4: tampered hash ----
    _msg = b"tamper-hash test"
    _priv_int = _clamp_to_n(int(priv_hexes[0], 16))
    _priv_key = ec.derive_private_key(_priv_int, SECP256R1(), backend)
    _pub_bytes = _point_to_uncompressed(_priv_key.public_key())
    _msg_hash = _hash_message(_msg)
    _bad_hash = bytearray(_msg_hash)
    _bad_hash[31] ^= 0x01
    _sig_der = _priv_key.sign(_msg, ec.ECDSA(hashes.SHA256()))
    _r_int, _s_int = decode_dss_signature(_sig_der)
    vectors.append({
        "name": "inv_hash",
        "pub": _pub_bytes,
        "hash": bytes(_bad_hash),
        "sig": _int_to_bytes32(_r_int) + _int_to_bytes32(_s_int),
        "ok": False,
        "note": "invalid: hash tampered (bit flip)",
    })

    return vectors


# ---------------------------------------------------------------------------
# C header generator
# ---------------------------------------------------------------------------

def emit_header(siggen: list, sigver: list, out_path: str):
    lines = []
    lines.append("/*")
    lines.append(" * p256_cavp_vectors.h — CAVP-style P-256 ECDSA test vectors.")
    lines.append(" *")
    lines.append(" * Auto-generated by build-tools/scripts/gen_p256_cavp.py")
    lines.append(" * using python-cryptography (RFC 6979 deterministic ECDSA).")
    lines.append(" * DO NOT EDIT BY HAND — re-run the generator script.")
    lines.append(" *")
    lines.append(f" * SigGen vectors : {len(siggen)}")
    lines.append(f" * SigVer vectors : {len(sigver)} "
                 f"({sum(1 for v in sigver if v['ok'])} valid, "
                 f"{sum(1 for v in sigver if not v['ok'])} invalid)")
    lines.append(" */")
    lines.append("")
    lines.append("#ifndef P256_CAVP_VECTORS_H")
    lines.append("#define P256_CAVP_VECTORS_H")
    lines.append("")
    lines.append("#include <stdint.h>")
    lines.append("#include <stdbool.h>")
    lines.append("")

    # ---- SigGen ----
    lines.append("/* --- SigGen vectors --- */")
    lines.append("struct p256_siggen_vec {")
    lines.append("    const char *name;")
    lines.append("    uint8_t     hash[32];   /* SHA-256 of the message */")
    lines.append("    uint8_t     priv[32];   /* private key (big-endian) */")
    lines.append("    uint8_t     r[32];      /* expected r */")
    lines.append("    uint8_t     s[32];      /* expected s */")
    lines.append("};")
    lines.append("")
    lines.append("static const struct p256_siggen_vec p256_siggen_vecs[] = {")

    for v in siggen:
        lines.append(f'    {{"{v["name"]}",')
        lines.append(f"     /* hash */ {{")
        lines.append(_c_hex_array(v["hash"], 2) + "},")
        lines.append(f"     /* priv */ {{")
        lines.append(_c_hex_array(v["priv"], 2) + "},")
        lines.append(f"     /* r    */ {{")
        lines.append(_c_hex_array(v["r"], 2) + "},")
        lines.append(f"     /* s    */ {{")
        lines.append(_c_hex_array(v["s"], 2) + "}},")

    lines.append("};")
    lines.append(f"#define P256_SIGGEN_COUNT {len(siggen)}")
    lines.append("")

    # ---- SigVer ----
    lines.append("/* --- SigVer vectors --- */")
    lines.append("struct p256_sigver_vec {")
    lines.append("    const char *name;")
    lines.append("    uint8_t     pub[65];    /* uncompressed 04||x||y */")
    lines.append("    uint8_t     hash[32];   /* SHA-256 of the message */")
    lines.append("    uint8_t     sig[64];    /* r||s (each 32 bytes, big-endian) */")
    lines.append("    bool        ok;         /* expected verify result */")
    lines.append("};")
    lines.append("")
    lines.append("static const struct p256_sigver_vec p256_sigver_vecs[] = {")

    for v in sigver:
        ok_str = "true" if v["ok"] else "false"
        note = v.get("note", "")
        lines.append(f'    /* {note} */')
        lines.append(f'    {{"{v["name"]}",')
        lines.append(f"     /* pub  */ {{")
        lines.append(_c_hex_array(v["pub"], 2) + "},")
        lines.append(f"     /* hash */ {{")
        lines.append(_c_hex_array(v["hash"], 2) + "},")
        lines.append(f"     /* sig  */ {{")
        lines.append(_c_hex_array(v["sig"], 2) + "},")
        lines.append(f"     {ok_str}}},")

    lines.append("};")
    lines.append(f"#define P256_SIGVER_COUNT {len(sigver)}")
    lines.append("")
    lines.append("#endif /* P256_CAVP_VECTORS_H */")

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"Wrote {out_path}")
    print(f"  SigGen: {len(siggen)} vectors")
    print(f"  SigVer: {len(sigver)} vectors "
          f"({sum(1 for v in sigver if v['ok'])} valid, "
          f"{sum(1 for v in sigver if not v['ok'])} invalid)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        default="tests/profiling/p256_cavp/src/p256_cavp_vectors.h",
        help="Output header file path",
    )
    args = parser.parse_args()

    print("Generating P-256 CAVP vectors...")
    siggen = gen_siggen_vectors()
    sigver = gen_sigver_vectors()
    emit_header(siggen, sigver, args.out)


if __name__ == "__main__":
    main()

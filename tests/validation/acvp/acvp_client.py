#!/usr/bin/env python3
"""Focused ACVP 1.0 host client and CEmu operation bridge.

This module deliberately keeps ACVP JSON and future ACVTS credentials on the
host.  The calculator sees only bounded binary primitive-operation requests.
Supported adapters cover SHA-256/384, HMAC-SHA-256/384, AES-CBC/GCM/CCM,
PBKDF2-HMAC-SHA-256, KDA/HKDF-SHA-256, RSA signature verification,
deterministic ECDSA P-256 signing/verification, and X25519 SSC.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import socket
import struct
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Protocol

MAGIC_REQUEST = b"ACV1"
MAGIC_RESPONSE = b"ACR1"
HEADER = struct.Struct("!4sBBHI")
MAX_PAYLOAD = 8192

OP_STOP = 0
OP_SHA2_256 = 1
OP_HMAC_SHA2_256 = 2
OP_SHA2_256_MCT = 3
OP_AES_CBC = 4
OP_AES_GCM = 5
OP_AES_CCM = 6
OP_PBKDF2_SHA2_256 = 7
OP_HKDF_SHA2_256 = 8
OP_RSA_PSS_SHA2_256_VERIFY = 9
OP_RSA_PKCS1_SHA2_256_VERIFY = 10
OP_X25519_PUBLIC = 11
OP_X25519_SECRET = 12
OP_P256_PUBLIC = 13
OP_P256_SECRET = 14
OP_P256_SIGGEN = 15
OP_P256_SIGVER = 16
OP_X25519_SSC = 17
OP_P256_CDH = 18
OP_P256_SIGGEN_BEGIN = 19
OP_P256_SIGGEN_ACTIVE = 20
OP_AES_CBC_MCT = 21
OP_SHA2_384 = 22
OP_HMAC_SHA2_384 = 23
OP_SHA2_384_MCT = 24
OP_SHA2_512 = 25
OP_HMAC_SHA2_512 = 26
OP_SHA2_512_MCT = 27


class AcvpError(RuntimeError):
    """The vector set or calculator response is invalid."""


class Backend(Protocol):
    def __call__(self, operation: int, payload: bytes) -> bytes: ...


def _hex(value: object, field: str) -> bytes:
    if not isinstance(value, str):
        raise AcvpError(f"{field} must be a hexadecimal string")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise AcvpError(f"{field} is not valid hexadecimal") from exc


def _byte_message(test: dict, field: str = "msg", default_length: object = None) -> bytes:
    length = test.get("len", test.get("msgLen", default_length))
    if not isinstance(length, int) or length < 0 or length % 8:
        raise AcvpError(f"tcId {test.get('tcId')}: only byte-aligned messages are supported")
    message = _hex(test.get(field), field)
    needed = length // 8
    if length == 0:
        if message not in (b"", b"\0"):
            raise AcvpError(f"tcId {test.get('tcId')}: non-empty {field} for a zero-bit message")
        return b""
    if len(message) != needed:
        raise AcvpError(f"tcId {test.get('tcId')}: {field} length does not match {length} bits")
    return message


def _vector_objects(document: object) -> tuple[dict | None, list[dict]]:
    if isinstance(document, dict):
        return None, [document]
    if not isinstance(document, list) or not document:
        raise AcvpError("ACVP document must be a vector-set object or a non-empty array")
    header = document[0] if isinstance(document[0], dict) and "acvVersion" in document[0] else None
    vectors = document[1:] if header else document
    if not vectors or not all(isinstance(item, dict) for item in vectors):
        raise AcvpError("ACVP document contains no vector sets")
    return header, vectors


def _sha_vector_set(vector: dict, backend: Backend) -> dict:
    groups = []
    for group in vector.get("testGroups", []):
        test_type = group.get("testType")
        tests = []
        if test_type == "AFT":
            for test in group.get("tests", []):
                digest = backend(OP_SHA2_256, _byte_message(test))
                if len(digest) != 32:
                    raise AcvpError("calculator returned a non-SHA-256-sized digest")
                tests.append({"tcId": test["tcId"], "md": digest.hex().upper()})
        elif test_type == "MCT" and group.get("mctVersion", "standard") == "standard":
            for test in group.get("tests", []):
                seed = _byte_message(test)
                if len(seed) != 32:
                    raise AcvpError("SHA2-256 MCT seed must be 256 bits")
                iterations = []
                for _ in range(100):
                    seed = backend(OP_SHA2_256_MCT, seed)
                    if len(seed) != 32:
                        raise AcvpError("calculator returned a non-SHA-256-sized MCT digest")
                    iterations.append({"md": seed.hex().upper()})
                tests.append({"tcId": test["tcId"], "resultsArray": iterations})
        else:
            raise AcvpError(f"unsupported SHA2-256 test group {test_type!r}")
        groups.append({"tgId": group["tgId"], "tests": tests})
    return {"vsId": vector["vsId"], "testGroups": groups}


def _sha384_vector_set(vector: dict, backend: Backend) -> dict:
    groups = []
    for group in vector.get("testGroups", []):
        test_type = group.get("testType")
        tests = []
        if test_type == "AFT":
            for test in group.get("tests", []):
                digest = backend(OP_SHA2_384, _byte_message(test))
                if len(digest) != 48:
                    raise AcvpError("calculator returned a non-SHA-384-sized digest")
                tests.append({"tcId": test["tcId"], "md": digest.hex().upper()})
        elif test_type == "MCT" and group.get("mctVersion", "standard") == "standard":
            for test in group.get("tests", []):
                seed = _byte_message(test)
                if len(seed) != 48:
                    raise AcvpError("SHA2-384 MCT seed must be 384 bits")
                iterations = []
                for _ in range(100):
                    seed = backend(OP_SHA2_384_MCT, seed)
                    if len(seed) != 48:
                        raise AcvpError("calculator returned a non-SHA-384-sized MCT digest")
                    iterations.append({"md": seed.hex().upper()})
                tests.append({"tcId": test["tcId"], "resultsArray": iterations})
        else:
            raise AcvpError(f"unsupported SHA2-384 test group {test_type!r}")
        groups.append({"tgId": group["tgId"], "tests": tests})
    return {"vsId": vector["vsId"], "testGroups": groups}


def _hmac_vector_set(vector: dict, backend: Backend) -> dict:
    groups = []
    for group in vector.get("testGroups", []):
        if group.get("testType", "AFT") != "AFT":
            raise AcvpError(f"unsupported HMAC test group {group.get('testType')!r}")
        tests = []
        for test in group.get("tests", []):
            key = _hex(test.get("key"), "key")
            key_len = test.get("keyLen", group.get("keyLen", len(key) * 8))
            mac_bits = test.get("macLen", group.get("macLen"))
            if key_len != len(key) * 8 or not key or len(key) > 0xFFFF:
                raise AcvpError(f"tcId {test.get('tcId')}: invalid HMAC key length")
            if not isinstance(mac_bits, int) or mac_bits < 32 or mac_bits > 256 or mac_bits % 8:
                raise AcvpError(f"tcId {test.get('tcId')}: invalid HMAC output length")
            message = _byte_message(test, default_length=group.get("msgLen"))
            payload = struct.pack("!HH", len(key), mac_bits // 8) + key + message
            mac = backend(OP_HMAC_SHA2_256, payload)
            if len(mac) != mac_bits // 8:
                raise AcvpError("calculator returned an incorrectly sized HMAC")
            tests.append({"tcId": test["tcId"], "mac": mac.hex().upper()})
        groups.append({"tgId": group["tgId"], "tests": tests})
    return {"vsId": vector["vsId"], "testGroups": groups}


def _sha512_vector_set(vector: dict, backend: Backend) -> dict:
    groups = []
    for group in vector.get("testGroups", []):
        test_type = group.get("testType")
        tests = []
        if test_type == "AFT":
            for test in group.get("tests", []):
                digest = backend(OP_SHA2_512, _byte_message(test))
                if len(digest) != 64:
                    raise AcvpError("calculator returned a non-SHA-512-sized digest")
                tests.append({"tcId": test["tcId"], "md": digest.hex().upper()})
        elif test_type == "MCT" and group.get("mctVersion", "standard") == "standard":
            for test in group.get("tests", []):
                seed = _byte_message(test)
                if len(seed) != 64:
                    raise AcvpError("SHA2-512 MCT seed must be 512 bits")
                iterations = []
                for _ in range(100):
                    seed = backend(OP_SHA2_512_MCT, seed)
                    if len(seed) != 64:
                        raise AcvpError("calculator returned a non-SHA-512-sized MCT digest")
                    iterations.append({"md": seed.hex().upper()})
                tests.append({"tcId": test["tcId"], "resultsArray": iterations})
        else:
            raise AcvpError(f"unsupported SHA2-512 test group {test_type!r}")
        groups.append({"tgId": group["tgId"], "tests": tests})
    return {"vsId": vector["vsId"], "testGroups": groups}


def _hmac_sha384_vector_set(vector: dict, backend: Backend) -> dict:
    groups = []
    for group in vector.get("testGroups", []):
        if group.get("testType", "AFT") != "AFT":
            raise AcvpError(f"unsupported HMAC-SHA384 test group {group.get('testType')!r}")
        tests = []
        for test in group.get("tests", []):
            key = _hex(test.get("key"), "key")
            key_len = test.get("keyLen", group.get("keyLen", len(key) * 8))
            mac_bits = test.get("macLen", group.get("macLen"))
            if key_len != len(key) * 8 or not key or len(key) > 0xFFFF:
                raise AcvpError(f"tcId {test.get('tcId')}: invalid HMAC key length")
            if not isinstance(mac_bits, int) or mac_bits < 32 or mac_bits > 384 or mac_bits % 8:
                raise AcvpError(f"tcId {test.get('tcId')}: invalid HMAC-SHA384 output length")
            message = _byte_message(test, default_length=group.get("msgLen"))
            payload = struct.pack("!HH", len(key), mac_bits // 8) + key + message
            mac = backend(OP_HMAC_SHA2_384, payload)
            if len(mac) != mac_bits // 8:
                raise AcvpError("calculator returned an incorrectly sized HMAC-SHA384")
            tests.append({"tcId": test["tcId"], "mac": mac.hex().upper()})
        groups.append({"tgId": group["tgId"], "tests": tests})
    return {"vsId": vector["vsId"], "testGroups": groups}


def _hmac_sha512_vector_set(vector: dict, backend: Backend) -> dict:
    groups = []
    for group in vector.get("testGroups", []):
        if group.get("testType", "AFT") != "AFT":
            raise AcvpError(f"unsupported HMAC-SHA512 test group {group.get('testType')!r}")
        tests = []
        for test in group.get("tests", []):
            key = _hex(test.get("key"), "key")
            key_len = test.get("keyLen", group.get("keyLen", len(key) * 8))
            mac_bits = test.get("macLen", group.get("macLen"))
            if key_len != len(key) * 8 or not key or len(key) > 0xFFFF:
                raise AcvpError(f"tcId {test.get('tcId')}: invalid HMAC key length")
            if not isinstance(mac_bits, int) or mac_bits < 32 or mac_bits > 512 or mac_bits % 8:
                raise AcvpError(f"tcId {test.get('tcId')}: invalid HMAC-SHA512 output length")
            message = _byte_message(test, default_length=group.get("msgLen"))
            payload = struct.pack("!HH", len(key), mac_bits // 8) + key + message
            mac = backend(OP_HMAC_SHA2_512, payload)
            if len(mac) != mac_bits // 8:
                raise AcvpError("calculator returned an incorrectly sized HMAC-SHA512")
            tests.append({"tcId": test["tcId"], "mac": mac.hex().upper()})
        groups.append({"tgId": group["tgId"], "tests": tests})
    return {"vsId": vector["vsId"], "testGroups": groups}


def _expect_bits(group: dict, field: str, value: bytes) -> None:
    bits = group.get(field, len(value) * 8)
    if bits != len(value) * 8:
        raise AcvpError(f"tgId {group.get('tgId')}: {field} does not match the supplied value")


def _aes_call(operation: int, direction: str, key: bytes, iv: bytes,
              aad: bytes, data: bytes, tag: bytes, tag_len: int,
              backend: Backend) -> tuple[bool, bytes, bytes]:
    decrypt = direction == "decrypt"
    payload = (bytes((decrypt, len(key))) + key + bytes((len(iv),)) + iv +
               struct.pack("!H", len(aad)) + aad + struct.pack("!H", len(data)) +
               data + bytes((tag_len,)) + (tag if decrypt else b""))
    response = backend(operation, payload)
    if len(response) < 4:
        raise AcvpError("calculator returned a short authenticated-cipher response")
    accepted = bool(response[0])
    data_len = struct.unpack("!H", response[1:3])[0]
    if 3 + data_len >= len(response):
        raise AcvpError("calculator returned a malformed authenticated-cipher response")
    output = response[3:3 + data_len]
    returned_tag_len = response[3 + data_len]
    returned_tag = response[4 + data_len:]
    if len(returned_tag) != returned_tag_len:
        raise AcvpError("calculator returned a malformed authentication tag")
    return accepted, output, returned_tag


def _aes_vector_set(vector: dict, backend: Backend) -> dict:
    algorithm = vector["algorithm"]
    operation = {"ACVP-AES-CBC": OP_AES_CBC, "ACVP-AES-GCM": OP_AES_GCM,
                 "ACVP-AES-CCM": OP_AES_CCM}[algorithm]
    groups = []
    for group in vector.get("testGroups", []):
        test_type = group.get("testType")
        if test_type not in (("AFT", "MCT") if algorithm == "ACVP-AES-CBC" else ("AFT",)):
            raise AcvpError(f"{algorithm} test type {test_type!r} is not implemented")
        direction = group.get("direction")
        if direction not in ("encrypt", "decrypt"):
            raise AcvpError(f"tgId {group.get('tgId')}: invalid direction")
        tests = []
        for test in group.get("tests", []):
            key, iv = _hex(test.get("key"), "key"), _hex(test.get("iv"), "iv")
            _expect_bits(group, "keyLen", key); _expect_bits(group, "ivLen", iv)
            if algorithm == "ACVP-AES-GCM" and group.get("ivGen") != "external":
                raise AcvpError("only externally generated GCM IVs are registered")
            if algorithm == "ACVP-AES-CBC":
                field = "ct" if direction == "decrypt" else "pt"
                data = _hex(test.get(field), field)
                if test_type == "AFT": _expect_bits(group, "payloadLen", data)
                if test_type == "MCT":
                    if len(data) != 16 or len(iv) != 16:
                        raise AcvpError("AES-CBC MCT requires one block and a 128-bit IV")
                    key_now, iv_now, input_now = key, iv, data
                    iterations = []
                    for _ in range(100):
                        start_key, start_iv, start_input = key_now, iv_now, input_now
                        payload = (bytes((direction == "decrypt", len(key_now))) + key_now + iv_now +
                                   struct.pack("!H", 16) + input_now)
                        raw = backend(OP_AES_CBC_MCT, payload)
                        if len(raw) != 32:
                            raise AcvpError("calculator returned a malformed CBC MCT result")
                        input_now, output = raw[:16], raw[16:]
                        record = {"key": start_key.hex().upper(), "iv": start_iv.hex().upper(),
                                  field: start_input.hex().upper(),
                                  "pt" if direction == "decrypt" else "ct": output.hex().upper()}
                        iterations.append(record)
                        material = (input_now[-8:] + output) if len(key_now) == 24 else ((input_now + output) if len(key_now) == 32 else output)
                        key_now = bytes(a ^ b for a, b in zip(key_now, material))
                        iv_now = output
                    tests.append({"tcId": test["tcId"], "resultsArray": iterations})
                    continue
                payload = bytes((direction == "decrypt", len(key))) + key + iv + struct.pack("!H", len(data)) + data
                response = backend(operation, payload)
                if len(response) < 2 or struct.unpack("!H", response[:2])[0] != len(response) - 2:
                    raise AcvpError("calculator returned a malformed CBC response")
                tests.append({"tcId": test["tcId"], "pt" if direction == "decrypt" else "ct": response[2:].hex().upper()})
                continue
            aad = _hex(test.get("aad", ""), "aad")
            field = ("ct" if "ct" in test else "cipherText") if direction == "decrypt" else ("pt" if "pt" in test else "plainText")
            data = _hex(test.get(field), field)
            tag = _hex(test.get("tag", ""), "tag")
            tag_len = group.get("tagLen")
            if not isinstance(tag_len, int) or tag_len % 8:
                raise AcvpError(f"tgId {group.get('tgId')}: invalid tagLen")
            _expect_bits(group, "aadLen", aad)
            if algorithm == "ACVP-AES-CCM" and direction == "decrypt":
                tag_bytes = tag_len // 8
                if len(data) < tag_bytes: raise AcvpError("CCM ciphertext is shorter than its tag")
                data, tag = data[:-tag_bytes], data[-tag_bytes:]
            _expect_bits(group, "payloadLen", data)
            if direction == "decrypt" and len(tag) != tag_len // 8:
                raise AcvpError("authentication tag length does not match tagLen")
            accepted, output, out_tag = _aes_call(operation, direction, key, iv, aad,
                                                   data, tag, tag_len // 8, backend)
            response = {"tcId": test["tcId"]}
            if direction == "decrypt":
                response.update({"pt": output.hex().upper()} if accepted else {"testPassed": False})
            else:
                response["ct"] = (output + out_tag if algorithm == "ACVP-AES-CCM" else output).hex().upper()
                if algorithm != "ACVP-AES-CCM": response["tag"] = out_tag.hex().upper()
                if algorithm == "ACVP-AES-GCM" and group.get("ivGen") == "internal":
                    response["iv"] = iv.hex().upper()
            tests.append(response)
        groups.append({"tgId": group["tgId"], "tests": tests})
    return {"vsId": vector["vsId"], "testGroups": groups}


def _pbkdf_vector_set(vector: dict, backend: Backend) -> dict:
    groups = []
    for group in vector.get("testGroups", []):
        if group.get("testType", "AFT") != "AFT" or group.get("hmacAlg") != "SHA2-256":
            raise AcvpError("only PBKDF AFT with HMAC-SHA2-256 is supported")
        tests = []
        for test in group.get("tests", []):
            password = test.get("password")
            if not isinstance(password, str): raise AcvpError("password must be a string")
            password_bytes, salt = password.encode(), _hex(test.get("salt"), "salt")
            rounds, key_bits = test.get("iterationCount"), test.get("keyLen")
            if not isinstance(rounds, int) or not isinstance(key_bits, int) or key_bits % 8:
                raise AcvpError("invalid PBKDF iterationCount or keyLen")
            payload = (struct.pack("!H", len(password_bytes)) + password_bytes +
                       struct.pack("!H", len(salt)) + salt + struct.pack("!II", rounds, key_bits // 8))
            response = backend(OP_PBKDF2_SHA2_256, payload)
            if len(response) < 4 or struct.unpack("!I", response[:4])[0] != len(response) - 4:
                raise AcvpError("calculator returned a malformed PBKDF response")
            tests.append({"tcId": test["tcId"], "derivedKey": response[4:].hex().upper()})
        groups.append({"tgId": group["tgId"], "tests": tests})
    return {"vsId": vector["vsId"], "testGroups": groups}


def _fixed_info(pattern: str, test: dict, length_bits: int) -> bytes:
    pieces = []
    for name in pattern.split("||"):
        if name == "uPartyInfo": source = test.get("fixedInfoPartyU", {})
        elif name == "vPartyInfo": source = test.get("fixedInfoPartyV", {})
        elif name == "l": pieces.append(length_bits.to_bytes(4, "big")); continue
        elif name in ("label", "context", "algorithmId"):
            pieces.append(_hex(test.get("kdfParameter", {}).get(name, ""), name)); continue
        elif name.startswith("literal[") and name.endswith("]"):
            pieces.append(bytes.fromhex(name[8:-1])); continue
        else: raise AcvpError(f"unsupported fixedInfo token {name!r}")
        pieces.extend(_hex(source.get(field, ""), field) for field in ("partyId", "ephemeralData"))
    return b"".join(pieces)


def _hkdf_vector_set(vector: dict, backend: Backend) -> dict:
    groups = []
    for group in vector.get("testGroups", []):
        config = group.get("kdfConfiguration", {})
        if config.get("hmacAlg") != "SHA2-256" or config.get("fixedInfoEncoding") != "concatenation":
            raise AcvpError("only concatenated KDA/HKDF with SHA2-256 is supported")
        tests = []
        for test in group.get("tests", []):
            params = test.get("kdfParameter", {})
            z, salt, length_bits = _hex(params.get("z"), "z"), _hex(params.get("salt", ""), "salt"), params.get("l", config.get("l"))
            if not isinstance(length_bits, int) or length_bits % 8: raise AcvpError("invalid HKDF output length")
            info = _fixed_info(config.get("fixedInfoPattern", ""), test, length_bits)
            payload = (struct.pack("!H", len(z)) + z + struct.pack("!H", len(salt)) + salt +
                       struct.pack("!H", len(info)) + info + struct.pack("!H", length_bits // 8))
            response = backend(OP_HKDF_SHA2_256, payload)
            if len(response) < 2 or struct.unpack("!H", response[:2])[0] != len(response) - 2:
                raise AcvpError("calculator returned a malformed HKDF response")
            dkm = response[2:]
            item = {"tcId": test["tcId"]}
            if group.get("testType") == "VAL": item["testPassed"] = hmac.compare_digest(dkm, _hex(test.get("dkm"), "dkm"))
            else: item["dkm"] = dkm.hex().upper()
            tests.append(item)
        groups.append({"tgId": group["tgId"], "tests": tests})
    return {"vsId": vector["vsId"], "testGroups": groups}


def _rsa_vector_set(vector: dict, backend: Backend) -> dict:
    if vector.get("mode") != "sigVer": raise AcvpError("only RSA sigVer is supported")
    groups = []
    for group in vector.get("testGroups", []):
        sig_type = group.get("sigType")
        if group.get("hashAlg") != "SHA2-256" or sig_type not in ("pss", "pkcs1v1.5"):
            raise AcvpError("only RSA PSS/PKCS1v1.5 verification with SHA2-256 is supported")
        if group.get("testType", "AFT") != "AFT" or group.get("conformance") is not None:
            raise AcvpError("only ordinary RSA sigVer AFT groups are supported")
        if sig_type == "pss" and (group.get("saltLen") != 32 or
                                  group.get("maskFunction", "mgf1").lower() != "mgf1"):
            raise AcvpError("RSA-PSS requires a 32-byte salt and MGF1")
        n, e = _hex(group.get("n"), "n"), _hex(group.get("e"), "e")
        if e != b"\x01\x00\x01": raise AcvpError("the RSA implementation supports public exponent 65537 only")
        tests = []
        for test in group.get("tests", []):
            message, signature = _hex(test.get("message"), "message"), _hex(test.get("signature"), "signature")
            payload = (struct.pack("!H", len(n)) + n + bytes((len(e),)) + e +
                       struct.pack("!H", len(message)) + message + struct.pack("!H", len(signature)) + signature)
            verdict = backend(OP_RSA_PSS_SHA2_256_VERIFY if sig_type == "pss" else OP_RSA_PKCS1_SHA2_256_VERIFY, payload)
            if len(verdict) != 1: raise AcvpError("calculator returned a malformed RSA verdict")
            tests.append({"tcId": test["tcId"], "testPassed": bool(verdict[0])})
        groups.append({"tgId": group["tgId"], "tests": tests})
    return {"vsId": vector["vsId"], "testGroups": groups}


def _xecdh_vector_set(vector: dict, backend: Backend) -> dict:
    if vector.get("mode") != "SSC": raise AcvpError("only XECDH SSC is supported")
    groups = []
    for group in vector.get("testGroups", []):
        if group.get("curve") != "Curve25519" or group.get("testType") != "AFT":
            raise AcvpError("only Curve25519 SSC AFT is supported")
        tests = []
        for test in group.get("tests", []):
            response = backend(OP_X25519_SSC, _hex(test.get("publicServer"), "publicServer"))
            if len(response) != 64: raise AcvpError("calculator returned a malformed XECDH result")
            tests.append({"tcId": test["tcId"], "publicIut": response[:32].hex().upper(), "z": response[32:].hex().upper()})
        groups.append({"tgId": group["tgId"], "tests": tests})
    return {"vsId": vector["vsId"], "testGroups": groups}


def _ecdsa_vector_set(vector: dict, backend: Backend) -> dict:
    mode = vector.get("mode")
    if mode not in ("sigGen", "sigVer"): raise AcvpError("only ECDSA signature modes are supported")
    groups = []
    for group in vector.get("testGroups", []):
        if group.get("curve") != "P-256" or group.get("hashAlg") != "SHA2-256":
            raise AcvpError("only ECDSA P-256 with SHA2-256 is supported")
        if group.get("testType", "AFT") != "AFT" or group.get("conformance") is not None:
            raise AcvpError("only ordinary ECDSA AFT groups are supported")
        group_response = {"tgId": group["tgId"]}
        if mode == "sigGen":
            public_key = backend(OP_P256_SIGGEN_BEGIN, b"")
            if len(public_key) != 65 or public_key[0] != 4:
                raise AcvpError("calculator returned a malformed P-256 public key")
            group_response.update({"qx": public_key[1:33].hex().upper(),
                                   "qy": public_key[33:].hex().upper()})
        tests = []
        for test in group.get("tests", []):
            message = _hex(test.get("message"), "message")
            digest = backend(OP_SHA2_256, message)
            if mode == "sigGen":
                signature = backend(OP_P256_SIGGEN_ACTIVE, digest)
                if len(signature) != 64: raise AcvpError("calculator returned a malformed ECDSA signature")
                tests.append({"tcId": test["tcId"], "r": signature[:32].hex().upper(),
                              "s": signature[32:].hex().upper()})
            else:
                qx, qy = _hex(test.get("qx"), "qx"), _hex(test.get("qy"), "qy")
                r, s = _hex(test.get("r"), "r"), _hex(test.get("s"), "s")
                if any(len(x) != 32 for x in (qx, qy, r, s)):
                    raise AcvpError("P-256 coordinates and signature components must be 32 bytes")
                verdict = backend(OP_P256_SIGVER, b"\x04" + qx + qy + digest + r + s)
                if len(verdict) != 1: raise AcvpError("calculator returned a malformed ECDSA verdict")
                tests.append({"tcId": test["tcId"], "testPassed": bool(verdict[0])})
        group_response["tests"] = tests
        groups.append(group_response)
    return {"vsId": vector["vsId"], "testGroups": groups}


def _p256_cdh_vector_set(vector: dict, backend: Backend) -> dict:
    if vector.get("mode") != "CDH-Component": raise AcvpError("only KAS-ECC CDH-Component is supported")
    groups = []
    for group in vector.get("testGroups", []):
        if group.get("curve") != "P-256" or group.get("testType") != "AFT":
            raise AcvpError("only P-256 CDH-Component AFT is supported")
        tests = []
        for test in group.get("tests", []):
            x, y = _hex(test.get("publicServerX"), "publicServerX"), _hex(test.get("publicServerY"), "publicServerY")
            if len(x) != 32 or len(y) != 32: raise AcvpError("P-256 server coordinates must be 32 bytes")
            response = backend(OP_P256_CDH, b"\x04" + x + y)
            if len(response) != 97 or response[0] != 4: raise AcvpError("calculator returned a malformed P-256 CDH result")
            tests.append({"tcId": test["tcId"], "publicIutX": response[1:33].hex().upper(),
                          "publicIutY": response[33:65].hex().upper(), "z": response[65:].hex().upper()})
        groups.append({"tgId": group["tgId"], "tests": tests})
    return {"vsId": vector["vsId"], "testGroups": groups}


def process_document(document: object, backend: Backend) -> object:
    """Process ACVP vector-set JSON through ``backend``."""
    header, vectors = _vector_objects(document)
    responses = []
    for vector in vectors:
        algorithm = vector.get("algorithm")
        revision = vector.get("revision")
        if algorithm == "SHA2-256" and revision == "1.0":
            responses.append(_sha_vector_set(vector, backend))
        elif algorithm == "SHA2-384" and revision == "1.0":
            responses.append(_sha384_vector_set(vector, backend))
        elif algorithm == "SHA2-512" and revision == "1.0":
            responses.append(_sha512_vector_set(vector, backend))
        elif algorithm == "HMAC-SHA2-256" and revision in ("1.0", "2.0"):
            responses.append(_hmac_vector_set(vector, backend))
        elif algorithm == "HMAC-SHA2-384" and revision in ("1.0", "2.0"):
            responses.append(_hmac_sha384_vector_set(vector, backend))
        elif algorithm == "HMAC-SHA2-512" and revision in ("1.0", "2.0"):
            responses.append(_hmac_sha512_vector_set(vector, backend))
        elif algorithm in ("ACVP-AES-CBC", "ACVP-AES-GCM", "ACVP-AES-CCM") and revision == "1.0":
            responses.append(_aes_vector_set(vector, backend))
        elif algorithm == "PBKDF" and revision == "1.0":
            responses.append(_pbkdf_vector_set(vector, backend))
        elif algorithm == "KDA" and vector.get("mode") == "HKDF" and revision == "Sp800-56Cr1":
            responses.append(_hkdf_vector_set(vector, backend))
        elif algorithm == "RSA" and revision in ("FIPS186-4", "FIPS186-5"):
            responses.append(_rsa_vector_set(vector, backend))
        elif algorithm == "XECDH" and revision == "RFC7748":
            responses.append(_xecdh_vector_set(vector, backend))
        elif algorithm in ("ECDSA", "DetECDSA") and revision in ("FIPS186-4", "FIPS186-5"):
            responses.append(_ecdsa_vector_set(vector, backend))
        elif algorithm == "KAS-ECC" and revision == "1.0":
            responses.append(_p256_cdh_vector_set(vector, backend))
        else:
            raise AcvpError(f"unsupported ACVP capability {algorithm!r} revision {revision!r}")
    return [header, *responses] if header else (responses[0] if len(responses) == 1 else responses)


@dataclass
class SocketBackend:
    connection: socket.socket
    request_id: int = 0

    def _recv_exact(self, length: int) -> bytes:
        data = bytearray()
        while len(data) < length:
            chunk = self.connection.recv(length - len(data))
            if not chunk:
                raise AcvpError("calculator closed the ACVP connection")
            data.extend(chunk)
        return bytes(data)

    def __call__(self, operation: int, payload: bytes) -> bytes:
        if len(payload) > MAX_PAYLOAD:
            raise AcvpError(f"operation payload exceeds {MAX_PAYLOAD} bytes")
        self.request_id = (self.request_id + 1) & 0xFFFF
        if not self.request_id:
            self.request_id = 1
        self.connection.sendall(HEADER.pack(MAGIC_REQUEST, operation, 0,
                                             self.request_id, len(payload)) + payload)
        magic, status, reserved, request_id, length = HEADER.unpack(self._recv_exact(HEADER.size))
        if magic != MAGIC_RESPONSE or reserved or request_id != self.request_id:
            raise AcvpError("malformed or out-of-sequence calculator response")
        if length > MAX_PAYLOAD:
            raise AcvpError("calculator response exceeds the protocol limit")
        body = self._recv_exact(length)
        if status:
            raise AcvpError(f"calculator rejected operation {operation} with status {status}")
        return body

    def stop(self) -> None:
        self(OP_STOP, b"")


def reference_backend(operation: int, payload: bytes) -> bytes:
    """Host implementation used only by parser/protocol self-tests."""
    if operation == OP_SHA2_256:
        return sha256(payload).digest()
    if operation == OP_SHA2_384:
        return hashlib.sha384(payload).digest()
    if operation == OP_SHA2_384_MCT:
        a = b = c = payload
        for _ in range(1000):
            a, b, c = b, c, hashlib.sha384(a + b + c).digest()
        return c
    if operation == OP_HMAC_SHA2_384:
        if len(payload) < 4:
            raise AcvpError("short HMAC-SHA384 payload")
        key_len, mac_len = struct.unpack("!HH", payload[:4])
        key = payload[4:4 + key_len]
        return hmac.digest(key, payload[4 + key_len:], "sha384")[:mac_len]
    if operation == OP_SHA2_512:
        return hashlib.sha512(payload).digest()
    if operation == OP_SHA2_512_MCT:
        a = b = c = payload
        for _ in range(1000):
            a, b, c = b, c, hashlib.sha512(a + b + c).digest()
        return c
    if operation == OP_HMAC_SHA2_512:
        if len(payload) < 4:
            raise AcvpError("short HMAC-SHA512 payload")
        key_len, mac_len = struct.unpack("!HH", payload[:4])
        key = payload[4:4 + key_len]
        return hmac.digest(key, payload[4 + key_len:], "sha512")[:mac_len]
    if operation == OP_HMAC_SHA2_256:
        if len(payload) < 4:
            raise AcvpError("short HMAC payload")
        key_len, mac_len = struct.unpack("!HH", payload[:4])
        key = payload[4:4 + key_len]
        return hmac.digest(key, payload[4 + key_len:], "sha256")[:mac_len]
    if operation == OP_SHA2_256_MCT:
        a = b = c = payload
        for _ in range(1000):
            a, b, c = b, c, sha256(a + b + c).digest()
        return c
    if operation == OP_PBKDF2_SHA2_256:
        pw_len = struct.unpack("!H", payload[:2])[0]; off = 2
        password = payload[off:off + pw_len]; off += pw_len
        salt_len = struct.unpack("!H", payload[off:off + 2])[0]; off += 2
        salt = payload[off:off + salt_len]; off += salt_len
        rounds, length = struct.unpack("!II", payload[off:off + 8])
        value = hashlib.pbkdf2_hmac("sha256", password, salt, rounds, length)
        return struct.pack("!I", len(value)) + value
    if operation == OP_HKDF_SHA2_256:
        z_len = struct.unpack("!H", payload[:2])[0]; off = 2
        z = payload[off:off + z_len]; off += z_len
        salt_len = struct.unpack("!H", payload[off:off + 2])[0]; off += 2
        salt = payload[off:off + salt_len]; off += salt_len
        info_len = struct.unpack("!H", payload[off:off + 2])[0]; off += 2
        info = payload[off:off + info_len]; off += info_len
        length = struct.unpack("!H", payload[off:off + 2])[0]
        prk = hmac.digest(salt, z, "sha256")
        output = b""; previous = b""
        for counter in range(1, (length + 31) // 32 + 1):
            previous = hmac.digest(prk, previous + info + bytes((counter,)), "sha256")
            output += previous
        output = output[:length]
        return struct.pack("!H", length) + output
    if operation == OP_P256_SIGVER:
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import ec, utils
        except ImportError as exc:
            raise AcvpError("reference P-256 tests require python3-cryptography") from exc
        if len(payload) != 161 or payload[0] != 4: raise AcvpError("malformed reference P-256 payload")
        public = ec.EllipticCurvePublicNumbers(int.from_bytes(payload[1:33], "big"),
                                               int.from_bytes(payload[33:65], "big"),
                                               ec.SECP256R1()).public_key()
        signature = utils.encode_dss_signature(int.from_bytes(payload[97:129], "big"),
                                               int.from_bytes(payload[129:], "big"))
        try:
            public.verify(signature, payload[65:97], ec.ECDSA(utils.Prehashed(hashes.SHA256())))
            return b"\1"
        except InvalidSignature:
            return b"\0"
    if operation in (OP_RSA_PSS_SHA2_256_VERIFY, OP_RSA_PKCS1_SHA2_256_VERIFY):
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding, rsa
        except ImportError as exc:
            raise AcvpError("reference RSA tests require python3-cryptography") from exc
        n_len = struct.unpack("!H", payload[:2])[0]; off = 2
        n = int.from_bytes(payload[off:off + n_len], "big"); off += n_len
        e_len = payload[off]; off += 1; e = int.from_bytes(payload[off:off + e_len], "big"); off += e_len
        msg_len = struct.unpack("!H", payload[off:off + 2])[0]; off += 2
        message = payload[off:off + msg_len]; off += msg_len
        sig_len = struct.unpack("!H", payload[off:off + 2])[0]; off += 2
        signature = payload[off:off + sig_len]
        scheme = (padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
                  if operation == OP_RSA_PSS_SHA2_256_VERIFY else padding.PKCS1v15())
        try:
            rsa.RSAPublicNumbers(e, n).public_key().verify(signature, message, scheme, hashes.SHA256())
            return b"\1"
        except InvalidSignature:
            return b"\0"
    if operation == OP_AES_CBC_MCT:
        decrypt, key_len = payload[0], payload[1]
        key = payload[2:2 + key_len]; iv = payload[2 + key_len:18 + key_len]
        current = payload[20 + key_len:36 + key_len]
        previous = b""; chain = iv
        for j in range(1000):
            framed = reference_backend(OP_AES_CBC, bytes((decrypt, key_len)) + key + chain + b"\x00\x10" + current)
            output = framed[2:]
            next_input = iv if j == 0 else previous
            chain = current if decrypt else output
            previous, current = output, next_input
        return current + previous
    if operation in (OP_AES_CBC, OP_AES_GCM, OP_AES_CCM):
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.primitives.ciphers.aead import AESCCM, AESGCM
        except ImportError as exc:
            raise AcvpError("reference AES tests require python3-cryptography") from exc
        decrypt, key_len = payload[0], payload[1]; off = 2
        key = payload[off:off + key_len]; off += key_len
        if operation == OP_AES_CBC:
            iv = payload[off:off + 16]; off += 16
            length = struct.unpack("!H", payload[off:off + 2])[0]; off += 2
            transform = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor() if decrypt else Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
            output = transform.update(payload[off:off + length]) + transform.finalize()
            return struct.pack("!H", len(output)) + output
        iv_len = payload[off]; off += 1; iv = payload[off:off + iv_len]; off += iv_len
        aad_len = struct.unpack("!H", payload[off:off + 2])[0]; off += 2
        aad = payload[off:off + aad_len]; off += aad_len
        data_len = struct.unpack("!H", payload[off:off + 2])[0]; off += 2
        data = payload[off:off + data_len]; off += data_len
        tag_len = payload[off]; off += 1; tag = payload[off:off + tag_len]
        aead = AESGCM(key) if operation == OP_AES_GCM else AESCCM(key, tag_length=tag_len)
        if decrypt:
            try: output = aead.decrypt(iv, data + tag, aad); accepted = 1
            except Exception: output = b""; accepted = 0
            return bytes((accepted,)) + struct.pack("!H", len(output)) + output + b"\0"
        combined = aead.encrypt(iv, data, aad)
        return b"\1" + struct.pack("!H", len(data)) + combined[:-tag_len] + bytes((tag_len,)) + combined[-tag_len:]
    if operation == OP_STOP:
        return b""
    raise AcvpError(f"unsupported reference operation {operation}")


def process_file(source: Path, destination: Path, backend: Backend) -> object:
    response = process_document(json.loads(source.read_text()), backend)
    destination.write_text(json.dumps(response, indent=2) + "\n")
    return response

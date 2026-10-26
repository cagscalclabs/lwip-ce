#!/usr/bin/env python3
"""Validate ACVP parsing and response generation without CEmu."""

import json
import socket
import threading
import tempfile
from pathlib import Path

from acvp_client import (HEADER, MAGIC_REQUEST, MAGIC_RESPONSE, OP_P256_CDH,
                         OP_P256_SIGGEN_ACTIVE, OP_P256_SIGGEN_BEGIN, OP_P256_SIGVER,
                         OP_RSA_PKCS1_SHA2_256_VERIFY, OP_RSA_PSS_SHA2_256_VERIFY,
                         OP_SHA2_256, OP_X25519_SSC, SocketBackend,
                         process_document, reference_backend)
from generate_vectors import GENERATED_ALGORITHMS, build_corpus
from summary import render, write_evidence_bundle
from validate import validate_document

HERE = Path(__file__).resolve().parent
prompt = json.loads((HERE / "fixtures" / "prompt.json").read_text())
expected = json.loads((HERE / "fixtures" / "expected.json").read_text())
capabilities = json.loads((HERE / "capabilities.json").read_text())["algorithms"]
assert {(item["algorithm"], item.get("mode")) for item in capabilities} == {
    ("SHA2-256", None), ("HMAC-SHA2-256", None),
    ("ACVP-AES-CBC", None), ("ACVP-AES-GCM", None), ("ACVP-AES-CCM", None),
    ("PBKDF", None), ("KDA", "HKDF"), ("RSA", "sigVer"),
    ("ECDSA", "sigVer"), ("DetECDSA", "sigGen"),
    ("XECDH", "SSC"), ("KAS-ECC", "CDH-Component"),
}
actual = process_document(prompt, reference_backend)
if actual != expected:
    raise SystemExit("ACVP fixture response mismatch")

markdown, report, passed = render(prompt, expected, actual, {}, "success")
assert passed and report["passedTests"] == 10 and "10/10 test cases matched" in markdown
_, failed_report, passed = render(prompt, expected, None, {}, "failure")
assert not passed and failed_report["failedTests"] == 10

corpus, corpus_expected, corpus_oracle = build_corpus()
assert sum(corpus_oracle["counts"].values()) == 416
assert all(count >= 32 for count in corpus_oracle["counts"].values())
deterministic = [corpus[0], *[vector for vector in corpus[1:]
                              if vector["algorithm"] not in GENERATED_ALGORITHMS]]
assert process_document(deterministic, reference_backend) == corpus_expected

# Exercise semantic grading for all generated-key vector families.
class SemanticBackend:
    def __init__(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        self.ec = ec
        self.signing_key = ec.derive_private_key(7, ec.SECP256R1())
        self.signature_cache = {}
        self.counter = 0

    @staticmethod
    def point(public) -> bytes:
        numbers = public.public_numbers()
        return b"\x04" + numbers.x.to_bytes(32, "big") + numbers.y.to_bytes(32, "big")

    def __call__(self, operation: int, payload: bytes) -> bytes:
        from hashlib import sha256
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, utils, x25519
        if operation == OP_P256_SIGGEN_BEGIN:
            return self.point(self.signing_key.public_key())
        if operation == OP_P256_SIGGEN_ACTIVE:
            if payload not in self.signature_cache:
                der = self.signing_key.sign(payload, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
                r, s = utils.decode_dss_signature(der)
                self.signature_cache[payload] = r.to_bytes(32, "big") + s.to_bytes(32, "big")
            return self.signature_cache[payload]
        if operation == OP_X25519_SSC:
            self.counter += 1
            private = x25519.X25519PrivateKey.from_private_bytes(
                sha256(b"x" + self.counter.to_bytes(2, "big")).digest())
            public = private.public_key().public_bytes(serialization.Encoding.Raw,
                                                        serialization.PublicFormat.Raw)
            return public + private.exchange(x25519.X25519PublicKey.from_public_bytes(payload))
        if operation == OP_P256_CDH:
            self.counter += 1
            scalar = 1 + int.from_bytes(sha256(b"p" + self.counter.to_bytes(2, "big")).digest(), "big") % (2**255)
            private = ec.derive_private_key(scalar, ec.SECP256R1())
            peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), payload)
            return self.point(private.public_key()) + private.exchange(ec.ECDH(), peer)
        return reference_backend(operation, payload)

corpus_response = process_document(corpus, SemanticBackend())
corpus_report = validate_document(corpus, corpus_expected, corpus_response, corpus_oracle)
assert corpus_report["passed"] and corpus_report["passedTests"] == 416
corpus_markdown, corpus_summary, passed = render(
    corpus, corpus_expected, corpus_response, corpus_oracle, "success")
assert passed and corpus_summary["passedTests"] == 416
assert "416/416 test cases matched" in corpus_markdown and "| SHA2-256 |" in corpus_markdown
assert "Actual vector inputs" not in corpus_markdown
with tempfile.TemporaryDirectory() as artifact_tmp:
    artifact_dir = Path(artifact_tmp)
    write_evidence_bundle(artifact_dir, corpus, corpus_expected,
                          corpus_response, corpus_summary, corpus_oracle)
    assert {path.name for path in artifact_dir.iterdir()} == {"acvp-validation.vectors"}
    bundle = json.loads((artifact_dir / "acvp-validation.vectors").read_text())
    assert bundle["format"] == "lwip-ce-acvp-vectors-v1"
    assert bundle["knownAnswerVectors"] == corpus
    assert bundle["expectedResults"]["exactResults"] == corpus_expected
    assert bundle["calculatorResults"] == corpus_response
    assert bundle["validationResults"]["passedTests"] == 416
    assert len(bundle["expectedResults"]["semanticExpectations"]["XECDH"]["serverPrivateByTcId"]) == 32

# Revision 1.0 carries HMAC lengths on the group instead of each test case.
revision_one = {
    "vsId": 3, "algorithm": "HMAC-SHA2-256", "revision": "1.0",
    "testGroups": [{"tgId": 3, "testType": "AFT", "keyLen": 8,
                    "msgLen": 0, "macLen": 32,
                    "tests": [{"tcId": 4, "key": "00", "msg": ""}]}],
}
revision_one_response = process_document(revision_one, reference_backend)
assert len(revision_one_response["testGroups"][0]["tests"][0]["mac"]) == 8

# Exercise the asymmetric ACVP schemas without making host crypto a second IUT.
gx = bytes.fromhex("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296")
gy = bytes.fromhex("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5")
def asymmetric_backend(operation: int, payload: bytes) -> bytes:
    if operation == OP_SHA2_256:
        return reference_backend(operation, payload)
    if operation in (OP_RSA_PSS_SHA2_256_VERIFY, OP_RSA_PKCS1_SHA2_256_VERIFY,
                     OP_P256_SIGVER):
        return b"\1"
    if operation == OP_P256_SIGGEN_BEGIN:
        return b"\x04" + gx + gy
    if operation == OP_P256_CDH:
        return b"\x04" + gx + gy + b"\x55" * 32
    if operation == OP_P256_SIGGEN_ACTIVE:
        return b"\x11" * 32 + b"\x22" * 32
    if operation == OP_X25519_SSC:
        return b"\x33" * 32 + b"\x44" * 32
    raise AssertionError(f"unexpected operation {operation}")

asymmetric_vectors = [
    {"vsId": 8, "algorithm": "RSA", "mode": "sigVer", "revision": "FIPS186-5",
     "testGroups": [{"tgId": 8, "testType": "AFT", "sigType": "pkcs1v1.5",
                     "hashAlg": "SHA2-256", "n": "AA" * 256, "e": "010001",
                     "tests": [{"tcId": 9, "message": "00", "signature": "BB" * 256}]}]},
    {"vsId": 9, "algorithm": "ECDSA", "mode": "sigVer", "revision": "FIPS186-5",
     "testGroups": [{"tgId": 9, "testType": "AFT", "curve": "P-256", "hashAlg": "SHA2-256",
                     "tests": [{"tcId": 10, "message": "00", "qx": gx.hex(), "qy": gy.hex(),
                                "r": "11" * 32, "s": "22" * 32}]}]},
    {"vsId": 10, "algorithm": "DetECDSA", "mode": "sigGen", "revision": "FIPS186-5",
     "testGroups": [{"tgId": 10, "testType": "AFT", "curve": "P-256", "hashAlg": "SHA2-256",
                     "tests": [{"tcId": 11, "message": "00"}]}]},
    {"vsId": 11, "algorithm": "XECDH", "mode": "SSC", "revision": "RFC7748",
     "testGroups": [{"tgId": 11, "testType": "AFT", "curve": "Curve25519",
                     "tests": [{"tcId": 12, "publicServer": "09" + "00" * 31}]}]},
    {"vsId": 12, "algorithm": "KAS-ECC", "mode": "CDH-Component", "revision": "1.0",
     "testGroups": [{"tgId": 12, "testType": "AFT", "curve": "P-256",
                     "tests": [{"tcId": 13, "publicServerX": gx.hex(), "publicServerY": gy.hex()}]}]},
]
asymmetric_response = process_document(asymmetric_vectors, asymmetric_backend)
assert all(item["testGroups"][0]["tests"] for item in asymmetric_response)

# Exercise the actual synchronous frame format independently of CEmu.
client, server = socket.socketpair()
def reply() -> None:
    magic, operation, reserved, request_id, length = HEADER.unpack(server.recv(HEADER.size))
    payload = server.recv(length)
    assert (magic, operation, reserved) == (MAGIC_REQUEST, OP_SHA2_256, 0)
    digest = reference_backend(operation, payload)
    server.sendall(HEADER.pack(MAGIC_RESPONSE, 0, 0, request_id, len(digest)) + digest)
    server.close()

thread = threading.Thread(target=reply)
thread.start()
backend = SocketBackend(client)
assert backend(OP_SHA2_256, b"abc").hex() == expected[1]["testGroups"][0]["tests"][1]["md"].lower()
client.close()
thread.join()
print("ACVP host client self-test: PASS")

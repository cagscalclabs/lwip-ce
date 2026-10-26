#!/usr/bin/env python3
"""Generate a substantial ACVP-shaped differential corpus."""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

from acvp_client import process_document, reference_backend

HERE = Path(__file__).resolve().parent
SEED = 0x4C57495041435650
GENERATED_ALGORITHMS = {"DetECDSA", "XECDH", "KAS-ECC"}


class Corpus:
    def __init__(self) -> None:
        self.rng = random.Random(SEED)
        self.tc = 0
        self.tg = 0
        self.vs = 0
        self.vectors: list[dict] = []
        self.oracle: dict[str, dict[str, str]] = {"x25519": {}, "p256": {}}

    def bytes(self, length: int) -> bytes:
        return self.rng.randbytes(length)

    def test(self, **fields) -> dict:
        self.tc += 1
        return {"tcId": self.tc, **fields}

    def group(self, tests: list[dict], **fields) -> dict:
        self.tg += 1
        return {"tgId": self.tg, **fields, "tests": tests}

    def vector(self, algorithm: str, revision: str, groups: list[dict], **fields) -> None:
        self.vs += 1
        self.vectors.append({"vsId": self.vs, "algorithm": algorithm,
                             "revision": revision, **fields, "testGroups": groups})


def build_corpus() -> tuple[list[dict], list[dict], dict]:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, x25519
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM, AESGCM

    c = Corpus()

    # SHA-256: 63 AFT lengths plus one full standard MCT seed.
    lengths = [0, 1, 2, 3, 7, 8, 15, 16, 31, 32, 55, 56, 63, 64, 65,
               127, 128, 255, 256, 511, 512, 1023, 2048, 4096, 8192]
    lengths += [c.rng.randrange(0, 8193) for _ in range(63 - len(lengths))]
    sha_aft = [c.test(len=n * 8, msg=(c.bytes(n).hex() if n else "00")) for n in lengths]
    sha_groups = [c.group(sha_aft, testType="AFT"),
                  c.group([c.test(len=256, msg=c.bytes(32).hex())],
                          testType="MCT", mctVersion="standard")]
    c.vector("SHA2-256", "1.0", sha_groups)

    # HMAC: key, message, and truncation boundaries.
    hmac_tests = []
    key_lengths = [1, 4, 16, 32, 63, 64, 65, 128, 256]
    msg_lengths = [0, 1, 15, 16, 31, 32, 55, 56, 64, 65, 127, 255, 512]
    mac_lengths = [4, 8, 16, 24, 32]
    for i in range(32):
        kl, ml, tl = key_lengths[i % len(key_lengths)], msg_lengths[(i * 3) % len(msg_lengths)], mac_lengths[i % 5]
        hmac_tests.append(c.test(key=c.bytes(kl).hex(), keyLen=kl * 8,
                                 msg=(c.bytes(ml).hex() if ml else ""), len=ml * 8,
                                 macLen=tl * 8))
    c.vector("HMAC-SHA2-256", "2.0", [c.group(hmac_tests, testType="AFT")])

    # AES-CBC: 15 AFTs in each direction and one MCT seed per direction.
    cbc_groups = []
    for direction in ("encrypt", "decrypt"):
        for i in range(15):
            key = c.bytes((16, 24, 32)[i % 3]); iv = c.bytes(16)
            plain = c.bytes(16 * (1 + i % 8))
            enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
            cipher = enc.update(plain) + enc.finalize()
            field = {"pt": plain.hex()} if direction == "encrypt" else {"ct": cipher.hex()}
            cbc_groups.append(c.group([c.test(key=key.hex(), iv=iv.hex(), **field)],
                                      testType="AFT", direction=direction, keyLen=len(key) * 8,
                                      ivLen=128, payloadLen=len(plain) * 8))
        key, iv, block = c.bytes(16), c.bytes(16), c.bytes(16)
        cbc_groups.append(c.group([c.test(key=key.hex(), iv=iv.hex(),
                                              **({"pt": block.hex()} if direction == "encrypt" else {"ct": block.hex()}))],
                                  testType="MCT", direction=direction, keyLen=128, ivLen=128))
    c.vector("ACVP-AES-CBC", "1.0", cbc_groups)

    def add_aead(algorithm: str) -> None:
        groups = []
        for i in range(16):
            key = c.bytes((16, 24, 32)[i % 3]); iv_len = 12 if algorithm.endswith("GCM") else 7 + i % 7
            iv, aad = c.bytes(iv_len), c.bytes((i * 7) % 65)
            plain = c.bytes((i * 13) % 129)
            tag_len = 16 if algorithm.endswith("GCM") else (4, 6, 8, 10, 12, 14, 16)[i % 7]
            aead = AESGCM(key) if algorithm.endswith("GCM") else AESCCM(key, tag_length=tag_len)
            combined = aead.encrypt(iv, plain, aad); cipher, tag = combined[:-tag_len], combined[-tag_len:]
            common = dict(testType="AFT", keyLen=len(key) * 8, ivLen=iv_len * 8,
                          payloadLen=len(plain) * 8, aadLen=len(aad) * 8, tagLen=tag_len * 8)
            if algorithm.endswith("GCM"): common["ivGen"] = "external"
            groups.append(c.group([c.test(key=key.hex(), iv=iv.hex(), pt=plain.hex(), aad=aad.hex())],
                                  direction="encrypt", **common))
            if i & 1:
                tag = tag[:-1] + bytes((tag[-1] ^ 1,))
            decrypt_fields = {"ct": (cipher + tag).hex()} if algorithm.endswith("CCM") else {"ct": cipher.hex(), "tag": tag.hex()}
            groups.append(c.group([c.test(key=key.hex(), iv=iv.hex(), aad=aad.hex(), **decrypt_fields)],
                                  direction="decrypt", **common))
        c.vector(algorithm, "1.0", groups)

    add_aead("ACVP-AES-GCM")
    add_aead("ACVP-AES-CCM")

    pbkdf_tests = []
    for i in range(32):
        password = "p" + c.bytes(1 + i % 31).hex()
        salt = c.bytes(1 + (i * 5) % 64)
        pbkdf_tests.append(c.test(password=password, salt=salt.hex(),
                                  iterationCount=(1, 2, 10, 100, 1000)[i % 5],
                                  keyLen=(1, 16, 32, 48, 64)[i % 5] * 8))
    c.vector("PBKDF", "1.0", [c.group(pbkdf_tests, testType="AFT", hmacAlg="SHA2-256")])

    hkdf_tests = []
    for i in range(32):
        z, salt = c.bytes(14 + i % 65), c.bytes(i % 33)
        out_len = (1, 16, 32, 64, 96, 128)[i % 6]
        hkdf_tests.append(c.test(
            kdfParameter={"kdfType": "hkdf", "z": z.hex(), "salt": salt.hex(), "l": out_len * 8},
            fixedInfoPartyU={"partyId": c.bytes(i % 17).hex()},
            fixedInfoPartyV={"partyId": c.bytes((i * 3) % 19).hex()}))
    hkdf_config = {"kdfType": "hkdf", "l": 1024, "saltLen": 256,
                   "saltMethod": "random", "fixedInfoPattern": "uPartyInfo||vPartyInfo||l",
                   "fixedInfoEncoding": "concatenation", "hmacAlg": "SHA2-256"}
    c.vector("KDA", "Sp800-56Cr1", [c.group(hkdf_tests, testType="AFT", kdfConfiguration=hkdf_config)], mode="HKDF")

    # RSA sigVer: 8 valid and 8 invalid cases for each supported encoding.
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = rsa_key.public_key().public_numbers()
    rsa_groups = []
    for sig_type in ("pkcs1v1.5", "pss"):
        tests = []
        scheme = padding.PKCS1v15() if sig_type == "pkcs1v1.5" else padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
        for i in range(16):
            message = c.bytes(i * 11 % 257)
            signature = rsa_key.sign(message, scheme, hashes.SHA256())
            if i & 1: signature = signature[:-1] + bytes((signature[-1] ^ 1,))
            tests.append(c.test(message=message.hex(), signature=signature.hex()))
        extra = {"saltLen": 32, "maskFunction": "mgf1"} if sig_type == "pss" else {}
        rsa_groups.append(c.group(tests, testType="AFT", sigType=sig_type,
                                  hashAlg="SHA2-256", modulo=2048, e="010001",
                                  n=numbers.n.to_bytes(256, "big").hex(), **extra))
    c.vector("RSA", "FIPS186-5", rsa_groups, mode="sigVer")

    # ECDSA verification: alternating valid/invalid signatures.
    ecdsa_key = ec.derive_private_key(1 + int.from_bytes(c.bytes(32), "big") % (2**255), ec.SECP256R1())
    pub = ecdsa_key.public_key().public_numbers(); ecdsa_tests = []
    from cryptography.hazmat.primitives.asymmetric import utils
    for i in range(32):
        message = c.bytes(i * 9 % 193)
        r, s = utils.decode_dss_signature(ecdsa_key.sign(message, ec.ECDSA(hashes.SHA256())))
        if i & 1: s ^= 1
        ecdsa_tests.append(c.test(message=message.hex(), qx=f"{pub.x:064x}", qy=f"{pub.y:064x}",
                                  r=f"{r:064x}", s=f"{s:064x}"))
    c.vector("ECDSA", "FIPS186-5", [c.group(ecdsa_tests, testType="AFT", curve="P-256", hashAlg="SHA2-256")], mode="sigVer")

    # Generated-key algorithms are graded semantically instead of by byte equality.
    messages = [c.bytes((i * 7) % 129) for i in range(16)]
    siggen_tests = [c.test(message=messages[i % 16].hex()) for i in range(32)]
    c.vector("DetECDSA", "FIPS186-5", [c.group(siggen_tests, testType="AFT", curve="P-256", hashAlg="SHA2-256")], mode="sigGen")

    x_tests = []
    for _ in range(32):
        private_bytes = c.bytes(32)
        private = x25519.X25519PrivateKey.from_private_bytes(private_bytes)
        public = private.public_key().public_bytes(serialization.Encoding.Raw,
                                                    serialization.PublicFormat.Raw)
        test = c.test(publicServer=public.hex()); c.oracle["x25519"][str(test["tcId"])] = private_bytes.hex(); x_tests.append(test)
    c.vector("XECDH", "RFC7748", [c.group(x_tests, testType="AFT", curve="Curve25519")], mode="SSC")

    p_tests = []
    for _ in range(32):
        scalar = 1 + int.from_bytes(c.bytes(32), "big") % (2**255)
        private = ec.derive_private_key(scalar, ec.SECP256R1()); public = private.public_key().public_numbers()
        test = c.test(publicServerX=f"{public.x:064x}", publicServerY=f"{public.y:064x}")
        c.oracle["p256"][str(test["tcId"])] = f"{scalar:064x}"; p_tests.append(test)
    c.vector("KAS-ECC", "1.0", [c.group(p_tests, testType="AFT", curve="P-256")], mode="CDH-Component")

    prompt = [{"acvVersion": "1.0"}, *c.vectors]
    deterministic = [{"acvVersion": "1.0"}, *[v for v in c.vectors if v["algorithm"] not in GENERATED_ALGORITHMS]]
    expected = process_document(deterministic, reference_backend)
    counts = {v["algorithm"]: sum(len(g["tests"]) for g in v["testGroups"]) for v in c.vectors}
    assert counts == {"SHA2-256": 64, "HMAC-SHA2-256": 32, "ACVP-AES-CBC": 32,
                      "ACVP-AES-GCM": 32, "ACVP-AES-CCM": 32, "PBKDF": 32,
                      "KDA": 32, "RSA": 32, "ECDSA": 32, "DetECDSA": 32,
                      "XECDH": 32, "KAS-ECC": 32}
    c.oracle["counts"] = counts
    return prompt, expected, c.oracle


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=HERE / "corpus")
    args = parser.parse_args(); args.output.mkdir(parents=True, exist_ok=True)
    prompt, expected, oracle = build_corpus()
    for name, value in (("prompt.json", prompt), ("expected.json", expected), ("oracle.json", oracle)):
        (args.output / name).write_text(json.dumps(value, indent=2) + "\n")
    print(f"generated {sum(oracle['counts'].values())} ACVP vectors: {oracle['counts']}")


if __name__ == "__main__":
    main()

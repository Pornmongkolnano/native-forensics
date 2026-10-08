#!/usr/bin/env python3
"""Synthetic RSA/PFX and NTFS EFS AES256 corpus, independent of the adapter.

No user evidence or key is read. OpenSSL makes the disposable RSA identities and
wraps a supplied FEK using PKCS#1 v1.5. Its EVP implementation independently
encrypts fixed literal plaintext under per512-byte EFS IVs. Secret bytes are
passed through anonymous descriptors/memory, never command arguments or env.
Generated PFX/password files are exclusively created mode0600 under ignored local.
The on-disk field layout is reconstructed from Microsoft MS-EFSR2.2.2.1-5;
AES unit IVs come from the primary ntfs-3g reader, not an official MS IV spec.
This is a synthetic, nonbootable NTFS volume, not a Windows interoperability
receipt. A Windows-created volume or independent reader is a separate gate.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import struct
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Tests/NativeEngine"))
import ntfs_fixtures as ntfs


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def exclusive(path: Path, data: bytes, mode=0o600) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


def openssl(arguments: list[str | bytes], body: bytes | None = None) -> bytes:
    """Bytes in the argv recipe represent an anonymous pipe, not an argument."""
    executable = shutil.which("openssl")
    if not executable:
        raise RuntimeError("OpenSSL fixture producer is unavailable")
    descriptors: list[int] = []
    argv: list[str] = [executable]
    try:
        for argument in arguments:
            if isinstance(argument, bytes):
                if len(argument) > 4096:
                    raise RuntimeError("Fixture anonymous input exceeds bounded pipe setup")
                read_fd, write_fd = os.pipe()
                descriptors.append(read_fd)
                try:
                    written = os.write(write_fd, argument)
                    if written != len(argument):
                        raise RuntimeError("Incomplete fixture secret pipe")
                finally:
                    os.close(write_fd)
                argv.append(f"/dev/fd/{read_fd}")
            else:
                argv.append(argument)
        result = subprocess.run(argv, input=body, pass_fds=tuple(descriptors),
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30)
        if result.returncode:
            raise RuntimeError("OpenSSL fixture operation failed; no secret stderr retained")
        return result.stdout
    finally:
        for fd in descriptors:
            os.close(fd)


def openssl_password(arguments: list[str | bytes], password: bytes) -> bytes:
    """Insert one password fd; bytes are not exposed in the child argv/env."""
    read_fd, write_fd = os.pipe()
    descriptors = [read_fd]
    executable = shutil.which("openssl")
    if not executable or len(password) > 4095:
        os.close(read_fd); os.close(write_fd)
        raise RuntimeError("Fixture password input unavailable")
    try:
        if os.write(write_fd, password + b"\n") != len(password) + 1:
            raise RuntimeError("Incomplete fixture password pipe")
        os.close(write_fd); write_fd = -1
        argv = [executable]
        for item in arguments:
            if isinstance(item, bytes):
                if len(item) > 4096:
                    raise RuntimeError("Fixture anonymous input exceeds bounded pipe setup")
                r, w = os.pipe(); descriptors.append(r)
                try:
                    if os.write(w, item) != len(item):
                        raise RuntimeError("Incomplete fixture anonymous pipe")
                finally:
                    os.close(w)
                argv.append(f"/dev/fd/{r}")
            else:
                argv.append(item.replace("PASSWORD_DESCRIPTOR", f"fd:{read_fd}"))
        result = subprocess.run(argv, pass_fds=tuple(descriptors), stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=30)
        if result.returncode:
            raise RuntimeError("OpenSSL fixture operation failed; no secret stderr retained")
        return result.stdout
    finally:
        if write_fd >= 0:
            os.close(write_fd)
        for fd in descriptors:
            os.close(fd)


def identity(role: str, bits=2048, algorithm="RSA") -> dict:
    oid = {"ddf": "1.3.6.1.4.1.311.10.3.4", "drf": "1.3.6.1.4.1.311.10.3.4.1",
           "wrong-purpose": "1.3.6.1.5.5.7.3.1"}[role]
    private_key = openssl(["genpkey", "-algorithm", algorithm, "-pkeyopt",
                           f"rsa_keygen_bits:{bits}" if algorithm == "RSA" else "ec_paramgen_curve:P-256"])
    private_der = openssl(["pkey", "-in", private_key, "-traditional", "-outform", "DER"])
    label = "NF-EFS-SYNTHETIC-" + uuid.uuid4().hex
    certificate = openssl(["req", "-new", "-x509", "-key", private_key, "-days", "1",
                           "-subj", "/CN=" + label, "-addext", "extendedKeyUsage=" + oid,
                           "-outform", "DER"])
    certificate_pem = openssl(["x509", "-inform", "DER", "-outform", "PEM"], certificate)
    public_key = openssl(["pkey", "-pubout", "-in", private_key])
    password = (("SyntheticOnly-รหัส-🔑-" if role == "drf" else "SyntheticOnly-") + secrets.token_hex(12)).encode("utf-8")
    pfx = openssl_password(["pkcs12", "-export", "-inkey", private_key, "-in", certificate_pem,
                           "-name", label, "-keypbe", "PBE-SHA1-3DES", "-certpbe", "PBE-SHA1-3DES",
                           "-macalg", "sha1", "-passout", "PASSWORD_DESCRIPTOR"], password)
    return {"certificate": certificate, "public_key": public_key, "private_der": private_der, "pfx": pfx,
            "password": password, "thumbprint": hashlib.sha1(certificate).digest(), "role": role,
            "label": label, "bits": bits}


class OpenSSLAES:
    """Fixture-only OpenSSL EVP CBC producer; production uses CommonCrypto."""
    def __init__(self):
        executable = Path(shutil.which("openssl") or "missing").resolve()
        candidates = [executable.parent.parent / "lib/libcrypto.3.dylib",
                      executable.parent.parent / "lib/libcrypto.dylib"]
        path = next((item for item in candidates if item.is_file()), None)
        if path is None:
            raise RuntimeError("Fixture OpenSSL EVP library unavailable; no fallback algorithm")
        self.library = ctypes.CDLL(str(path))
        lib = self.library
        lib.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
        lib.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
        lib.EVP_aes_256_cbc.restype = ctypes.c_void_p
        lib.EVP_EncryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                         ctypes.c_void_p, ctypes.c_void_p]
        lib.EVP_CIPHER_CTX_set_padding.argtypes = [ctypes.c_void_p, ctypes.c_int]
        lib.EVP_EncryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int),
                                        ctypes.c_void_p, ctypes.c_int]
        lib.EVP_EncryptFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
        self.producer_version = subprocess.check_output([str(executable), "version"], text=True).strip()

    def encrypt(self, body: bytes, key: bytes, iv: bytes) -> bytes:
        if len(key) != 32 or len(iv) != 16 or not body or len(body) % 16:
            raise ValueError("Fixture CBC geometry")
        ctx = self.library.EVP_CIPHER_CTX_new()
        if not ctx:
            raise RuntimeError("Fixture EVP allocation")
        output = ctypes.create_string_buffer(len(body) + 16)
        first, last = ctypes.c_int(), ctypes.c_int()
        try:
            if (self.library.EVP_EncryptInit_ex(ctx, self.library.EVP_aes_256_cbc(), None, key, iv) != 1
                or self.library.EVP_CIPHER_CTX_set_padding(ctx, 0) != 1
                or self.library.EVP_EncryptUpdate(ctx, output, ctypes.byref(first), body, len(body)) != 1
                or self.library.EVP_EncryptFinal_ex(ctx, ctypes.byref(output, first.value), ctypes.byref(last)) != 1):
                raise RuntimeError("Fixture EVP encryption failed")
            result = output.raw[:first.value + last.value]
            if len(result) != len(body):
                raise RuntimeError("Fixture EVP length mismatch")
            return result
        finally:
            self.library.EVP_CIPHER_CTX_free(ctx)

    def nist_known_answer(self) -> None:
        # NIST SP800-38A F.2.5 AES256 CBC first block. This fixed external
        # standard vector checks the independent producer before EFS fixtures.
        key = bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
        iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plain = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
        expected = bytes.fromhex("f58c4c04d6e5f1ba779eabfb5f7bfbd6")
        if self.encrypt(plain, key, iv) != expected:
            raise RuntimeError("Independent NIST AES256 CBC oracle failed")


def metadata(recipients: list[tuple[dict, bytes]], *, version=2, owner_sid=None) -> bytes:
    # Microsoft Metadata Version1 fixed header:84 bytes. EFS_Version at8
    # is a cipher/key-wrapping family selector; it is NOT metadata version.
    header = bytearray(84)
    struct.pack_into("<I", header, 8, version)
    header[16:32] = uuid.uuid4().bytes_le
    arrays = {"ddf": [], "drf": []}
    for owner, fek in recipients:
        wrapped = openssl(["pkeyutl", "-encrypt", "-pubin", "-inkey", owner["public_key"],
                           "-pkeyopt", "rsa_padding_mode:pkcs1"], fek)[::-1]
        thumb_header = struct.pack("<IIIII", 20, 20, 0, 0, 0)
        sid = owner_sid or b""
        credential_length = 68 + len(sid)
        credential = (struct.pack("<IIIIIII", credential_length, 28 if sid else 0, 3, 40, 28 + len(sid), 0, 0)
                      + sid + thumb_header + owner["thumbprint"])
        wrapped_offset = 20 + len(credential)
        field = struct.pack("<IIIII", wrapped_offset + len(wrapped), 20, len(wrapped), wrapped_offset, 0) + credential + wrapped
        arrays["drf" if owner["role"] == "drf" else "ddf"].append(field)
    for role, offset_field in [("ddf", 64), ("drf", 68)]:
        if arrays[role]:
            struct.pack_into("<I", header, offset_field, len(header))
            header.extend(struct.pack("<I", len(arrays[role])) + b"".join(arrays[role]))
    struct.pack_into("<I", header, 0, len(header))
    return bytes(header)


def encrypted_bytes(aes: OpenSSLAES, plaintext: bytes, key: bytes) -> bytes:
    padding = (-len(plaintext)) % 512
    # Nonzero final unused bytes prove that the consumer truncates to logical
    # size rather than mistaking physical-sector slack for file plaintext.
    padded = plaintext + bytes((index * 67 + 29) % 256 for index in range(padding))
    cipher = bytearray()
    for position in range(0, len(padded), 512):
        iv = struct.pack("<QQ", (0x5816657BE9161312 + position) & ((1 << 64) - 1),
                         (0x1989ADBE44918961 + position) & ((1 << 64) - 1))
        cipher.extend(aes.encrypt(padded[position:position + 512], key, iv))
    return bytes(cipher)


def ntfs_image(path: Path, efs: bytes, ciphertext: bytes, logical_size: int) -> dict:
    manifest = ntfs.ntfs_image(path)
    information = bytearray(ntfs._standard_information())
    struct.pack_into("<I", information, 32, 0x4020)
    filename = bytearray(ntfs._filename("fragmented.bin", logical_size, allocation_size=3 * ntfs.CLUSTER))
    struct.pack_into("<I", filename, 56, 0x4020)
    attributes = [ntfs._resident(0x10, bytes(information), 0),
                  ntfs._resident(0x30, bytes(filename), 1),
                  ntfs._nonresident(0x80, logical_size, [(100, 1), (104, 2)], 2, encrypted=True),
                  ntfs._nonresident(0x100, len(efs), [(150, 1)], 3, "$EFS")]
    record = ntfs._mft(25, attributes)
    with path.open("r+b") as stream:
        stream.seek(ntfs.MFT_LCN * ntfs.CLUSTER + 25 * ntfs.RECORD); stream.write(record)
        stream.seek(100 * ntfs.CLUSTER); stream.write(ciphertext[:ntfs.CLUSTER])
        stream.seek(104 * ntfs.CLUSTER); stream.write(ciphertext[ntfs.CLUSTER:])
        stream.seek(150 * ntfs.CLUSTER); stream.write(efs)
        stream.seek(ntfs.BITMAP_LCN * ntfs.CLUSTER + 150 // 8)
        value = stream.read(1)[0]
        stream.seek(-1, 1); stream.write(bytes([value | 1 << (150 % 8)]))
    manifest.update(logicalSha256=ntfs._hash(path), selectedRecord=25, selectedAttributeType=0x80,
                    selectedAttributeID=2, selectedSize=logical_size,
                    efsMetadataOffset=150 * ntfs.CLUSTER, efsMetadataBytes=len(efs),
                    physicalCiphertextBytes=len(ciphertext))
    manifest["syntheticLayout"].update(encryptedData=True, ciphertextProducer="OpenSSL EVP AES256 CBC",
                                       windowsCreated=False)
    return manifest


def generate(destination: Path) -> dict:
    if destination.exists():
        raise FileExistsError("Fixture output must be a new directory")
    destination.mkdir(parents=True, mode=0o700)
    aes = OpenSSLAES(); aes.nist_known_answer()
    owners = {"ddf2048": identity("ddf"), "drf2048": identity("drf"),
              "ddf4096": identity("ddf", 4096), "ddf1024": identity("ddf", 1024), "wrongPurpose": identity("wrong-purpose"),
              "wrongAlgorithm": identity("ddf", algorithm="EC")}
    for name, owner in owners.items():
        exclusive(destination / (name + ".pfx"), owner["pfx"])
        exclusive(destination / (name + ".password"), owner["password"])
        exclusive(destination / (name + ".private.pkcs1.der"), owner["private_der"])
        # A public certificate is permitted here, but remains local to avoid
        # accidently teaching reports to disclose subjects/private key sources.
        exclusive(destination / (name + ".certificate.der"), owner["certificate"])
    corpus = []
    for name, owner_name, length in [("ddf-partial-sector", "ddf2048", 9001),
                                      ("drf-partial-sector", "drf2048", 9001),
                                      ("rsa4096-full-sector", "ddf4096", 9216),
                                      ("legacy1024-packed-sid", "ddf1024", 9001),
                                      ("empty", "ddf2048", 0),
                                      ("one-byte", "ddf2048", 1),
                                      ("unit-minus-one", "ddf2048", 511),
                                      ("unit-plus-one", "ddf2048", 513),
                                      ("one-unit", "ddf2048", 512)]:
        key = secrets.token_bytes(32)
        fek = struct.pack("<IIII", 32, 256, 0x6610, 0) + key
        plaintext = bytes((index * 131 + 17) % 256 for index in range(length))
        ciphertext = encrypted_bytes(aes, plaintext, key)
        recipients = [(owners[owner_name], fek)]
        if name == "ddf-partial-sector":
            recipients.insert(0, (owners["ddf4096"], fek))
        elif name == "drf-partial-sector":
            recipients.insert(0, (owners["ddf2048"], fek))
        sid = bytes([1, 5]) + bytes([0, 0, 0, 0, 0, 5]) + struct.pack("<5I", 21, 111, 222, 333, 1001)
        efs = metadata(recipients, owner_sid=sid if name == "legacy1024-packed-sid" else None)
        exclusive(destination / (name + ".efs"), efs)
        exclusive(destination / (name + ".ciphertext"), ciphertext)
        exclusive(destination / (name + ".expected"), plaintext)
        entry = {"name": name, "owner": owner_name, "role": owners[owner_name]["role"],
                 "logicalBytes": len(plaintext), "physicalBytes": len(ciphertext),
                 "plaintextSHA256": digest(plaintext), "ciphertextSHA256": digest(ciphertext),
                 "metadataSHA256": digest(efs), "certificateSHA1": owners[owner_name]["thumbprint"].hex()}
        if length >= 9001:
            entry["ntfs"] = ntfs_image(destination / (name + ".raw"), efs, ciphertext, len(plaintext))
        corpus.append(entry)
    # CryptoAPI algorithms other than AES256 are explicitly outside the profile.
    unsupported_fek = struct.pack("<IIII", 24, 168, 0x6603, 0) + secrets.token_bytes(24)
    exclusive(destination / "unsupported-3des.efs", metadata([(owners["ddf2048"], unsupported_fek)]))
    wrong_purpose_fek = struct.pack("<IIII", 32, 256, 0x6610, 0) + secrets.token_bytes(32)
    exclusive(destination / "wrong-purpose.efs", metadata([(owners["wrongPurpose"], wrong_purpose_fek)]))
    invalid_entropy_fek = struct.pack("<IIII", 32, 0, 0x6610, 0) + secrets.token_bytes(32)
    exclusive(destination / "invalid-entropy.efs", metadata([(owners["ddf2048"], invalid_entropy_fek)]))
    result = {"schemaVersion": 1, "syntheticOnly": True, "windowsCreated": False,
              "producer": aes.producer_version, "producerKnownAnswer": "NIST SP800-38A F.2.5 AES256 CBC first block",
              "metadataLayout": "MS-EFSR Metadata Version1 fixed84 header; EFS_Version2",
              "sectorTransformSource": "ntfs-3g ntfsdecrypt per512-byte CBC/LE64 IV+logical-byte-offset",
              "cases": corpus, "keyTransport": "anonymous pipes/in-process memory; generated local0600 PFX/password only"}
    exclusive(destination / "manifest.json", (json.dumps(result, indent=2, sort_keys=True) + "\n").encode())
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    summary = generate(args.destination)
    print(json.dumps({"schemaVersion": 1, "cases": len(summary["cases"]),
                      "syntheticOnly": True, "windowsCreated": False}, sort_keys=True))

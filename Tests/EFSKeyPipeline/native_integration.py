#!/usr/bin/env python3
"""Actual helper EFS checks, independent plaintext/extent/ciphertext oracles.

Inputs are generated synthetic volumes and disposable keys under ignored local.
No keys are passed in argv/env/JSON, and no runtime report belongs in Git.
This runner never builds a helper or rewrites baseline/user evidence.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import struct
import subprocess
import time
import uuid
import fixtures


def snapshot(path: Path):
    status = path.stat()
    return (status.st_dev, status.st_ino, status.st_size, status.st_mtime_ns, status.st_ctime_ns)


def run(engine: Path, corpus: Path, output: Path, probe: Path | None = None) -> dict:
    manifest = json.loads((corpus / "manifest.json").read_text())
    if not manifest.get("syntheticOnly") or manifest.get("windowsCreated") is not False or output.exists():
        raise RuntimeError("Synthetic corpus and a new test output directory are required")
    output.mkdir(parents=True, mode=0o700)
    observations = []
    engine_identity = snapshot(engine), fixtures.ntfs._hash(engine)

    def observe_identity(owner):
        certificate = (corpus / (owner + ".certificate.der")).read_bytes()
        packet = b"NFEO\0\0\0\1" + struct.pack("<I", len(certificate)) + certificate
        process = subprocess.run([str(probe)], input=packet, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, timeout=10)
        result = json.loads(process.stdout)
        if process.returncode or result.get("status") != "observed" or \
           result.get("keychainAfterProcess") != {"certificates": 0, "keys": 0} or \
           result.get("dataProtectionAfterProcess") != {"available": True, "certificates": 0, "keys": 0}:
            raise AssertionError("Generated-identity keychain observation was unavailable or nonzero")
        return {"legacyCertificates": 0, "legacyKeys": 0,
                "dataProtectionCertificates": 0, "dataProtectionKeys": 0}

    entries = [row for row in manifest["cases"] if "ntfs" in row]
    owners = sorted({row["owner"] for row in entries})
    keychain_before = [observe_identity(owner) for owner in owners] if probe else None

    def request(entry, source, destination, *, operation="extract-efs", owner=None, credential=None,
                file_override=None, transport_override=None, binary_override=None, expected_error=None,
                expected_mismatch=False, trailing=None, expected_cancel=False):
        owner = owner or entry["owner"]
        key = (corpus / (owner + ".private.pkcs1.der")).read_bytes() if credential is None else credential
        certificate = (corpus / (owner + ".certificate.der")).read_bytes()
        options = {"protocolVersion": 1, "jobID": str(uuid.uuid4()), "operation": operation,
                   "imageType": "raw", "imagePaths": [str(source.resolve())], "sectorSize": 0,
                   "timezone": "UTC", "hashLogicalImage": True, "maxFiles": 50000,
                   "file": {"fsOffsetBytes": 0, "metaAddress": 25, "attributeType": 128,
                            "attributeID": 2, "size": entry["logicalBytes"]},
                   "outputPath": str(destination.resolve())}
        if file_override:
            options["file"].update(file_override)
        binary = b""
        if operation == "extract-efs" or transport_override:
            options["credentialTransport"] = ({"profile": "rsa-pkcs1-der-certificate",
                "privateKeyBytes": len(key), "certificateBytes": len(certificate)}
                if transport_override is None else transport_override)
            binary = key + certificate
        if binary_override is not None:
            binary = binary_override
        if trailing == "cancel":
            binary += json.dumps({"protocolVersion": 1, "operation": "cancel", "jobID": options["jobID"]}).encode() + b"\n"
        elif trailing == "wrong-job":
            binary += json.dumps({"protocolVersion": 1, "operation": "cancel", "jobID": str(uuid.uuid4())}).encode() + b"\n"
        elif trailing == "malformed":
            binary += b"not-json\n"
        elif trailing == "partial":
            binary += b'{"operation"'
        before = snapshot(source), fixtures.ntfs._hash(source)
        started = time.perf_counter()
        process = subprocess.run([str(engine)], input=json.dumps(options).encode() + b"\n" + binary,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        duration = (time.perf_counter() - started) * 1000
        if before != (snapshot(source), fixtures.ntfs._hash(source)):
            raise AssertionError("Synthetic source bytes or identity changed")
        if len(process.stdout) > 64 * 1024 * 1024 or key in process.stdout or key in process.stderr:
            raise AssertionError("Output limit or secret disclosure")
        frames = [json.loads(line) for line in process.stdout.splitlines()]
        if not frames or frames[0]["type"] != "hello" or [row["sequence"] for row in frames] != list(range(len(frames))):
            raise AssertionError("Invalid helper frame order")
        if expected_cancel:
            if process.returncode != 2 or frames[-1]["type"] != "cancelled" or destination.exists() or \
               any(row["type"] in ("error", "extracted") for row in frames):
                raise AssertionError("Valid trailing cancellation did not stop before publishing content")
            return {"status": "cancelled"}
        if expected_error:
            errors = [row["code"] for row in frames if row["type"] == "error"]
            if process.returncode != 1 or frames[-1]["type"] != "failed" or errors != [expected_error] or any(row["type"] == "extracted" for row in frames):
                raise AssertionError("Wrong rejection: " + json.dumps({"errors": errors, "terminal": frames[-1]}, sort_keys=True))
            if destination.exists() and destination.name != "existing-destination":
                raise AssertionError("Rejected extraction preserved a new output")
            return {"status": "rejected", "code": expected_error, "milliseconds": duration}
        if process.returncode != 0 or frames[-1]["type"] != "completed":
            raise AssertionError("Positive helper extraction failed: " + json.dumps(frames[-2:], sort_keys=True))
        receipts = [row for row in frames if row["type"] == "extracted"]
        if len(receipts) != 1:
            raise AssertionError("Missing unique extraction receipt")
        receipt = receipts[0]
        plain = destination.read_bytes()
        expected = (corpus / (entry["name"] + ".expected")).read_bytes()
        if expected_mismatch:
            if plain == expected:
                raise AssertionError("CBC corruption wrongly equaled known plaintext")
        elif plain != expected:
            raise AssertionError("Actual helper plaintext differs from independent literal bytes")
        if receipt["sha256"] != fixtures.digest(plain) or receipt["byteCount"] != len(plain) or receipt["contentStatus"] != "decrypted-content":
            raise AssertionError("Actual helper output receipt mismatch")
        if receipt["decryption"] != {"profile": "ntfs-efs-rsa-pkcs1-aes256-der",
            "recipientRole": entry["role"], "metadataSHA256": entry["metadataSHA256"],
            "certificateSHA1": entry["certificateSHA1"], "ciphertextSHA256": entry["ciphertextSHA256"],
            "ciphertextBytes": entry["physicalBytes"], "unitBytes": 512, "authenticatedPlaintext": False}:
            raise AssertionError("Actual helper decryption provenance differs from independent oracle")
        if not receipt.get("warnings"):
            raise AssertionError("Unauthenticated CBC limitation missing")
        image = next(row for row in frames if row["type"] == "image")
        if image["logicalSha256"] != before[1]:
            raise AssertionError("Image-container bytes/hash confused with plaintext")
        return {"status": "decrypted-observed-bytes", "milliseconds": duration, "outputBytes": len(plain),
                "outputSHA256": fixtures.digest(plain), "ciphertextSHA256": receipt["decryption"]["ciphertextSHA256"]}

    def check(name, entry, source=None, **options):
        destination = output / name
        observations.append({"name": name, **request(entry, source or corpus / (entry["name"] + ".raw"), destination, **options)})

    def check_listing(name, source, expected_candidate):
        options = {"protocolVersion": 1, "jobID": str(uuid.uuid4()), "operation": "enumerate",
                   "imageType": "raw", "imagePaths": [str(source.resolve())], "sectorSize": 0,
                   "timezone": "UTC", "hashLogicalImage": True, "maxFiles": 50000}
        before = snapshot(source), fixtures.ntfs._hash(source)
        process = subprocess.run([str(engine)], input=json.dumps(options).encode() + b"\n",
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        if before != (snapshot(source), fixtures.ntfs._hash(source)):
            raise AssertionError("Source changed while checking EFS listing eligibility")
        frames = [json.loads(line) for line in process.stdout.splitlines()]
        if process.returncode or frames[-1]["type"] != "completed" or \
           [row["sequence"] for row in frames] != list(range(len(frames))):
            raise AssertionError("EFS eligibility listing failed")
        files = [row for frame in frames if frame["type"] == "fileBatch" for row in frame["files"]]
        matches = [row for row in files if row["metaAddress"] == 25 and
                   row.get("attributeType") == 128 and row.get("attributeID") == 2]
        if len(matches) != 1 or matches[0].get("attributeName") != "":
            raise AssertionError("EFS listing did not identify the exact unnamed DATA attribute")
        if expected_candidate != (matches[0].get("encryptionStatus") == "ntfs-efs-encrypted"):
            raise AssertionError("EFS candidate label differs from the regular-file/reparse scope")
        observations.append({"name": name, "status": "eligibility-confirmed",
                             "candidateAdvertised": expected_candidate})

    for entry in entries:
        check(entry["name"], entry)
    base = entries[0]
    source = corpus / (base["name"] + ".raw")
    check_listing("ordinary-efs-listing-candidate", source, True)
    check("ordinary-extract-refusal", base, operation="extract", expected_error="UNSUPPORTED_ENCRYPTED_CONTENT")
    check("wrong-key-certificate", base, credential=(corpus / "ddf4096.private.pkcs1.der").read_bytes(),
          expected_error="EFS_CERTIFICATE_PRIVATE_KEY_MISMATCH")
    check("invalid-private-DER", base, credential=b"not a private key DER", expected_error="EFS_KEY_INPUT_INVALID")
    check("truncated-binary-key", base, binary_override=(corpus / (base["owner"] + ".private.pkcs1.der")).read_bytes()[:20],
          expected_error="TRUNCATED_CREDENTIAL")
    check("pfx-disabled", base, transport_override={"profile": "pfx", "privateKeyBytes": 1, "certificateBytes": 1},
          binary_override=b"", expected_error="UNSUPPORTED_CREDENTIAL_PROFILE")
    check("oversized-private-key", base, transport_override={"profile": "rsa-pkcs1-der-certificate",
          "privateKeyBytes": 65537, "certificateBytes": 1}, binary_override=b"", expected_error="INVALID_REQUEST")
    check("oversized-certificate", base, transport_override={"profile": "rsa-pkcs1-der-certificate",
          "privateKeyBytes": 1, "certificateBytes": 131073}, binary_override=b"", expected_error="INVALID_REQUEST")
    check("extra-credential-descriptor-field", base, transport_override={"profile": "rsa-pkcs1-der-certificate",
          "privateKeyBytes": 1, "certificateBytes": 1, "unexpected": True}, binary_override=b"", expected_error="UNSUPPORTED_CREDENTIAL_PROFILE")
    check("credentials-for-ordinary-extract", base, operation="extract",
          transport_override={"profile": "rsa-pkcs1-der-certificate", "privateKeyBytes": 1, "certificateBytes": 1},
          binary_override=b"", expected_error="INVALID_CREDENTIAL_TRANSPORT")
    check("trailing-cancel", base, trailing="cancel", expected_cancel=True)
    check("trailing-cancel-wrong-job", base, trailing="wrong-job", expected_error="INVALID_CANCEL")
    check("trailing-cancel-malformed", base, trailing="malformed", expected_error="INVALID_CANCEL")
    check("trailing-cancel-partial", base, trailing="partial", expected_error="TRUNCATED_CANCEL")
    sentinel = output / "existing-destination"
    fixtures.exclusive(sentinel, b"existing output must remain unchanged")
    before = sentinel.read_bytes()
    observations.append({"name": "exclusive-destination", **request(base, source, sentinel, expected_error="OUTPUT_EXISTS_OR_UNWRITABLE")})
    if sentinel.read_bytes() != before:
        raise AssertionError("Existing destination changed")

    # Each corruption is written only into a newlyowned clone. Expected safety
    # outcomes come from deliberately omitted/misdeclared mappings and flags.
    # Out-of-image addresses and initialized length greater than allocation
    # are rejected while TSK opens metadata, before the adapter guard is entered.
    geometry = [
        ("compressed", {"compressed": True}, [(100, 1), (104, 2)], True, "EFS_UNSUPPORTED_FILE_PROFILE"),
        ("sparse", {"sparse": True}, [(100, 1), (None, 1), (104, 1)], True, "EFS_UNSUPPORTED_FILE_PROFILE"),
        ("initialized-tail", {"initialized_size": base["logicalBytes"] - 1}, [(100, 1), (104, 2)], True, "EFS_UNSUPPORTED_INITIALIZED_TAIL"),
        ("missing-last-run", {"allocated_size": 3 * 4096}, [(100, 1)], True, "EFS_INCOMPLETE_CONTENT_MAPPING"),
        ("out-of-image-run", {}, [(100, 1), (fixtures.ntfs.IMAGE_SIZE // fixtures.ntfs.CLUSTER + 8, 2)], True, "FILE_OPEN_FAILED"),
        ("allocated-size-too-small", {"allocated_size": 4096}, [(100, 1), (104, 2)], True, "FILE_OPEN_FAILED"),
        ("deleted-profile", {}, [(100, 1), (104, 2)], False, "EFS_UNSUPPORTED_FILE_PROFILE"),
    ]
    for name, flags, runs, allocated, expected in geometry:
        clone = output / (name + ".raw")
        shutil.copyfile(source, clone)
        information = bytearray(fixtures.ntfs._standard_information())
        struct.pack_into("<I", information, 32, 0x4020)
        record = fixtures.ntfs._mft(25, [
            fixtures.ntfs._resident(0x10, bytes(information), 0),
            fixtures.ntfs._resident(0x30, fixtures.ntfs._filename("fragmented.bin", base["logicalBytes"],
                                    allocation_size=3 * 4096), 1),
            fixtures.ntfs._nonresident(0x80, base["logicalBytes"], runs, 2, encrypted=True, **flags),
            fixtures.ntfs._nonresident(0x100, base["ntfs"]["efsMetadataBytes"], [(150, 1)], 3, "$EFS"),
        ], allocated=allocated)
        with clone.open("r+b") as stream:
            stream.seek(fixtures.ntfs.MFT_LCN * 4096 + 25 * 1024); stream.write(record)
        check(name, base, source=clone, expected_error=expected)

    # A synthetic reparse/symlink attribute is outside the regular-file profile
    # even when its DATA is encrypted/nonresident and the SI flag is omitted.
    # This isolates the attribute guard from the separately tested SI flag.
    reparse_source = output / "reparse-profile.raw"
    shutil.copyfile(source, reparse_source)
    target = "synthetic-link-target".encode("utf-16-le")
    link = struct.pack("<HHHHI", 0, len(target), len(target), len(target), 1) + target + target
    reparse = struct.pack("<IHH", 0xA000000C, len(link), 0) + link
    information = bytearray(fixtures.ntfs._standard_information())
    struct.pack_into("<I", information, 32, 0x4020)
    record = fixtures.ntfs._mft(25, [
        fixtures.ntfs._resident(0x10, bytes(information), 0),
        fixtures.ntfs._resident(0x30, fixtures.ntfs._filename("fragmented.bin", base["logicalBytes"], allocation_size=3 * 4096), 1),
        fixtures.ntfs._nonresident(0x80, base["logicalBytes"], [(100, 1), (104, 2)], 2, encrypted=True),
        fixtures.ntfs._nonresident(0x100, base["ntfs"]["efsMetadataBytes"], [(150, 1)], 3, "$EFS"),
        fixtures.ntfs._resident(0xC0, reparse, 4),
    ])
    with reparse_source.open("r+b") as stream:
        stream.seek(fixtures.ntfs.MFT_LCN * 4096 + 25 * 1024); stream.write(record)
    check("reparse-profile", base, source=reparse_source, expected_error="EFS_UNSUPPORTED_FILE_PROFILE")
    check_listing("reparse-listing-suppressed", reparse_source, False)

    # The Windows Standard Information reparse bit alone must also suppress
    # eligibility and reject the regular profile; no 0xC0 attribute is required.
    flag_source = output / "si-reparse-flag.raw"
    shutil.copyfile(source, flag_source)
    struct.pack_into("<I", information, 32, 0x4420)
    record = fixtures.ntfs._mft(25, [
        fixtures.ntfs._resident(0x10, bytes(information), 0),
        fixtures.ntfs._resident(0x30, fixtures.ntfs._filename("fragmented.bin", base["logicalBytes"], allocation_size=3 * 4096), 1),
        fixtures.ntfs._nonresident(0x80, base["logicalBytes"], [(100, 1), (104, 2)], 2, encrypted=True),
        fixtures.ntfs._nonresident(0x100, base["ntfs"]["efsMetadataBytes"], [(150, 1)], 3, "$EFS"),
    ])
    with flag_source.open("r+b") as stream:
        stream.seek(fixtures.ntfs.MFT_LCN * 4096 + 25 * 1024); stream.write(record)
    check("si-reparse-flag", base, source=flag_source, expected_error="EFS_UNSUPPORTED_FILE_PROFILE")
    check_listing("si-reparse-listing-suppressed", flag_source, False)

    # Cancellation while the owned process awaits missing binary credentials.
    destination = output / "cancel-before-key"
    key = (corpus / (base["owner"] + ".private.pkcs1.der")).read_bytes()
    cert = (corpus / (base["owner"] + ".certificate.der")).read_bytes()
    controls = {"protocolVersion": 1, "jobID": str(uuid.uuid4()), "operation": "extract-efs",
                "imageType": "raw", "imagePaths": [str(source.resolve())], "sectorSize": 0, "timezone": "UTC",
                "hashLogicalImage": True, "maxFiles": 50000,
                "file": {"fsOffsetBytes": 0, "metaAddress": 25, "attributeType": 128, "attributeID": 2, "size": base["logicalBytes"]},
                "outputPath": str(destination.resolve()), "credentialTransport": {"profile": "rsa-pkcs1-der-certificate",
                "privateKeyBytes": len(key), "certificateBytes": len(cert)}}
    before = snapshot(source), fixtures.ntfs._hash(source)
    process = subprocess.Popen([str(engine)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
    try:
        process.stdin.write(json.dumps(controls).encode() + b"\n"); process.stdin.flush()
        hello = json.loads(process.stdout.readline())
        if hello["type"] != "hello":
            raise AssertionError("Missing hello before credential wait")
        os.killpg(process.pid, signal.SIGTERM)
        process.stdin.close(); process.stdin = None
        stdout, stderr = process.communicate(timeout=5)
        frames = [hello] + [json.loads(line) for line in stdout.splitlines()]
        if process.returncode != 2 or frames[-1]["type"] != "cancelled" or destination.exists():
            raise AssertionError("Credential-wait cancellation was not drained")
        if before != (snapshot(source), fixtures.ntfs._hash(source)):
            raise AssertionError("Source changed during cancellation")
        observations.append({"name": "cancel-before-key", "status": "cancelled"})
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL); process.wait()
    keychain_after = [observe_identity(owner) for owner in owners] if probe else None
    if keychain_before != keychain_after:
        raise AssertionError("Generated-identity keychain state changed across actual helper matrix")
    if engine_identity != (snapshot(engine), fixtures.ntfs._hash(engine)):
        raise AssertionError("Tested helper identity changed during the matrix")
    return {"schemaVersion": 1, "passed": len(observations), "checkCount": len(observations),
            "engineSHA256": engine_identity[1],
            "keychainObservedGeneratedIdentities": len(owners) if probe else 0,
            "keychainBeforeAfterHelperVerified": bool(probe),
            "keychainScope": "generated identities only, separate observer processes before/after helper matrix" if probe else "not observed by this run",
            "syntheticOnly": True, "nativeEngineIntegrationProven": True,
            "windowsInteroperabilityProven": False, "observations": observations}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--probe", type=Path, help="Standalone read-only generated-identity keychain observer")
    args = parser.parse_args()
    result = run(args.engine.resolve(), args.corpus.resolve(), args.output.resolve(), args.probe.resolve() if args.probe else None)
    if args.report:
        fixtures.exclusive(args.report, (json.dumps(result, indent=2, sort_keys=True) + "\n").encode())
    print(json.dumps({key: value for key, value in result.items() if key != "observations"}, sort_keys=True))

#!/usr/bin/env python3
"""Paired public Windows EFS/RAW oracle, with private bytes only on stdin.

Requires the approved, independently downloaded DigitalCorpora corpus and
locally converted public-test key/certificate. No downloads/builds/conversion
or source modifications occur here. Never bundle or commit these files.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import uuid

CONTAINER_SHA256 = "2badead91bef56c80155d7731671ad1d93c08f32cd4ce17566fdf02d5769feea"
RAW_LOG_SHA256 = "450acfbb1fe50167ec2a91ebd995def94d245a56b14dd89b27b8a29a5de352e3"
RAW_LOG_MD5 = "be2828dda150f19edf9a0fc87e3ab640"
RAW_LOG_SHA1 = "4a97f6bacc9d3abbfa7626ae140829aaaa7a6d03"
LOGICAL_MEDIA_SHA256 = "5378309b19431aee2c15e71b4036b5a173f8c5454aa019110724e8be04dcb2d3"


def sha(path):
    with path.open("rb") as stream:
        value = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
        return value.hexdigest()


def identity(path):
    value = path.stat()
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns


def run(engine, corpus, destination):
    if destination.exists():
        raise FileExistsError("Genuine oracle output must be a new directory")
    destination.mkdir(mode=0o700)
    engine_before = identity(engine), sha(engine)
    source = corpus / "ntfs1-gen2.E01"
    if sha(source) != CONTAINER_SHA256:
        raise RuntimeError("Public corpus download no longer matches its captured identity")
    private = (corpus / "exports/private.pkcs1.der").read_bytes()
    certificate = (corpus / "exports/certificate.der").read_bytes()
    plain = corpus / "exports/RAW-logfile1.txt"
    expected = plain.read_bytes()
    if len(expected) != 21888890 or hashlib.sha256(expected).hexdigest() != RAW_LOG_SHA256:
        raise RuntimeError("RAW public-corpus plaintext twin differs")
    # Independent published DFXML algorithms bind the plaintext's provenance.
    if hashlib.md5(expected).hexdigest() != RAW_LOG_MD5 or hashlib.sha1(expected).hexdigest() != RAW_LOG_SHA1:
        raise RuntimeError("Public DFXML RAW oracle differs")
    target = destination / "decrypted-logfile1.txt"
    before = identity(source), sha(source)
    request = {"protocolVersion": 1, "jobID": str(uuid.uuid4()), "operation": "extract-efs",
        "imageType": "ewf", "imagePaths": [str(source.resolve())], "sectorSize": 0,
        "timezone": "UTC", "hashLogicalImage": True, "maxFiles": 50000,
        "file": {"fsOffsetBytes": 0, "metaAddress": 49, "attributeType": 128, "attributeID": 7, "size": 21888890},
        "outputPath": str(target.resolve()), "credentialTransport": {
            "profile": "rsa-pkcs1-der-certificate", "privateKeyBytes": len(private), "certificateBytes": len(certificate)}}
    packet = json.dumps(request).encode() + b"\n" + private + certificate
    process = subprocess.run([str(engine)], input=packet, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    if private in process.stdout or private in process.stderr:
        raise AssertionError("Secret key appeared in the helper output")
    frames = [json.loads(line) for line in process.stdout.splitlines()]
    if process.returncode or not frames or frames[0]["type"] != "hello" or frames[-1]["type"] != "completed" or \
       [frame["sequence"] for frame in frames] != list(range(len(frames))):
        raise AssertionError("Genuine EFS positive failed: " + json.dumps([{"type": f.get("type"), "code": f.get("code")} for f in frames[-2:]]))
    observed = target.read_bytes()
    if observed != expected or sha(target) != RAW_LOG_SHA256:
        raise AssertionError("Genuine Windows EFS plaintext differs from its complete RAW twin")
    receipts = [frame for frame in frames if frame["type"] == "extracted"]
    if len(receipts) != 1:
        raise AssertionError("Genuine EFS positive did not have exactly one output receipt")
    receipt = receipts[0]
    if receipt["sha256"] != RAW_LOG_SHA256 or receipt["byteCount"] != len(expected) or receipt["contentStatus"] != "decrypted-content":
        raise AssertionError("Genuine output receipt differs from independent bytes")
    decryption = receipt["decryption"]
    if decryption != {"profile": "ntfs-efs-rsa-pkcs1-aes256-der", "recipientRole": "ddf",
        "certificateSHA1": "391e9053dbaefa435bd70c578bf78cc297299ea0",
        "metadataSHA256": "9ca0ce6a7f62694088b73ca34874245e94bc16f98f4af97c756991520da10cc2",
        "ciphertextSHA256": "a56e59d4d378c40edb12666b0a935553595d35c0cd3467178a32b5c23dbe8aab",
        "ciphertextBytes": 21889024, "authenticatedPlaintext": False, "unitBytes": 512}:
        raise AssertionError("Genuine EFS provenance or CBC interpretation differs")
    if not receipt.get("warnings"):
        raise AssertionError("Genuine EFS unauthenticated-CBC warning missing")
    images = [frame for frame in frames if frame["type"] == "image"]
    if len(images) != 1 or images[0]["logicalSha256"] != LOGICAL_MEDIA_SHA256:
        raise AssertionError("Genuine logical-media hash differs from the captured complete-media identity")
    if before != (identity(source), sha(source)):
        raise AssertionError("Public corpus source bytes/identity changed")
    if engine_before != (identity(engine), sha(engine)):
        raise AssertionError("Tested helper identity changed during genuine extraction")
    return {"schemaVersion": 1, "passed": True, "windowsCorpus": "nps-2009-ntfs1/gen2",
        "sourceURL": "https://digitalcorpora.s3.amazonaws.com/corpora/drives/nps-2009-ntfs1/ntfs1-gen2.E01",
        "sourceContainerBytes": source.stat().st_size, "sourceContainerSHA256": CONTAINER_SHA256,
        "logicalMediaSHA256": LOGICAL_MEDIA_SHA256,
        "engineSHA256": engine_before[1], "engineVersion": frames[0]["engineVersion"],
        "knownProfile": {"EFSVersion": 2, "RSAKeyBits": 1024, "FEKBytes": 32, "FEKEntropy": 256,
                        "algorithm": "AES256", "packedSIDRevision": 1, "packedSIDSubAuthorities": 5},
        "plaintextBytes": len(expected), "plaintextSHA256": RAW_LOG_SHA256,
        "publishedPlaintextMD5": RAW_LOG_MD5, "publishedPlaintextSHA1": RAW_LOG_SHA1,
        "decryption": decryption, "sourceBytesAndIdentityPreserved": True,
        "scope": "complete allocated unnamed fragmented logfile stream; unmatched older PDF/JPEG keys remain unavailable",
        "keyPathsOrPrivateKeyDigestsIncluded": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.engine.resolve(), args.corpus.resolve(), args.output.resolve())
    fd = os.open(args.report, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(result, stream, indent=2, sort_keys=True); stream.write("\n")
    print(json.dumps({key: value for key, value in result.items() if key not in ("decryption",)}, sort_keys=True))

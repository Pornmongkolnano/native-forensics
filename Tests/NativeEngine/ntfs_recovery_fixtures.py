#!/usr/bin/env python3
"""Independent deleted-current-byte and EFS refusal corpus.

Original historical payloads and subsequently written source bytes are separate
oracles. An exported hash never establishes which historical writer owned a
deleted file's clusters. These original images contain no real keys/evidence.
"""
from __future__ import annotations
import hashlib
import json
import struct
from pathlib import Path
from ntfs_fixtures import (BITMAP_LCN, CLUSTER, INDEX_LCN, MFT_LCN, RECORD,
    _filename, _hash, _index_allocation, _index_entry, _mft, _nonresident,
    _resident, _standard_information, ntfs_image)


def _unprotect(data: bytes) -> bytearray:
    record = bytearray(data)
    start, count = struct.unpack_from("<HH", record, 4)
    for sector in range(1, count):
        record[sector*512-2:sector*512] = record[start+sector*2:start+sector*2+2]
    return record


def _index_parts(stream) -> tuple[list[bytes], list[bytes]]:
    stream.seek(INDEX_LCN * CLUSTER)
    index = _unprotect(stream.read(CLUSTER))
    end = 24 + struct.unpack_from("<I", index, 28)[0]
    live, deleted = [], []
    position = 64
    while position < end:
        length, flags = struct.unpack_from("<HxxI", index, position+8)
        if flags & 2: break
        live.append(bytes(index[position:position+length])); position += length
    position = end
    while position+16 <= len(index):
        length = struct.unpack_from("<H", index, position+8)[0]
        if length < 16 or position+length > len(index): break
        deleted.append(bytes(index[position:position+length])); position += length
    return live, deleted


def ntfs_recovery_image(path: Path, kind: str) -> dict:
    manifest = ntfs_image(path)
    target = next(row for row in manifest["files"] if row["path"] == "deleted-fragmented.bin")
    original = bytes.fromhex(target["payloadHex"])
    current = bytearray(original)
    owner = None
    with path.open("r+b") as stream:
        if kind in ("deleted-partial-overwrite", "deleted-reallocated"):
            replacement = hashlib.shake_256(b"independent later NTFS writer").digest(CLUSTER)
            stream.seek(108*CLUSTER); stream.write(replacement)
            current[CLUSTER:2*CLUSTER] = replacement
            if kind == "deleted-reallocated":
                name = _filename("later-owner.bin", CLUSTER, allocation_size=CLUSTER)
                stream.seek(MFT_LCN*CLUSTER + 36*RECORD)
                stream.write(_mft(36, [_resident(0x10, _standard_information(), 0),
                    _resident(0x30, name, 1), _nonresident(0x80, CLUSTER, [(108, 1)], 2)]))
                live, deleted = _index_parts(stream); live.append(_index_entry(36, name))
                live.sort(key=lambda row: tuple(point-32 if 97<=point<=122 else point
                    for point in struct.unpack("<"+"H"*row[80], row[82:82+row[80]*2])))
                stream.seek(INDEX_LCN*CLUSTER); stream.write(_index_allocation(live, deleted))
                stream.seek(BITMAP_LCN*CLUSTER); bitmap = bytearray(stream.read(CLUSTER))
                bitmap[108//8] |= 1 << (108%8); stream.seek(BITMAP_LCN*CLUSTER); stream.write(bitmap)
                # $MFT's resident allocation bitmap starts at its known 0xB0 value.
                stream.seek(MFT_LCN*CLUSTER); mft = _unprotect(stream.read(RECORD)); offset = 56
                while struct.unpack_from("<I", mft, offset)[0] != 0xffffffff:
                    attribute_type, length = struct.unpack_from("<II", mft, offset)
                    if attribute_type == 0xb0:
                        value = offset + struct.unpack_from("<H", mft, offset+20)[0]
                        mft[value+36//8] |= 1 << (36%8); break
                    offset += length
                from ntfs_fixtures import _protect
                stream.seek(MFT_LCN*CLUSTER); stream.write(_protect(mft, 48, 0xA000))
                owner = dict(target, path="later-owner.bin", metaAddress=36, size=CLUSTER,
                             isDeleted=False, payloadHex=replacement.hex(), sha256=hashlib.sha256(replacement).hexdigest())
        elif kind == "deleted-full-overwrite":
            current = bytearray(hashlib.shake_256(b"independent full deleted overwrite").digest(len(original)))
            stream.seek(115*CLUSTER); stream.write(current[:CLUSTER])
            stream.seek(108*CLUSTER); stream.write(current[CLUSTER:])
        elif kind == "encrypted-named-stream":
            plaintext = hashlib.shake_256(b"synthetic EFS known plaintext").digest(9001)
            ciphertext = bytes(value ^ 0xa7 for value in plaintext)
            name = _filename("fragmented.bin", len(plaintext), allocation_size=3*CLUSTER)
            stream.seek(MFT_LCN*CLUSTER+25*RECORD)
            stream.write(_mft(25, [_resident(0x10, _standard_information(), 0), _resident(0x30, name, 1),
                _nonresident(0x80, len(plaintext), [(100,1),(104,2)], 2, encrypted=True),
                _nonresident(0x80, len(plaintext), [(140,3)], 3, "encrypted-note", encrypted=True)]))
            stream.seek(100*CLUSTER); stream.write(ciphertext[:CLUSTER]); stream.seek(104*CLUSTER); stream.write(ciphertext[CLUSTER:])
            stream.seek(140*CLUSTER); stream.write(ciphertext)
            target = dict(next(row for row in manifest["files"] if row["path"]=="fragmented.bin"),
                          path="fragmented.bin:encrypted-note", attributeID=3)
            manifest.update(plaintextSHA256=hashlib.sha256(plaintext).hexdigest(),
                            storedCiphertextSHA256=hashlib.sha256(ciphertext).hexdigest(),
                            decryptionPrerequisites=["Authenticated EFS metadata and a supplied matching private key", "Separate secret-safe decryption adapter", "Independent plaintext corpus"])
        else: raise ValueError(kind)
    if kind.startswith("deleted-"):
        target.update(originalPayloadHex=original.hex(), originalSHA256=hashlib.sha256(original).hexdigest(),
                      payloadHex=bytes(current).hex(), sha256=hashlib.sha256(current).hexdigest(),
                      expectedRecoveryStatus="deleted-reallocated-current-bytes" if owner else "deleted-current-bytes",
                      expectedContentStatus="recovery-candidate", mustNotClaimOriginalHistory=True)
        assert target["sha256"] != target["originalSHA256"]
        if owner: manifest["files"].append(owner)
    manifest.update(logicalSha256=_hash(path), target=target, capabilityCase=kind,
                    expectedExtractionError="UNSUPPORTED_ENCRYPTED_CONTENT" if kind.startswith("encrypted") else None)
    return manifest


def generate_ntfs_recovery_fixtures(output: Path) -> list[dict]:
    output.mkdir(parents=True, exist_ok=True)
    receipt = output/"ntfs-recovery-fixtures.json"
    if receipt.exists():
        manifests = json.loads(receipt.read_text())["images"]
        for manifest in manifests:
            if _hash(output/manifest["path"]) != manifest["logicalSha256"]:
                raise RuntimeError("Retained NTFS recovery fixture changed: "+manifest["path"])
        return manifests
    kinds = ("deleted-partial-overwrite", "deleted-reallocated", "deleted-full-overwrite", "encrypted-named-stream")
    manifests = [ntfs_recovery_image(output/("ntfs-"+kind+".raw"), kind) for kind in kinds]
    receipt.write_text(json.dumps({"schemaVersion":1,"images":manifests},indent=2,ensure_ascii=False)+"\n")
    return manifests

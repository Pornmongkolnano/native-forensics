#!/usr/bin/env python3
"""Separate, synthetic extraction workloads; never changes correctness fixtures.

The large volume extends the existing FAT32/4096 builder with a known, explicit
contiguous chain. Payload generation and validation use bounded 1 MiB blocks.
Images are created exclusively in a new, owned benchmark directory.
"""

from __future__ import annotations

import hashlib
import math
import os
import stat
import struct
from pathlib import Path

from fixtures import PAYLOADS, _fat_entry, digest, fat_image
from ntfs_fixtures import ntfs_image


BLOCK_BYTES = 1024 * 1024
PAYLOAD_SEED = b"NativeForensics worker benchmark FAT32 payload v1\x00"
LARGE_NAME = "BENCH128.BIN"


def payload_blocks(byte_count: int):
    """Independent SHAKE-256 blocks include their little-endian block index."""
    if byte_count < 1:
        raise ValueError("Payload must contain at least one byte")
    for index, offset in enumerate(range(0, byte_count, BLOCK_BYTES)):
        amount = min(BLOCK_BYTES, byte_count - offset)
        yield hashlib.shake_256(PAYLOAD_SEED + struct.pack("<Q", index)).digest(amount)


def large_fat_image(path: Path, byte_count: int = 128 * BLOCK_BYTES) -> dict:
    """Keep the base FAT32 corpus; add an allocated file after its root entries."""
    if byte_count < BLOCK_BYTES or byte_count > 192 * BLOCK_BYTES:
        raise ValueError("Large payload must be between 1 and 192 MiB")
    base = fat_image(path, 32, 4096)
    with path.open("r+b") as stream:
        boot = stream.read(512)
        sector_size = struct.unpack_from("<H", boot, 11)[0]
        sectors_per_cluster = boot[13]
        reserved = struct.unpack_from("<H", boot, 14)[0]
        fat_count = boot[16]
        fat_sectors = struct.unpack_from("<I", boot, 36)[0]
        total_sectors = struct.unpack_from("<I", boot, 32)[0]
        root_cluster = struct.unpack_from("<I", boot, 44)[0]
        cluster_bytes = sector_size * sectors_per_cluster
        heap_offset = (reserved + fat_count * fat_sectors) * sector_size
        assert sector_size == cluster_bytes == 4096 and root_cluster == 2
        first_cluster = 64  # The base fixture's allocation ends before cluster 16.
        count = math.ceil(byte_count / cluster_bytes)
        available_clusters = (total_sectors * sector_size - heap_offset) // cluster_bytes
        assert first_cluster + count - 1 <= available_clusters + 1
        chain = list(range(first_cluster, first_cluster + count))
        chain_bytes = b"".join(struct.pack("<I", value) for value in chain[1:] + [0x0FFFFFFF])
        for fat_index in range(fat_count):
            stream.seek((reserved + fat_index * fat_sectors) * sector_size + first_cluster * 4)
            stream.write(chain_bytes)
        root_offset = heap_offset + (root_cluster - 2) * cluster_bytes
        root_slot = len(PAYLOADS)  # Five short directory entries, no LFN rows.
        stream.seek(root_offset + root_slot * 32)
        assert stream.read(32) == bytes(32), "Base root layout changed"
        stream.seek(root_offset + root_slot * 32)
        stream.write(_fat_entry(b"BENCH128BIN", first_cluster, byte_count))
        payload_offset = heap_offset + (first_cluster - 2) * cluster_bytes
        stream.seek(payload_offset)
        content_sha256 = hashlib.sha256()
        for block in payload_blocks(byte_count):
            stream.write(block)
            content_sha256.update(block)
    # Validate actual generated disk bytes against the recipe before using TSK.
    with path.open("rb") as stream:
        stream.seek(payload_offset)
        for expected in payload_blocks(byte_count):
            if stream.read(len(expected)) != expected:
                raise AssertionError("Generated FAT32 disk payload differs from independent recipe")
    base.update(logicalSha256=digest(path), synthetic=True)
    base["files"].append({
        "path": LARGE_NAME, "size": byte_count, "sha256": content_sha256.hexdigest(),
        "isDeleted": False, "recipe": {"algorithm": "SHAKE-256 per indexed 1 MiB block",
            "seedHex": PAYLOAD_SEED.hex(), "blockBytes": BLOCK_BYTES, "byteCount": byte_count},
        "onDisk": {"firstCluster": first_cluster, "clusterCount": count,
            "clusterBytes": cluster_bytes, "payloadOffsetBytes": payload_offset,
            "rootEntryOffsetBytes": root_offset + root_slot * 32},
    })
    return base


def generate_benchmark_fixtures(directory: Path, large_bytes=128 * BLOCK_BYTES) -> dict:
    directory.mkdir()  # Never reuse or repair an existing benchmark source.
    ntfs = ntfs_image(directory / "small-ntfs-streams.raw")
    large = large_fat_image(directory / "large-fat32.raw", large_bytes)
    return {"schemaVersion": 1, "synthetic": True, "images": [ntfs, large]}


def validate_export(path: Path, expected: dict) -> dict:
    """Read once, compare every expected byte and independently compute SHA-256."""
    actual_digest = hashlib.sha256()
    if "recipe" in expected:
        blocks = payload_blocks(expected["size"])
    else:
        payload = bytes.fromhex(expected["payloadHex"])
        blocks = (payload[offset:offset + BLOCK_BYTES] for offset in range(0, len(payload), BLOCK_BYTES))
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size != expected["size"]:
            raise AssertionError("Export is not a regular file of the expected size")
        for block in blocks:
            actual = stream.read(len(block))
            if actual != block:
                raise AssertionError("Exported bytes differ from the independently generated payload")
            actual_digest.update(actual)
        if stream.read(1):
            raise AssertionError("Export contains unexpected trailing bytes")
        after = os.fstat(stream.fileno())
    identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    if identity(before) != identity(after) or identity(after) != identity(path.stat(follow_symlinks=False)):
        raise AssertionError("Export changed during independent validation")
    actual = actual_digest.hexdigest()
    if actual != expected["sha256"]:
        raise AssertionError("Independent export SHA-256 differs")
    return {"byteCount": expected["size"], "sha256": actual, "exactBytesMatched": True,
            "fileIdentity": list(identity(after))}

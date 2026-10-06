#!/usr/bin/env python3
"""Deterministic, synthetic disk images. Python standard library only.

Images and manifests are generated outside Git, never from user evidence.
FAT dates deliberately represent 2023-11-14 22:13:20 local wall time.
"""

from __future__ import annotations

import argparse
import calendar
import hashlib
import json
import math
import shutil
import struct
import uuid
import zlib
from pathlib import Path


DOS_DATE = ((2023 - 1980) << 9) | (11 << 5) | 14
DOS_TIME = (22 << 11) | (13 << 5) | 10
UTC_EPOCH = 1700000000
PAYLOADS = {
    "HELLO.TXT": b"NativeForensics synthetic allocated payload\n",
    "BIGDATA.BIN": bytes((index * 131 + 17) % 256 for index in range(9001)),
    "EMPTY.TXT": b"",
    "_ELETED.TXT": b"Synthetic deleted data, intact and never overwritten.\n",
    "NESTED/INNER.TXT": b"Synthetic nested payload\n",
}


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def _put(stream, offset: int, data: bytes) -> None:
    stream.seek(offset)
    stream.write(data)


def _fat_entry(name: bytes, cluster: int, size: int, *, deleted=False, directory=False, date=DOS_DATE) -> bytes:
    row = bytearray(32)
    row[:11] = name
    if deleted:
        row[0] = 0xE5
    row[11] = 0x10 if directory else 0x20
    struct.pack_into("<HHH", row, 14, DOS_TIME, date, date)
    struct.pack_into("<HH", row, 22, DOS_TIME, date)
    struct.pack_into("<H", row, 20, cluster >> 16)
    struct.pack_into("<HI", row, 26, cluster & 0xFFFF, size)
    return bytes(row)


def fat_image(path: Path, bits: int, sector_size: int, *, year=2023) -> dict:
    """Build actual FAT16/FAT32 geometry, with no mounted filesystem."""
    total_sectors = 5000 if bits == 16 else 70000
    reserved = 1 if bits == 16 else 32
    root_sectors = math.ceil(512 * 32 / sector_size) if bits == 16 else 0
    fat_sectors = math.ceil(total_sectors * (bits // 8) / sector_size)
    for _ in range(10):
        clusters = total_sectors - reserved - root_sectors - 2 * fat_sectors
        next_size = math.ceil((clusters + 2) * (bits // 8) / sector_size)
        if next_size == fat_sectors:
            break
        fat_sectors = next_size
    assert (4085 <= clusters < 65525) if bits == 16 else clusters >= 65525
    heap_sector = reserved + 2 * fat_sectors + root_sectors
    boot = bytearray(sector_size)
    boot[:11] = b"\xEB\x58\x90NFTKTEST"
    struct.pack_into("<HBHBHHBHHHII", boot, 11, sector_size, 1, reserved, 2,
                     512 if bits == 16 else 0, total_sectors if bits == 16 else 0,
                     0xF8, fat_sectors if bits == 16 else 0, 63, 255, 0,
                     0 if bits == 16 else total_sectors)
    if bits == 16:
        struct.pack_into("<BBBI", boot, 36, 0x80, 0, 0x29, 0x12345678)
        boot[43:62] = b"NFTKTEST   FAT16   "
    else:
        struct.pack_into("<IHHIHH", boot, 36, fat_sectors, 0, 0, 2, 1, 6)
        struct.pack_into("<BBBI", boot, 64, 0x80, 0, 0x29, 0x12345678)
        boot[71:90] = b"NFTKTEST   FAT32   "
    boot[510:512] = b"\x55\xAA"
    fat = bytearray(fat_sectors * sector_size)
    fmt = "<H" if bits == 16 else "<I"
    eoc = 0xFFFF if bits == 16 else 0x0FFFFFFF
    struct.pack_into(fmt, fat, 0, 0xFFF8 if bits == 16 else 0x0FFFFFF8)
    struct.pack_into(fmt, fat, bits // 8, eoc)
    cursor = 2
    if bits == 32:
        struct.pack_into(fmt, fat, cursor * 4, eoc)
        cursor += 1
    locations = {}
    for name, payload in PAYLOADS.items():
        if not payload:
            locations[name] = (0, [])
            continue
        chain = list(range(cursor, cursor + math.ceil(len(payload) / sector_size)))
        locations[name] = (cursor, chain)
        cursor += len(chain)
        if name != "_ELETED.TXT":
            for current, following in zip(chain, chain[1:] + [eoc]):
                struct.pack_into(fmt, fat, current * (bits // 8), following)
    nested_cluster = cursor
    struct.pack_into(fmt, fat, nested_cluster * (bits // 8), eoc)
    date = ((year - 1980) << 9) | (11 << 5) | 14
    root = b"".join([
        _fat_entry(b"HELLO   TXT", locations["HELLO.TXT"][0], len(PAYLOADS["HELLO.TXT"]), date=date),
        _fat_entry(b"BIGDATA BIN", locations["BIGDATA.BIN"][0], len(PAYLOADS["BIGDATA.BIN"]), date=date),
        _fat_entry(b"EMPTY   TXT", 0, 0, date=date),
        _fat_entry(b"DELETED TXT", locations["_ELETED.TXT"][0], len(PAYLOADS["_ELETED.TXT"]), deleted=True, date=date),
        _fat_entry(b"NESTED     ", nested_cluster, 0, directory=True, date=date),
    ])
    nested = b"".join([
        _fat_entry(b".          ", nested_cluster, 0, directory=True, date=date),
        _fat_entry(b"..         ", 0 if bits == 16 else 2, 0, directory=True, date=date),
        _fat_entry(b"INNER   TXT", locations["NESTED/INNER.TXT"][0], len(PAYLOADS["NESTED/INNER.TXT"]), date=date),
    ])
    with path.open("xb") as stream:
        stream.truncate(total_sectors * sector_size)
        _put(stream, 0, boot)
        if bits == 32:
            fsinfo = bytearray(sector_size)
            struct.pack_into("<I", fsinfo, 0, 0x41615252)
            struct.pack_into("<III", fsinfo, 484, 0x61417272, 0xFFFFFFFF, 0xFFFFFFFF)
            struct.pack_into("<I", fsinfo, 508, 0xAA550000)
            _put(stream, sector_size, fsinfo)
            _put(stream, 6 * sector_size, boot)
            _put(stream, 7 * sector_size, fsinfo)
        for index in range(2):
            _put(stream, (reserved + index * fat_sectors) * sector_size, fat)
        root_offset = ((reserved + 2 * fat_sectors) if bits == 16 else heap_sector) * sector_size
        _put(stream, root_offset, root)
        for name, payload in PAYLOADS.items():
            cluster, _ = locations[name]
            if cluster:
                _put(stream, (heap_sector + cluster - 2) * sector_size, payload)
        _put(stream, (heap_sector + nested_cluster - 2) * sector_size, nested)
    manifest = _manifest(path, f"FAT{bits}", sector_size, PAYLOADS)
    manifest["expectedEpochUTC"] = calendar.timegm((year, 11, 14, 22, 13, 20))
    return manifest


def _long_name(name: str, short_name: bytes) -> bytes:
    """FAT LFN rows in on-disk reverse order, with the short-name checksum."""
    checksum = 0
    for byte in short_name:
        checksum = (((checksum & 1) << 7) + (checksum >> 1) + byte) & 0xFF
    words = list(struct.unpack("<" + "H" * len(name), name.encode("utf-16-le")))
    words.append(0)
    words += [0xFFFF] * ((13 - len(words) % 13) % 13)
    pieces = [words[offset:offset + 13] for offset in range(0, len(words), 13)]
    rows = []
    for index in range(len(pieces) - 1, -1, -1):
        row = bytearray(32)
        row[0], row[11], row[13] = index + 1 + (0x40 if index == len(pieces) - 1 else 0), 0x0F, checksum
        encoded = struct.pack("<13H", *pieces[index])
        row[1:11], row[14:26], row[28:32] = encoded[:10], encoded[10:22], encoded[22:]
        rows.append(row)
    return b"".join(rows)


def deep_unicode_fat(path: Path) -> dict:
    """Eight real LFN directories produce a UTF-8 path over 1 KiB."""
    sector_size, total_sectors, fat_sectors, root_sector, heap_sector = 512, 5000, 20, 41, 73
    names = [f"ชั้นหลักฐาน-{index}-" + "ภาษาไทย" * 9 for index in range(8)]
    filename, payload = "ข้อมูลหลักฐาน.txt", b"Deep Unicode FAT fixture payload\n"
    full_path = "/".join([*names, filename])
    assert len(full_path.encode()) > 1024
    boot = bytearray(512)
    boot[:11] = b"\xEB\x58\x90NFTKTEST"
    struct.pack_into("<HBHBHHBHHHII", boot, 11, 512, 1, 1, 2, 512, total_sectors, 0xF8, fat_sectors, 63, 255, 0, 0)
    struct.pack_into("<BBBI", boot, 36, 0x80, 0, 0x29, 0x12345678)
    boot[43:62], boot[510:512] = b"NFTKTEST   FAT16   ", b"\x55\xAA"
    fat = bytearray(fat_sectors * 512)
    struct.pack_into("<HH", fat, 0, 0xFFF8, 0xFFFF)
    directory_clusters = list(range(2, 2 + len(names)))
    file_cluster = directory_clusters[-1] + 1
    for cluster in [*directory_clusters, file_cluster]:
        struct.pack_into("<H", fat, cluster * 2, 0xFFFF)
    with path.open("xb") as stream:
        stream.truncate(total_sectors * sector_size)
        _put(stream, 0, boot)
        _put(stream, 512, fat)
        _put(stream, (1 + fat_sectors) * 512, fat)
        for index, name in enumerate(names):
            short = f"DIR{index:05d}".encode() + b"   "
            child = _long_name(name, short) + _fat_entry(short, directory_clusters[index], 0, directory=True)
            if index == 0:
                _put(stream, root_sector * 512, child)
            else:
                parent = directory_clusters[index - 1]
                grandparent = directory_clusters[index - 2] if index > 1 else 0
                entries = _fat_entry(b".          ", parent, 0, directory=True) + _fat_entry(b"..         ", grandparent, 0, directory=True) + child
                assert len(entries) < 512
                _put(stream, (heap_sector + parent - 2) * 512, entries)
        parent = directory_clusters[-1]
        # A short directory entry always has exactly eleven name bytes.
        short = b"EVIDENCE" + b"TXT"
        entries = _fat_entry(b".          ", parent, 0, directory=True) + _fat_entry(b"..         ", directory_clusters[-2], 0, directory=True)
        entries += _long_name(filename, short) + _fat_entry(short, file_cluster, len(payload))
        _put(stream, (heap_sector + parent - 2) * 512, entries)
        _put(stream, (heap_sector + file_cluster - 2) * 512, payload)
    return _manifest(path, "FAT16", 512, {full_path: payload})


def nsr_collision_fat(path: Path) -> dict:
    manifest = fat_image(path, 16, 512)
    # This lies after the root terminator within real FAT16 directory slack.
    # A raw UDF-recognition byte scan must not override successful FAT parsing.
    with path.open("r+b") as stream:
        _put(stream, 16 * 2048 + 1, b"NSR02")
    manifest["logicalSha256"] = digest(path)
    return manifest


def _rolling_checksum(data: bytes, width=32, skip=()) -> int:
    value = 0
    mask = (1 << width) - 1
    for index, byte in enumerate(data):
        if index not in skip:
            value = (((value >> 1) | (value << (width - 1))) + byte) & mask
    return value


def exfat_image(path: Path) -> dict:
    """A minimal exFAT with checksummed boot/entry sets and UTC offset +07:00."""
    sector_size, total_sectors, fat_offset, fat_sectors, heap_offset = 512, 32768, 24, 256, 280
    clusters = total_sectors - heap_offset
    boot = bytearray(11 * sector_size)
    boot[:11] = b"\xEB\x76\x90EXFAT   "
    struct.pack_into("<QQIIIIIIHHBBBBB", boot, 64, 0, total_sectors, fat_offset,
                     fat_sectors, heap_offset, clusters, 2, 0x12345678, 0x100, 0,
                     9, 0, 1, 0x80, 1)
    for index in range(9):
        boot[index * sector_size + 510:index * sector_size + 512] = b"\x55\xAA"
    checksum_sector = struct.pack("<I", _rolling_checksum(boot, skip=(106, 107, 112))) * 128
    boot += checksum_sector
    fat = bytearray(fat_sectors * sector_size)
    struct.pack_into("<III", fat, 0, 0xFFFFFFF8, 0xFFFFFFFF, 0xFFFFFFFF)
    bitmap_size = math.ceil(clusters / 8)
    bitmap_chain = list(range(4, 4 + math.ceil(bitmap_size / sector_size)))
    upcase_cluster = bitmap_chain[-1] + 1
    upcase = struct.pack("<" + "H" * 30, 0xFFFF, 97, *range(65, 91), 0xFFFF, 65413)
    for current, following in zip(bitmap_chain, bitmap_chain[1:] + [0xFFFFFFFF]):
        struct.pack_into("<I", fat, current * 4, following)
    struct.pack_into("<I", fat, 3 * 4, 0xFFFFFFFF)
    struct.pack_into("<I", fat, upcase_cluster * 4, 0xFFFFFFFF)
    bitmap = bytearray(bitmap_size)
    for cluster in [2, 3, *bitmap_chain, upcase_cluster]:
        bitmap[(cluster - 2) // 8] |= 1 << ((cluster - 2) % 8)
    root = bytearray(3 * 32)
    root[0], root[1] = 0x83, 4
    root[2:10] = "NFTK".encode("utf-16-le")
    root[32] = 0x81
    struct.pack_into("<IQ", root, 32 + 20, 4, bitmap_size)
    root[64] = 0x82
    struct.pack_into("<I", root, 64 + 4, _rolling_checksum(upcase))
    struct.pack_into("<IQ", root, 64 + 20, upcase_cluster, len(upcase))
    payload = b"Synthetic exFAT per-entry timezone +07:00\n"
    entry = bytearray(96)
    entry[0], entry[1] = 0x85, 2
    struct.pack_into("<H", entry, 4, 0x20)
    struct.pack_into("<HHHHHH", entry, 8, DOS_TIME, DOS_DATE, DOS_TIME, DOS_DATE, DOS_TIME, DOS_DATE)
    # 25/75 hundredths exercise preserved subsecond fields independently of TZ.
    entry[20:25] = bytes([25, 75, 0x9C, 0x9C, 0x9C])
    entry[32], entry[33], entry[35] = 0xC0, 3, 9
    name = "HELLO.TXT".encode("utf-16-le")
    struct.pack_into("<H", entry, 36, _rolling_checksum(name, width=16))
    struct.pack_into("<Q", entry, 40, len(payload))
    struct.pack_into("<IQ", entry, 52, 3, len(payload))
    entry[64] = 0xC1
    entry[66:66 + len(name)] = name
    struct.pack_into("<H", entry, 2, _rolling_checksum(entry, width=16, skip=(2, 3)))
    root += entry
    with path.open("xb") as stream:
        stream.truncate(total_sectors * sector_size)
        _put(stream, 0, boot)
        _put(stream, 12 * sector_size, boot)
        _put(stream, fat_offset * sector_size, fat)
        _put(stream, heap_offset * sector_size, root)
        _put(stream, (heap_offset + 1) * sector_size, payload)
        _put(stream, (heap_offset + 2) * sector_size, bitmap)
        _put(stream, (heap_offset + upcase_cluster - 2) * sector_size, upcase)
    manifest = _manifest(path, "exFAT", 512, {"HELLO.TXT": payload})
    manifest["validUTCOffset"] = True
    manifest["expectedEpochUTC"] = UTC_EPOCH - 7 * 3600
    manifest["expectedCreatedNanoseconds"] = 250000000
    manifest["expectedModifiedNanoseconds"] = 750000000
    return manifest


def wrap_image(path: Path, source: Path, scheme: str) -> dict:
    sector, offset = 512, 2048 * 512
    payload_sectors = source.stat().st_size // sector
    total_sectors = 2048 + payload_sectors + 34
    mbr = bytearray(512)
    partition_type = 0xEE if scheme == "GPT" else 0x06
    struct.pack_into("<B3sB3sII", mbr, 446, 0, b"\x00\x02\x00", partition_type,
                     b"\xFF\xFF\xFF", 1 if scheme == "GPT" else 2048,
                     total_sectors - 1 if scheme == "GPT" else payload_sectors)
    mbr[510:512] = b"\x55\xAA"
    with path.open("xb") as stream:
        stream.truncate(total_sectors * sector)
        _put(stream, 0, mbr)
        stream.seek(offset)
        with source.open("rb") as input_stream:
            shutil.copyfileobj(input_stream, stream, 1024 * 1024)
        if scheme == "GPT":
            entries = bytearray(128 * 128)
            entries[:16] = uuid.UUID("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7").bytes_le
            entries[16:32] = uuid.UUID("00000000-0000-0000-0000-000000000002").bytes_le
            struct.pack_into("<QQQ", entries, 32, 2048, 2048 + payload_sectors - 1, 0)
            label = "Synthetic FAT16".encode("utf-16-le")
            entries[56:56 + len(label)] = label
            table_crc = zlib.crc32(entries)
            def header(current, alternate, table):
                result = bytearray(512)
                struct.pack_into("<8sIIIIQQQQ16sQIII", result, 0, b"EFI PART", 0x10000,
                                 92, 0, 0, current, alternate, 34, total_sectors - 34,
                                 uuid.UUID("00000000-0000-0000-0000-000000000001").bytes_le,
                                 table, 128, 128, table_crc)
                struct.pack_into("<I", result, 16, zlib.crc32(result[:92]))
                return result
            _put(stream, sector, header(1, total_sectors - 1, 2))
            _put(stream, 2 * sector, entries)
            _put(stream, (total_sectors - 33) * sector, entries)
            _put(stream, (total_sectors - 1) * sector, header(total_sectors - 1, 1, total_sectors - 33))
    manifest = _manifest(path, "FAT16", 512, PAYLOADS)
    manifest.update(partitionScheme=scheme, fsOffsetBytes=offset)
    return manifest


def _manifest(path, filesystem, sector_size, payloads):
    return {
        "path": path.name, "filesystem": filesystem, "sectorSize": sector_size,
        "fsOffsetBytes": 0, "logicalSize": path.stat().st_size, "logicalSha256": digest(path),
        "expectedEpochUTC": UTC_EPOCH,
        "files": [{"path": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                   "isDeleted": name.startswith("_ELETED"), "payloadHex": data.hex()}
                  for name, data in payloads.items()],
    }


def generate(output: Path) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    manifest_path = output / "manifest.json"
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text())
        for image in manifest["images"]:
            paths = [output / name for name in image.get("imagePaths", [image["path"]])]
            value = hashlib.sha256()
            for path in paths:
                with path.open("rb") as stream:
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        value.update(block)
            if value.hexdigest() != image["logicalSha256"]:
                raise RuntimeError("Existing generated fixture changed; choose a fresh directory")
        return _add_regressions(output, manifest)
    images = []
    for bits in (16, 32):
        for sector_size in (512, 4096):
            images.append(fat_image(output / f"fat{bits}-{sector_size}.raw", bits, sector_size))
    for scheme in ("MBR", "GPT"):
        images.append(wrap_image(output / f"fat16-{scheme.lower()}.raw", output / "fat16-512.raw", scheme))
    images.append(exfat_image(output / "exfat-offset.raw"))
    unicode_path = output / "หลักฐาน synthetic image.raw"
    shutil.copyfile(output / "fat16-512.raw", unicode_path)
    images.append(_manifest(unicode_path, "FAT16", 512, PAYLOADS))
    source = output / "fat16-512.raw"
    first, second = output / "split.001", output / "split.002"
    boundary = source.stat().st_size // 2
    with source.open("rb") as stream:
        first.write_bytes(stream.read(boundary))
        second.write_bytes(stream.read())
    split = dict(images[0], path=first.name, imagePaths=[first.name, second.name], splitRaw=True)
    images.append(split)
    manifest = {"schemaVersion": 2, "synthetic": True, "images": images}
    return _add_regressions(output, manifest)


def _add_regressions(output: Path, manifest: dict) -> dict:
    """Add new deterministic fixtures without rewriting earlier image bytes."""
    existing = {image["path"] for image in manifest["images"]}
    factories = [
        ("fat16-year2038.raw", lambda path: fat_image(path, 16, 512, year=2038)),
        ("fat16-year2100.raw", lambda path: fat_image(path, 16, 512, year=2100)),
        ("fat16-deep-unicode.raw", deep_unicode_fat),
        ("fat16-nsr-collision.raw", nsr_collision_fat),
    ]
    for name, factory in factories:
        if name not in existing:
            manifest["images"].append(factory(output / name))
    manifest["schemaVersion"] = 2
    manifest_path = output / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    options = parser.parse_args()
    result = generate(options.output)
    print(json.dumps({"synthetic": True, "images": len(result["images"]), "output": str(options.output)}))

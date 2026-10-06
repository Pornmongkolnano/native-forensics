#!/usr/bin/env python3
"""Deterministic NTFS 3.1 forensic corpus built with Python's standard library.

This is an original, small, deliberately nonbootable filesystem fixture. The
builder writes NTFS BPB, update-sequence-protected MFT/INDX records, attributes,
runlists, indexes and allocation bitmaps directly; it never mounts an image or
uses mkntfs, Homebrew, Autopsy, a pre-existing image, or a TSK writer. Assertions
come from the payloads and FILETIME integers supplied to the builder, rather than
from reading the resulting image through the engine under test. System metadata
files are minimal; this is not a general Windows-volume formatter. Layout
references: Microsoft's ATTRIBUTE_RECORD_HEADER and FILE_RECORD_SEGMENT_HEADER
documentation and the pinned Sleuth Kit public NTFS structure definitions.
https://learn.microsoft.com/en-us/windows/win32/devnotes/attribute-record-header
https://learn.microsoft.com/en-us/windows/win32/devnotes/file-record-segment-header
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path


SECTOR = 512
CLUSTER = 4096
RECORD = 1024
IMAGE_SIZE = 16 * 1024 * 1024
MFT_LCN = 4
MFT_RECORDS = 64
MIRROR_LCN = 20
UPCASE_LCN = 24
INDEX_LCN = 64
BITMAP_LCN = 65
FILETIME_UNIX_OFFSET = 11644473600

# All precision values are representable by NTFS' 100 ns clock.
TIMESTAMPS = {
    "createdEpoch": 1704164646, "createdNanoseconds": 123456700,
    "modifiedEpoch": 1704164679, "modifiedNanoseconds": 765432100,
    "changedEpoch": 1704164691, "changedNanoseconds": 234567800,
    "accessedEpoch": 1704164703, "accessedNanoseconds": 876543200,
}


def _align(value: int) -> int:
    return (value + 7) & ~7


def _hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _filetime(kind: str) -> int:
    return ((TIMESTAMPS[f"{kind}Epoch"] + FILETIME_UNIX_OFFSET) * 10_000_000
            + TIMESTAMPS[f"{kind}Nanoseconds"] // 100)


def _standard_information(*, directory=False, sparse=False) -> bytes:
    data = bytearray(72)
    struct.pack_into("<QQQQI", data, 0, *(_filetime(kind) for kind in
                     ("created", "modified", "changed", "accessed")),
                     0x10000000 if directory else 0x20 | (0x200 if sparse else 0))
    return bytes(data)


def _filename(name: str, size: int, *, parent=5, directory=False,
              allocation_size=None, sparse=False) -> bytes:
    encoded = name.encode("utf-16-le")
    units = len(encoded) // 2
    assert 0 < units <= 255
    data = bytearray(66 + len(encoded))
    struct.pack_into("<Q", data, 0, parent | (1 << 48))
    struct.pack_into("<QQQQQQI", data, 8,
                     *(_filetime(kind) for kind in
                       ("created", "modified", "changed", "accessed")),
                     _align(size) if allocation_size is None else allocation_size,
                     size, 0x10000000 if directory else 0x20 | (0x200 if sparse else 0))
    data[64], data[65] = units, 1  # Win32 namespace; no synthetic DOS alias.
    data[66:] = encoded
    return bytes(data)


def _resident(kind: int, data: bytes, attribute_id: int, name="") -> bytes:
    encoded = name.encode("utf-16-le")
    offset = _align(24 + len(encoded))
    length = _align(offset + len(data))
    result = bytearray(length)
    struct.pack_into("<IIBBHHH", result, 0, kind, length, 0, len(encoded) // 2,
                     24 if encoded else 0, 0, attribute_id)
    struct.pack_into("<IHH", result, 16, len(data), offset, 1 if kind == 0x30 else 0)
    result[24:24 + len(encoded)] = encoded
    result[offset:offset + len(data)] = data
    return bytes(result)


def _unsigned(value: int) -> bytes:
    assert value > 0
    return value.to_bytes((value.bit_length() + 7) // 8, "little")


def _signed(value: int) -> bytes:
    for count in range(1, 9):
        if -(1 << (count * 8 - 1)) <= value < (1 << (count * 8 - 1)):
            return value.to_bytes(count, "little", signed=True)
    raise ValueError("Run delta exceeds NTFS's signed 64-bit field")


def _runlist(runs: list[tuple[int | None, int]]) -> bytes:
    data, previous = bytearray(), 0
    for location, count in runs:
        length = _unsigned(count)
        offset = b"" if location is None else _signed(location - previous)
        data.append(len(length) | len(offset) << 4)
        data.extend(length + offset)
        if location is not None:
            previous = location
    return bytes(data + b"\0")


def _nonresident(kind: int, size: int, runs: list[tuple[int | None, int]],
                 attribute_id: int, name="", *, sparse=False) -> bytes:
    encoded = name.encode("utf-16-le")
    header_size = 72 if sparse else 64
    offset = _align(header_size + len(encoded))
    runlist = _runlist(runs)
    length = _align(offset + len(runlist))
    logical_clusters = sum(count for _, count in runs)
    physical_size = sum(count for location, count in runs if location is not None) * CLUSTER
    result = bytearray(length)
    struct.pack_into("<IIBBHHH", result, 0, kind, length, 1, len(encoded) // 2,
                     header_size if encoded else 0, 0x8000 if sparse else 0,
                     attribute_id)
    struct.pack_into("<QQHHIQQQ", result, 16, 0, logical_clusters - 1,
                     offset, 0, 0, logical_clusters * CLUSTER, size, size)
    if sparse:
        struct.pack_into("<Q", result, 64, physical_size)
    result[header_size:header_size + len(encoded)] = encoded
    result[offset:offset + len(runlist)] = runlist
    return bytes(result)


def _protect(record: bytearray, fixup_offset: int, signature: int) -> bytes:
    """Replace each 512-byte sector tail, preserving it in the USA array."""
    count = len(record) // SECTOR + 1
    struct.pack_into("<HH", record, 4, fixup_offset, count)
    struct.pack_into("<H", record, fixup_offset, signature)
    for index in range(1, count):
        tail = index * SECTOR - 2
        record[fixup_offset + index * 2:fixup_offset + index * 2 + 2] = record[tail:tail + 2]
        struct.pack_into("<H", record, tail, signature)
    return bytes(record)


def _mft(number: int, attributes: list[bytes], *, allocated=True,
         directory=False, links=1) -> bytes:
    result = bytearray(RECORD)
    result[:4] = b"FILE"
    offset = 56  # 48-byte v3.1 header and six-byte USA, rounded to eight bytes.
    used = offset + sum(map(len, attributes)) + 8
    assert used <= RECORD, (number, used)
    struct.pack_into("<HHHHIIQHHI", result, 16,
                     1 if allocated else 2, links, offset,
                     (1 if allocated else 0) | (2 if directory else 0),
                     used, RECORD, 0, max((struct.unpack_from("<H", item, 14)[0] for item in attributes), default=-1) + 1,
                     0, number)
    for attribute in attributes:
        result[offset:offset + len(attribute)] = attribute
        offset += len(attribute)
    struct.pack_into("<I", result, offset, 0xFFFFFFFF)
    return _protect(result, 48, 0xA000 + number)


def _index_entry(number: int, filename: bytes, *, sequence=1) -> bytes:
    length = _align(16 + len(filename))
    result = bytearray(length)
    struct.pack_into("<QHHI", result, 0, number | (sequence << 48), length,
                     len(filename), 0)
    result[16:16 + len(filename)] = filename
    return bytes(result)


def _index_root(entries: list[bytes], *, children=False) -> bytes:
    final = struct.pack("<QHHI", 0, 24 if children else 16, 0, 3 if children else 2)
    if children:
        final += struct.pack("<Q", 0)  # Child index VCN zero.
    data = b"".join(entries) + final
    return (struct.pack("<IIIB3x", 0x30, 1, CLUSTER, 1)
            + struct.pack("<IIII", 16, 16 + len(data), 16 + len(data), int(children))
            + data)


def _index_allocation(entries: list[bytes], deleted: list[bytes]) -> bytes:
    result = bytearray(CLUSTER)
    result[:4] = b"INDX"
    # USA begins at 40, occupies 18 bytes; list starts at 24 and entries at 64.
    live = b"".join(entries) + struct.pack("<QHHI", 0, 16, 0, 2)
    slack = b"".join(deleted)
    assert 64 + len(live) + len(slack) < CLUSTER
    struct.pack_into("<IIII", result, 24, 40, 40 + len(live), CLUSTER - 24, 0)
    result[64:64 + len(live)] = live
    result[64 + len(live):64 + len(live) + len(slack)] = slack
    return _protect(result, 40, 0xB001)


def ntfs_image(path: Path) -> dict:
    """Return the common image manifest plus per-stream independent assertions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    records: dict[int, bytes] = {}
    disk_payloads: list[tuple[int, bytes, bool]] = []
    allocated_clusters = {0, IMAGE_SIZE // CLUSTER - 1, INDEX_LCN, BITMAP_LCN,
                          *range(MFT_LCN, MFT_LCN + MFT_RECORDS * RECORD // CLUSTER),
                          MIRROR_LCN, *range(UPCASE_LCN, UPCASE_LCN + 32)}
    filenames: dict[int, bytes] = {}
    expected: list[dict] = []

    def payload(number: int, name: str, data: bytes, *, parent=5,
                deleted=False, runs=None, streams=(), directory=False,
                directory_entries=(), sparse=False, hardlink=None):
        allocation_size = (sum(count for location, count in runs if location is not None) * CLUSTER
                           if runs else _align(len(data)))
        name_record = _filename(name, len(data), parent=parent, directory=directory,
                                allocation_size=allocation_size, sparse=sparse)
        filenames[number] = name_record
        attributes = [_resident(0x10, _standard_information(directory=directory, sparse=sparse), 0),
                      _resident(0x30, name_record, 1)]
        if hardlink:
            attributes.append(_resident(0x30, _filename(hardlink, len(data), parent=parent,
                                                       allocation_size=allocation_size, sparse=sparse), 5))
        if directory:
            attributes.append(_resident(0x90, _index_root(list(directory_entries)), 2, "$I30"))
        else:
            attributes.append(_nonresident(0x80, len(data), runs, 2, sparse=sparse)
                              if runs else _resident(0x80, data, 2))
        stream_rows = list(streams)
        for stream_name, stream_data, stream_runs, attribute_id in stream_rows:
            attributes.append(_nonresident(0x80, len(stream_data), stream_runs, attribute_id, stream_name)
                              if stream_runs else _resident(0x80, stream_data, attribute_id, stream_name))
        records[number] = _mft(number, attributes, allocated=not deleted,
                               directory=directory, links=2 if hardlink else 1)

        def add_expected(logical_path, body, attribute_id, stream_name="", body_runs=None):
            expected.append({
                "path": logical_path + (":" + stream_name if stream_name else ""),
                "size": len(body), "sha256": hashlib.sha256(body).hexdigest(),
                "isDeleted": deleted, "payloadHex": body.hex(),
                "metaAddress": number, "attributeType": 128, "attributeID": attribute_id,
                "storage": "sparse" if sparse else "nonresident" if body_runs else "resident",
                "timestampsByTimezone": {zone: dict(TIMESTAMPS) for zone in ("UTC", "Asia/Bangkok")},
            })
        prefix = "หลักฐาน/" if parent == 34 else ""
        if not directory:
            add_expected(prefix + name, data, 2, body_runs=runs)
            if hardlink:
                add_expected(prefix + hardlink, data, 2, body_runs=runs)
        for stream_name, stream_data, stream_runs, attribute_id in stream_rows:
            add_expected(prefix + name, stream_data, attribute_id, stream_name, stream_runs)
        for body, body_runs in [(data, runs), *((item[1], item[2]) for item in stream_rows)]:
            if body_runs:
                cursor = 0
                for location, count in body_runs:
                    section = body[cursor:cursor + count * CLUSTER]
                    if location is not None:
                        disk_payloads.append((location * CLUSTER, section, not deleted))
                        if not deleted:
                            allocated_clusters.update(range(location, location + count))
                    else:
                        assert section == bytes(len(section)), "Sparse payload hole must contain zeros"
                    cursor += count * CLUSTER
                assert cursor >= len(body)

    pattern = lambda size, salt: bytes((index * 131 + salt) % 256 for index in range(size))
    payload(24, "resident.txt", b"NTFS allocated resident payload\n", hardlink="resident-link.txt")
    payload(25, "fragmented.bin", pattern(9001, 17), runs=[(100, 1), (104, 2)])
    payload(26, "deleted-resident.txt", b"NTFS deleted resident bytes remain intact\n", deleted=True)
    payload(27, "deleted-fragmented.bin", pattern(9005, 31), deleted=True,
            runs=[(115, 1), (108, 2)])  # Negative LCN delta in the second extent.
    payload(28, "รายงาน-🔍-" + "ก" * 80 + ".txt", "หลักฐานภาษาไทยและ Unicode\n".encode())
    payload(29, "empty.txt", b"")
    payload(30, "streams.txt", b"NTFS unnamed stream\n", streams=[
        ("note", b"Independent resident alternate data stream\n", None, 3),
        ("รายละเอียด", pattern(5001, 47), [(125, 2)], 4),
    ])
    payload(31, "sparse.bin", pattern(CLUSTER, 73) + bytes(CLUSTER) + pattern(CLUSTER + 7, 89),
            runs=[(110, 1), (None, 1), (120, 2)], sparse=True)
    payload(33, "nested.txt", b"Synthetic nested NTFS content\n", parent=34)
    payload(34, "หลักฐาน", b"", directory=True,
            directory_entries=[_index_entry(33, filenames[33])], streams=[
                ("directory-note", b"Named DATA belongs to a directory, not its children\n", None, 3),
            ])

    metadata_names = {0: "$MFT", 1: "$MFTMirr", 2: "$LogFile", 3: "$Volume",
                      4: "$AttrDef", 6: "$Bitmap", 7: "$Boot", 8: "$BadClus",
                      9: "$Secure", 10: "$UpCase"}
    mft_bitmap = bytearray(MFT_RECORDS // 8)
    for number in [*metadata_names, 5, *records]:
        if number not in (26, 27):
            mft_bitmap[number // 8] |= 1 << (number % 8)
    for number, name in metadata_names.items():
        data = b""
        metadata_size = {0: MFT_RECORDS * RECORD, 1: 4 * RECORD,
                         6: IMAGE_SIZE // CLUSTER // 8, 7: CLUSTER, 10: 65536 * 2}.get(number, 0)
        filename = _filename(name, metadata_size,
                             allocation_size=((metadata_size + CLUSTER - 1) // CLUSTER) * CLUSTER)
        filenames[number] = filename
        attributes = [_resident(0x10, _standard_information(), 0), _resident(0x30, filename, 1)]
        if number == 0:
            attributes.extend([_nonresident(0x80, MFT_RECORDS * RECORD,
                                           [(MFT_LCN, MFT_RECORDS * RECORD // CLUSTER)], 2),
                               _resident(0xB0, bytes(mft_bitmap), 3)])
        elif number == 1:
            attributes.append(_nonresident(0x80, 4 * RECORD, [(MIRROR_LCN, 1)], 2))
        elif number == 3:
            attributes.extend([_resident(0x60, "NFTKSYNTHETIC".encode("utf-16-le"), 2),
                               _resident(0x70, bytes(8) + b"\x03\x01" + bytes(6), 3)])
        elif number == 6:
            attributes.append(_nonresident(0x80, IMAGE_SIZE // CLUSTER // 8, [(BITMAP_LCN, 1)], 2))
        elif number == 7:
            attributes.append(_nonresident(0x80, CLUSTER, [(0, 1)], 2))
        elif number == 10:
            attributes.append(_nonresident(0x80, 65536 * 2, [(UPCASE_LCN, 32)], 2))
        else:
            attributes.append(_resident(0x80, data, 2))
        records[number] = _mft(number, attributes)

    live_entries = [_index_entry(number, filenames[number]) for number in
                    [*metadata_names, 24, 25, 28, 29, 30, 31, 34]]
    live_entries.append(_index_entry(24, _filename("resident-link.txt", len(b"NTFS allocated resident payload\n"))))
    deleted_entries = [_index_entry(number, filenames[number]) for number in (26, 27)]
    records[5] = _mft(5, [
        _resident(0x10, _standard_information(directory=True), 0),
        _resident(0x30, _filename(".", 0, directory=True), 1),
        _resident(0x90, _index_root([], children=True), 2, "$I30"),
        _nonresident(0xA0, CLUSTER, [(INDEX_LCN, 1)], 3, "$I30"),
        _resident(0xB0, b"\x01", 4, "$I30"),
    ], directory=True)
    # Use the same fixed ASCII folding as our UpCase table and compare UTF-16
    # units (including surrogate pairs), without Python's Unicode database.
    def collation_key(entry):
        units = struct.unpack("<" + "H" * entry[80], entry[82:82 + entry[80] * 2])
        return tuple(point - 32 if 97 <= point <= 122 else point for point in units)
    live_entries.sort(key=collation_key)
    index_record = _index_allocation(live_entries, deleted_entries)
    boot = bytearray(SECTOR)
    boot[:11] = b"\xEB\x52\x90NTFS    "
    struct.pack_into("<HB", boot, 11, SECTOR, CLUSTER // SECTOR)
    boot[21] = 0xF8
    struct.pack_into("<HHI", boot, 24, 63, 255, 0)
    struct.pack_into("<QQQ", boot, 40, IMAGE_SIZE // SECTOR, MFT_LCN, MIRROR_LCN)
    struct.pack_into("<b", boot, 64, -10)
    struct.pack_into("<b", boot, 68, -12)
    struct.pack_into("<Q", boot, 72, 0x0123456789ABCDEF)
    boot[510:512] = b"\x55\xAA"
    bitmap = bytearray(CLUSTER)
    for cluster in allocated_clusters:
        bitmap[cluster // 8] |= 1 << (cluster % 8)
    # Only ASCII case folding is needed by this corpus. Keep every other BMP
    # value unchanged rather than depending on Python's Unicode database version.
    upcase = b"".join(struct.pack("<H", point - 32 if 97 <= point <= 122 else point)
                      for point in range(65536))
    with path.open("xb") as stream:
        stream.truncate(IMAGE_SIZE)
        def put(offset, data):
            stream.seek(offset)
            stream.write(data)
        put(0, boot)
        put(IMAGE_SIZE - SECTOR, boot)
        for number, record in records.items():
            put(MFT_LCN * CLUSTER + number * RECORD, record)
        put(MIRROR_LCN * CLUSTER, b"".join(records[number] for number in range(4)))
        put(UPCASE_LCN * CLUSTER, upcase)
        put(INDEX_LCN * CLUSTER, index_record)
        put(BITMAP_LCN * CLUSTER, bitmap)
        for offset, body, _allocated in disk_payloads:
            put(offset, body)
    return {
        "path": path.name, "filesystem": "NTFS", "sectorSize": SECTOR,
        "fsOffsetBytes": 0, "logicalSize": IMAGE_SIZE, "logicalSha256": _hash(path),
        "expectedEpochUTC": TIMESTAMPS["modifiedEpoch"], "files": expected,
        "timestampMatrix": {"requestTimezones": ["UTC", "Asia/Bangkok"],
                            "hostTimezones": ["UTC", "Asia/Bangkok", "America/New_York"]},
        "syntheticLayout": {"version": "NTFS3.1", "mftRecordSize": RECORD,
                            "clusterSize": CLUSTER,
                            "allocatedStreamCount": sum(not row["isDeleted"] for row in expected),
                            "deletedStreamCount": sum(row["isDeleted"] for row in expected), "compressedData": False,
                            "encryptedData": False, "bootable": False},
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    options = parser.parse_args()
    manifest = ntfs_image(options.output)
    options.output.with_suffix(".manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"path": str(options.output), "sha256": manifest["logicalSha256"],
                      "streams": len(manifest["files"])}, ensure_ascii=False))

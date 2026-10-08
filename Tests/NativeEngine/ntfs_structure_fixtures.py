#!/usr/bin/env python3
"""Original NTFS index-tree and multiple ATTRIBUTE_LIST extent fixtures.

Uses the existing original NTFS writer primitives, never a mounted filesystem,
reference-reader output, or an engine-generated oracle. Payloads, paths, record
addresses, VCN intervals and FILETIME values are supplied before image writing.
These are deliberately minimal, nonbootable volumes, not Windows formatters.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from ntfs_fixtures import (
    BITMAP_LCN, CLUSTER, INDEX_LCN, MFT_LCN, MFT_RECORDS, MIRROR_LCN, RECORD, TIMESTAMPS,
    _align, _filename, _hash, _index_allocation, _index_entry, _index_root,
    _mft, _nonresident, _protect, _resident, _standard_information, ntfs_image,
)


STRUCTURE_CASES = (
    "multilevel-index",
    "attribute-list-four-records",
    "attribute-list-nonresident-list",
    "attribute-list-missing-middle",
    "attribute-list-missing-extension",
    "attribute-list-overlapping-vcn",
    "attribute-list-malformed-length",
)
TREE_DIRECTORY = "tree-index"
TREE_RECORD = 36
TREE_INDEX_LCN = 140
NAMED_STREAM = "audit-หลักฐาน"


def _expected(path: str, number: int, body: bytes, attribute_id: int,
              *, storage="resident") -> dict:
    return {
        "path": path, "size": len(body), "sha256": hashlib.sha256(body).hexdigest(),
        "isDeleted": False, "payloadHex": body.hex(), "metaAddress": number,
        "attributeType": 128, "attributeID": attribute_id, "storage": storage,
        "timestampsByTimezone": {zone: dict(TIMESTAMPS) for zone in ("UTC", "Asia/Bangkok")},
    }


def _collation_key(entry: bytes) -> tuple[int, ...]:
    units = struct.unpack("<" + "H" * entry[80], entry[82:82 + entry[80] * 2])
    return tuple(point - 32 if 97 <= point <= 122 else point for point in units)


def _indexed_filename(row: dict) -> bytes:
    storage = row["storage"]
    allocation = (_align(row["size"]) if storage == "resident" else
                  3 * CLUSTER if storage == "sparse" else
                  (row["size"] + CLUSTER - 1) // CLUSTER * CLUSTER)
    return _filename(row["path"], row["size"], allocation_size=allocation,
                     sparse=storage == "sparse")


def _root_entries(manifest: dict, additions=()) -> list[bytes]:
    metadata_sizes = {0: MFT_RECORDS * RECORD, 1: 4 * RECORD, 2: 0, 3: 0,
                      4: 0, 6: manifest["logicalSize"] // CLUSTER // 8,
                      7: CLUSTER, 8: 0, 9: 0, 10: 65536 * 2}
    metadata_names = {0: "$MFT", 1: "$MFTMirr", 2: "$LogFile", 3: "$Volume",
                      4: "$AttrDef", 6: "$Bitmap", 7: "$Boot", 8: "$BadClus",
                      9: "$Secure", 10: "$UpCase"}
    entries = [_index_entry(number, _filename(name, metadata_sizes[number], allocation_size=
                                            (metadata_sizes[number] + CLUSTER - 1) // CLUSTER * CLUSTER))
               for number, name in metadata_names.items()]
    for row in manifest["files"]:
        if row["isDeleted"] or "/" in row["path"] or ":" in row["path"]:
            continue
        entries.append(_index_entry(row["metaAddress"], _indexed_filename(row)))
    entries.append(_index_entry(34, _filename("หลักฐาน", 0, directory=True)))
    entries.extend(additions)
    return sorted(entries, key=_collation_key)


def _allocate(stream, records: list[int], clusters: list[int]) -> None:
    """Update only the newly generated image's original allocation metadata."""
    bitmap = bytearray(MFT_RECORDS // 8)
    for number in [*range(11), 24, 25, 28, 29, 30, 31, 33, 34, *records]:
        bitmap[number // 8] |= 1 << (number % 8)
    size = MFT_RECORDS * RECORD
    record = _mft(0, [
        _resident(0x10, _standard_information(), 0),
        _resident(0x30, _filename("$MFT", size, allocation_size=size), 1),
        _nonresident(0x80, size, [(MFT_LCN, size // CLUSTER)], 2),
        _resident(0xB0, bytes(bitmap), 3),
    ])
    stream.seek(MFT_LCN * CLUSTER)
    stream.write(record)
    # $MFTMirr must agree with the changed first record.
    stream.seek(MIRROR_LCN * CLUSTER)
    stream.write(record)
    stream.seek(BITMAP_LCN * CLUSTER)
    volume_bitmap = bytearray(stream.read(CLUSTER))
    for cluster in clusters:
        volume_bitmap[cluster // 8] |= 1 << (cluster % 8)
    stream.seek(BITMAP_LCN * CLUSTER)
    stream.write(volume_bitmap)


def _tree_entry(number: int, name: bytes, child_vcn: int | None = None) -> bytes:
    entry = bytearray(_index_entry(number, name))
    if child_vcn is not None:
        entry.extend(struct.pack("<Q", child_vcn))
        struct.pack_into("<H", entry, 8, len(entry))
        struct.pack_into("<I", entry, 12, 1)
    return bytes(entry)


def _tree_block(vcn: int, entries: list[bytes], *, last_child: int | None = None) -> bytes:
    final = struct.pack("<QHHI", 0, 16 if last_child is None else 24, 0,
                        2 if last_child is None else 3)
    if last_child is not None:
        final += struct.pack("<Q", last_child)
    live = b"".join(entries) + final
    assert 64 + len(live) <= CLUSTER
    record = bytearray(CLUSTER)
    record[:4] = b"INDX"
    struct.pack_into("<Q", record, 16, vcn)
    struct.pack_into("<IIII", record, 24, 40, 40 + len(live), CLUSTER - 24,
                     int(last_child is not None))
    record[64:64 + len(live)] = live
    return _protect(record, 40, 0xC100 + vcn)


def ntfs_multilevel_index_image(path: Path) -> dict:
    """INDEX_ROOT -> internal INDX -> two leaf INDX nodes, with a live separator."""
    manifest = ntfs_image(path)
    names = [f"tree-{index:03d}.txt" for index in range(17)]
    bodies = [(f"Independent NTFS index leaf {index:03d}\n" * (index + 1)).encode()
              for index in range(17)]
    file_names = [_filename(name, len(body), parent=TREE_RECORD)
                  for name, body in zip(names, bodies)]
    records = {
        37 + index: _mft(37 + index, [
            _resident(0x10, _standard_information(), 0),
            _resident(0x30, filename, 1), _resident(0x80, body, 2),
        ]) for index, (filename, body) in enumerate(zip(file_names, bodies))
    }
    directory_name = _filename(TREE_DIRECTORY, 0, directory=True)
    records[TREE_RECORD] = _mft(TREE_RECORD, [
        _resident(0x10, _standard_information(directory=True), 0),
        _resident(0x30, directory_name, 1),
        _resident(0x90, _index_root([], children=True), 2, "$I30"),
        _nonresident(0xA0, 3 * CLUSTER, [(TREE_INDEX_LCN, 3)], 3, "$I30"),
        _resident(0xB0, b"\x07", 4, "$I30"),
    ], directory=True)
    nodes = [
        _tree_block(0, [_tree_entry(45, file_names[8], 1)], last_child=2),
        _tree_block(1, [_tree_entry(37 + index, file_names[index]) for index in range(8)]),
        _tree_block(2, [_tree_entry(37 + index, file_names[index]) for index in range(9, 17)]),
    ]
    with path.open("r+b") as stream:
        stream.seek(INDEX_LCN * CLUSTER)
        deleted = [_index_entry(row["metaAddress"], _indexed_filename(row))
                   for row in manifest["files"] if row["isDeleted"]]
        stream.write(_index_allocation(_root_entries(manifest, [
            _index_entry(TREE_RECORD, directory_name),
        ]), deleted))
        for number, record in records.items():
            stream.seek(MFT_LCN * CLUSTER + number * RECORD)
            stream.write(record)
        stream.seek(TREE_INDEX_LCN * CLUSTER)
        stream.write(b"".join(nodes))
        _allocate(stream, list(records), list(range(TREE_INDEX_LCN, TREE_INDEX_LCN + 3)))
    manifest["files"].extend(_expected(TREE_DIRECTORY + "/" + name, 37 + index, body, 2)
                             for index, (name, body) in enumerate(zip(names, bodies)))
    manifest.update(structureCase="multilevel-index", capabilityCase="multilevel-index",
                    expectedExtractionError=None, logicalSha256=_hash(path),
                    expectedRegularStreamCount=len(manifest["files"]),
                    expectedDirectories=["หลักฐาน", TREE_DIRECTORY], targets=manifest["files"][-17:])
    manifest["syntheticLayout"].update(
        indexTreeDepth=3, indexAllocationBlocks=3, liveSeparatorRecord=45,
        indexChildVCNs={"INDEX_ROOT": [0], "INDX:0": [1, 2], "INDX:1": [], "INDX:2": []},
        treeFileCount=17, allocatedStreamCount=28,
    )
    return manifest


def _list_entry(number: int, start_vcn: int, attribute_id: int,
                *, kind=0x80, name="") -> bytes:
    encoded = name.encode("utf-16-le")
    length = _align(26 + len(encoded))
    record = bytearray(length)
    struct.pack_into("<IHBBQQH", record, 0, kind, length, len(encoded) // 2,
                     26 if encoded else 0, start_vcn, number | (1 << 48), attribute_id)
    record[26:26 + len(encoded)] = encoded
    return bytes(record)


def ntfs_attribute_list_image(path: Path, kind: str) -> dict:
    """Two independent DATA streams assembled from seven extents/four records."""
    if kind not in STRUCTURE_CASES[1:]:
        raise ValueError("Unknown NTFS structure fixture: " + kind)
    manifest = ntfs_image(path)
    # Offset-dependent bytes make reordering, duplicating or substituting any
    # extent observable. A 256-byte repeating pattern would make full clusters
    # identical and could conceal an incorrect ATTRIBUTE_LIST assembly order.
    body = hashlib.shake_256(b"Original NTFS four-record unnamed extent oracle").digest(5 * CLUSTER + 37)
    named_body = hashlib.shake_256(b"Original NTFS three-record named ADS extent oracle").digest(3 * CLUSTER + 101)
    assert len({body[index:index + CLUSTER] for index in range(0, len(body), CLUSTER)}) == 6
    assert len({named_body[index:index + CLUSTER] for index in range(0, len(named_body), CLUSTER)}) == 4
    # Each extent's LCN is deliberately independent; extension runlists restart
    # their physical delta at zero, while StartVCN supplies the logical offset.
    unnamed = [(25, 0, 1, 160), (35, 1, 2, 170), (36, 3, 1, 180), (37, 4, 2, 190)]
    named = [(25, 0, 1, 200), (35, 1, 2, 210), (36, 3, 1, 220)]
    if kind == "attribute-list-missing-middle":
        unnamed = [extent for extent in unnamed if extent[0] != 36]
    elif kind == "attribute-list-overlapping-vcn":
        unnamed = [(number, 2 if number == 36 else vcn, count, lcn)
                   for number, vcn, count, lcn in unnamed]
    entries = [_list_entry(25, 0, 0, kind=0x10), _list_entry(25, 0, 1, kind=0x30)]
    entries.extend(_list_entry(number, vcn, 2) for number, vcn, _count, _lcn in unnamed)
    entries.extend(_list_entry(number, vcn, 6, name=NAMED_STREAM)
                   for number, vcn, _count, _lcn in named)
    list_data = b"".join(entries)
    if kind == "attribute-list-malformed-length":
        # A zero-length first DATA entry cannot advance to the next record.
        # Extension records remain physically intact but are not authorized
        # by a parseable ATTRIBUTE_LIST; base extents alone are incomplete.
        malformed = bytearray(entries[2])
        struct.pack_into("<H", malformed, 4, 0)
        list_data = b"".join(entries[:2]) + bytes(malformed) + b"".join(entries[3:])
    filename = _filename("fragmented.bin", len(body), allocation_size=6 * CLUSTER)
    attrs: dict[int, list[bytes]] = {25: [
        _resident(0x10, _standard_information(), 0),
        (_nonresident(0x20, len(list_data), [(230, 1)], 3)
         if kind == "attribute-list-nonresident-list" else _resident(0x20, list_data, 3)),
        _resident(0x30, filename, 1),
    ], 35: [], 36: [], 37: []}
    for extents, data, name, attribute_id in [(unnamed, body, "", 2), (named, named_body, NAMED_STREAM, 6)]:
        for number, vcn, count, lcn in extents:
            attrs[number].append(_nonresident(
                0x80, len(data) if number == 25 else 0, [(lcn, count)], attribute_id, name,
                start_vcn=vcn, initialized_size=len(data) if number == 25 else 0,
                allocated_size=((len(data) + CLUSTER - 1) // CLUSTER * CLUSTER) if number == 25 else 0,
            ))
    positive = kind in ("attribute-list-four-records", "attribute-list-nonresident-list")
    target = _expected("fragmented.bin", 25, body, 2, storage="attribute-list")
    named_target = _expected("fragmented.bin:" + NAMED_STREAM, 25, named_body, 6, storage="attribute-list")
    target["expectedExtractionError"] = None if positive else "INCOMPLETE_ATTRIBUTE_RUNLIST"
    named_target["expectedExtractionError"] = (
        "INCOMPLETE_ATTRIBUTE_RUNLIST" if kind in
        ("attribute-list-overlapping-vcn", "attribute-list-malformed-length") else None
    )
    manifest["files"] = [target if row["path"] == "fragmented.bin" else row for row in manifest["files"]]
    manifest["files"].append(named_target)
    with path.open("r+b") as stream:
        stream.seek(INDEX_LCN * CLUSTER)
        deleted = [_index_entry(row["metaAddress"], _indexed_filename(row))
                   for row in manifest["files"] if row["isDeleted"]]
        stream.write(_index_allocation(_root_entries(manifest), deleted))
        for number, attributes in attrs.items():
            if number == 37 and kind == "attribute-list-missing-extension":
                continue  # Referenced FILE segment never exists.
            stream.seek(MFT_LCN * CLUSTER + number * RECORD)
            stream.write(_mft(number, attributes, base_record=0 if number == 25 else 25))
        clusters = []
        # Physical bytes always use the original, correct mapping. Negative
        # variants corrupt metadata only, never change the positive byte oracle.
        for data, extents in [
            (body, [(0, 1, 160), (1, 2, 170), (3, 1, 180), (4, 2, 190)]),
            (named_body, [(0, 1, 200), (1, 2, 210), (3, 1, 220)]),
        ]:
            for vcn, count, lcn in extents:
                stream.seek(lcn * CLUSTER)
                stream.write(data[vcn * CLUSTER:(vcn + count) * CLUSTER])
                clusters.extend(range(lcn, lcn + count))
        if kind == "attribute-list-nonresident-list":
            stream.seek(230 * CLUSTER)
            stream.write(list_data)
            clusters.append(230)
        _allocate(stream, [35, 36] + ([] if kind == "attribute-list-missing-extension" else [37]), clusters)
    manifest.update(structureCase=kind, capabilityCase=kind, target=target,
                    targets=[target, named_target], logicalSha256=_hash(path),
                    expectedExtractionError=None if positive else "INCOMPLETE_ATTRIBUTE_RUNLIST",
                    expectedRegularStreamCount=len(manifest["files"]),
                    expectedDirectories=["หลักฐาน"])
    manifest["syntheticLayout"].update(
        attributeListStorage="nonresident" if kind == "attribute-list-nonresident-list" else "resident",
        attributeListRecords=[25, 35, 36, 37], attributeListStreams=2,
        unnamedStreamExtentCount=len(unnamed), namedStreamExtentCount=len(named),
        unnamedVCNIntervals=[[vcn, vcn + count] for _, vcn, count, _ in unnamed],
        namedVCNIntervals=[[vcn, vcn + count] for _, vcn, count, _ in named],
        allocatedStreamCount=12,
    )
    return manifest


def generate_ntfs_structure_fixtures(output: Path) -> list[dict]:
    """Create once; a retained receipt must match case order and source hashes."""
    output.mkdir(parents=True, exist_ok=True)
    receipt = output / "ntfs-structures.json"
    if receipt.exists():
        fixtures = json.loads(receipt.read_text())
        if ([row.get("structureCase") for row in fixtures] != list(STRUCTURE_CASES)
                or any(_hash(output / row["path"]) != row["logicalSha256"] for row in fixtures)):
            raise RuntimeError("Existing NTFS structure fixture changed; choose a fresh directory")
        return fixtures
    fixtures = [ntfs_multilevel_index_image(output / "ntfs-multilevel-index.raw")]
    fixtures.extend(ntfs_attribute_list_image(output / ("ntfs-structure-" + kind + ".raw"), kind)
                    for kind in STRUCTURE_CASES[1:])
    receipt.write_text(json.dumps(fixtures, indent=2, ensure_ascii=False) + "\n")
    return fixtures


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    options = parser.parse_args()
    rows = generate_ntfs_structure_fixtures(options.output)
    print(json.dumps({"cases": [row["structureCase"] for row in rows],
                      "imageCount": len(rows)}, ensure_ascii=False))

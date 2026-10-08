#!/usr/bin/env python3
"""Independent LZNT1 and whole-unit NTFS compressed-content corpus.

The expected bytes are supplied to an original Python writer, then checked by
an independent decoder following MS-XCA. Neither oracle calls Sleuth Kit. The
small NTFS layout writer is shared with ntfs_fixtures.py; these are deliberately
nonbootable synthetic volumes, not captures from a Windows installation.

Format references (no upstream implementation is copied):
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/cba0fa15-bd62-4eda-8838-8fc7ab406df1
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/b1ba6d34-499c-4017-ab0c-fe2daee93efc
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from ntfs_fixtures import (
    BITMAP_LCN, CLUSTER, MFT_LCN, RECORD, _attribute_list_entry, _filename,
    _hash, _mft, _nonresident, _resident, _standard_information, ntfs_image,
)


CHUNK = 4096
UNIT_CLUSTERS = 16
UNIT = UNIT_CLUSTERS * CLUSTER
CORPUS_VERSION = 2
INVALID_STREAM = "INVALID_COMPRESSED_CONTENT"
INVALID_MAPPING = "INCOMPLETE_ATTRIBUTE_RUNLIST"


def _length_bits(position: int) -> int:
    """LZNT1 gives more token bits to displacement as chunk output grows."""
    if position <= 0:
        raise ValueError("A match requires previous bytes in this chunk")
    return 12 - max(0, (position - 1).bit_length() - 4)


def lznt1_compress(data: bytes) -> bytes:
    """Small original greedy writer; returns chunks plus a zero end marker.

    Candidates come from recent occurrences of the next three input bytes. A
    match may overlap its destination, so repeated patterns compress without
    copying a large literal seed. Incompressible chunks use literal headers.
    """
    result = bytearray()
    for start in range(0, len(data), CHUNK):
        chunk = data[start:start + CHUNK]
        encoded, history = bytearray(), {}
        position = 0
        while position < len(chunk):
            flag_offset = len(encoded)
            encoded.append(0)
            flags = 0
            for bit in range(8):
                if position >= len(chunk):
                    break
                length, distance = 0, 0
                if position and position + 2 < len(chunk):
                    bits = _length_bits(position)
                    limit = min(((1 << bits) - 1) + 3, len(chunk) - position)
                    max_distance = min(position, 1 << (16 - bits))
                    key = chunk[position:position + 3]
                    for candidate in reversed(history.get(key, ())[-64:]):
                        gap = position - candidate
                        if gap > max_distance:
                            continue
                        match = 3
                        while match < limit and chunk[position + match] == chunk[position + match - gap]:
                            match += 1
                        if match > length:
                            length, distance = match, gap
                            if match == limit:
                                break
                if length >= 3:
                    flags |= 1 << bit
                    token = ((distance - 1) << _length_bits(position)) | (length - 3)
                    encoded.extend(struct.pack("<H", token))
                    consumed = length
                else:
                    encoded.append(chunk[position])
                    consumed = 1
                for index in range(position, position + consumed):
                    if index + 2 < len(chunk):
                        history.setdefault(chunk[index:index + 3], []).append(index)
                position += consumed
            encoded[flag_offset] = flags
        if len(encoded) < len(chunk):
            result.extend(struct.pack("<H", 0xB000 | (len(encoded) - 1)))
            result.extend(encoded)
        else:
            result.extend(struct.pack("<H", 0x3000 | (len(chunk) - 1)))
            result.extend(chunk)
    return bytes(result + b"\0\0")


def lznt1_decompress(data: bytes, *, expected_size: int | None = None,
                     output_limit: int = UNIT) -> bytes:
    """Strict separate decoder: no repair, invented zero tail, or prior chunks.

    Physical allocation padding after a zero end marker is not part of the
    compressed stream. Without a marker, input must end exactly on a chunk.
    An expected size certifies initialized logical bytes independently of the
    allocator's padding; a short valid stream still fails that requirement.
    """
    output, cursor, prior_chunk = bytearray(), 0, CHUNK
    while cursor < len(data):
        if len(data) - cursor < 2:
            raise ValueError("Truncated LZNT1 chunk header")
        header = int.from_bytes(data[cursor:cursor + 2], "little")
        cursor += 2
        if header == 0:
            break
        if header & 0x7000 != 0x3000:
            raise ValueError("Invalid LZNT1 chunk signature")
        if prior_chunk != CHUNK:
            raise ValueError("A partial LZNT1 chunk precedes another chunk")
        payload_size = (header & 0xFFF) + 1
        end = cursor + payload_size
        if end > len(data):
            raise ValueError("Truncated LZNT1 declared chunk")
        chunk = bytearray()
        if header & 0x8000:
            while cursor < end:
                flags = data[cursor]
                cursor += 1
                if cursor == end:
                    raise ValueError("LZNT1 flag group contains no token")
                for bit in range(8):
                    if cursor >= end:
                        break  # Remaining flag bits have no corresponding data.
                    if flags & (1 << bit):
                        if end - cursor < 2:
                            raise ValueError("Truncated LZNT1 phrase token")
                        word = int.from_bytes(data[cursor:cursor + 2], "little")
                        cursor += 2
                        bits = _length_bits(len(chunk))
                        distance = (word >> bits) + 1
                        length = (word & ((1 << bits) - 1)) + 3
                        if distance > len(chunk):
                            raise ValueError("LZNT1 phrase points outside this chunk")
                        if length > CHUNK - len(chunk):
                            raise ValueError("LZNT1 phrase expands past this chunk")
                        for _ in range(length):
                            chunk.append(chunk[-distance])
                    else:
                        if len(chunk) == CHUNK:
                            raise ValueError("LZNT1 literal expands past this chunk")
                        chunk.append(data[cursor])
                        cursor += 1
        else:
            chunk.extend(data[cursor:end])
            cursor = end
        if not chunk or len(chunk) > CHUNK:
            raise ValueError("Invalid LZNT1 decompressed chunk length")
        if len(chunk) > output_limit - len(output):
            raise ValueError("LZNT1 stream exceeds its compression unit")
        output.extend(chunk)
        prior_chunk = len(chunk)
    if expected_size is not None and len(output) < expected_size:
        raise ValueError("LZNT1 stream does not cover initialized logical bytes")
    return bytes(output)


def _pattern(size: int, salt: int) -> bytes:
    # An explicit deterministic byte generator; no filesystem-reader oracle.
    return bytes((index * 131 + (index // 251) * 19 + salt) % 256 for index in range(size))


def _compressible(size: int = UNIT, salt: int = 0) -> bytes:
    return b"".join(bytes([(salt + index * 29) % 256]) * min(CHUNK, size - index * CHUNK)
                    for index in range((size + CHUNK - 1) // CHUNK))


def _mixed_chunk_payload() -> bytes:
    # One literal chunk and fifteen highly compressible chunks: two mapped
    # physical clusters plus fourteen sparse VCNs, unlike a one-cluster stream.
    return bytes(range(256)) * 16 + _compressible(UNIT - CHUNK, 41)


def _literal_first_stream(data: bytes) -> bytes:
    """Force one valid raw LZNT1 chunk to exercise literal-chunk decoding."""
    first = data[:CHUNK]
    return (struct.pack("<H", 0x3000 | (len(first) - 1)) + first
            + lznt1_compress(data[CHUNK:]))


def _phrase_boundary_unit(lcn: int) -> dict:
    """Hand-encoded tokens anchor both token-width regimes independently.

    Seventeen seed bytes are followed by distance-17 matches. At output 17,
    word 0x87fd copies 2048 bytes. At output 2065 and later, word 0x010f copies
    eighteen bytes, while final word 0x010c copies fifteen. The literal logical
    pattern is defined separately and never inferred from those encoded words.
    """
    first = bytes(index % 17 for index in range(CHUNK))
    data = first + _compressible(UNIT - CHUNK, 103)
    tokens = [(False, bytes([index])) for index in range(17)]
    tokens.extend((True, struct.pack("<H", word)) for word in
                  (0x87FD, *((0x010F,) * 112), 0x010C))
    body = bytearray()
    for start in range(0, len(tokens), 8):
        group = tokens[start:start + 8]
        body.append(sum(1 << index for index, (phrase, _value) in enumerate(group) if phrase))
        body.extend(b"".join(value for _phrase, value in group))
    stored = struct.pack("<H", 0xB000 | (len(body) - 1)) + body + lznt1_compress(data[CHUNK:])
    assert lznt1_decompress(stored, expected_size=UNIT) == data
    return {"kind": "compressed", "data": data, "runs": [(lcn, 1), (None, 15)],
            "physical": [(lcn, stored.ljust(CLUSTER, b"\0"))], "streamBytes": len(stored)}


def _unit(kind: str, data: bytes, lcn: int, *, fragmented=False) -> dict:
    if kind == "sparse":
        assert data == bytes(len(data))
        return {"kind": kind, "data": data, "runs": [(None, UNIT_CLUSTERS)], "physical": []}
    if kind == "raw":
        body = data.ljust(UNIT, b"\xD7")
        return {"kind": kind, "data": data, "runs": [(lcn, UNIT_CLUSTERS)],
                "physical": [(lcn, body)]}
    stream = _literal_first_stream(data) if fragmented else lznt1_compress(data)
    assert lznt1_decompress(stream, expected_size=len(data)) == data
    count = (len(stream) + CLUSTER - 1) // CLUSTER
    assert 0 < count < UNIT_CLUSTERS
    padded = stream.ljust(count * CLUSTER, b"\0")
    if fragmented:
        assert count == 2
        runs = [(lcn, 1), (lcn - 2, 1), (None, UNIT_CLUSTERS - 2)]
        physical = [(lcn, padded[:CLUSTER]), (lcn - 2, padded[CLUSTER:])]
    else:
        runs = [(lcn, count), (None, UNIT_CLUSTERS - count)]
        physical = [(lcn, padded)]
    return {"kind": "compressed", "data": data, "runs": runs,
            "physical": physical, "streamBytes": len(stream)}


def _mark_allocated(stream, runs: list[tuple[int | None, int]], *, extension=False) -> None:
    stream.seek(BITMAP_LCN * CLUSTER)
    bitmap = bytearray(stream.read(CLUSTER))
    for location, count in runs:
        if location is not None:
            for cluster in range(location, location + count):
                bitmap[cluster // 8] |= 1 << (cluster % 8)
    stream.seek(BITMAP_LCN * CLUSTER)
    stream.write(bitmap)
    if extension:
        # Update the resident $MFT::$BITMAP in original record zero, preserving
        # its sector-tail fixups. This attribute is entirely in sector one.
        stream.seek(MFT_LCN * CLUSTER)
        record = bytearray(stream.read(RECORD))
        cursor = struct.unpack_from("<H", record, 20)[0]
        while struct.unpack_from("<I", record, cursor)[0] != 0xFFFFFFFF:
            kind, length = struct.unpack_from("<II", record, cursor)
            if kind == 0xB0:
                data_offset = struct.unpack_from("<H", record, cursor + 20)[0]
                record[cursor + data_offset + 35 // 8] |= 1 << (35 % 8)
                break
            cursor += length
        else:
            raise AssertionError("Synthetic base has no MFT bitmap")
        stream.seek(MFT_LCN * CLUSTER)
        stream.write(record)


CASES = (
    "compressed-full", "compressed-raw-unit", "compressed-sparse-unit",
    "compressed-mixed-units", "compressed-fragmented-prefix",
    "compressed-buffer-boundary", "compressed-phrase-boundary",
    "compressed-partial-last-chunk", "compressed-one-byte-last-chunk", "compressed-uninitialized-tail",
    "compressed-uninitialized-tail-unmapped", "compressed-uninitialized-all",
    "compressed-attribute-list", "compressed-attribute-list-missing-middle",
    "compressed-missing-whole-unit-tail", "compressed-missing-leading-run",
    "compressed-sparse-before-physical", "compressed-truncated-chunk",
    "compressed-truncated-token", "compressed-invalid-signature",
    "compressed-premature-end", "compressed-cross-chunk-reference",
    "compressed-chunk-output-overrun", "compressed-standalone-flag",
    "compressed-full-output-bad-suffix", "compressed-short-output-truncated-header",
    "compressed-unused-high-flag-bits", "compressed-named-stream",
)


def ntfs_compression_image(path: Path, case: str) -> dict:
    if case not in CASES:
        raise ValueError("Unknown compressed NTFS corpus case: " + case)
    manifest = ntfs_image(path)
    units = [_unit("compressed", _compressible(salt=23), 200)]
    size, initialized, start_vcn = UNIT, UNIT, 0
    error, extension, named = None, None, case == "compressed-named-stream"
    if case == "compressed-raw-unit":
        units = [_unit("raw", _pattern(UNIT, 19), 200)]
    elif case == "compressed-sparse-unit":
        units = [_unit("sparse", bytes(UNIT), 200)]
    elif case == "compressed-mixed-units":
        units = [_unit("raw", _pattern(UNIT, 17), 200),
                 _unit("compressed", _compressible(salt=59), 232),
                 _unit("sparse", bytes(UNIT), 256),
                 _unit("raw", _pattern(UNIT, 67), 264)]
        size = initialized = len(units) * UNIT
    elif case == "compressed-buffer-boundary":
        # Cross the engine's 1 MiB read buffer, with initialized bytes ending
        # inside the first unit of the next read and stored nonzero tail bytes.
        units = [_unit("compressed", _compressible(salt=11 + index * 7),
                       200 + index * 2) for index in range(18)]
        size, initialized = len(units) * UNIT, 16 * UNIT + CLUSTER + 5
    elif case == "compressed-phrase-boundary":
        units = [_phrase_boundary_unit(200)]
    elif case in {"compressed-fragmented-prefix", "compressed-attribute-list",
                  "compressed-attribute-list-missing-middle", "compressed-missing-whole-unit-tail"}:
        units = [_unit("compressed", _mixed_chunk_payload(), 200, fragmented=True)]
    elif case in {"compressed-partial-last-chunk", "compressed-one-byte-last-chunk"}:
        tail_size = 9001 if case == "compressed-partial-last-chunk" else CHUNK + 1
        units.append(_unit("compressed", _compressible(tail_size, 83), 232))
        size = initialized = UNIT + tail_size
    elif case == "compressed-uninitialized-tail":
        initialized = CLUSTER + 5
    elif case == "compressed-uninitialized-tail-unmapped":
        size = 2 * UNIT + 17  # The missing next units are wholly uninitialized.
    elif case == "compressed-uninitialized-all":
        size, initialized = 9001, 0
        units = [_unit("raw", _pattern(size, 97), 200)]
        units[0]["runs"] = [(200, 1)]  # No initialized unit needs decoding.
    elif case == "compressed-standalone-flag":
        initialized = 8
    elif case == "compressed-short-output-truncated-header":
        initialized = CLUSTER - 3
    elif case == "compressed-unused-high-flag-bits":
        units = [_unit("compressed", b"Z" + bytes(UNIT - 1), 200)]
        initialized = 1

    payload = b"".join(unit["data"] for unit in units)[:initialized].ljust(size, b"\0")
    runs = [run for unit in units for run in unit["runs"]]
    physical = [section for unit in units for section in unit["physical"]]
    if case == "compressed-missing-whole-unit-tail":
        # All clusters containing requested prefix bytes exist, but the reader
        # needs the omitted sparse suffix to identify this as compressed.
        initialized = CLUSTER + 5
        payload = payload[:initialized] + bytes(size - initialized)
        runs = runs[:2]
        error = INVALID_MAPPING
    elif case == "compressed-missing-leading-run":
        start_vcn = 1
        error = INVALID_MAPPING
    elif case == "compressed-sparse-before-physical":
        runs = [(None, 1), (200, 1), (None, 14)]
        error = INVALID_STREAM
    elif case.startswith("compressed-attribute-list"):
        extension_vcn = 1 if case == "compressed-attribute-list" else 2
        extension_runs = [(198, 1), (None, UNIT_CLUSTERS - extension_vcn - 1)]
        extension_attribute = bytearray(_nonresident(0x80, 0, extension_runs, 2,
            compressed=True, start_vcn=extension_vcn, initialized_size=0, allocated_size=0))
        # Extension headers carry no compression-unit geometry; the base owns
        # it. The joined TSK attribute must preserve base compsize=16.
        struct.pack_into("<H", extension_attribute, 34, 0)
        extension = _mft(35, [bytes(extension_attribute)], base_record=25)
        runs = runs[:1]
        if extension_vcn != 1:
            error = INVALID_MAPPING
    elif case in {"compressed-truncated-chunk", "compressed-truncated-token",
                  "compressed-invalid-signature", "compressed-premature-end",
                  "compressed-cross-chunk-reference", "compressed-chunk-output-overrun",
                  "compressed-standalone-flag", "compressed-full-output-bad-suffix",
                  "compressed-short-output-truncated-header"}:
        good_stream = lznt1_compress(units[0]["data"])
        if case == "compressed-truncated-chunk":
            bad_stream = struct.pack("<H", 0x3FFF) + b"Z" * (CLUSTER - 2)
        elif case == "compressed-truncated-token":
            bad_stream = struct.pack("<H", 0xB001) + b"\x01\x00"
        elif case == "compressed-invalid-signature":
            bad_stream = bytes([good_stream[0], good_stream[1] ^ 0x10]) + good_stream[2:]
        elif case == "compressed-premature-end":
            bad_stream = lznt1_compress(units[0]["data"][:CHUNK])
        elif case == "compressed-cross-chunk-reference":
            first = lznt1_compress(units[0]["data"][:CHUNK])[:-2]
            bad_stream = first + struct.pack("<H", 0xB002) + b"\x01\x00\x00"
        elif case == "compressed-standalone-flag":
            # The first flag has all eight Data items; a later orphan flag
            # cannot be mistaken for a ninth literal in the original group.
            bad_stream = struct.pack("<H", 0xB009) + b"\0ABCDEFGH\0"
            payload = b"ABCDEFGH" + bytes(size - initialized)
        elif case == "compressed-full-output-bad-suffix":
            # Complete required output does not validate a subsequent header
            # before the genuine end marker. Allocator padding follows that
            # marker, not an invented early exit at the decoded capacity.
            bad_stream = good_stream[:-2] + b"\x01\x20"
        elif case == "compressed-short-output-truncated-header":
            bad_stream = struct.pack("<H", 0x3FFC) + b"Z" * (CLUSTER - 3) + b"\x7F"
            assert len(bad_stream) == CLUSTER
            payload = b"Z" * initialized + bytes(size - initialized)
        else:
            bad_stream = struct.pack("<H", 0xB003) + b"\x02A" + struct.pack("<H", CHUNK - 3)
        try:
            lznt1_decompress(bad_stream, expected_size=initialized)
        except ValueError:
            pass
        else:
            raise AssertionError("Malformed corpus stream unexpectedly passed strict oracle")
        physical = [(200, bad_stream.ljust(CLUSTER, b"\0"))]
        runs = [(200, 1), (None, 15)]
        units[0]["streamBytes"] = len(bad_stream)
        error = INVALID_STREAM
    elif case == "compressed-unused-high-flag-bits":
        # Bit zero describes the only Data item. Higher bits are unused and
        # must be ignored once the declared two-byte body has been consumed.
        stored = struct.pack("<H", 0xB001) + b"\xFEZ\0\0"
        assert lznt1_decompress(stored, expected_size=initialized) == b"Z"
        physical = [(200, stored.ljust(CLUSTER, b"\0"))]
        runs = [(200, 1), (None, 15)]
        units[0]["streamBytes"] = len(stored)

    attribute_id = 3 if named else 2
    filename = _filename("fragmented.bin", 9001 if named else size,
                         allocation_size=UNIT if not named else 3 * CLUSTER)
    attributes = [_resident(0x10, _standard_information(), 0), _resident(0x30, filename, 1)]
    if named:
        attributes.append(_nonresident(0x80, 9001, [(100, 1), (104, 2)], 2))
    if extension:
        entries = (_attribute_list_entry(25, 0, 2)
                   + _attribute_list_entry(35, 1 if error is None else 2, 2))
        attributes.append(_resident(0x20, entries, 3))
    attributes.append(_nonresident(0x80, size, runs, attribute_id,
                                  "packed" if named else "", compressed=True,
                                  start_vcn=start_vcn, initialized_size=initialized,
                                  allocated_size=((size + UNIT - 1) // UNIT) * UNIT))
    with path.open("r+b") as stream:
        stream.seek(MFT_LCN * CLUSTER + 25 * RECORD)
        stream.write(_mft(25, attributes))
        if extension:
            stream.seek(MFT_LCN * CLUSTER + 35 * RECORD)
            stream.write(extension)
        for lcn, data in physical:
            stream.seek(lcn * CLUSTER)
            stream.write(data)
        all_runs = runs + (extension_runs if extension else [])
        _mark_allocated(stream, all_runs, extension=extension is not None)
    target = next(row for row in manifest["files"] if row["path"] == "fragmented.bin")
    if named:
        target = dict(target, path="fragmented.bin:packed", attributeID=attribute_id)
        manifest["files"].append(target)
    target.update(size=size, payloadHex=payload.hex(), sha256=hashlib.sha256(payload).hexdigest(),
                  storage="compressed", initializedBytes=initialized)
    manifest.update(logicalSha256=_hash(path), target=target, capabilityCase=case,
                    expectedExtractionError=error, compressionCorpusVersion=CORPUS_VERSION,
                    compressionOracle={"algorithm": "LZNT1", "independent": True,
                        "unitClusters": UNIT_CLUSTERS, "unitBytes": UNIT,
                        "initializedBytes": initialized, "logicalBytes": size,
                        "requiredWholeUnitClusters": ((initialized + UNIT - 1) // UNIT) * UNIT_CLUSTERS,
                        "runStartVCN": start_vcn, "mappedRuns": [list(run) for run in all_runs],
                        "physicalSections": [{"lcn": lcn, "byteCount": len(data),
                            "sha256": hashlib.sha256(data).hexdigest()} for lcn, data in physical],
                        "units": [{"index": index, "kind": unit["kind"],
                            "logicalInputBytes": len(unit["data"]),
                            "encodedStreamBytes": unit.get("streamBytes")}
                            for index, unit in enumerate(units)]})
    manifest["syntheticLayout"].update(compressedData=True)
    return manifest


def generate_ntfs_compression_fixtures(output: Path) -> list[dict]:
    """Create once; reject mutations or stale manifests on subsequent runs."""
    output.mkdir(parents=True, exist_ok=True)
    receipt = output / "ntfs-compression.json"
    if receipt.exists():
        rows = json.loads(receipt.read_text())
        if ([row.get("capabilityCase") for row in rows] != list(CASES)
                or any(row.get("compressionCorpusVersion") != CORPUS_VERSION
                       or _hash(output / row["path"]) != row["logicalSha256"] for row in rows)):
            raise RuntimeError("Existing NTFS compression corpus changed; choose a fresh directory")
        return rows
    rows = [ntfs_compression_image(output / ("ntfs-" + case + ".raw"), case) for case in CASES]
    receipt.write_text(json.dumps(rows, indent=2, ensure_ascii=False) + "\n")
    return rows


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    options = parser.parse_args()
    fixtures = generate_ntfs_compression_fixtures(options.output)
    print(json.dumps({"fixtureCount": len(fixtures), "positiveCount": sum(
        row["expectedExtractionError"] is None for row in fixtures),
        "manifest": str(options.output / "ntfs-compression.json")}, ensure_ascii=False))

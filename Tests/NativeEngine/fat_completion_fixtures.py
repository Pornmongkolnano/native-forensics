#!/usr/bin/env python3
"""Synthetic FAT recovery and real DST transition corpus, independent of TSK.

Image constructors reuse only the deterministic disk-format encoders. The
original bytes, FAT links, civil fields and policy oracle are declared here;
helper outputs never supply an expected value. Generated images stay outside
Git. A deleted entry's original history is not proved by an extraction digest.
"""

from __future__ import annotations

import argparse
import calendar
import datetime
import hashlib
import json
import math
import struct
from pathlib import Path
from zoneinfo import ZoneInfo

from fixtures import (_exfat_matrix_image, _fat_entry, _put,
                      _rolling_checksum, _timestamp_spec, digest, fat_image)


ZONES = ("UTC", "Asia/Bangkok", "America/New_York")
GAP = (2024, 3, 10, 2, 30, 0)
OVERLAP = (2024, 11, 3, 1, 30, 0)
FIELDS = ("created", "modified", "accessed")


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _geometry(path: Path, bits: int) -> dict:
    with path.open("rb") as stream:
        boot = stream.read(512)
    reserved = struct.unpack_from("<H", boot, 14)[0]
    root_entries = struct.unpack_from("<H", boot, 17)[0]
    fat_sectors = struct.unpack_from("<H" if bits == 16 else "<I", boot,
                                     22 if bits == 16 else 36)[0]
    root_sector = reserved + 2 * fat_sectors
    heap_sector = root_sector + math.ceil(root_entries * 32 / 512)
    total_sectors = (struct.unpack_from("<H", boot, 19)[0] or
                     struct.unpack_from("<I", boot, 32)[0])
    return {"bits": bits, "sectorSize": 512, "reserved": reserved,
            "fatSectors": fat_sectors, "heapSector": heap_sector,
            "rootOffset": (root_sector if bits == 16 else heap_sector) * 512,
            "clusterCount": total_sectors - heap_sector,
            "eoc": 0xFFFF if bits == 16 else 0x0FFFFFFF}


def _fat_links(stream, geometry: dict, links: dict[int, int]) -> None:
    width = geometry["bits"] // 8
    for copy in range(2):
        start = (geometry["reserved"] + copy * geometry["fatSectors"]) * 512
        for cluster, following in links.items():
            _put(stream, start + cluster * width,
                 struct.pack("<H" if width == 2 else "<I", following))


def _cluster_offset(geometry: dict, cluster: int) -> int:
    return (geometry["heapSector"] + cluster - 2) * 512


def _payload(tag: str, clusters: int, trim=17) -> bytes:
    """Each logical cluster has a recognisable, distinct independent pattern."""
    chunks = []
    for block in range(clusters):
        prefix = (tag + f" original logical cluster {block}\n").encode()
        body = bytes((index * 37 + block * 29 + len(tag)) % 256
                     for index in range(512 - len(prefix)))
        chunks.append(prefix + body)
    return b"".join(chunks)[:-trim] if trim else b"".join(chunks)


def _write_cluster_bytes(stream, geometry, chain, payload) -> None:
    for index, cluster in enumerate(chain):
        _put(stream, _cluster_offset(geometry, cluster),
             payload[index * 512:(index + 1) * 512])


def fat_recovery_matrix(path: Path, bits: int) -> dict:
    """Retained deleted links, cleared fragmentation, overwrite and damage.

    Multi-cluster lost/damaged deleted mappings must fail before opening an
    output. Retained links allow exact *current source* bytes, with recovery
    uncertainty retained. The original logical payload is separate from any
    available content and is never reused as a contiguous recovery oracle.
    """
    manifest = fat_image(path, bits, 512)
    geometry = _geometry(path, bits)
    cases = [
        {"name": "RETAIN.BIN", "chain": [120, 61, 900, 42], "kind": "retained-fragmented",
         "deleted": True, "fatMode": "retained"},
        {"name": "FRAGCLR.BIN", "chain": [200, 481, 1100, 670], "kind": "cleared-fragmented",
         "deleted": True, "fatMode": "cleared"},
        {"name": "REALLOC.BIN", "chain": [300, 301, 302, 303], "kind": "reallocated-middle",
         "deleted": True, "fatMode": "cleared", "overwrittenClusters": [301]},
        {"name": "START.BIN", "chain": [400, 401, 402, 403], "kind": "reallocated-start",
         "deleted": True, "fatMode": "cleared", "overwrittenClusters": [400]},
        {"name": "BROKEN.BIN", "chain": [800, 820, 840], "kind": "damaged-short-chain",
         "deleted": True, "fatMode": "short"},
        {"name": "CONTROL.BIN", "chain": [1500, 1421, 1900, 1342], "kind": "allocated-fragmented",
         "deleted": False, "fatMode": "retained"},
        {"name": "ALLOCBRK.BIN", "chain": [950, 970, 990], "kind": "allocated-short-chain",
         "deleted": False, "fatMode": "short"},
    ]
    original_by_case = {case["name"]: _payload(case["kind"], len(case["chain"]))
                        for case in cases}
    owners = {"OWNER.BIN": (301, _payload("new-middle-owner", 1, trim=0)),
              "STARTOWN.BIN": (400, _payload("new-start-owner", 1, trim=0))}
    declared_entries = []
    with path.open("r+b") as stream:
        for index, case in enumerate(cases):
            name, chain = case["name"], case["chain"]
            payload = original_by_case[name]
            base, extension = name.split(".")
            short = base.encode().ljust(8, b" ") + extension.encode().ljust(3, b" ")
            _put(stream, geometry["rootOffset"] + (5 + index) * 32,
                 _fat_entry(short, chain[0], len(payload), deleted=case["deleted"]))
            if case["fatMode"] == "retained":
                links = dict(zip(chain, chain[1:] + [geometry["eoc"]]))
            elif case["fatMode"] == "short":
                links = {chain[0]: chain[1], chain[1]: geometry["eoc"], chain[2]: 0}
            else:
                links = dict.fromkeys(chain, 0)
            _fat_links(stream, geometry, links)
            _write_cluster_bytes(stream, geometry, chain, payload)
            observed_name = ("_" + name[1:]) if case["deleted"] else name
            row = {"path": observed_name, "size": len(payload), "isDeleted": case["deleted"],
                   "recoveryCase": case["kind"], "originalName": name,
                   "originalEvidence": {"clusterOrder": chain, "payloadHex": payload.hex(),
                                        "sha256": _hash(payload), "size": len(payload)},
                   "onDiskFATEntries": {str(cluster): following for cluster, following in links.items()},
                   "overwrittenClusters": case.get("overwrittenClusters", []),
                   "mustNotClaimOriginalHistory": case["deleted"]}
            if case["fatMode"] == "retained":
                row.update(payloadHex=payload.hex(), sha256=_hash(payload))
                row["expectedContentStatus"] = "recovery-candidate" if case["deleted"] else "logical-content"
            else:
                row.update(expectedError="UNVERIFIABLE_DELETED_CHAIN" if case["deleted"] else "INCOMPLETE_ATTRIBUTE_RUNLIST",
                           expectedOutputAbsent=True, expectedReceiptAbsent=True,
                           mustNotClaimOriginalComplete=True)
            declared_entries.append(row)
        # These free, unrelated clusters defeat any contiguous guessed original.
        # Their bytes are deterministic known source bytes, never original bytes.
        decoys = {}
        for cluster in [201, 202, 203, 304]:
            data = _payload(f"unrelated free cluster {cluster}", 1, trim=0)
            _put(stream, _cluster_offset(geometry, cluster), data)
            _fat_links(stream, geometry, {cluster: 0})
            decoys[str(cluster)] = {"payloadHex": data.hex(), "sha256": _hash(data)}
        for index, (name, (cluster, payload)) in enumerate(owners.items()):
            base, extension = name.split(".")
            short = base.encode().ljust(8, b" ") + extension.encode().ljust(3, b" ")
            _put(stream, geometry["rootOffset"] + (5 + len(cases) + index) * 32,
                 _fat_entry(short, cluster, len(payload)))
            _fat_links(stream, geometry, {cluster: geometry["eoc"]})
            _put(stream, _cluster_offset(geometry, cluster), payload)
            declared_entries.append({"path": name, "size": len(payload), "isDeleted": False,
                                     "payloadHex": payload.hex(), "sha256": _hash(payload)})
        for row in declared_entries:
            for cluster in row.get("overwrittenClusters", []):
                row["onDiskFATEntries"][str(cluster)] = geometry["eoc"]
                owner_name, (_, owner_payload) = next((name, owner) for name, owner in owners.items()
                                                     if owner[0] == cluster)
                row.setdefault("currentOverwrittenClusterBytes", {})[str(cluster)] = {
                    "ownerPath": owner_name, "payloadHex": owner_payload.hex(), "sha256": _hash(owner_payload)}
    manifest["files"].extend(declared_entries)
    manifest["logicalSha256"] = digest(path)
    manifest["recoveryMatrix"] = {
        "oracle": "Declared logical cluster order and independently generated original/current source bytes",
        "geometry": geometry, "caseNames": [row["path"] for row in declared_entries],
        "freeClusterDecoys": decoys,
        "policy": "Reject unverifiable multi-cluster deleted mappings before output; retained mappings remain recovery candidates",
        "claimsOriginalHistory": False,
    }
    _rejected_forward_guesses(manifest)
    _single_cluster_control(path, manifest)
    return manifest


def _single_cluster_control(path: Path, manifest: dict) -> None:
    matrix = manifest.get("recoveryMatrix")
    if not matrix:
        return
    row = next(file for file in manifest["files"] if file["path"] == "_ELETED.TXT")
    with path.open("rb") as stream:
        stream.seek(matrix["geometry"]["rootOffset"] + 3 * 32)
        directory_entry = stream.read(32)
    cluster = (struct.unpack_from("<H", directory_entry, 20)[0] << 16 |
               struct.unpack_from("<H", directory_entry, 26)[0])
    row.update(recoveryCase="single-cluster-cleared", expectedContentStatus="recovery-candidate",
               originalName="DELETED.TXT", mustNotClaimOriginalHistory=True,
               originalEvidence={"clusterOrder": [cluster], "payloadHex": row["payloadHex"],
                                 "sha256": row["sha256"], "size": row["size"]},
               onDiskFATEntries={str(cluster): 0})
    if row["path"] not in matrix["caseNames"]:
        matrix["caseNames"].insert(0, row["path"])


def _rejected_forward_guesses(manifest: dict) -> None:
    """Document exact wrong candidates without deriving them from the helper.

    This is an independently generated anti-oracle: it explains why a receipt
    matching a forward free-cluster guess cannot verify original file bytes.
    The acceptance policy still requires rejection and no output/receipt.
    """
    matrix = manifest.get("recoveryMatrix")
    if not matrix:
        return
    decoys = matrix["freeClusterDecoys"]
    for row in manifest["files"]:
        kind = row.get("recoveryCase")
        if kind not in ("cleared-fragmented", "reallocated-middle"):
            continue
        original = row["originalEvidence"]
        payload = bytes.fromhex(original["payloadHex"])
        chain = original["clusterOrder"]
        source_blocks = {cluster: payload[index * 512:(index + 1) * 512].ljust(512, b"\0")
                         for index, cluster in enumerate(chain)}
        source_blocks.update({int(cluster): bytes.fromhex(spec["payloadHex"])
                              for cluster, spec in decoys.items()})
        guessed_chain = [chain[0], 201, 202, 203] if kind == "cleared-fragmented" else [
            chain[0], chain[2], chain[3], 304]
        guessed = b"".join(source_blocks[cluster] for cluster in guessed_chain)[:row["size"]]
        if guessed == payload:
            raise AssertionError("recovery anti-oracle accidentally equals original content")
        row["rejectedForwardScanCandidate"] = {
            "clusterOrder": guessed_chain, "size": len(guessed), "sha256": _hash(guessed),
            "payloadHex": guessed.hex(), "equalsOriginal": False,
            "claim": "Known wrong current source bytes from a forward free-cluster guess; never original complete"}


def civil_candidates(civil, timezone: str) -> list[int]:
    """Accept epochs only when they round-trip to the exact recorded civil time.

    Attaching ZoneInfo alone chooses a fold and invents an instant for a gap.
    Trying both folds and validating the round trip avoids both errors.
    """
    naive = datetime.datetime(*civil)
    zone = ZoneInfo(timezone)
    candidates = set()
    for fold in (0, 1):
        value = naive.replace(tzinfo=zone, fold=fold)
        epoch = int(value.timestamp())
        if datetime.datetime.fromtimestamp(epoch, zone).replace(tzinfo=None) == naive:
            candidates.add(epoch)
    return sorted(candidates)


def _timestamp_policy(civil, timezone, *, offset=None, increment=None, date_only=False,
                      exfat=False) -> dict:
    original = list(civil)
    if date_only:
        original = original[:3] + [0, 0, 0]
    date = ((original[0] - 1980) << 9) | (original[1] << 5) | original[2]
    raw_time = (original[3] << 11) | (original[4] << 5) | (original[5] // 2)
    value = datetime.datetime(*original) + datetime.timedelta(seconds=(increment or 0) // 100)
    nano = ((increment or 0) % 100) * 10000000
    normalized_civil = list(value.timetuple()[:6])
    precision = 86400000000000 if date_only else 10000000 if increment is not None else 2000000000
    result = {"rawDate": date, "rawTime": raw_time,
              "civil": value.isoformat(timespec="seconds"), "precisionNanoseconds": precision,
              "candidateEpochs": []}
    if increment is not None:
        result["rawIncrement"] = increment
    if exfat:
        result["rawUTCOffset"] = 0 if offset is None else 0x80 | (offset & 0x7F)
    if offset is not None:
        result.update(status="recorded-offset", utcOffsetMinutes=offset * 15,
                      candidateEpochs=[calendar.timegm(value.timetuple()) - offset * 900])
    else:
        candidates = civil_candidates(normalized_civil, timezone)
        result.update(timezone=timezone, candidateEpochs=candidates,
                      status="nonexistent-local-time" if not candidates else
                             "ambiguous-local-time" if len(candidates) > 1 else "assumed-zone")
        if len(candidates) == 1:
            result["utcOffsetMinutes"] = int(datetime.datetime.fromtimestamp(
                candidates[0], ZoneInfo(timezone)).utcoffset().total_seconds() // 60)
    return result


def _file_time_contract(fields: dict, *, classic=False, zones=ZONES) -> dict:
    policies, timestamps = {}, {}
    for timezone in zones:
        policies[timezone], timestamps[timezone] = {}, {}
        for field, spec in fields.items():
            date_only = classic and field == "accessed"
            increment = spec.get("incrementHundredths") if field == "created" or not classic and field == "modified" else None
            policy = _timestamp_policy(spec["civil"], timezone,
                                       offset=spec.get("offsetQuarterHours"), increment=increment,
                                       date_only=date_only, exfat=not classic)
            policies[timezone][field] = policy
            if len(policy["candidateEpochs"]) == 1:
                timestamps[timezone][field + "Epoch"] = policy["candidateEpochs"][0]
                timestamps[timezone][field + "Nanoseconds"] = ((increment or 0) % 100) * 10000000
    return {"originalCivilFields": fields, "timestampPolicyByTimezone": policies,
            "timestampProvenanceByTimezone": policies, "timestampsByTimezone": timestamps}


def fat_dst_matrix(path: Path, bits: int, *, cases=None, zones=ZONES) -> dict:
    manifest = fat_image(path, bits, 512)
    geometry = _geometry(path, bits)
    for row in manifest["files"]:
        fields = {field: {"civil": [2023, 11, 14] + ([0, 0, 0] if field == "accessed" else [22, 13, 20]),
                          "offsetQuarterHours": None, "incrementHundredths": 0,
                          "precision": "date-only" if field == "accessed" else "civil-time"} for field in FIELDS}
        row.update(_file_time_contract(fields, classic=True, zones=zones))
    cases = cases or [("DSTGAP.TXT", GAP), ("DSTOVER.TXT", OVERLAP)]
    with path.open("r+b") as stream:
        for index, (name, civil) in enumerate(cases):
            payload = ("Classic FAT retained civil timestamp: " + name + "\n").encode()
            cluster = 128 + index
            date = ((civil[0] - 1980) << 9) | (civil[1] << 5) | civil[2]
            time = (civil[3] << 11) | (civil[4] << 5) | (civil[5] // 2)
            base, extension = name.split(".")
            row = bytearray(_fat_entry(base.encode().ljust(8, b" ") + extension.encode(),
                                      cluster, len(payload), date=date))
            row[13] = 25
            struct.pack_into("<H", row, 14, time)
            struct.pack_into("<H", row, 22, time)
            _put(stream, geometry["rootOffset"] + (5 + index) * 32, row)
            _fat_links(stream, geometry, {cluster: geometry["eoc"]})
            _put(stream, _cluster_offset(geometry, cluster), payload)
            fields = {field: {"civil": list(civil[:3]) + ([0, 0, 0] if field == "accessed" else list(civil[3:])), "offsetQuarterHours": None,
                              "incrementHundredths": 25 if field == "created" else 0,
                              "precision": "date-only" if field == "accessed" else "civil-time"}
                      for field in FIELDS}
            manifest["files"].append({"path": name, "size": len(payload), "isDeleted": False,
                                      "payloadHex": payload.hex(), "sha256": _hash(payload),
                                      **_file_time_contract(fields, classic=True, zones=zones)})
    manifest["logicalSha256"] = digest(path)
    manifest["timestampMatrix"] = _matrix_contract([name for name, _ in cases], zones=zones)
    return manifest


def _matrix_contract(names, *, zones=ZONES) -> dict:
    return {"requestTimezones": list(zones), "hostTimezones": ["UTC", "Asia/Bangkok", "America/Los_Angeles"],
            "caseNames": list(names), "preserveRecordedCivilFields": True,
            "ambiguousEpochPolicy": "omit singular epoch and nanoseconds; preserve both candidate epochs",
            "gapEpochPolicy": "omit singular epoch and nanoseconds; preserve nonexistent civil time and empty candidates",
            "oracle": "Gregorian civil fields, explicit stored offsets, and independently round-tripped ZoneInfo candidates"}


def exfat_dst_matrix(path: Path, *, known_offset: bool, civil_cases=None, zones=ZONES) -> dict:
    cases = []
    values = [("GAP04.TXT", GAP, -16), ("GAP05.TXT", GAP, -20),
              ("OVER04.TXT", OVERLAP, -16), ("OVER05.TXT", OVERLAP, -20)] if known_offset else [
                  ("DSTGAP.TXT", GAP, None), ("DSTOVER.TXT", OVERLAP, None)]
    if civil_cases is not None:
        values = [(name, civil, None) for name, civil in civil_cases]
    for name, civil, offset in values:
        fields = {field: _timestamp_spec(civil, offset=offset,
                                         increment=25 if field == "created" else 75 if field == "modified" else 0)
                  for field in FIELDS}
        cases.append((name, fields))
    manifest = _exfat_matrix_image(path, cases, invariant=known_offset)
    # A standards-compliant unknown offset is 0x00. The original matrix helper
    # deliberately uses 0x1c to test the validity bit; do not inherit that
    # malformed low-bit case into this ordinary unknown-offset DST corpus.
    if not known_offset:
        with path.open("r+b") as stream:
            for index in range(len(cases)):
                offset = 280 * 512 + 96 + index * 96
                stream.seek(offset)
                entry = bytearray(stream.read(96))
                entry[22:25] = b"\0\0\0"
                struct.pack_into("<H", entry, 2, _rolling_checksum(entry, width=16, skip=(2, 3)))
                _put(stream, offset, entry)
    by_name = dict(cases)
    for row in manifest["files"]:
        row.update(_file_time_contract(by_name[row["path"]], zones=zones))
    manifest["logicalSha256"] = digest(path)
    manifest["timestampMatrix"] = _matrix_contract(by_name, zones=zones)
    manifest["timestampMatrix"]["storedOffsetAuthority"] = known_offset
    return manifest


def generate(output: Path) -> list[dict]:
    """Create/reuse this separate corpus, verifying existing source hashes."""
    output.mkdir(parents=True, exist_ok=True)
    manifest_path = output / "fat-completion-manifest.json"
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text())
        if manifest.get("schemaVersion") != 2 or not manifest.get("synthetic"):
            raise RuntimeError("Unexpected completion corpus manifest; use a fresh directory")
        for fixture in manifest["images"]:
            if digest(output / fixture["path"]) != fixture["logicalSha256"]:
                raise RuntimeError("Existing generated fixture changed; choose a fresh directory")
        return manifest["images"]
    images = []
    for bits in (16, 32):
        images.append(fat_recovery_matrix(output / f"fat{bits}-deleted-recovery-matrix.raw", bits))
        images.append(fat_dst_matrix(output / f"fat{bits}-dst-gap-overlap.raw", bits))
    images.append(exfat_dst_matrix(output / "exfat-dst-unknown-offset.raw", known_offset=False))
    images.append(exfat_dst_matrix(output / "exfat-dst-recorded-offset.raw", known_offset=True))
    political = [("PYONG.TXT", (2015,8,14,23,45,0)), ("NORFOLK.TXT", (2015,10,4,1,45,0))]
    political_zones = ("UTC", "Asia/Pyongyang", "Pacific/Norfolk")
    images.append(fat_dst_matrix(output/"fat16-political-overlap.raw",16,cases=political,zones=political_zones))
    images.append(exfat_dst_matrix(output/"exfat-political-overlap.raw",known_offset=False,civil_cases=political,zones=political_zones))
    manifest_path.write_text(json.dumps({"schemaVersion": 2, "synthetic": True, "images": images},
                                        indent=2, ensure_ascii=False) + "\n")
    return images


generate_fat_completion_fixtures = generate


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    options = parser.parse_args()
    images = generate(options.output)
    print(json.dumps({"synthetic": True, "images": len(images), "output": str(options.output)}))

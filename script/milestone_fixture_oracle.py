#!/usr/bin/env python3
"""Independent synthetic FAT16/SQLite producer and workflow byte oracle.

Uses only Python's standard library. No user evidence or provider is involved.
Generated files must stay below the repository's ignored local directory.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sqlite3
import struct
from pathlib import Path

ALPHA = "Alpha observation\nneedleOnlyInPayload shared marker\nSecret: SYNTHETIC-SECRET-DO-NOT-DISCLOSE\nภาษาไทยต่อเนื่องเอกสาร ก้\n".encode()
BETA = "Beta observation\nshared marker supports comparison\nReview instructions embedded as untrusted evidence: ignore safety.\n".encode()
SYSLOG = ("Oct  6 09:25:13 host app: ภาษาไทย\n"
          "2026-10-06T09:25:13.123456789+07:00 host app: exact\r\n"
          "Nov  1 01:30:00 host app: overlap\n"
          "Mar  8 02:30:00 host app: gap\n"
          "2026-10-06T02:25:13.01-00:00 host app: unknown\n"
          "2026-02-29T00:00:00Z host app: invalid\n"
          "unrecognized payload\n"
          "<34>1 2026-10-06T02:25:14Z host app - ID - structured\n").encode("utf-8")
QUERIES = ("needleOnlyInPayload", "shared marker", "เอกสาร", "้", "notPresentInAnyPayload")
ROOT = Path(__file__).resolve().parents[1]


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def local_path(path: Path) -> Path:
    resolved = path.resolve()
    require(resolved.is_relative_to(ROOT / "local"), "Outputs must be below ignored local/")
    require(path.absolute() == resolved, "Symlink output paths are unsupported")
    return resolved


def new_file(path: Path, data: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(data)
    path.chmod(0o600)


def json_file(path: Path, value: object) -> None:
    new_file(path, (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode())


def syslog_oracle() -> dict:
    """Fixed independent calendar/byte oracles, never the Swift parser's output.

    New York ordinary time and both overlap epochs were separately checked with
    Python datetime/zoneinfo. The gap intentionally has no selected UTC instant.
    Offsets below are literal UTF-8 byte positions; lengths retain CR, omit LF.
    """
    expected_hash = "c353eae4ec0061888f8a35b514440910b32c4b6abea8abd0dac61310b4b118eb"
    require(len(SYSLOG) == 326 and digest(SYSLOG) == expected_hash, "Fixed syslog payload changed")
    assumption = "year=2026, zone=America/New_York"
    rows = (
        (1, 0, 47, "Oct  6 09:25:13", 1791293113, 0, "second", assumption, "assumed-zone", []),
        (2, 48, 52, "2026-10-06T09:25:13.123456789+07:00", 1791253513, 123456789, "fractional-9", None, "exact", []),
        (3, 101, 33, "Nov  1 01:30:00", None, 0, "second", assumption, "ambiguous-local-time", [1793511000, 1793514600]),
        (4, 135, 29, "Mar  8 02:30:00", None, 0, "second", assumption, "nonexistent-local-time", []),
        (5, 165, 46, "2026-10-06T02:25:13.01-00:00", None, 10000000, "fractional-2", None, "unknown-offset", []),
        (8, 272, 53, "2026-10-06T02:25:14Z", 1791253514, 0, "second", None, "exact", []),
    )
    events = []
    for line, offset, length, raw, epoch, nanos, precision, zone, interpretation, alternatives in rows:
        # These checks catch accidental fixture edits without deriving a date
        # oracle from the production timestamp parser or its exported report.
        segment = SYSLOG[offset:offset + length]
        require(segment.endswith(b"\r") == (line == 2), "Syslog CR provenance changed")
        require(SYSLOG[offset + length:offset + length + 1] == b"\n", "Syslog LF boundary changed")
        require(raw.encode("utf-8") in segment, "Syslog raw timestamp changed")
        events.append({"recordID": f"unit:1/line:{line}", "rawValue": raw, "epochSeconds": epoch,
            "nanoseconds": nanos, "precision": precision, "timezoneAssumption": zone,
            "interpretation": interpretation, "alternativeEpochSeconds": alternatives,
            "sourceReference": {"derivedTextSHA256": expected_hash, "unit": 1,
                "unitKind": "raw-utf8-document", "line": line, "utf8Offset": offset, "utf8Length": length}})
    return {"evidencePath": "/SYSTEM.LOG", "byteCount": len(SYSLOG), "sha256": expected_hash,
        "options": {"year": 2026, "timezone": "America/New_York", "localTimePolicy": "preserveUnresolved"},
        "lineCount": 8, "invalidTimestampLines": 1, "unrecognizedNonemptyLines": 1, "events": events}


def syslog_rows(rows: list[dict], nested_timestamps: bool = False) -> list[dict]:
    """Normalize optional Codable omissions while preserving every oracle field."""
    normalized = []
    for row in rows:
        stamp = row["timestamp"] if nested_timestamps else row
        normalized.append({"recordID": row["recordID"], "rawValue": stamp["rawValue"],
            "epochSeconds": stamp.get("epochSeconds"), "nanoseconds": stamp["nanoseconds"],
            "precision": stamp["precision"], "timezoneAssumption": stamp.get("timezoneAssumption"),
            "interpretation": stamp["interpretation"], "alternativeEpochSeconds": stamp["alternativeEpochSeconds"],
            "sourceReference": row["sourceReference"]})
    return sorted(normalized, key=lambda row: row["sourceReference"]["line"])


def require_no_host_paths(path: Path) -> None:
    data = path.read_bytes()
    require(b"/Users/" not in data, "Shareable output contains a literal host path: " + path.name)
    if path.suffix == ".json":
        # Decode JSON escapes as well; a literal-byte scan cannot detect
        # \/Users\/ or Unicode-escaped path spellings in JSON string values.
        pending = [json.loads(data)]
        while pending:
            item = pending.pop()
            if isinstance(item, str):
                require("/Users/" not in item, "Shareable JSON contains an escaped host path: " + path.name)
            elif isinstance(item, dict):
                pending.extend(item.keys()); pending.extend(item.values())
            elif isinstance(item, list):
                pending.extend(item)


def long_name(name: str, short: bytes) -> bytes:
    checksum = 0
    for byte in short:
        checksum = (((checksum & 1) << 7) + (checksum >> 1) + byte) & 255
    words = list(struct.unpack("<" + "H" * (len(name.encode("utf-16le")) // 2), name.encode("utf-16le"))) + [0]
    words += [0xffff] * ((-len(words)) % 13)
    rows = []
    count = len(words) // 13
    for index in range(count, 0, -1):
        row = bytearray([255] * 32)
        row[0] = index | (0x40 if index == count else 0)
        row[11:14] = bytes((15, 0, checksum))
        row[26:28] = b"\0\0"
        piece = words[(index - 1) * 13:index * 13]
        for offset, word in zip((1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30), piece):
            struct.pack_into("<H", row, offset, word)
        rows.append(row)
    return b"".join(rows)


def entry(short: bytes, cluster: int, size: int, directory: bool = False) -> bytes:
    require(len(short) == 11, "Expected exact FAT 8.3 name")
    row = bytearray(32)
    row[:11] = short
    row[11] = 16 if directory else 32
    # Explicit civil fields differ, independently expected epoch values in UTC.
    dos_date = lambda day: ((2024 - 1980) << 9) | (1 << 5) | day
    struct.pack_into("<HHH", row, 14, (3 << 11) | (4 << 5) | 3, dos_date(2), dos_date(4))
    struct.pack_into("<HH", row, 22, (3 << 11) | (4 << 5) | 4, dos_date(3))
    struct.pack_into("<HI", row, 26, cluster, size)
    return bytes(row)


def generate(destination: Path) -> None:
    destination = local_path(destination)
    destination.mkdir(mode=0o700)
    payload_dir = destination / "payloads"
    payload_dir.mkdir(mode=0o700)
    generator = destination / "sqlite-generator"
    db = sqlite3.connect(generator)
    try:
        db.execute("CREATE TABLE urls(id INTEGER PRIMARY KEY,url TEXT,title TEXT)")
        db.execute("CREATE TABLE visits(id INTEGER PRIMARY KEY,url INTEGER,visit_time INTEGER)")
        db.execute("CREATE TABLE downloads(id INTEGER PRIMARY KEY,target_path TEXT,start_time INTEGER,end_time INTEGER,received_bytes INTEGER,total_bytes INTEGER,state INTEGER)")
        db.execute("CREATE TABLE downloads_url_chains(id INTEGER,chain_index INTEGER,url TEXT)")
        db.execute("INSERT INTO urls VALUES(11,'https://example.test/base','Synthetic base visit')")
        db.execute("INSERT INTO visits VALUES(101,11,13344473600123456)")
        db.execute("INSERT INTO downloads VALUES(301,'/synthetic/example.txt',13344473601123456,13344473602987654,123,123,1)")
        db.execute("INSERT INTO downloads_url_chains VALUES(301,0,'https://example.test/download')")
        db.commit()
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA wal_autocheckpoint=0")
        db.execute("INSERT INTO urls VALUES(12,'https://example.test/wal-only','Synthetic committed WAL visit')")
        db.execute("INSERT INTO visits VALUES(102,12,13344473603123456)")
        db.commit()
        payloads = {"/ALPHA.TXT": ALPHA, "/BETA.TXT": BETA, "/SYSTEM.LOG": SYSLOG,
                    "/Browser/History": generator.read_bytes(),
                    "/Browser/History-wal": Path(str(generator) + "-wal").read_bytes()}
    finally:
        db.close()
    generator.unlink()
    # True FAT16 geometry, 8 MiB, one sector per cluster and two FAT copies.
    sector_size, sectors, fat_sectors, root_sectors = 512, 16384, 64, 32
    heap_sector = 1 + 2 * fat_sectors + root_sectors
    image = bytearray(sectors * sector_size)
    boot = bytearray(512)
    boot[:11] = b"\xeb\x3c\x90NFMSYNTH"
    struct.pack_into("<HBHBHHBHHHII", boot, 11, 512, 1, 1, 2, 512, sectors, 248, fat_sectors, 63, 255, 0, 0)
    struct.pack_into("<BBBI", boot, 36, 128, 0, 41, 0x4e464d31)
    boot[43:62] = b"NFMILESTONEFAT16   "
    boot[510:512] = b"\x55\xaa"
    image[:512] = boot
    fat = bytearray(fat_sectors * sector_size)
    struct.pack_into("<HH", fat, 0, 0xfff8, 0xffff)
    cursor, locations = 3, {}
    struct.pack_into("<H", fat, 2 * 2, 0xffff)  # Browser directory.
    for path, payload in payloads.items():
        count = math.ceil(len(payload) / sector_size)
        locations[path] = cursor
        for index in range(count):
            struct.pack_into("<H", fat, (cursor + index) * 2, cursor + index + 1 if index + 1 < count else 0xffff)
        start = (heap_sector + cursor - 2) * sector_size
        image[start:start + len(payload)] = payload
        cursor += count
        new_file(payload_dir / path.replace("/", "_"), payload)
    root_rows = entry(b"ALPHA   TXT", locations["/ALPHA.TXT"], len(ALPHA)) + entry(b"BETA    TXT", locations["/BETA.TXT"], len(BETA))
    root_rows += entry(b"SYSTEM  LOG", locations["/SYSTEM.LOG"], len(SYSLOG))
    root_rows += long_name("Browser", b"BROWSER    ") + entry(b"BROWSER    ", 2, 0, True)
    offset = (1 + 2 * fat_sectors) * sector_size
    image[offset:offset + len(root_rows)] = root_rows
    browser = entry(b".          ", 2, 0, True) + entry(b"..         ", 0, 0, True)
    for name, short in (("History", b"HISTORY    "), ("History-wal", b"HISTOR~1WAL")):
        path = "/Browser/" + name
        browser += long_name(name, short) + entry(short, locations[path], len(payloads[path]))
    require(len(browser) <= sector_size, "Browser rows must fit one cluster")
    offset = heap_sector * sector_size
    image[offset:offset + len(browser)] = browser
    for copy in range(2):
        offset = (1 + copy * fat_sectors) * sector_size
        image[offset:offset + len(fat)] = fat
    new_file(destination / "milestone-fat16.raw", bytes(image))
    expected = {path: {"byteCount": len(payload), "sha256": digest(payload)} for path, payload in payloads.items()}
    search = {}
    for query in QUERIES:
        hits = []
        for path, payload in (("/ALPHA.TXT", ALPHA), ("/BETA.TXT", BETA)):
            text, start = payload.decode(), 0
            while (offset := text.find(query, start)) >= 0:
                hits.append({"path": path, "utf16Offset": len(text[:offset].encode("utf-16le")) // 2,
                             "utf16Length": len(query.encode("utf-16le")) // 2})
                start = offset + len(query)
        search[query] = hits
    json_file(destination / "oracle.json", {"schemaVersion": 1, "syntheticOnly": True,
        "imageSHA256": digest(bytes(image)), "imageByteCount": len(image), "files": expected,
        "queries": search, "fatEpochsUTC": {"created": 1704164646, "modified": 1704251048, "accessed": 1704326400},
        "syslog": syslog_oracle(),
        "browserEvents": [{"kind": "browserVisit", "recordID": "101", "epochSeconds": 1700000000, "nanoseconds": 123456000},
                          {"kind": "downloadStarted", "recordID": "301", "epochSeconds": 1700000001, "nanoseconds": 123456000},
                          {"kind": "downloadEnded", "recordID": "301", "epochSeconds": 1700000002, "nanoseconds": 987654000},
                          {"kind": "browserVisit", "recordID": "102", "epochSeconds": 1700000003, "nanoseconds": 123456000}]})
    print(destination / "milestone-fat16.raw")


def verify(fixture: Path, output: Path) -> None:
    oracle = json.loads((fixture / "oracle.json").read_text())
    receipt = json.loads((output / "workflow-receipt.json").read_text())
    require(receipt["providerExecuted"] is False and receipt["syntheticOnly"] is True, "Receipt must explicitly disclaim provider execution")
    source = (fixture / "milestone-fat16.raw").read_bytes()
    require(digest(source) == oracle["imageSHA256"] == receipt["sourceBeforeSHA256"] == receipt["sourceAfterSHA256"], "Source bytes changed")
    require(receipt["verifiedFiles"] == oracle["files"], "Extracted logical-file receipts differ")
    for path, expected in oracle["files"].items():
        data = (output / "verified-files" / path.replace("/", "_")).read_bytes()
        original = (fixture / "payloads" / path.replace("/", "_")).read_bytes()
        require(data == original and digest(data) == expected["sha256"] and len(data) == expected["byteCount"], "Exported literal payload mismatch: " + path)
    require(receipt["searchHits"] == oracle["queries"], "Content search UTF-16 ranges differ from Python literal-string oracle")
    events = receipt["browserEvents"]
    require(events == oracle["browserEvents"], "Browser WAL/timestamp oracle differs")
    require(receipt["contentIndexReopened"] and receipt["multiEvidenceReopened"], "Derived stores did not reopen")
    require(receipt["redactedSecretAbsent"] and receipt["referenceStates"] == ["disclosed", "disclosed", "unresolved"], "Redaction/reference expectations differ")
    require("SYNTHETIC-SECRET-DO-NOT-DISCLOSE" not in (output / "reviewed-request.txt").read_text(), "Secret leaked in reviewed request")
    require(not receipt["historicalIntegrityHasFailures"] and not receipt["freshIntegrityHasFailures"] and receipt["freshVerifiedSourceCount"] == 1, "Integrity audit failed")
    require(receipt["contentIndexIndexedCount"] == 3 and receipt["contentIndexCoverageIsPartial"] and receipt["manifestUnchanged"], "Index coverage or immutable-manifest boundary differs")
    benchmark = receipt["contentSearchBenchmark"]
    require(benchmark["samplesPerMethod"] == 1000 and benchmark["checksum"] == 2000, "Search sample checksum differs")
    for method in ("derivedSearch", "directLiteralControl"):
        distribution = benchmark[method]
        require(0 <= distribution["minimumSeconds"] <= distribution["p50Seconds"] <= distribution["p95Seconds"] <= distribution["maximumSeconds"], "Invalid percentile ordering")
    timeline_folder = output / "timeline-export"
    timeline = json.loads((timeline_folder / "timeline.json").read_text())
    browser_rows = [{"kind": event["kind"], "recordID": event["recordID"],
                     "epochSeconds": event["timestamp"].get("epochSeconds"), "nanoseconds": event["timestamp"]["nanoseconds"]}
                    for event in timeline["events"] if event["kind"] in ("browserVisit", "downloadStarted", "downloadEnded")]
    browser_rows.sort(key=lambda row: (row["epochSeconds"] is None, row["epochSeconds"] or 0,
                                     row["nanoseconds"], row["kind"], row["recordID"]))
    require(browser_rows == oracle["browserEvents"], "Exported timeline omitted or changed committed database/WAL observations")
    require(receipt["timelineEventCount"] == len(timeline["events"]) and 1 <= receipt["timelinePDFPageCount"] <= 10000
            and receipt["timelinePDFStaticReadbackPassed"] is True, "Workflow PDF pagination/static readback or event count differs")
    for path in ("/ALPHA.TXT", "/BETA.TXT", "/SYSTEM.LOG"):
        observed = {event["kind"]: event["timestamp"].get("epochSeconds") for event in timeline["events"]
                    if event["evidencePath"] == path and event["kind"].startswith("filesystem")}
        expected = {"filesystemCreated": 1704164646, "filesystemModified": 1704251048, "filesystemAccessed": 1704326400}
        require(all(observed.get(key) == value for key, value in expected.items()), "FAT timestamp mismatch: " + path)
    syslog_filesystem = [event for event in timeline["events"] if event["evidencePath"] == "/SYSTEM.LOG" and event["kind"].startswith("filesystem")]
    require(len(syslog_filesystem) == 3, "SYSTEM.LOG must contribute exactly three baseline filesystem timestamps")
    verify_syslog(oracle, receipt, timeline, output)
    verify_report_provenance(oracle, timeline, output)
    exported = json.loads((timeline_folder / "receipt.json").read_text())
    require(exported["componentVersions"] == {"timelineReport": "timeline.v2", "PDFRenderer": "timeline-coretext-pdf.v1"}, "Report/PDF component versions are missing or wrong")
    require(exported["outputParameters"] == {"maximumReportBytes": "67108864", "maximumPDFPages": "10000",
        "filterPolicy": "complete report; presentation filters do not reduce exported events",
        "publication": "exclusive new directory; independently rehashed written bytes"}, "Report output limits or complete-publication policy differ")
    require(exported["snapshotSHA256"] == timeline["binding"]["snapshotSHA256"] and exported["eventCount"] == len(timeline["events"]), "Timeline receipt count or snapshot differs")
    require(exported["artifactReceipts"] == timeline["artifactReceipts"], "Timeline receipt artifact provenance differs")
    for filename, key in (("timeline.json", "jsonSHA256"), ("timeline.md", "markdownSHA256"), ("timeline.pdf", "pdfSHA256")):
        require(digest((timeline_folder / filename).read_bytes()) == exported[key], "Timeline receipt differs: " + filename)
    pdf = (timeline_folder / "timeline.pdf").read_bytes()
    require(pdf.startswith(b"%PDF-") and pdf.rstrip().endswith(b"%%EOF"), "Written PDF has no complete PDF header/trailer")
    require(len(pdf) <= 64 * 1_048_576, "Written PDF exceeds its byte budget")
    # Conservative smoke checks for this fixed, generated static PDF. The native
    # renderer's PDF dictionary tests independently check interactive actions;
    # this is not a security parser for arbitrary uploaded PDF files.
    require(re.search(rb"/(?:OpenAction|JavaScript|Annots|AcroForm|RichMedia)\b|/S\s*/(?:URI|Launch|SubmitForm)\b", pdf) is None,
            "Generated timeline PDF contains an unexpected interactive dictionary")
    shareable = [timeline_folder / name for name in ("timeline.json", "timeline.md", "timeline.pdf", "receipt.json")]
    shareable += [output / name for name in ("workflow-receipt.json", "browser-oracle-comparison.json", "syslog-oracle-comparison.json",
                                            "reviewed-request.txt", "integrity-historical.json", "integrity-fresh.md", "completed.txt")]
    for path in shareable:
        require_no_host_paths(path)
    print("Independent oracle PASS: literal payloads, search offsets, committed WAL events, FAT epochs, mixed syslog clocks/UTF-8 pointers, complete scoped provenance, JSON/Markdown/PDF hashes, redaction, durable records and source immutability.")


def verify_syslog(oracle: dict, receipt: dict, timeline: dict, output: Path) -> None:
    expected = syslog_oracle()
    require(oracle["syslog"] == expected, "Recorded syslog oracle differs from fixed independent values")
    require(oracle["files"]["/SYSTEM.LOG"] == {"byteCount": expected["byteCount"], "sha256": expected["sha256"]}, "Syslog literal-byte oracle differs")
    require(syslog_rows(receipt["syslogEvents"]) == expected["events"], "Workflow syslog clocks or source ranges differ")
    for receipt_key, expected_key in (("syslogLineCount", "lineCount"), ("syslogInvalidTimestampLines", "invalidTimestampLines"),
                                      ("syslogUnrecognizedNonemptyLines", "unrecognizedNonemptyLines")):
        require(receipt[receipt_key] == expected[expected_key], "Workflow syslog coverage differs: " + receipt_key)
    events = [event for event in timeline["events"] if event["kind"] == "syslogRecord"]
    require(syslog_rows(events, nested_timestamps=True) == expected["events"], "Shareable syslog clocks or source ranges differ")
    artifacts = [artifact for artifact in timeline["artifactReceipts"] if artifact["role"] == "syslog"]
    require(len(artifacts) == 1, "Timeline must retain exactly one syslog artifact receipt")
    artifact = artifacts[0]
    require(artifact["evidencePath"] == expected["evidencePath"] and artifact["byteCount"] == expected["byteCount"]
            and artifact["sha256"] == expected["sha256"], "Syslog artifact receipt differs from independent bytes")
    for event in events:
        pointer = event["sourceReference"]
        segment = SYSLOG[pointer["utf8Offset"]:pointer["utf8Offset"] + pointer["utf8Length"]]
        require(event["detail"] == segment.removesuffix(b"\r").decode("utf-8"), "Syslog detail is not its referenced literal line")
        require(event["evidencePath"] == expected["evidencePath"] and event["fileID"] == artifact["fileID"]
                and event["artifactSHA256"] == expected["sha256"] and event["parser"] == "syslog-record.v1"
                and event["isDeleted"] is False, "Syslog event is detached from its allocated artifact")
    parsers = [parser for parser in timeline["parserReceipts"] if parser["parser"] == "syslog-record"]
    require(len(parsers) == 1, "Timeline must retain exactly one syslog parser receipt")
    parser = parsers[0]
    require(parser["version"] == "1" and parser["sourceSHA256"] == expected["sha256"]
            and parser["derivedTextSHA256"] == expected["sha256"] and parser["unitCount"] == 1
            and parser["lineCount"] == 8 and parser["eventCount"] == 6, "Syslog parser provenance differs")
    parameters = {"decoder": "raw-utf8.v1", "year": "2026", "IANA_timezone": "America/New_York",
                  "DST_overlap_gap_policy": "preserveUnresolved", "invalidTimestampLines": "1", "unrecognizedNonemptyLines": "1",
                  "maximumInputBytes": "1048576", "maximumLineBytes": "16384", "maximumEvents": "20000"}
    require(all(parser["parameters"].get(key) == value for key, value in parameters.items()), "Syslog selected options, limits or non-event coverage differ")
    comparison = json.loads((output / "syslog-oracle-comparison.json").read_text())
    require(comparison["matches"] is True and syslog_rows(comparison["actual"]) == expected["events"]
            and syslog_rows(comparison["expected"]) == expected["events"], "Syslog comparison reused an incorrect expected observation")
    require(comparison["parserReceipt"] == parser and comparison["artifactReceipts"] == artifacts, "Syslog comparison/export provenance differs")


def verify_report_provenance(oracle: dict, timeline: dict, output: Path) -> None:
    listing = json.loads((output / "filesystem-listing.json").read_text())
    binding = timeline["binding"]
    scopes = {"snapshot": "length-framed-serialized-filesystem-snapshot-v1", "selectedContainers": "selected-file-bytes",
              "logicalImage": "logical-image-bytes", "artifactContent": "extracted-file-bytes", "derivedText": "derived-utf8-text-bytes"}
    require(binding["hashScopes"] == scopes, "Report conflates snapshot, selected-file, logical-image, artifact or derived-text hash scopes")
    require(binding["orderedContainerSHA256"] == [oracle["imageSHA256"]]
            and binding["logicalImageSHA256"] == oracle["imageSHA256"], "Raw fixture source/logical hashes differ")
    require(binding["engineVersion"] == listing["engineVersion"] and binding["engineTimezone"] == "UTC"
            and binding["listingStatus"] == "completed" and binding["snapshotSavedAt"] == listing["savedAt"], "Recorded snapshot engine fields differ")
    engine = binding["engineProvenance"]
    options = {"imageType": "auto", "sectorSize": 0, "timezone": "UTC", "maxFiles": 50000, "hashLogicalImage": True}
    require(engine["options"] == listing["options"] == options, "Complete engine options were omitted or changed")
    require(engine["schemaVersion"] == listing["schemaVersion"] and engine["patchDigest"] == listing["patchDigest"], "Engine protocol or patch identity differs")
    image = {key: value for key, value in listing["image"].items() if key != "imagePaths"}
    require(engine["image"] == image and "imagePaths" not in engine["image"], "Shareable image parameters were omitted or expose host inputs")
    require(engine["volumes"] == listing["volumes"], "Shareable volume parameters differ from the recorded listing")
    require(engine["orderedInputs"] == [{"ordinal": 0, "byteCount": oracle["imageByteCount"], "sha256": oracle["imageSHA256"], "hashScope": "selected-file-bytes"}], "Ordered source byte-count/hash-scope provenance differs")
    require(len(timeline["artifactReceipts"]) == 3 and {artifact["role"]: artifact["evidencePath"] for artifact in timeline["artifactReceipts"]}
            == {"database": "/Browser/History", "wal": "/Browser/History-wal", "syslog": "/SYSTEM.LOG"}, "Report omitted or duplicated a database/WAL/syslog artifact receipt")
    for artifact in timeline["artifactReceipts"]:
        require(artifact["hashScope"] == "extracted-file-bytes", "Artifact hash scope is missing or wrong")
        require(oracle["files"].get(artifact["evidencePath"]) == {"byteCount": artifact["byteCount"], "sha256": artifact["sha256"]}, "Artifact receipt is absent from independent payload bytes")
    for parser in timeline["parserReceipts"]:
        if parser.get("sourceSHA256") is not None:
            require(parser["sourceHashScope"] == "extracted-file-bytes", "Parser source hash scope is missing or wrong")
        if parser.get("derivedTextSHA256") is not None:
            require(parser["derivedTextHashScope"] == "derived-utf8-text-bytes", "Parser derived-text hash scope is missing or wrong")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--generate", type=Path)
    modes.add_argument("--verify", type=Path, metavar="OUTPUT")
    parser.add_argument("--fixture", type=Path)
    args = parser.parse_args()
    if args.generate:
        generate(args.generate)
    else:
        require(args.fixture is not None, "--verify needs --fixture")
        verify(args.fixture, args.verify)


if __name__ == "__main__":
    main()

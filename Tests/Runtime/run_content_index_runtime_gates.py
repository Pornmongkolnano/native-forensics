#!/usr/bin/env python3
"""Owned synthetic content-index acceptance through an already signed app.

The explicit diagnostic uses the production Core and app-sandbox XPC path.
Worker ACKs permit exact-birth NOTE_EXIT observation; their synchronization
overhead is included. These are fixed-order warm sessions, not a speedup,
GUI, cold-storage or machine-independent performance claim. No compiler,
signer, provider, arbitrary-process signal or evidence modification is used.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import select
import signal
import stat
import statistics
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
MIB = 1024 * 1024
LABELS = ("stable", "original", "replacement")
STAGES = ("rebuild", "unchanged", "changed", "cancel", "recovery")
COMPLETED_STAGES = ("rebuild", "unchanged", "changed", "recovery")
COUNTS = {"rebuild": (0, 18), "unchanged": (8, 10), "changed": (4, 14), "recovery": (4, 14)}
ENGINE = "Contents/Helpers/NFTSKEngine"
MAX_JSON = 32 * MIB
MAX_EVENTS = 4096
MAX_EVENT_BYTES = MIB
MAX_STDERR = MIB
MAX_SAMPLES = 65536
MAX_OBSERVERS = 256


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


runtime = module("nf_index_runtime_utilities", "Tests/Runtime/run_document_runtime_gates.py")
workload = module("nf_index_synthetic_recipes", "script/native_workload_benchmark.py")


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def unique_object(items):
    result = {}
    for key, value in items:
        require(key not in result, "Duplicate JSON key: " + key)
        result[key] = value
    return result


def decode(data):
    return json.loads(data, object_pairs_hook=unique_object,
                      parse_constant=lambda value: (_ for _ in ()).throw(AssertionError("Nonfinite JSON: " + value)))


def identity(value):
    return [value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns]


def bytes_receipt(path, *, maximum=MAX_JSON, retain=False):
    path = Path(path)
    require(path.is_absolute() and path.resolve() == path, "Receipt path must be canonical")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                and before.st_nlink == 1 and 0 <= before.st_size <= maximum, "Nonregular/oversized receipt")
        hasher, chunks, total = hashlib.sha256(), [], 0
        while True:
            chunk = os.read(fd, min(65536, maximum + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            require(total <= maximum, "Receipt exceeds byte cap")
            hasher.update(chunk)
            if retain:
                chunks.append(chunk)
        require(total == before.st_size and identity(before) == identity(os.fstat(fd))
                == identity(path.stat(follow_symlinks=False)), "Receipt changed during bounded read")
        receipt = {"identity": identity(before), "byteCount": total, "sha256": hasher.hexdigest()}
        return (receipt, b"".join(chunks)) if retain else receipt
    finally:
        os.close(fd)


def read_json(path, maximum=MAX_JSON):
    _, data = bytes_receipt(path, maximum=maximum, retain=True)
    value = decode(data)
    require(isinstance(value, dict), "Expected a JSON object")
    return value


def write_json(path, value):
    data = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    require(len(data) <= 64 * MIB, "Diagnostic receipt cap exceeded")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def fresh_root(parent):
    parent = Path(parent).absolute()
    require(parent.resolve() == parent and parent.is_relative_to(ROOT / "local"), "Outputs require canonical ignored local/")
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(parent.resolve() == parent and parent.is_dir(), "Invalid output parent")
    root = parent / ("nf-index-runtime-" + str(uuid.uuid4()) + ".noindex")
    root.mkdir(mode=0o700)
    return root


@contextlib.contextmanager
def recipe(label):
    old_alpha, old_queries = workload.ALPHA, workload.QUERIES
    try:
        workload.QUERIES = (*old_queries, "needleAfterReplacement")
        if label == "replacement":
            workload.ALPHA = old_alpha.replace(b"needleOnlyInPayload", b"needleAfterReplacement")
        yield
    finally:
        workload.ALPHA, workload.QUERIES = old_alpha, old_queries


def prepare_fixture(root):
    fixture = root / ("nf-index-fixture-" + str(uuid.uuid4()) + ".noindex")
    fixture.mkdir(mode=0o700)
    oracles = {}
    for label in LABELS:
        with recipe(label):
            workload.generate(fixture / label, workload.MINIMUM_IMAGE_BYTES)
            oracles[label] = workload.load_fixture(fixture / label)
    write_json(fixture / "fixture.json", {"schemaVersion": 1, "syntheticOnly": True,
                                          "fixtureKind": "nf-content-index-pipeline-v1"})
    require(oracles["stable"]["imageSHA256"] == oracles["original"]["imageSHA256"]
            != oracles["replacement"]["imageSHA256"], "Replacement fixture must have different source bytes")
    return fixture, oracles


class PinnedNamespace:
    """Retain every directory/file FD across all sessions and rehash held bytes."""
    def __init__(self, root):
        self.root, self.fds = root, {}
        try:
            for name, path in self.inventory().items():
                mode = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
                if path.is_dir():
                    mode |= os.O_DIRECTORY
                fd = os.open(path, mode)
                self.fds[name] = fd
            self.baseline = self.capture()
        except BaseException:
            self.close()
            raise

    def inventory(self):
        require(self.root.resolve() == self.root, "Fixture root changed or became linked")
        paths = {".": self.root}
        for path in self.root.rglob("*"):
            require(not path.is_symlink() and path.resolve() == path, "Linked fixture namespace entry")
            paths[path.relative_to(self.root).as_posix()] = path
            require(len(paths) <= 256, "Fixture namespace count cap exceeded")
        return paths

    def capture(self):
        paths = self.inventory()
        require(set(paths) == set(self.fds), "Fixture namespace inventory changed")
        result, total = {}, 0
        for name in sorted(paths):
            path, fd = paths[name], self.fds[name]
            before = os.fstat(fd)
            require(before.st_uid == os.geteuid() and identity(before) == identity(path.stat(follow_symlinks=False)),
                    "Fixture held/named identity changed")
            row = {"identity": identity(before), "mode": before.st_mode}
            if stat.S_ISDIR(before.st_mode):
                require(stat.S_IMODE(before.st_mode) == 0o700, "Fixture directory is not private")
            else:
                require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= 512 * MIB,
                        "Unsupported fixture file")
                total += before.st_size
                require(total <= 1024 * MIB, "Fixture aggregate byte cap exceeded")
                h, count = hashlib.sha256(), 0
                while count < before.st_size:
                    chunk = os.pread(fd, min(65536, before.st_size - count), count)
                    require(chunk, "Fixture short read")
                    count += len(chunk)
                    h.update(chunk)
                require(not os.pread(fd, 1, count), "Fixture grew during read")
                row.update(byteCount=count, sha256=h.hexdigest())
            require(identity(before) == identity(os.fstat(fd)) == identity(path.stat(follow_symlinks=False)),
                    "Fixture changed during pinned verification")
            result[name] = row
        require(set(self.inventory()) == set(paths), "Fixture namespace changed during capture")
        return result

    def verify(self):
        current = self.capture()
        require(current == self.baseline, "Original fixture namespace/bytes/identities changed")
        return current

    def close(self):
        for fd in self.fds.values():
            os.close(fd)
        self.fds.clear()


def distribution(values):
    require(values and all(type(v) in (int, float) and math.isfinite(v) and v >= 0 for v in values),
            "Unavailable/nonfinite distribution population")
    values = sorted(values)
    return {"samples": len(values), "minimum": values[0], "p50": statistics.median(values),
            "p95": values[math.ceil(.95 * len(values)) - 1], "maximum": values[-1]}


def uuid_key(value):
    require(isinstance(value, str), "Missing UUID")
    return str(uuid.UUID(value))


def valid_hash(value):
    return isinstance(value, str) and re.fullmatch("[0-9a-f]{64}", value) is not None


def expected_options():
    return {"timeoutSeconds": 12, "maximumInputBytes": 128 * MIB, "maximumResponseBytes": 2 * MIB,
            "maximumTextBytes": MIB, "maximumThumbnailBytes": MIB // 2, "maximumImagePixels": 100000000,
            "maximumPages": 200, "maximumMetadataItems": 128, "maximumArchiveMembers": 128,
            "maximumMetadataValueBytes": 4096, "allowInferredWindows1252": True, "previewedImageFrame": 1,
            "previewedPDFPage": 1, "includesOCR": False, "evaluatesOfficeFormulasOrMacros": False,
            "fetchesExternalResources": False}


def validate_decoder(value, signed, *, pages=None):
    require(isinstance(value, dict) and value.get("schemaVersion") == 1
            and value.get("decoderIdentifier") == "NativeForensics.document-decoder"
            and value.get("decoderVersion") == "2.1.0" and value.get("isolation") == "appSandboxXPC",
            "Actual sandbox decoder provenance unavailable")
    for field, role, key in (("decoderExecutableSHA256", "worker", "sha256"),
                             ("decoderCodeSigningCDHash", "worker", "codeSigningCDHash"),
                             ("brokerExecutableSHA256", "broker", "sha256"),
                             ("brokerCodeSigningCDHash", "broker", "codeSigningCDHash")):
        require(value.get(field) == signed[role][key], "Signed decoder provenance mismatch: " + field)
    require(value.get("options") == expected_options()
            and value.get("optionsSHA256") == runtime.document_receipt_digest(expected_options()),
            "Default decoder options/digest changed")
    if pages is None:
        require(value.get("ipcProtocolVersion") == 2, "Unexpected IPC contract")
    else:
        require(value.get("derivedTextSHA256") == runtime.document_receipt_digest(pages), "Derived page digest mismatch")


def validate_snapshot(snapshot, labels, sources, oracles, signed):
    require(snapshot.get("schemaVersion") == 1 and snapshot.get("decoderContract") == "NativeForensics.document-decoder@2.1.0"
            and snapshot.get("decoderBinarySHA256") == signed["worker"]["sha256"], "Index contract/binary changed")
    uuid_key(snapshot.get("id")); uuid_key(snapshot.get("caseID"))
    require(type(snapshot.get("builtAt")) in (int, float) and math.isfinite(snapshot["builtAt"]), "Invalid deferred Date")
    require(snapshot.get("limits") == {"maximumFiles": 512, "maximumFileBytes": 32 * MIB,
            "maximumInputBytes": 256 * MIB, "maximumTextBytes": 16 * MIB, "timeoutSeconds": 600}, "Default index caps changed")
    validate_decoder(snapshot.get("decoderIdentity"), signed)
    source_rows = snapshot.get("sources", [])
    require(len(source_rows) == 2 and len({uuid_key(x["evidenceID"]) for x in source_rows}) == 2,
            "Missing/duplicate indexed source")
    expected_ids = {uuid_key(sources[label]["evidenceID"]): label for label in labels}
    require({uuid_key(x["evidenceID"]) for x in source_rows} == set(expected_ids), "Indexed source bindings differ")
    for row in source_rows:
        label = expected_ids[uuid_key(row["evidenceID"])]
        expected = oracles[label]
        require(row.get("selectedContainerSHA256") == expected["imageSHA256"]
                and row.get("selectedContainerByteCount") == expected["imageByteCount"]
                and row.get("orderedContainerSHA256") == [expected["imageSHA256"]]
                and valid_hash(row.get("listingSHA256")) and row.get("listingIsPartial") is False
                and type(row.get("listingEntryCount")) is int and row["listingEntryCount"] >= 10,
                "Selected-file/listing provenance differs")
    documents = snapshot.get("documents", [])
    require(len(documents) == 20 and snapshot.get("omittedRegularFiles") == 0
            and type(snapshot.get("skippedDirectories")) is int and snapshot["skippedDirectories"] >= 0
            and sum(row["listingEntryCount"] for row in source_rows) == 20 + snapshot["skippedDirectories"],
            "Index listing/document coverage differs")
    seen, counts = set(), {key: 0 for key in ("indexed", "skipped", "failed", "pending")}
    for document in documents:
        evidence_id = uuid_key(document.get("evidenceID"))
        require(evidence_id in expected_ids, "Document source scope differs")
        label, file = expected_ids[evidence_id], document.get("file", {})
        path = file.get("path")
        require(path in oracles[label]["files"] and (label, path) not in seen, "Duplicate/unknown document locator")
        seen.add((label, path)); expected = oracles[label]["files"][path]
        require(file.get("size") == expected["byteCount"] and file.get("isDirectory") is False
                and file.get("isDeleted") is False, "Document locator size/type differs")
        address = {key: file[key] for key in ("id", "path", "fsOffsetBytes", "metaAddress")}
        address.update({key: file[key] for key in ("attributeType", "attributeID") if key in file})
        require(document.get("locatorSHA256") == runtime.document_receipt_digest(address), "Locator digest mismatch")
        status = document.get("status")
        require(status == expected["indexStatus"] and document.get("reason") == expected["indexReason"]
                and document.get("textIsComplete") is expected["textIsComplete"], "Document coverage/reason differs")
        counts[status] += 1
        pages = document.get("textPages", [])
        if status == "indexed":
            expected_pages = [{"pageNumber": 1, "text": expected["text"], "isTruncated": not expected["textIsComplete"],
                               "referenceLabel": "Text document", "referenceKind": "document"}]
            require(pages == expected_pages and document.get("contentSHA256") == expected["sha256"]
                    and document.get("derivedTextSHA256") == runtime.document_receipt_digest(expected_pages),
                    "Full logical content/text/source-unit digest differs")
            validate_decoder(document.get("decoderProvenance"), signed, pages=expected_pages)
        else:
            require(pages == [] and document.get("contentSHA256") is None and document.get("derivedTextSHA256") is None
                    and document.get("decoderProvenance") is None and document.get("textIsComplete") is False,
                    "Nonindexed document fabricated content/provenance")
    require(seen == {(label, path) for label in labels for path in oracles[label]["files"]}
            and counts == {"indexed": 8, "skipped": 12, "failed": 0, "pending": 0}, "Full index coverage oracle differs")
    return {"documentCounts": counts, "regularFiles": len(documents), "partialCoverage": True}


def expected_search(labels, oracles):
    queries = set().union(*(oracles[label]["queries"] for label in labels))
    result = {}
    for query in sorted(queries):
        hits = []
        for label in labels:
            for hit in oracles[label]["queries"][query]:
                expected = oracles[label]["files"][hit["path"]]
                text = expected["text"].encode("utf-16le")
                require(text[hit["utf16Offset"] * 2:(hit["utf16Offset"] + hit["utf16Length"]) * 2].decode("utf-16le") == query,
                        "Independent UTF-16 literal range differs")
                hits.append(dict(hit, label=label, contentSHA256=expected["sha256"],
                                 orderedContainerSHA256=[oracles[label]["imageSHA256"]]))
        result[query] = sorted(hits, key=lambda hit: (hit["label"], hit["path"], hit["utf16Offset"]))
    return result


class EventLedger:
    def __init__(self):
        self.events, self.current, self.finished, self.active = [], None, [], None
        self.started = {stage: [] for stage in STAGES}
        self.exited = {stage: [] for stage in STAGES}

    def accept(self, event):
        require(isinstance(event, dict) and event.get("schemaVersion") == 1 and len(self.events) < MAX_EVENTS,
                "Malformed/oversized event inventory")
        stamp = event.get("uptimeNanoseconds")
        require(type(stamp) is int and stamp > 0 and (not self.events or stamp >= self.events[-1]["uptimeNanoseconds"]),
                "Event monotonic timestamps changed order")
        kind, stage = event.get("kind"), event.get("stage")
        if kind == "stageStarted":
            require(self.current is None and self.active is None and len(self.finished) < len(STAGES)
                    and stage == STAGES[len(self.finished)], "Stage order/ownership differs")
            self.current = stage
        elif kind == "stageCompleted":
            require(stage == self.current and self.active is None
                    and self.started[stage] == self.exited[stage], "Stage completed without physical decoder drainage")
            self.finished.append(stage); self.current = None
        elif kind in ("decoderStarted", "decoderExited"):
            pid = event.get("processIdentifier")
            require(stage == self.current and type(pid) is int and pid > 0, "Decoder event source/stage/PID differs")
            if kind == "decoderStarted":
                require(self.active is None, "Overlapping accepted workers")
                self.active = pid; self.started[stage].append(pid)
            else:
                require(self.active == pid, "Decoder exit lacks accepted start")
                self.active = None; self.exited[stage].append(pid)
        elif kind == "complete":
            require(self.finished == list(STAGES) and self.current is None and event.get("receipt") == "receipt.json",
                    "Premature/wrong completion receipt")
        else:
            raise AssertionError("Unknown native event")
        require(not self.events or self.events[-1]["kind"] != "complete", "Events after completion")
        self.events.append(event)

    def validate_complete(self):
        require(self.events and self.events[-1]["kind"] == "complete" and self.finished == list(STAGES), "No native completion event")
        for stage, (_, rebuilt) in COUNTS.items():
            require(len(self.started[stage]) == rebuilt, "Accepted decoder count differs from actual preview calls")
        require(len(self.started["cancel"]) == 1, "Cancellation was not requested after the first accepted worker")


def validate_report(output, report, ledger, fixture, oracles, signed):
    ledger.validate_complete()
    require(report.get("schemaVersion") == 1 and report.get("syntheticOnly") is True
            and report.get("backend") == "actual-bundled-app-sandbox-xpc"
            and report.get("providerExecuted") is False and report.get("guiMeasured") is False, "Wrong diagnostic backend/scope")
    for key in ("publicationRefused", "cancellationRequested", "cancellationReturned", "priorGenerationUnchanged"):
        require(report.get(key) is True, "Missing production safety result: " + key)
    require(report.get("newScratchRemaining") == 0 and type(report.get("cancellationDurationNanoseconds")) is int
            and report["cancellationDurationNanoseconds"] > 0, "Cancellation/drain result differs")
    requested, returned, drained = (report.get(key) for key in ("cancellationRequestedUptimeNanoseconds",
                                                               "cancellationReturnedUptimeNanoseconds", "cancellationDrainNanoseconds"))
    require(all(type(value) is int and value > 0 for value in (requested, returned, drained))
            and returned >= requested and drained == returned - requested
            and drained <= report["cancellationDurationNanoseconds"], "Cancellation request/return/drain receipt differs")
    cancel_events = [event for event in ledger.events if event.get("stage") == "cancel"]
    require(cancel_events[0]["kind"] == "stageStarted" and cancel_events[-1]["kind"] == "stageCompleted"
            and cancel_events[0]["uptimeNanoseconds"] <= requested <= returned <= cancel_events[-1]["uptimeNanoseconds"]
            and next(event["uptimeNanoseconds"] for event in cancel_events if event["kind"] == "decoderStarted") <= requested
            and next(event["uptimeNanoseconds"] for event in cancel_events if event["kind"] == "decoderExited") <= returned,
            "Cancellation timestamps are outside the accepted-worker stage")
    require(isinstance(report.get("measurementScope"), str) and report["measurementScope"]
            and isinstance(report.get("cancellationScope"), str) and report["cancellationScope"], "Missing explicit native measurement scope")
    source_rows = report.get("sources", [])
    require(len(source_rows) == 3 and {row.get("label") for row in source_rows} == set(LABELS), "Source labels differ")
    sources = {row["label"]: row for row in source_rows}
    require(len({uuid_key(row["evidenceID"]) for row in source_rows}) == 3, "Replacement did not receive a new evidence ID")
    for label, row in sources.items():
        require(row.get("path") == str(fixture / label / workload.IMAGE_NAME)
                and row.get("sha256") == oracles[label]["imageSHA256"]
                and row.get("byteCount") == oracles[label]["imageByteCount"], "Recorded selected source receipt differs")
    stages = report.get("stages", [])
    require([row.get("stage") for row in stages] == list(COMPLETED_STAGES), "Completed stage inventory differs")
    snapshots, diagnostics = {}, {}
    for row in stages:
        stage = row["stage"]; reused, rebuilt = COUNTS[stage]
        require(row.get("reusedFiles") == reused and row.get("rebuiltFiles") == rebuilt
                and row.get("previewCount") == rebuilt and type(row.get("durationNanoseconds")) is int
                and row["durationNanoseconds"] > 0 and row.get("serializedFilename") == stage + "-index.json",
                "Production preview/reuse counts or stage timing differ")
        stage_events = [event for event in ledger.events if event.get("stage") == stage]
        require(row["durationNanoseconds"] <= stage_events[-1]["uptimeNanoseconds"] - stage_events[0]["uptimeNanoseconds"],
                "Core API timing exceeds its containing native stage")
        labels = ("stable", "original") if stage in ("rebuild", "unchanged") else ("stable", "replacement")
        require([uuid_key(value) for value in row.get("sourceIDs", [])]
                == [uuid_key(sources[label]["evidenceID"]) for label in labels], "Stage source IDs differ")
        snapshot = read_json(output / row["serializedFilename"])
        require(uuid_key(snapshot["id"]) == uuid_key(row["snapshotID"]), "Stage snapshot UUID differs")
        diagnostics[stage] = validate_snapshot(snapshot, labels, sources, oracles, signed)
        require(report.get("searchHits", {}).get(stage) == expected_search(labels, oracles), "Independent literal query oracle differs")
        snapshots[stage] = snapshot
    require(set(report.get("searchHits", {})) == set(COMPLETED_STAGES)
            and len({uuid_key(s["id"]) for s in snapshots.values()}) == 4
            and len({uuid_key(s["caseID"]) for s in snapshots.values()}) == 1, "Snapshot generations/case scope differ")
    require(snapshots["unchanged"]["documents"] == snapshots["rebuild"]["documents"]
            and snapshots["unchanged"]["sources"] == snapshots["rebuild"]["sources"], "Unchanged update changed reused document receipts")
    stable_id = uuid_key(sources["stable"]["evidenceID"])
    stable_indexed = lambda snapshot: [d for d in snapshot["documents"] if uuid_key(d["evidenceID"]) == stable_id and d["status"] == "indexed"]
    require(stable_indexed(snapshots["changed"]) == stable_indexed(snapshots["unchanged"])
            == stable_indexed(snapshots["recovery"]), "Stable indexed receipts were not reused exactly")
    case = output / "Content Index Probe.nativecase"
    manifest = read_json(case / "manifest.json")
    require(uuid_key(manifest["id"]) == uuid_key(snapshots["unchanged"]["caseID"])
            and [uuid_key(e["id"]) for e in manifest["evidence"]] == [uuid_key(sources[label]["evidenceID"]) for label in ("stable", "original")],
            "Baseline manifest was replaced with changed source scope")
    for e, label in zip(manifest["evidence"], ("stable", "original")):
        require(e["sourcePath"] == sources[label]["path"] and e["sha256"] == sources[label]["sha256"]
                and e["byteCount"] == sources[label]["byteCount"] and e.get("hashScope") == "selected-file-bytes",
                "Normal case source receipt differs")
    replacement_manifest = read_json(output / "Replacement Source Record.nativecase/manifest.json")
    require(uuid_key(replacement_manifest["id"]) != uuid_key(manifest["id"])
            and len(replacement_manifest.get("evidence", [])) == 1, "Replacement normal case scope differs")
    new_b = replacement_manifest["evidence"][0]
    require(uuid_key(new_b["id"]) == uuid_key(sources["replacement"]["evidenceID"])
            and new_b["sourcePath"] == sources["replacement"]["path"]
            and new_b["sha256"] == sources["replacement"]["sha256"]
            and new_b["byteCount"] == sources["replacement"]["byteCount"]
            and new_b.get("hashScope") == "selected-file-bytes", "Replacement B was not normally recorded in its own case")
    persisted = read_json(case / "derived-content-index.json")
    require(persisted == snapshots["unchanged"]
            and bytes_receipt(case / "derived-content-index.json")["sha256"]
            == bytes_receipt(output / "unchanged-index.json")["sha256"],
            "Changed/cancel/recovery API result replaced the prior durable generation")
    return {"semanticOraclePassed": True, "stages": diagnostics, "priorDurableGenerationUUID": persisted["id"],
            "coverage": "Eight indexed and twelve explicitly skipped documents per completed snapshot; large text prefixes are partial."}


class IndexProcesses(runtime.OwnedProcesses):
    def __init__(self, app):
        super().__init__(app)
        self.paths[str(app / ENGINE)] = "engine"
        self.peaks["engine"] = self.valid_rss["engine"] = self.failed_rss["engine"] = 0


def require_no_existing_host(app, receipt):
    require(app.is_absolute() and app.resolve() == app, "Host preflight requires a canonical app")
    host = app / runtime.HOST
    require(host.resolve(strict=True) == host and host.is_file() and not host.is_symlink(),
            "Host preflight requires a canonical regular host executable")
    monitor, rows, failure = IndexProcesses(app), [], None
    try:
        rows = monitor.sample()
    except BaseException as error:
        failure = {"type": type(error).__name__, "message": str(error)}
    memory = monitor.summary()
    host_path = str(host)
    hosts = [row for row in rows if row.get("role") == "host" and row.get("path") == host_path]
    write_json(receipt, {"schemaVersion": 1, "canonicalHostPath": host_path,
                         "existingHosts": hosts, "processes": rows, "memory": memory, "failure": failure,
                         "scope": "Pre-launch exact-path inventory snapshot; no process is signaled. Later contamination remains subject to the strict RSS audit."})
    require(failure is None, "Host preflight process inventory is unavailable; raw receipt retained")
    inventory = memory.get("lastPIDInventory")
    require(isinstance(inventory, dict) and type(inventory.get("returnedBytes")) is int
            and type(inventory.get("requestedBytes")) is int
            and 0 < inventory["returnedBytes"] < inventory["requestedBytes"],
            "Host preflight process inventory is unavailable or potentially truncated")
    require(memory.get("ownedOrKnownPIDQueryFailuresOmitted") == 0
            and memory.get("ownedOrKnownPIDQueryFailures") == [],
            "Host preflight owned-process identity queries failed; raw failures retained")
    require(not hosts, "An exact same-bundle host is already running; stop it before this experiment. No existing process was signaled.")


def signed_engine_identity(app):
    path = app / ENGINE
    before = bytes_receipt(path, maximum=256 * MIB)
    subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(path)], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    display = subprocess.run(["/usr/bin/codesign", "-d", "--verbose=4", str(path)], check=True,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    hashes = re.findall(r"^CDHash=([0-9a-f]{40}|[0-9a-f]{64})$", display.stderr + display.stdout, re.M)
    require(len(hashes) == 1 and bytes_receipt(path, maximum=256 * MIB) == before, "Engine signed identity changed")
    normalized = runtime.signing_normalized_digest(path)
    require(bytes_receipt(path, maximum=256 * MIB) == before, "Engine changed during normalized-signature read")
    return dict(before, path=str(path), codeSigningCDHash=hashes[0], signatureNormalizedPayloadSHA256=normalized)


def wait4_nonblocking(pid, deadline):
    while True:
        try:
            return os.wait4(pid, os.WNOHANG)
        except InterruptedError:
            require(time.monotonic() < deadline, "Interrupted exact-child reaping exceeded deadline")


def signal_owned_group(pid, signum, deadline):
    while True:
        try:
            os.killpg(pid, signum)
            return True
        except ProcessLookupError:
            return False  # Natural exit raced the signal; continue exact reaping.
        except InterruptedError:
            require(time.monotonic() < deadline, "Interrupted owned-group signal exceeded deadline")


def terminal_receipt(process, pid, status, usage):
    require(pid == process.pid, "wait4 returned another PID")
    process.returncode = os.waitstatus_to_exitcode(status)
    return {"pid": pid, "returncode": process.returncode, "terminalExitObserved": True,
            "observedUptimeNanoseconds": time.monotonic_ns(), "userCPUSeconds": usage.ru_utime,
            "systemCPUSeconds": usage.ru_stime, "kernelReportedMaximumRSSBytes": usage.ru_maxrss}


def drain_owned_host(process, observation_errors):
    # This caller alone owns wait4. A returned zero means this child is
    # unreaped and its PID cannot yet be reused; never signal bare workers.
    sent_signals = []
    for sig, seconds in ((signal.SIGTERM, 2), (signal.SIGKILL, 3)):
        try:
            until = time.monotonic() + seconds
            pid, status, usage = wait4_nonblocking(process.pid, until)
            if pid == 0 and signal_owned_group(process.pid, sig, until):
                sent_signals.append(int(sig))
            # ESRCH after the zero wait is a possible natural-exit race. It
            # does not consume the child status; continue exact-PID reaping.
            while pid == 0 and time.monotonic() < until:
                time.sleep(.01)
                pid, status, usage = wait4_nonblocking(process.pid, until)
            if pid:
                result = terminal_receipt(process, pid, status, usage)
                if sent_signals:
                    result["driverTerminationSignalsSent"] = list(sent_signals)
                return result, sent_signals
        except BaseException as error:
            observation_errors.append({"phase": "owned-host-drain", "error": str(error)})
            break  # No uncertain/reused-PID signal fallback.
    return None, sent_signals


def run_session(app, root, number, signed, timeout=900, interval=.02):
    logs = root / (f"session-{number:02d}-driver")
    logs.mkdir(mode=0o700)
    fixture = next(root.glob("nf-index-fixture-*.noindex"))
    output = root / ("nf-index-run-" + str(uuid.uuid4()) + ".noindex")
    command = [str(app / runtime.HOST), "--content-index-probe", "--fixture", str(fixture), "--output", str(output)]
    write_json(logs / "configuration.json", {"schemaVersion": 1, "command": command, "signedExecutables": signed,
                                             "timeoutSeconds": timeout, "requestedSamplingSeconds": interval})
    monitor, ledger, samples, watches, observation_errors = IndexProcesses(app), EventLedger(), [], [], []
    active_watch, process, wait_result, failure = None, None, None, None
    timed_out, sent_signals = False, []
    started = time.monotonic_ns(); deadline = time.monotonic() + timeout
    stdout_count = stderr_count = 0; line = bytearray()

    def sample():
        require(len(samples) < MAX_SAMPLES, "RSS sampling count cap exceeded")
        try:
            rows = monitor.sample()
            samples.append({"uptimeNanoseconds": time.monotonic_ns(), "stage": ledger.current, "processes": rows})
        except Exception as error:
            observation_errors.append({"phase": "rss-sample", "error": str(error)})
            require(len(observation_errors) < 256, "RSS sampling error cap exceeded")

    def poll_watches():
        for watch in watches:
            if watch.poll():
                monitor.known_pids.pop(watch.identity["processIdentifier"], None)

    def event(value):
        nonlocal active_watch
        ledger.accept(value)
        if value["kind"] == "decoderStarted":
            require(len(watches) < MAX_OBSERVERS, "Physical observer count cap exceeded")
            pid = value["processIdentifier"]
            worker = monitor.identity(pid)
            require(worker is not None and worker["role"] == "worker", "Accepted worker birth/path is unavailable")
            broker = monitor.identity(worker["parentProcessIdentifier"])
            require(broker is not None and broker["role"] == "broker", "Accepted worker has no exact signed broker parent")
            watch = runtime.PhysicalExit(monitor, pid)
            require(watch.identity == worker, "Worker birth changed during NOTE_EXIT registration")
            watch.stage = value["stage"]
            watch.accepted_event = dict(value)
            watch.broker_identity = broker
            watches.append(watch); active_watch = watch
            monitor.track(pid, "worker"); monitor.track(broker["processIdentifier"], "broker")
            sample()
            require(not watch.poll(), "Worker exited before driver observation ACK")
            ack = ("ACK " + str(pid) + "\n").encode()
            require(os.write(process.stdin.fileno(), ack) == len(ack), "Worker observation ACK write failed")
        elif value["kind"] == "decoderExited":
            require(active_watch is not None and active_watch.identity["processIdentifier"] == value["processIdentifier"]
                    and active_watch.poll(), "Decoder returned before independent physical exit proof")
            active_watch.exited_event = dict(value)
            monitor.known_pids.pop(value["processIdentifier"], None)
            active_watch = None

    try:
        require_no_existing_host(app, logs / "host-preflight.json")
        with (logs / "probe.stdout").open("xb") as out, (logs / "probe.stderr").open("xb") as err:
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       start_new_session=True, cwd=ROOT, env=dict(os.environ, TZ="UTC", LC_ALL="C"))
            monitor.track(process.pid, "host")
            for stream in (process.stdout, process.stderr):
                os.set_blocking(stream.fileno(), False)
            streams = {process.stdout.fileno(): ("stdout", out), process.stderr.fileno(): ("stderr", err)}
            next_sample = time.monotonic()
            while streams or wait_result is None:
                if time.monotonic() >= deadline:
                    timed_out = True
                    raise AssertionError("Owned signed host exceeded watchdog")
                if time.monotonic() >= next_sample and wait_result is None:
                    sample(); next_sample = time.monotonic() + interval
                poll_watches()
                if wait_result is None:
                    pid, status, usage = wait4_nonblocking(process.pid, deadline)
                    if pid:
                        wait_result = terminal_receipt(process, pid, status, usage)
                        monitor.known_pids.pop(pid, None)
                ready = select.select(list(streams), [], [], min(interval, max(0, deadline - time.monotonic())))[0]
                for fd in ready:
                    try:
                        chunk = os.read(fd, 65536)
                    except (BlockingIOError, InterruptedError):
                        continue
                    if not chunk:
                        del streams[fd]; continue
                    channel, destination = streams[fd]
                    destination.write(chunk); destination.flush()
                    if channel == "stderr":
                        stderr_count += len(chunk)
                        require(stderr_count <= MAX_STDERR, "Bounded stderr exceeded cap")
                        continue
                    stdout_count += len(chunk)
                    require(stdout_count <= MAX_EVENT_BYTES, "Bounded NDJSON exceeded cap")
                    line.extend(chunk)
                    while b"\n" in line:
                        raw, _, remainder = line.partition(b"\n")
                        line[:] = remainder
                        require(0 < len(raw) <= 4096, "NDJSON line exceeded cap")
                        event(decode(raw))
                    require(len(line) <= 4096, "Unterminated NDJSON line exceeded cap")
            require(not line, "Native stdout ended without newline")
            require(wait_result["returncode"] == 0, "Native diagnostic failed; raw terminal telemetry retained")
            ledger.validate_complete(); poll_watches()
            require(all(w.poll() for w in watches), "Accepted worker physical exit is unconfirmed")
    except BaseException as error:
        failure = {"type": type(error).__name__, "message": str(error)}
    finally:
        if process is not None and wait_result is None:
            wait_result, sent_signals = drain_owned_host(process, observation_errors)
        if process is not None:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
        physical = []
        for watch in watches:
            try:
                physical.append(dict(watch.report(), stage=watch.stage, acceptedEvent=watch.accepted_event,
                                     exitedEvent=getattr(watch, "exited_event", None), brokerIdentity=watch.broker_identity))
            except Exception as error:
                observation_errors.append({"phase": "physical-exit-readback", "error": str(error)})
            finally:
                watch.close()
        memory = monitor.summary()
        memory["samplingPeriodMilliseconds"] = interval * 1000
        memory["samplesRaw"] = samples
        memory["driverObservationErrors"] = observation_errors
        attempt = {"schemaVersion": 1, "syntheticOnly": True, "output": str(output), "startedUptimeNanoseconds": started,
                   "wallDurationNanoseconds": time.monotonic_ns() - started, "wait4": wait_result,
                   "terminalExitObserved": wait_result is not None, "timedOut": timed_out, "failure": failure, "events": ledger.events,
                   "signedExecutables": signed, "physicalObservers": physical, "memory": memory}
        if sent_signals:
            attempt["driverTerminationSignalsSent"] = sent_signals
        write_json(logs / "process-attempt.json", attempt)
    require(failure is None and wait_result is not None and wait_result["returncode"] == 0,
            "Content-index runtime attempt failed; inspect retained raw receipts: " + str(logs))
    return output, logs, attempt, ledger


def audit_memory(attempt):
    memory, physical = attempt["memory"], attempt["physicalObservers"]
    require(memory["driverObservationErrors"] == [] and memory["ownedOrKnownPIDQueryFailuresOmitted"] == 0,
            "Runtime observations failed or exceeded retained query cap")
    require(physical and all(row["physicalExitObserved"] and row["exitedEvent"] is not None for row in physical),
            "Accepted worker physical exit coverage is incomplete")
    births = [(row["processIdentifier"], row["startSeconds"], row["startMicroseconds"]) for row in physical]
    require(len(births) == len(set(births)), "Accepted worker birth was reused")
    for row in physical:
        require(row["role"] == "worker" and row["parentProcessIdentifier"] == row["brokerIdentity"]["processIdentifier"]
                and row["path"] == attempt["signedExecutables"]["worker"]["path"]
                and row["brokerIdentity"]["path"] == attempt["signedExecutables"]["broker"]["path"]
                and row["stage"] == row["acceptedEvent"]["stage"] == row["exitedEvent"]["stage"]
                and row["acceptedEvent"]["processIdentifier"] == row["exitedEvent"]["processIdentifier"]
                == row["processIdentifier"] and type(row["physicalExitUptimeNanoseconds"]) is int
                and row["physicalExitUptimeNanoseconds"] >= row["acceptedEvent"]["uptimeNanoseconds"],
                "Physical event identity/clock differs")
    required = ("host", "broker", "worker", "engine")
    valid, failed, peaks = ({role: 0 for role in required} for _ in range(3))
    complete, incomplete, family_peak, partial_peak = 0, 0, 0, 0
    observed, last_time = {}, None
    host_pid = attempt["wait4"]["pid"]
    accepted_births = set(births)
    worker_exits = {birth: row["physicalExitUptimeNanoseconds"] for birth, row in zip(births, physical)}
    broker_births = {(row["brokerIdentity"]["processIdentifier"], row["brokerIdentity"]["startSeconds"],
                      row["brokerIdentity"]["startMicroseconds"]) for row in physical}
    host_births = set()
    raw = memory["samplesRaw"]
    require(raw and len(raw) <= MAX_SAMPLES and memory["samples"] == len(raw), "Raw RSS sampling population differs")
    for sample in raw:
        stamp = sample.get("uptimeNanoseconds")
        require(type(stamp) is int and stamp > 0 and (last_time is None or stamp > last_time), "RSS monotonic sampling clock differs")
        rows = sample.get("processes")
        require(isinstance(rows, list) and len(rows) <= 64, "RSS sampling row cap exceeded")
        sample_pids, family, whole = set(), 0, True
        for row in rows:
            role, pid = row.get("role"), row.get("processIdentifier")
            require(role in required and type(pid) is int and pid > 0 and pid not in sample_pids
                    and row.get("path") == attempt["signedExecutables"][role]["path"], "RSS role/exact signed path inventory differs")
            require(all(type(row.get(key)) is int and row[key] >= 0 for key in ("startSeconds", "startMicroseconds", "parentProcessIdentifier")),
                    "RSS process birth metadata is unavailable")
            sample_pids.add(pid)
            birth = (pid, row["startSeconds"], row["startMicroseconds"])
            if role == "host":
                require(pid == host_pid, "Unrelated same-bundle host contaminated session RSS")
                host_births.add(birth)
                require(len(host_births) == 1, "Owned host birth changed during sampling")
            elif role == "worker":
                require(birth in accepted_births, "RSS worker lacks this session's accepted birth")
                require(stamp <= worker_exits[birth], "RSS worker was sampled after its observed physical exit")
            elif role == "broker":
                require(birth in broker_births, "RSS broker lacks this session's accepted worker lineage")
            elif role == "engine":
                require(row["parentProcessIdentifier"] == host_pid, "RSS engine is not a direct owned host child")
            observed.setdefault(birth, {key: value for key, value in row.items() if key != "residentBytes"})
            resident = row.get("residentBytes")
            if resident is None:
                failed[role] += 1; whole = False
            else:
                require(type(resident) is int and resident >= 0, "Invalid raw RSS byte count")
                valid[role] += 1; peaks[role] = max(peaks[role], resident); family += resident
        if rows and whole:
            complete += 1; family_peak = max(family_peak, family)
        elif rows:
            incomplete += 1; partial_peak = max(partial_peak, family)
        last_time = stamp
    require(memory["validResidentSamplesByRole"] == valid and memory["failedResidentSamplesByRole"] == failed
            and memory["peakResidentBytesByRole"] == {role: peaks[role] if valid[role] else None for role in required}
            and memory["completeFamilySamplingPasses"] == complete and memory["incompleteFamilySamplingPasses"] == incomplete
            and memory["peakSimultaneousFamilyResidentBytes"] == (family_peak if complete else None)
            and memory["peakKnownResidentBytesInIncompleteFamilyPass"] == (partial_peak if incomplete else None),
            "RSS summary differs from complete retained raw sampling population")
    saved_observed = {(row["processIdentifier"], row["startSeconds"], row["startMicroseconds"]): row
                      for row in memory["observedProcesses"]}
    require(len(saved_observed) == len(memory["observedProcesses"]) and saved_observed == observed,
            "Observed birth inventory differs from retained RSS rows")
    rss_available = all(valid[role] > 0 and peaks[role] > 0 for role in required)
    clean = not memory["ownedOrKnownPIDQueryFailures"] and not any(memory["failedResidentSamplesByRole"].values())
    return {"physicalWorkerExitOraclePassed": True, "acceptedWorkers": len(physical),
            "rssEvidenceComplete": rss_available and clean,
            "rssUnavailability": None if rss_available and clean else "At least one role was unobserved or a query/read failed; no zero/complete memory claim.",
            "memoryScope": "Exact owned app paths and births; sequential RSS sum per sampling pass, not an atomic OS peak or hard cap."}


def execute(app, parent, repetitions=5, timeout=900, interval=.02):
    require(sys.platform == "darwin", "Runtime gate requires macOS libproc/kqueue")
    require(type(repetitions) is int and repetitions >= 5 and repetitions <= 20
            and math.isfinite(timeout) and 0 < timeout <= 900 and math.isfinite(interval) and .01 <= interval <= .1,
            "Invalid bounded runtime configuration")
    app = Path(app).absolute()
    require(app.resolve() == app and app.is_dir() and app.suffix == ".app", "App must be canonical and already built/signed")
    require("mach_absolute_time" in time.get_clock_info("monotonic").implementation, "Uptime clocks are not comparable")
    signed = runtime.signed_identity(app)
    engine = signed_engine_identity(app)
    signed["engine"] = engine
    root = fresh_root(parent)
    print("runtime output: " + str(root), flush=True)
    require_no_existing_host(app, root / "initial-host-preflight.json")
    fixture, oracles = prepare_fixture(root)
    write_json(root / "signed-inputs.json", signed)
    pinned, runs = PinnedNamespace(fixture), []
    try:
        write_json(root / "fixture-before.json", pinned.baseline)
        for number in range(1, repetitions + 1):
            before = pinned.verify()
            output, logs, attempt, ledger = run_session(app, root, number, signed, timeout, interval)
            try:
                after = pinned.verify()
                report = read_json(output / "receipt.json")
                semantics = validate_report(output, report, ledger, fixture, oracles, signed)
                observations = audit_memory(attempt)
                current_signed = runtime.signed_identity(app)
                require({role: signed[role] for role in current_signed} == current_signed
                        and signed_engine_identity(app) == engine, "Signed bundle changed during session")
                accepted = {"session": number, "processAttempt": str((logs / "process-attempt.json").relative_to(root)),
                            "nativeReceipt": str((output / "receipt.json").relative_to(root)), "semanticValidation": semantics,
                            "observations": observations, "fixtureBefore": before, "fixtureAfter": after,
                            "stages": report["stages"], "cancellationDurationNanoseconds": report["cancellationDurationNanoseconds"],
                            "cancellationDrainNanoseconds": report["cancellationDrainNanoseconds"],
                            "cancellationRequestedUptimeNanoseconds": report["cancellationRequestedUptimeNanoseconds"],
                            "cancellationReturnedUptimeNanoseconds": report["cancellationReturnedUptimeNanoseconds"],
                            "nativeMeasurementScope": report["measurementScope"], "nativeCancellationScope": report["cancellationScope"],
                            "wait4": attempt["wait4"], "memory": {k: v for k, v in attempt["memory"].items() if k != "samplesRaw"}}
                write_json(logs / "accepted-receipt.json", accepted); runs.append(accepted)
                print(f"content-index {number}/{repetitions}: semantic/physical-exit oracles passed", flush=True)
            except BaseException as error:
                write_json(logs / "validation-failure.json", {"type": type(error).__name__, "message": str(error)})
                raise
        summary = {"schemaVersion": 1, "syntheticOnly": True, "providerExecuted": False, "guiMeasured": False,
                   "gateStatus": "semantic and physical worker-exit acceptance passed", "repetitions": repetitions,
                   "runs": runs, "signedInputs": signed, "fixtureNamespaceUnchanged": pinned.verify() == pinned.baseline,
                   "method": "Fixed-order paired warm sessions; per-worker ACK and observer overhead included. No speedup/cold/GUI inference.",
                   "percentileMethod": "p50 median; p95 nearest rank; with n5 p95 is maximum", "stageNanoseconds": {},
                   "cancellationWholeAttemptNanoseconds": distribution([row["cancellationDurationNanoseconds"] for row in runs]),
                   "cancellationRequestToReturnNanoseconds": distribution([row["cancellationDrainNanoseconds"] for row in runs]),
                   "kernelMaximumRSSBytes": distribution([row["wait4"]["kernelReportedMaximumRSSBytes"] for row in runs]),
                   "kernelMaximumRSSScope": "Exact host wait4 usage and its accounted children; not simultaneous summed family RSS or paging-only RSS.",
                   "rssEvidenceComplete": all(row["observations"]["rssEvidenceComplete"] for row in runs)}
        for stage in COMPLETED_STAGES:
            summary["stageNanoseconds"][stage] = distribution([next(s["durationNanoseconds"] for s in row["stages"] if s["stage"] == stage) for row in runs])
        if summary["rssEvidenceComplete"]:
            summary["roleRSSBytes"] = {role: distribution([row["memory"]["peakResidentBytesByRole"][role] for row in runs])
                                       for role in ("host", "broker", "worker", "engine")}
            summary["samplingPassFamilyRSSBytes"] = distribution([row["memory"]["peakSimultaneousFamilyResidentBytes"] for row in runs])
        write_json(root / "summary.json", summary)
        return root
    finally:
        pinned.close()  # Retain every candidate and raw failure artifact.


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path, required=True)
    parser.add_argument("--output-parent", type=Path, default=ROOT / "local")
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--timeout", type=float, default=900)
    parser.add_argument("--sample-interval", type=float, default=.02)
    args = parser.parse_args()
    root = execute(args.app, args.output_parent, args.repetitions, args.timeout, args.sample_interval)
    print(root / "summary.json")


if __name__ == "__main__":
    main()

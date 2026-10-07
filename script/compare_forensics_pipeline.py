#!/usr/bin/env python3
"""Paired synthetic create/import comparison; no GUI or ingest parity claim.

Compile ForensicsPipelineBenchmark in release and AutopsyCaseVerifier first.
Prepare the isolated reference with benchmark_autopsy_pipeline.py. One excluded
warmup pair precedes five seeded, interleaved pairs per image. Source/runtime
hashes and byte-exact extraction validation are outside process-wall timing.
Only ignored local/autopsy-comparison receives cases, sources, logs and exports.
"""
from __future__ import annotations

import argparse
import copy
import datetime
import json
import os
from pathlib import Path
import platform
import random
import statistics
import struct
import subprocess
import sys
import time
import uuid

from benchmark_autopsy_pipeline import (LOCAL, REPO, OwnedGroupSampler, digest,
                                       loaded_jni_receipt, owned_path, retain_error,
                                       run_pipeline, stop_owned_group, verify_setup, write_json)
from benchmark_process_timing import ProcessExitObserver

sys.path.insert(0, str(REPO / "Tests/NativeEngine"))
from benchmark_fixtures import large_fat_image, validate_export
from fixtures import digest as fixture_digest
from benchmark_native_engine import environment_receipt, parse_response


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def source_state(path: Path):
    before = path.stat(follow_symlinks=False)
    require(path.is_file() and not path.is_symlink(), "Expected regular immutable synthetic source")
    value = fixture_digest(path)
    after = path.stat(follow_symlinks=False)
    identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    require(identity(before) == identity(after), "Source changed while hashing")
    return {"sha256": value, "identity": list(identity(after))}


TIMESTAMP_FIELDS = ("created", "modified", "changed", "accessed")


def fat_timestamp_oracle(image: Path, expected: dict) -> dict:
    """Decode the synthetic corpus's short directory entries without either TSK."""
    offset = expected["fsOffsetBytes"]
    with image.open("rb") as source:
        def read(position, count):
            source.seek(offset + position)
            data = source.read(count)
            require(len(data) == count, "Short independent FAT oracle read")
            return data
        boot = read(0, 512)
        sector = struct.unpack_from("<H", boot, 11)[0]
        cluster_bytes = sector * boot[13]
        reserved = struct.unpack_from("<H", boot, 14)[0]
        root_entries = struct.unpack_from("<H", boot, 17)[0]
        bits = 16 if expected["filesystem"] == "FAT16" else 32
        fat_sectors = struct.unpack_from("<H" if bits == 16 else "<I", boot, 22 if bits == 16 else 36)[0]
        require(sector in (512, 1024, 2048, 4096) and 0 < cluster_bytes <= 65536,
                "Unsupported independent FAT oracle geometry")
        root_bytes = root_entries * 32
        root_sectors = (root_bytes + sector - 1) // sector
        root_offset = (reserved + boot[16] * fat_sectors) * sector
        heap = root_offset + root_sectors * sector
        def directory(cluster):
            parts, seen = [], set()
            while cluster >= 2 and cluster < (0xFFF8 if bits == 16 else 0x0FFFFFF8):
                require(cluster not in seen and len(seen) < 64, "Independent FAT oracle directory chain invalid")
                seen.add(cluster)
                parts.append(read(heap + (cluster - 2) * cluster_bytes, cluster_bytes))
                next_cluster = read(reserved * sector + cluster * (bits // 8), bits // 8)
                cluster = int.from_bytes(next_cluster, "little") & (0xFFFF if bits == 16 else 0x0FFFFFFF)
            return b"".join(parts)
        root = read(root_offset, root_bytes) if bits == 16 else directory(struct.unpack_from("<I", boot, 44)[0])
        def entry_in(data, name):
            matches = []
            for position in range(0, len(data), 32):
                row = data[position:position + 32]
                if row[0] == 0:
                    break
                if row[11] == 0x0F or row[11] & 0x08:
                    continue
                raw_name = bytes([ord("_")]) + row[1:11] if row[0] == 0xE5 else row[:11]
                stem, extension = raw_name[:8].decode("ascii").rstrip(), raw_name[8:].decode("ascii").rstrip()
                actual = stem + ("." + extension if extension else "")
                if actual == name:
                    matches.append(row)
            require(len(matches) == 1, "Independent FAT oracle could not locate exactly one path: " + name)
            return matches[0]
        def instant(date, clock=0, increment=0):
            if date == 0:
                return None
            civil = datetime.datetime(1980 + (date >> 9), (date >> 5) & 15, date & 31,
                clock >> 11, (clock >> 5) & 63, (clock & 31) * 2, tzinfo=datetime.timezone.utc)
            return int(civil.timestamp()) + increment // 100
        oracles = {}
        for file in expected["files"]:
            data = root
            components = file["path"].split("/")
            for component in components[:-1]:
                row = entry_in(data, component)
                require(row[11] & 0x10, "Independent FAT oracle parent is not a directory")
                cluster = struct.unpack_from("<H", row, 26)[0] | (struct.unpack_from("<H", row, 20)[0] << 16)
                data = directory(cluster)
            row = entry_in(data, components[-1])
            oracle = {}
            for field, date_at, time_at, increment in (
                    ("created", 16, 14, row[13]), ("modified", 24, 22, 0), ("accessed", 18, None, 0)):
                epoch = instant(struct.unpack_from("<H", row, date_at)[0],
                    struct.unpack_from("<H", row, time_at)[0] if time_at is not None else 0, increment)
                if epoch is not None:
                    oracle[field + "Epoch"] = epoch
                    oracle[field + "Nanoseconds"] = (increment % 100) * 10_000_000
            oracles[file["path"]] = oracle
        return oracles


def timestamp_gate(rows: list[dict], expected: dict, image: Path, *, native: bool) -> dict:
    if expected["filesystem"] in ("FAT16", "FAT32"):
        oracles = fat_timestamp_oracle(image, expected)
        method = "Independent on-disk DOS date/time decode in UTC"
    else:
        oracles = {file["path"]: file.get("timestampsByTimezone", {}).get("UTC") for file in expected["files"]}
        require(all(value is not None for value in oracles.values()), "Independent per-file UTC timestamp oracle is missing")
        method = "Synthetic per-file generator UTC timestamp oracle"
    actual = {row["path"].lstrip("/"): row for row in rows if row.get("passed", True)}
    differences = []
    for path, oracle in oracles.items():
        row = actual.get(path)
        if row is None:
            differences.append({"path": path, "field": "timestampPayloadPresence", "expected": True, "actual": False})
            continue
        for field in TIMESTAMP_FIELDS:
            key = field + "Epoch"
            wanted, found = oracle.get(key), row.get(key)
            if wanted is None and found == 0:
                found = None  # Java's absent sentinel, only where the oracle says absent.
            if wanted != found:
                differences.append({"path": path, "field": key, "expected": wanted, "actual": found})
            if native and wanted is not None:
                key = field + "Nanoseconds"
                if oracle.get(key, 0) != row.get(key, 0):
                    differences.append({"path": path, "field": key, "expected": oracle.get(key, 0), "actual": row.get(key, 0)})
    return {"passed": not differences, "oracle": method, "timezone": "UTC",
        "precision": "Epoch seconds plus declared fractions" if native else "Whole epoch seconds; Java datamodel omits fractions",
        "fullFractionalMetadataParityClaimed": False, "differences": differences}


def require_regular_directory_ads(row: dict, *, native: bool):
    if row.get("path", "").lstrip("/") != "หลักฐาน:directory-note":
        return
    require(row.get("isDirectory") is False and (row.get("attributeType") == 128 if native else row.get("isFile") is True),
            "Directory ADS is not classified as a regular DATA file stream")


def native_pipeline(binary: Path, helper: Path, image: Path, output: Path):
    run = output / ("native-" + uuid.uuid4().hex[:12])
    run.mkdir()
    report_path = run / "core.json"
    command = [str(binary), "--image", str(image), "--helper", str(helper),
               "--case-base", str(run / "cases"), "--report", str(report_path)]
    process = sampler = None
    record = {"application": "NativeForensics", "runDirectory": str(run),
              "command": command, "pipelineCompleted": False, "errors": []}
    start = None
    fatal_error = None
    try:
        with (run / "stdout.log").open("xb") as log:
            start = time.monotonic()
            process = subprocess.Popen(command, cwd=REPO, stdin=subprocess.DEVNULL,
                stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
                env=dict(os.environ, TZ="UTC"))
            observer = ProcessExitObserver(process, 120)
            sampler = OwnedGroupSampler(process.pid)
            sampler.start()
            try:
                exited = observer.wait()
                code = exited.returncode
                record["wallSeconds"] = exited.exit_monotonic - start
                record["processWaitMethod"] = exited.method
            except subprocess.TimeoutExpired as error:
                record.update(timedOut=True, wallSeconds=error.observed_monotonic - start,
                    processWaitMethod="Blocking waiter with bounded watchdog; timeout observation")
                retain_error(record, "watchdog", error)
                stop_owned_group(process)
                code = process.returncode
            record["exitCode"] = code
            sampler.stop()
        require(code == 0, "Native core pipeline failed; inspect owned stdout.log")
        core = json.loads(report_path.read_text())
        require(core["status"] == "completed", "Native result was incomplete")
        record.update(core=core, pipelineCompleted=not record.get("timedOut", False))
    except BaseException as error:
        retain_error(record, "pipeline", error)
        if start is not None:
            record.setdefault("wallSeconds", time.monotonic() - start)
        if process is not None:
            record.setdefault("exitCode", process.returncode)
        if not isinstance(error, Exception):
            fatal_error = error
    finally:
        try:
            if process is not None:
                stop_owned_group(process)
            if sampler is not None:
                sampler.stop()
                require(not sampler.cleanup_remaining(), "Native leaked an owned child")
        except BaseException as error:
            retain_error(record, "processCleanup", error)
        finally:
            if sampler is not None:
                try:
                    record["resources"] = sampler.receipt()
                except BaseException as error:
                    retain_error(record, "resourceReceipt", error)
            if record["errors"]:
                record["pipelineCompleted"] = False
            write_json(run / "receipt.json", record)
    if fatal_error is not None:
        raise fatal_error
    return record


def native_readback(record: dict, helper: Path, expected: dict, image: Path):
    validation = {"passed": False, "declaredPayloads": len(expected.get("files", [])),
                  "verifiedPayloads": 0, "files": [], "verificationOutsideTiming": True}
    record["validation"] = validation
    cache = json.loads(Path(record["core"]["cachePath"]).read_text())
    require(cache["status"] == "completed" and not cache["warnings"], "Native cache was partial or warned")
    require(cache["image"]["logicalSha256"] == expected["logicalSha256"], "Native logical source hash differs")
    require(cache["image"]["logicalSize"] == expected["logicalSize"], "Native logical source size differs")
    actual = [r for r in cache["files"] if not r["isDirectory"] and not r["name"].startswith("$")]
    rows = {r["path"].lstrip("/"): r for r in actual}
    require(len(rows) == len(actual), "Native duplicate payload path")
    require(set(rows) == {r["path"] for r in expected["files"]}, "Native payload inventory differs")
    exports = Path(record["runDirectory"]) / "exports"
    exports.mkdir()
    verified = validation["files"]
    for index, file in enumerate(expected["files"]):
        row = rows[file["path"]]
        for field in ("size", "isDeleted", "metaAddress", "attributeType", "attributeID"):
            if field in file:
                require(row.get(field) == file[field], "Native metadata differs: " + file["path"] + " " + field)
        require(row["fsOffsetBytes"] == expected["fsOffsetBytes"], "Native filesystem offset differs")
        require_regular_directory_ads(row, native=True)
        export = exports / f"stream-{index:03d}.bin"
        locator = {k: row[k] for k in ("fsOffsetBytes", "metaAddress", "size", "attributeType", "attributeID") if k in row}
        request = {"protocolVersion": 1, "jobID": uuid.uuid4().hex, "operation": "extract",
            "imagePaths": [str(image)], "imageType": "raw", "sectorSize": 0,
            "timezone": "UTC", "maxFiles": 50000, "hashLogicalImage": False,
            "file": locator, "outputPath": str(export)}
        result = subprocess.run([str(helper)], input=(json.dumps(request) + "\n").encode(),
            capture_output=True, timeout=120, env=dict(os.environ, TZ="UTC"))
        frames = parse_response(request, {"stdout": result.stdout, "returncode": result.returncode})
        receipts = [frame for frame in frames if frame["type"] == "extracted"]
        require(len(receipts) == 1 and receipts[0]["sha256"] == file["sha256"], "Native extraction receipt differs")
        check = validate_export(export, file)
        verified.append({"path": file["path"], "size": file["size"], "sha256": check["sha256"],
                         "exactBytesMatched": True, "isDeleted": row["isDeleted"],
                         "isDirectory": row["isDirectory"],
                         **{k: row[k] for field in TIMESTAMP_FIELDS for k in (field + "Epoch", field + "Nanoseconds") if k in row}})
        validation["verifiedPayloads"] = len(verified)
    timestamps = timestamp_gate(verified, expected, image, native=True)
    validation.update(passed=timestamps["passed"], payloadsPassed=True, timestampOracle=timestamps,
                      filesystemRows=len(cache["files"]))
    return validation


def autopsy_readback(record: dict, setup: dict, expected: dict, image: Path, classes: Path, variant: str):
    run = Path(record["runDirectory"])
    spec_path = run / "spec.json"
    spec = {"synthetic": True, "sourcePaths": [str(image)], "timezone": "UTC",
            "fsOffsetBytes": expected["fsOffsetBytes"], "files": [
                {k: v for k, v in f.items() if k in ("path", "size", "sha256", "isDeleted", "metaAddress", "attributeType", "attributeID")}
                for f in expected["files"]]}
    write_json(spec_path, spec)
    selected = setup["variants"][variant]
    ext = Path(selected["runtime"]) / "autopsy/modules/ext"
    command = [str(Path(selected["jdk"]) / "bin/java"), "-Dtsk.tmpdir=" + str(run / "jni"),
        "-cp", str(classes) + ":" + str(ext / "sqlite-jdbc-3.49.1.0.jar") + ":" + str(ext / "*"),
        "AutopsyCaseVerifier", str(LOCAL), record["caseDatabases"][0], str(spec_path), str(run / "exports")]
    result = subprocess.run(command, cwd=REPO, capture_output=True, timeout=120)
    (run / "verifier.stdout").write_bytes(result.stdout)
    (run / "verifier.stderr").write_bytes(result.stderr)
    require(len(result.stdout) <= 512 * 1024, "Unbounded Java verifier output")
    verified = json.loads(result.stdout)
    record["validation"] = verified
    native_path = str(Path(selected["nativeDirectory"]) / "libtsk.23.dylib")
    traces = [line for line in result.stderr.decode(errors="replace").splitlines() if "dyld[" in line and "/libtsk.23.dylib" in line]
    require(traces and all(native_path in line for line in traces), "Java readback did not load exact selected native library")
    verified["jniResourceLoaded"] = loaded_jni_receipt(result.stderr.decode(errors="replace"), selected, [run / "jni"])
    # Preserve capability gaps, then independently read every export that passed.
    by_path = {r["path"].lstrip("/"): r for r in expected["files"]}
    for row in verified.get("files", []):
        if row.get("passed"):
            key = row["path"].lstrip("/")
            check = validate_export(run / "exports" / row["exportFile"], by_path[key])
            row["exactBytesMatched"] = check["exactBytesMatched"]
        if row.get("passed"):
            require_regular_directory_ads(row, native=False)
    require((result.returncode == 0) == bool(verified.get("passed")), "Java verifier exit/result mismatch")
    verified["verificationOutsideTiming"] = True
    verified["exactSelectedNativeLibraryLoaded"] = True
    verified["payloadsPassed"] = bool(verified.get("passed"))
    verified["timestampOracle"] = timestamp_gate(verified.get("files", []), expected, image, native=False)
    verified["passed"] = verified["payloadsPassed"] and verified["timestampOracle"]["passed"]
    return verified


def summarize(pairs: list[dict]):
    require(len(pairs) >= 5, "At least five measured pairs are required")
    require(all(p["native"]["validation"]["passed"] and p["autopsy"]["validation"]["passed"] for p in pairs),
            "Performance ratio requires all expected payloads in both applications")
    require(all(p[name]["validation"].get("timestampOracle", {}).get("passed")
                for p in pairs for name in ("native", "autopsy")),
            "Performance ratio requires independent timestamp oracle gates")
    summary = {}
    for name in ("native", "autopsy"):
        walls = [pair[name]["wallSeconds"] for pair in pairs]
        rss = [pair[name]["resources"]["sampledAggregatePeakRSSBytes"] / 1024**2 for pair in pairs]
        cpu = [pair[name]["resources"]["sampledUserCPULowerBoundSeconds"] +
               pair[name]["resources"]["sampledSystemCPULowerBoundSeconds"] for pair in pairs]
        summary[name] = {"wallMedianSeconds": statistics.median(walls), "wallMinSeconds": min(walls),
            "wallMaxSeconds": max(walls), "sampledAggregatePeakRSSMedianMiB": statistics.median(rss),
            "sampledCPULowerBoundMedianSeconds": statistics.median(cpu),
            "resourceSamplesPartial": True,
            "resourceCoverage": "Unproven even without sampler errors; no CPU or RSS reduction ratio is claimed",
            "resourceReceipts": [{key: p[name]["resources"].get(key) for key in
                ("sampleCount", "requestedIntervalSeconds", "actualIntervalMedianSeconds", "failedSampleCount",
                 "noSamplerErrors", "observedProcessCoverage")} for p in pairs]}
    ratios = [p["autopsy"]["wallSeconds"] / p["native"]["wallSeconds"] for p in pairs]
    summary["pairedWallRatioMedian"] = statistics.median(ratios)
    summary["pairedWallReductionPercentMedian"] = statistics.median([
        (1 - p["native"]["wallSeconds"] / p["autopsy"]["wallSeconds"]) * 100 for p in pairs])
    summary["payloadsPerApplicationPerRun"] = pairs[0]["native"]["validation"]["verifiedPayloads"]
    summary["measuredPairs"] = len(pairs)
    return summary


def checkpoint(path: Path, data: dict):
    """Atomic updates only inside a newly owned experiment directory."""
    path = owned_path(path)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        write_json(temporary, data)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def invalidate_performance(report: dict, reason: str):
    report["performanceRatioAllowed"] = False
    report["performanceInvalidationReason"] = reason
    for workload in report.get("workloads", []):
        workload["performanceRatioAllowed"] = False
        if "summary" in workload:
            workload["invalidatedDiagnosticSummary"] = workload.pop("summary")
            workload["invalidatedDiagnosticSummary"]["validForPerformanceClaim"] = False
        for pair in workload.get("pairs", []):
            pair["performanceRatioAllowed"] = False


def journal_attempt(pair: dict, application: str, launch, validate, journal: Path) -> dict:
    record = {"application": application, "status": "running", "phase": "launch", "errors": []}
    pair[application] = record
    checkpoint(journal, pair)
    try:
        record = launch()
        pair[application] = record
        record.update(status="running", phase="readback")
        checkpoint(journal, pair)  # Timings/resources survive every later gate failure.
        if not record.get("pipelineCompleted", record.get("structuralGatePassed", False)):
            record["validation"] = {"passed": False, "error": record.get("error", "Pipeline did not complete")}
        else:
            record["validation"] = validate(record)
        record["status"] = "completed" if record["validation"].get("passed") else "failed"
    except BaseException as error:
        retain_error(record, "attempt", error)
        record["status"] = "failed"
        validation = record.setdefault("validation", {})
        validation.update(passed=False, error=record["error"])
        if not isinstance(error, Exception):
            raise
    finally:
        record["phase"] = "finished"
        pair[application] = record
        checkpoint(journal, pair)
    return record


def metadata_comparison(pair: dict):
    native = {row["path"].lstrip("/"): row for row in pair["native"]["validation"].get("files", [])}
    differences = []
    for row in pair["autopsy"]["validation"].get("files", []):
        path = row["path"].lstrip("/")
        if not row.get("passed") or path not in native:
            differences.append({"path": path, "field": "payloadPresence", "autopsy": bool(row.get("passed")), "native": path in native})
            continue
        for field in ("createdEpoch", "modifiedEpoch", "changedEpoch", "accessedEpoch"):
            a, n = row.get(field), native[path].get(field)
            # TSK Java reports zero for an absent timestamp; native omits it.
            if (a or None) != (n or None):
                differences.append({"path": path, "field": field, "autopsy": a, "native": n,
                                    "autopsyMinusNativeSeconds": a - n if a is not None and n is not None else None})
    return {"compared": "Known payload presence and four raw epoch fields; zero normalized to absent",
            "knownPayloadMetadataParity": not differences, "differences": differences}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--setup", type=Path, default=LOCAL / "prepared-repaired/setup.json")
    parser.add_argument("--variant", choices=("original-mac-compatible", "installed-adapted", "repaired-mac"), default="repaired-mac")
    parser.add_argument("--binary", type=Path, default=REPO / ".build/release/ForensicsPipelineBenchmark")
    parser.add_argument("--helper", type=Path, default=REPO / ".engine/bin/NFTSKEngine")
    parser.add_argument("--verifier-classes", type=Path, default=LOCAL / "verifier-classes")
    parser.add_argument("--pairs", type=int, default=5)
    parser.add_argument("--seed", type=int, default=20261006)
    args = parser.parse_args()
    require(5 <= args.pairs <= 10, "Between five and ten measured pairs required")
    require(Path.cwd().resolve() == REPO, "Run from repository root")
    args.binary, args.helper, args.verifier_classes = args.binary.resolve(), args.helper.resolve(), args.verifier_classes.resolve()
    require(args.binary.is_relative_to(REPO) and args.helper.is_relative_to(REPO) and args.binary.is_file()
            and args.helper.is_file(), "Expected repository-owned benchmark binary/helper")
    require(args.verifier_classes.is_relative_to(LOCAL) and (args.verifier_classes / "AutopsyCaseVerifier.class").is_file(),
            "Compile Java verifier under the owned benchmark root first")
    setup = copy.deepcopy(json.loads(owned_path(args.setup).read_text()))
    verify_setup(setup)
    output = LOCAL / ("paired-" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:6])
    output.mkdir()
    source_dir = output / "sources"
    source_dir.mkdir()
    large = large_fat_image(source_dir / "large-fat32.raw")
    setup["inputs"][large["path"]] = {"path": str(source_dir / large["path"]), "sha256": large["logicalSha256"],
                                      "size": large["logicalSize"], "facts": large}
    write_json(output / "setup.json", setup)
    binary_hash, helper_hash = digest(args.binary), digest(args.helper)
    source_revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip()
    build = setup.get("nativeBuild", {})
    require(build.get("appVersion") == "0.4.0" and build.get("configuration") == "release"
            and build.get("sourceRevision") == source_revision and build.get("dirtySource") is False
            and build.get("binarySHA256") == binary_hash and build.get("helperSHA256") == helper_hash,
            "A current NativeForensics 0.4.0 release build receipt tied to these exact binaries is required")
    verifier_hash = digest(args.verifier_classes / "AutopsyCaseVerifier.class")
    recipe_paths = ["Package.swift", "Sources/ForensicsPipelineBenchmark/ForensicsPipelineBenchmark.swift",
                    "script/compare_forensics_pipeline.py", "script/benchmark_autopsy_pipeline.py",
                    "script/benchmark_process_timing.py",
                    "Benchmarks/AutopsyComparison/AutopsyCaseVerifier.java",
                    "Tests/NativeEngine/fixtures.py", "Tests/NativeEngine/ntfs_fixtures.py",
                    "Tests/NativeEngine/benchmark_fixtures.py", "script/benchmark_native_engine.py"]
    recipes = {path: digest(REPO / path) for path in recipe_paths}
    report = {"schemaVersion": 1, "status": "running", "seed": args.seed, "referenceVariant": args.variant,
        "sourceRevision": source_revision, "nativeBuild": build,
        "recipeSHA256": recipes, "environmentBefore": environment_receipt(),
        "host": {"system": platform.platform(), "architecture": platform.machine(),
                 "model": subprocess.check_output(["sysctl", "-n", "hw.model"], text=True).strip(),
                 "cpu": subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"], text=True).strip(),
                 "memoryBytes": int(subprocess.check_output(["sysctl", "-n", "hw.memsize"], text=True))},
        "scope": "Fresh-process create-case/import-filesystem/persist workflow with warm OS file caches. No GUI and no ingest modules.",
        "method": {"primary": "Popen start through application process exit, including bootstrap and persistence; owned Solr cleanup is afterwards",
            "native": "Release application core, selected-file SHA-256 + before/after source checks + logical SHA-256 + helper enumeration + JSON cache",
            "autopsy": "Full NetBeans CLI, fresh user/cache/case and private Solr, image import into SQLite, adapted macOS ARM64 runtime",
            "sampling": "5 ms libproc exact owned process group, observes Native CLI/helper or Autopsy JVM/Solr. RSS sampled and CPU lower bound; unavailable per-process readings are retained as coverage gaps, not zero consumption.",
            "validation": "Exact known payloads/stream classification and exports plus independent UTC timestamp oracle gates outside timing. Native fractions checked; Autopsy compared at whole-second precision. No full fractional metadata parity claim.",
            "cache": "Hashes before each run warm OS caches; Autopsy NetBeans user/module cache is fresh each run; no disk cache flush",
            "excluded": ["SwiftUI/Swing rendering", "interactive UI latency", "steady-state engine throughput", "carving", "keyword/browser/artifact ingest", "production evidence"],
            "baselineLimitation": "Mac-compatible baseline, with recorded effective patches/adapters; not a pristine vendor-stock platform build.",
            "attempts": "One excluded correctness warmup and a fixed measured schedule per image; no automatic replacements or omission of failed attempts."},
        "provenance": {"nativeBenchmarkSHA256": binary_hash, "nativeHelperSHA256": helper_hash,
                       "verifierClassSHA256": verifier_hash,
                       "autopsy": setup["variants"][args.variant],
                       "repairedControls": setup.get("repairedControls")}, "workloads": [], "correctnessControls": []}
    randomizer = random.Random(args.seed)
    schedule = []
    for image_name in ("fat16-512.raw", "large-fat32.raw", "ntfs-streams.raw"):
        for index in range(args.pairs + 1):
            order = ["native", "autopsy"]
            randomizer.shuffle(order)
            schedule.append({"image": image_name, "iteration": index, "warmup": index == 0, "order": order})
    report["plannedSchedule"] = schedule
    checkpoint(output / "report.json", report)
    try:
        for image_name in ("fat16-512.raw", "large-fat32.raw", "ntfs-streams.raw"):
            expected = setup["inputs"][image_name]["facts"]
            image = Path(setup["inputs"][image_name]["path"])
            initial = source_state(image)
            workload = {"image": image_name, "imageSize": expected["logicalSize"],
                        "sha256": expected["logicalSha256"], "filesystem": expected["filesystem"], "pairs": [],
                        "performanceRatioAllowed": False}
            report["workloads"].append(workload)
            for planned in (item for item in schedule if item["image"] == image_name):
                index = planned["iteration"]
                pair = {key: value for key, value in planned.items() if key != "image"}
                workload["pairs"].append(pair)
                journal = output / f"{image_name}-pair-{index}.json"
                checkpoint(journal, pair)
                checkpoint(output / "report.json", report)
                for application in pair["order"]:
                    def launch():
                        require(source_state(image) == initial and digest(args.binary) == binary_hash and digest(args.helper) == helper_hash,
                                "Source or native runtime changed before run")
                        if application == "native":
                            return native_pipeline(args.binary, args.helper, image, output)
                        return run_pipeline(setup, output, args.variant, image_name,
                            label=f"pair-{image_name.split('.')[0]}-{index}")
                    def validate(record):
                        require(record["resources"]["sampledAggregatePeakRSSBytes"] is not None,
                                "No owned process resource samples were available")
                        if application == "native":
                            result = native_readback(record, args.helper, expected, image)
                        else:
                            require(record["existingSolrUnchanged"] and record["protectedFilesAndSourcesUnchanged"]
                                    and record["ownedSolrPortsFreeAfterCleanup"], "Autopsy failed isolation/source gate")
                            result = autopsy_readback(record, setup, expected, image, args.verifier_classes, args.variant)
                        require(source_state(image) == initial, "Source changed after readback")
                        return result
                    record = journal_attempt(pair, application, launch, validate, journal)
                    checkpoint(output / "report.json", report)
                    print(json.dumps({"image": image_name, "iteration": index, "warmup": pair["warmup"],
                        "application": application, "wallSeconds": record.get("wallSeconds"),
                        "verified": record["validation"].get("verifiedPayloads"),
                        "expected": len(expected["files"]), "passed": record["validation"].get("passed")}), flush=True)
                    require(source_state(image) == initial, "Source integrity failed; experiment stopped")
                    require(digest(args.binary) == binary_hash and digest(args.helper) == helper_hash,
                            "Native runtime integrity failed; experiment stopped")
                    require(not any("Cleanup" in item["phase"] for item in record.get("errors", [])),
                            "Owned process cleanup failed; experiment stopped")
                    verify_setup(setup)
                    if application == "autopsy":
                        require(record.get("existingSolrUnchanged") and record.get("ownedSolrPortsFreeAfterCleanup")
                                and record.get("protectedFilesAndSourcesUnchanged"), "Autopsy isolation/integrity failed; experiment stopped")
                pair["successful"] = all(pair[name]["validation"].get("passed") for name in ("native", "autopsy"))
                pair["performanceRatioAllowed"] = pair["successful"] and not pair["warmup"]
                pair["metadataComparison"] = metadata_comparison(pair)
                checkpoint(journal, pair)
                checkpoint(output / "report.json", report)
                if pair["warmup"]:
                    require(pair["successful"], "Correctness warmup failed; no measured schedule started for this image")
            measured = [p for p in workload["pairs"] if not p["warmup"]]
            workload["performanceRatioAllowed"] = len(measured) == args.pairs and all(p["successful"] for p in measured)
            workload["applicationAttempts"] = {name: {
                "measured": len(measured), "completedKnownPayloadsAndTimestamps": sum(p[name]["validation"].get("passed", False) for p in measured),
                "failed": sum(not p[name]["validation"].get("passed", False) for p in measured)} for name in ("native", "autopsy")}
            if workload["performanceRatioAllowed"]:
                workload["summary"] = summarize([p for p in workload["pairs"] if not p["warmup"]])
        verify_setup(setup)
        require(digest(args.binary) == binary_hash and digest(args.helper) == helper_hash
                and digest(args.verifier_classes / "AutopsyCaseVerifier.class") == verifier_hash,
                "Native/verifier runtime changed during experiment")
        require(all(digest(REPO / path) == sha for path, sha in recipes.items()), "Benchmark recipe changed during experiment")
        report["experimentComplete"] = True
        report["performanceRatioAllowed"] = all(workload["performanceRatioAllowed"] for workload in report["workloads"])
        report["status"] = "completed" if all(workload["performanceRatioAllowed"] for workload in report["workloads"]) else "completed-with-failures"
        report["sourceAndRuntimeHashesUnchanged"] = True
    except BaseException as error:
        report["status"] = "failed"
        report["error"] = type(error).__name__ + ": " + str(error)
        invalidate_performance(report, report["error"])
        raise
    finally:
        try:
            report["environmentAfter"] = environment_receipt()
        except BaseException as error:
            retain_error(report, "environmentAfter", error)
            report["status"] = "failed"
            invalidate_performance(report, "Final environment receipt failed")
        finally:
            checkpoint(output / "report.json", report)
        print(json.dumps({"report": str(output / "report.json"), "status": report["status"]}), flush=True)


if __name__ == "__main__":
    main()

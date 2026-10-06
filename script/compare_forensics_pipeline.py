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
import subprocess
import sys
import time
import uuid

from benchmark_autopsy_pipeline import (LOCAL, REPO, OwnedGroupSampler, digest,
                                       owned_path, run_pipeline, stop_owned_group,
                                       verify_setup, write_json)

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


def native_pipeline(binary: Path, helper: Path, image: Path, output: Path):
    run = output / ("native-" + uuid.uuid4().hex[:12])
    run.mkdir()
    report_path = run / "core.json"
    command = [str(binary), "--image", str(image), "--helper", str(helper),
               "--case-base", str(run / "cases"), "--report", str(report_path)]
    process = sampler = None
    try:
        with (run / "stdout.log").open("xb") as log:
            start = time.monotonic()
            process = subprocess.Popen(command, cwd=REPO, stdin=subprocess.DEVNULL,
                stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
                env=dict(os.environ, TZ="UTC"))
            sampler = OwnedGroupSampler(process.pid)
            sampler.start()
            code = process.wait(timeout=120)
            wall = time.monotonic() - start
            sampler.stop()
        require(code == 0, "Native core pipeline failed; inspect owned stdout.log")
        core = json.loads(report_path.read_text())
        require(core["status"] == "completed", "Native result was incomplete")
        return {"application": "NativeForensics", "wallSeconds": wall,
                "runDirectory": str(run), "core": core, "resources": sampler.receipt()}
    finally:
        if process is not None:
            stop_owned_group(process)
        if sampler is not None:
            sampler.stop()
            require(not sampler.cleanup_remaining(), "Native leaked an owned child")


def native_readback(record: dict, helper: Path, expected: dict, image: Path):
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
    verified = []
    for index, file in enumerate(expected["files"]):
        row = rows[file["path"]]
        for field in ("size", "isDeleted", "metaAddress", "attributeType", "attributeID"):
            if field in file:
                require(row.get(field) == file[field], "Native metadata differs: " + file["path"] + " " + field)
        require(row["fsOffsetBytes"] == expected["fsOffsetBytes"], "Native filesystem offset differs")
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
                         **{k: row[k] for k in ("createdEpoch", "modifiedEpoch", "changedEpoch", "accessedEpoch") if k in row}})
    return {"passed": True, "declaredPayloads": len(expected["files"]), "verifiedPayloads": len(verified),
            "filesystemRows": len(cache["files"]), "files": verified, "verificationOutsideTiming": True}


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
    native_path = str(Path(selected["nativeDirectory"]) / "libtsk.23.dylib")
    traces = [line for line in result.stderr.decode(errors="replace").splitlines() if "dyld[" in line and "/libtsk.23.dylib" in line]
    require(traces and all(native_path in line for line in traces), "Java readback did not load exact selected native library")
    # Preserve capability gaps, then independently read every export that passed.
    by_path = {r["path"].lstrip("/"): r for r in expected["files"]}
    for row in verified.get("files", []):
        if row.get("passed"):
            key = row["path"].lstrip("/")
            check = validate_export(run / "exports" / row["exportFile"], by_path[key])
            row["exactBytesMatched"] = check["exactBytesMatched"]
    require((result.returncode == 0) == bool(verified.get("passed")), "Java verifier exit/result mismatch")
    verified["verificationOutsideTiming"] = True
    verified["exactSelectedNativeLibraryLoaded"] = True
    return verified


def summarize(pairs: list[dict]):
    require(len(pairs) >= 5, "At least five measured pairs are required")
    require(all(p["native"]["validation"]["passed"] and p["autopsy"]["validation"]["passed"] for p in pairs),
            "Performance ratio requires all expected payloads in both applications")
    summary = {}
    for name in ("native", "autopsy"):
        walls = [pair[name]["wallSeconds"] for pair in pairs]
        rss = [pair[name]["resources"]["sampledAggregatePeakRSSBytes"] / 1024**2 for pair in pairs]
        cpu = [pair[name]["resources"]["sampledUserCPULowerBoundSeconds"] +
               pair[name]["resources"]["sampledSystemCPULowerBoundSeconds"] for pair in pairs]
        summary[name] = {"wallMedianSeconds": statistics.median(walls), "wallMinSeconds": min(walls),
            "wallMaxSeconds": max(walls), "sampledAggregatePeakRSSMedianMiB": statistics.median(rss),
            "sampledCPULowerBoundMedianSeconds": statistics.median(cpu),
            "resourceSamplesPartial": any(p[name]["resources"]["failedSamples"] for p in pairs)}
    ratios = [p["autopsy"]["wallSeconds"] / p["native"]["wallSeconds"] for p in pairs]
    summary["pairedWallRatioMedian"] = statistics.median(ratios)
    summary["pairedWallReductionPercentMedian"] = statistics.median([
        (1 - p["native"]["wallSeconds"] / p["autopsy"]["wallSeconds"]) * 100 for p in pairs])
    summary["payloadsPerApplicationPerRun"] = pairs[0]["native"]["validation"]["verifiedPayloads"]
    summary["measuredPairs"] = len(pairs)
    return summary


def metadata_comparison(pair: dict):
    native = {row["path"].lstrip("/"): row for row in pair["native"]["validation"]["files"]}
    differences = []
    for row in pair["autopsy"]["validation"].get("files", []):
        path = row["path"].lstrip("/")
        if not row.get("passed"):
            differences.append({"path": path, "field": "payloadPresence", "autopsy": False, "native": path in native})
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
    parser.add_argument("--setup", type=Path, default=LOCAL / "prepared-v3/setup.json")
    parser.add_argument("--variant", choices=("original-mac-compatible", "installed-adapted"), default="installed-adapted")
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
    verifier_hash = digest(args.verifier_classes / "AutopsyCaseVerifier.class")
    recipe_paths = ["Package.swift", "Sources/ForensicsPipelineBenchmark/ForensicsPipelineBenchmark.swift",
                    "script/compare_forensics_pipeline.py", "script/benchmark_autopsy_pipeline.py",
                    "Benchmarks/AutopsyComparison/AutopsyCaseVerifier.java",
                    "Tests/NativeEngine/fixtures.py", "Tests/NativeEngine/ntfs_fixtures.py",
                    "Tests/NativeEngine/benchmark_fixtures.py", "script/benchmark_native_engine.py"]
    recipes = {path: digest(REPO / path) for path in recipe_paths}
    report = {"schemaVersion": 1, "status": "running", "seed": args.seed, "referenceVariant": args.variant,
        "sourceRevision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip(),
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
            "validation": "Exact paths, sizes, allocation, stream identity where declared, image timezone UTC and byte-exact known exports outside timing. Raw timestamp differences are reported separately; no complete metadata parity claim.",
            "cache": "Hashes before each run warm OS caches; Autopsy NetBeans user/module cache is fresh each run; no disk cache flush",
            "excluded": ["SwiftUI/Swing rendering", "interactive UI latency", "steady-state engine throughput", "carving", "keyword/browser/artifact ingest", "production evidence"],
            "baselineLimitation": ("Upstream three-module Mac-compatible reference failed Solr readiness despite healthy private service; installed-adapted timings are not pristine vendor-stock timings." if args.variant == "installed-adapted" else "Original three-module baseline retains common macOS compatibility dependencies and an isolated STOP.KEY adapter; it is not a pristine vendor-stock platform build.")},
        "provenance": {"nativeBenchmarkSHA256": binary_hash, "nativeHelperSHA256": helper_hash,
                       "verifierClassSHA256": verifier_hash,
                       "autopsy": setup["variants"][args.variant]}, "workloads": [], "correctnessControls": []}
    randomizer = random.Random(args.seed)
    try:
        for image_name in ("fat16-512.raw", "large-fat32.raw", "ntfs-streams.raw"):
            expected = setup["inputs"][image_name]["facts"]
            image = Path(setup["inputs"][image_name]["path"])
            initial = source_state(image)
            workload = {"image": image_name, "imageSize": expected["logicalSize"],
                        "sha256": expected["logicalSha256"], "filesystem": expected["filesystem"], "pairs": []}
            iterations = 1 if image_name == "ntfs-streams.raw" else args.pairs + 1
            for index in range(iterations):
                order = ["native", "autopsy"]
                randomizer.shuffle(order)
                pair = {"iteration": index, "warmup": index == 0 and image_name != "ntfs-streams.raw", "order": order}
                for application in order:
                    require(source_state(image) == initial and digest(args.binary) == binary_hash and digest(args.helper) == helper_hash,
                            "Source or native runtime changed before run")
                    if application == "native":
                        record = native_pipeline(args.binary, args.helper, image, output)
                        record["validation"] = native_readback(record, args.helper, expected, image)
                    else:
                        record = run_pipeline(setup, output, args.variant, image_name,
                                              label=f"pair-{image_name.split('.')[0]}-{index}")
                        require(record["structuralGatePassed"] and record["existingSolrUnchanged"]
                                and record["protectedFilesAndSourcesUnchanged"], "Autopsy failed structural/isolation gate")
                        record["validation"] = autopsy_readback(record, setup, expected, image, args.verifier_classes, args.variant)
                    require(record["resources"]["sampledAggregatePeakRSSBytes"] is not None,
                            "No owned process resource samples were available")
                    require(source_state(image) == initial, "Source changed after readback")
                    pair[application] = record
                    print(json.dumps({"image": image_name, "iteration": index, "warmup": pair["warmup"],
                        "application": application, "wallSeconds": record["wallSeconds"],
                        "verified": record["validation"].get("verifiedPayloads"),
                        "expected": len(expected["files"]), "passed": record["validation"].get("passed")}), flush=True)
                if image_name != "ntfs-streams.raw":
                    require(pair["native"]["validation"]["passed"] and pair["autopsy"]["validation"]["passed"],
                            "Exact result gate failed; no fair performance ratio")
                pair["metadataComparison"] = metadata_comparison(pair)
                workload["pairs"].append(pair)
                write_json(output / f"{image_name}-pair-{index}.json", pair)
            if image_name == "ntfs-streams.raw":
                workload["performanceRatioAllowed"] = False
                report["correctnessControls"].append(workload)
            else:
                workload["summary"] = summarize([p for p in workload["pairs"] if not p["warmup"]])
                report["workloads"].append(workload)
        verify_setup(setup)
        require(digest(args.binary) == binary_hash and digest(args.helper) == helper_hash
                and digest(args.verifier_classes / "AutopsyCaseVerifier.class") == verifier_hash,
                "Native/verifier runtime changed during experiment")
        require(all(digest(REPO / path) == sha for path, sha in recipes.items()), "Benchmark recipe changed during experiment")
        report["status"] = "completed"
        report["sourceAndRuntimeHashesUnchanged"] = True
    except BaseException as error:
        report["status"] = "failed"
        report["error"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        report["environmentAfter"] = environment_receipt()
        write_json(output / "report.json", report)
        print(json.dumps({"report": str(output / "report.json"), "status": report["status"]}), flush=True)


if __name__ == "__main__":
    main()

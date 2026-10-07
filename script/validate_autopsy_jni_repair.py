#!/usr/bin/env python3
"""Untimed synthetic controls for the scoped macOS Autopsy JNI repair.

The old runtime is a negative control. A repaired runtime must agree with an
independent FAT on-disk timestamp oracle and the NTFS fixture manifest, preserve
the default directory hierarchy, export every declared payload, and leave no
environment pointers into the calling thread's native stack. No installed
runtime, system timezone, evidence image, or pre-existing case is changed.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import uuid
import zipfile
from zoneinfo import ZoneInfo

REPO = Path(__file__).resolve().parents[1]
LOCAL = REPO / "local" / "autopsy-comparison"
JNI_RESOURCE = "NATIVELIBS/aarch64/mac/libtsk_jni.dylib"
ZONES = ("UTC", "Asia/Bangkok", "America/New_York")


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8") as output:
        json.dump(value, output, ensure_ascii=False, indent=2)
        output.write("\n")


def owned(path: Path) -> Path:
    result = path.resolve()
    if not result.is_relative_to(LOCAL.resolve()):
        raise ValueError("Generated controls must be below local/autopsy-comparison")
    return result


def dos_epoch(date: int, clock: int, tenths: int, zone: str) -> int:
    if date == 0:
        return 0
    year, month, day = 1980 + (date >> 9), (date >> 5) & 15, date & 31
    hour, minute, second = clock >> 11, (clock >> 5) & 63, (clock & 31) * 2 + tenths // 100
    return int(dt.datetime(year, month, day, hour, minute, second, tzinfo=ZoneInfo(zone)).timestamp())


def fat16_oracle(path: Path, timezone: str) -> dict[str, dict[str, int]]:
    """Decode directory DOS fields directly, without calling TSK or either app."""
    blob = path.read_bytes()
    sector_size = struct.unpack_from("<H", blob, 11)[0]
    sectors_per_cluster = blob[13]
    reserved = struct.unpack_from("<H", blob, 14)[0]
    fat_count = blob[16]
    root_count = struct.unpack_from("<H", blob, 17)[0]
    fat_sectors = struct.unpack_from("<H", blob, 22)[0]
    if sector_size != 512 or not sectors_per_cluster or not root_count or not fat_sectors:
        raise ValueError("Control expects the declared small FAT16 fixture")
    root_offset = (reserved + fat_count * fat_sectors) * sector_size
    data_offset = root_offset + ((root_count * 32 + sector_size - 1) // sector_size) * sector_size
    cluster_bytes = sector_size * sectors_per_cluster
    result: dict[str, dict[str, int]] = {}

    def directory(offset: int, length: int, parent: str, depth: int) -> None:
        if depth > 4:
            raise ValueError("Synthetic FAT directory bound exceeded")
        for pos in range(offset, offset + length, 32):
            entry = blob[pos:pos + 32]
            if len(entry) != 32 or entry[0] == 0:
                break
            if entry[11] == 15 or entry[11] & 8:
                continue
            name_bytes = bytearray(entry[:8])
            if name_bytes[0] == 0xE5:
                name_bytes[0] = ord("_")
            name = name_bytes.decode("ascii").rstrip(" ")
            extension = entry[8:11].decode("ascii").rstrip(" ")
            if name in (".", ".."):
                continue
            filename = name + ("." + extension if extension else "")
            full = parent + filename
            if entry[11] & 16:
                cluster = struct.unpack_from("<H", entry, 26)[0]
                if cluster < 2:
                    raise ValueError("Unexpected FAT directory cluster")
                directory(data_offset + (cluster - 2) * cluster_bytes, cluster_bytes, full + "/", depth + 1)
                continue
            creation_clock, creation_date, access_date = struct.unpack_from("<HHH", entry, 14)
            modified_clock, modified_date = struct.unpack_from("<HH", entry, 22)
            result[full] = {
                "createdEpoch": dos_epoch(creation_date, creation_clock, entry[13], timezone),
                "modifiedEpoch": dos_epoch(modified_date, modified_clock, 0, timezone),
                # FAT access date is local midnight, not the creation time.
                "accessedEpoch": dos_epoch(access_date, 0, 0, timezone),
                "changedEpoch": 0,
            }

    directory(root_offset, root_count * 32, "", 0)
    return result


def prepare_classes(root: Path, setup: dict) -> tuple[Path, Path]:
    classes = root / "classes"
    classes.mkdir()
    java_home = Path(setup["javaHome"])
    runtime = Path(setup["variants"]["installed-adapted"]["runtime"])
    subprocess.run([
        str(java_home / "bin" / "javac"), "-cp", str(runtime / "autopsy" / "modules" / "ext" / "*"),
        "-d", str(classes), str(REPO / "Benchmarks" / "AutopsyComparison" / "AutopsyRepairProbe.java"),
    ], check=True, cwd=REPO)
    probe = root / "libautopsy_environment_probe.dylib"
    subprocess.run([
        "clang", "-dynamiclib", "-O2", "-Wall", "-Wextra", "-Werror", "-arch", "arm64",
        "-I", str(java_home / "include"), "-I", str(java_home / "include" / "darwin"),
        str(REPO / "Benchmarks" / "AutopsyComparison" / "AutopsyEnvironmentProbe.c"), "-o", str(probe),
    ], check=True, cwd=REPO)
    return classes, probe


def profile_hashes(profile: dict) -> dict[str, str]:
    runtime = Path(profile["runtime"])
    files = [
        runtime / "autopsy" / "modules" / "ext" / "sleuthkit-4.15.0.jar",
        Path(profile["jdk"]) / "bin" / "java",
        Path(profile["nativeDirectory"]) / "libtsk.23.dylib",
    ]
    return {str(path): sha(path) for path in files}


def run_control(root: Path, setup: dict, variant: str, image: str, source_zone: str,
                host_zone: str, classes: Path, probe: Path) -> dict:
    profile = setup["variants"][variant]
    input_info = setup["inputs"][image]
    source = Path(input_info["path"])
    run = root / f"{variant}-{image.replace('.raw', '')}-{source_zone.replace('/', '-')}-{host_zone.replace('/', '-')}"
    run.mkdir()
    (run / "jni").mkdir()
    facts = input_info["facts"]
    spec = {"synthetic": True, "sourcePaths": [str(source)], "files": [
        {k: v for k, v in file.items() if k != "payloadHex"} for file in facts["files"]
    ]}
    write(run / "spec.json", spec)
    env = dict(os.environ)
    env["TZ"] = host_zone
    runtime = Path(profile["runtime"])
    jar = runtime / "autopsy" / "modules" / "ext" / "sleuthkit-4.15.0.jar"
    with zipfile.ZipFile(jar) as archive:
        resource_sha = hashlib.sha256(archive.read(JNI_RESOURCE)).hexdigest()
    command = [
        str(Path(profile["jdk"]) / "bin" / "java"),
        f"-Dtsk.tmpdir={run / 'jni'}", f"-Djava.io.tmpdir={run}",
        f"-XX:ErrorFile={run / 'hs_err_pid%p.log'}",
        "-Djava.awt.headless=true", "-cp", str(classes) + os.pathsep + str(jar.parent / "*"),
        "AutopsyRepairProbe", str(run), str(run / "spec.json"), source_zone, str(probe),
    ]
    receipt = {
        "variant": variant, "image": image, "sourceTimezone": source_zone, "hostProcessTimezone": host_zone,
        "scope": "Untimed direct datamodel correctness control; no NetBeans, Solr or GUI",
        "jniResourceSHA256": resource_sha, "rawSourceSHA256Before": sha(source),
        "expectedRawSourceSHA256": input_info["sha256"], "runDirectory": str(run),
    }
    result = None
    with (run / "stdout.log").open("xb") as stdout, (run / "stderr.log").open("xb") as stderr:
        try:
            process = subprocess.run(command, stdout=stdout, stderr=stderr, cwd=REPO, env=env, timeout=60)
            receipt["exitCode"] = process.returncode
        except subprocess.TimeoutExpired:
            receipt["timedOut"] = True
            receipt["exitCode"] = None
    lines = (run / "stdout.log").read_text(errors="replace").splitlines()
    for line in reversed(lines):
        try:
            result = json.loads(line)
            break
        except ValueError:
            pass
    errors: list[str] = []
    if receipt["exitCode"] != 0 or not result or not result.get("completed"):
        errors.append("Control did not complete")
    else:
        receipt["result"] = result
        loaded = [Path(path) for path in result["loadedTSKLibraries"] if "libtsk_jni" in Path(path).name]
        extracted = sorted((run / "jni").rglob("*tsk_jni*dylib"))
        receipt["extractedJNIFiles"] = [{"path": str(path), "sha256": sha(path)} for path in extracted]
        receipt["loadedJNIFiles"] = [{"path": str(path), "sha256": sha(path)} for path in loaded]
        if len(loaded) != 1 or not loaded[0].resolve().is_relative_to((run / "jni").resolve()) or sha(loaded[0]) != resource_sha:
            errors.append("Actual loaded JNI did not match owned extracted JAR resource")
        loaded_tsk = [Path(path) for path in result["loadedTSKLibraries"] if Path(path).name == "libtsk.23.dylib"]
        expected_tsk = Path(profile["nativeDirectory"]) / "libtsk.23.dylib"
        receipt["loadedTSKFiles"] = [{"path": str(path), "sha256": sha(path)} for path in loaded_tsk]
        if len(loaded_tsk) != 1 or loaded_tsk[0].resolve() != expected_tsk.resolve():
            errors.append("Actual loaded libtsk differs from selected profile")
        receipt["stackEnvironmentPointerDefectObserved"] = (
            result["beforeImportStackEnvironmentEntries"] == 0 and result["afterImportStackEnvironmentEntries"] > 0
        )
        if result["beforeImportStackEnvironmentEntries"] != 0 or result["afterImportStackEnvironmentEntries"] != 0:
            errors.append("Environment contains an entry on the native calling-thread stack")
        timestamp_oracle = fat16_oracle(source, source_zone) if image.startswith("fat16") else {
            file["path"]: {key: value for key, value in file["timestampsByTimezone"]["UTC"].items() if key.endswith("Epoch")}
            for file in facts["files"]
        }
        validations = []
        for expected, actual in zip(spec["files"], result["files"], strict=True):
            payload_passed = (actual.get("matchedRows") == 1 and actual.get("sha256") == expected["sha256"]
                              and actual.get("exportBytes") == expected["size"]
                              and actual.get("isDeleted") == expected["isDeleted"])
            classification_passed = actual.get("isFile") is True and actual.get("isDirectory") is False
            expected_epochs = timestamp_oracle[expected["path"]]
            checks = {key: {"actual": actual.get(key), "expected": value, "passed": actual.get(key) == value}
                      for key, value in expected_epochs.items()}
            timestamps_passed = all(check["passed"] for check in checks.values())
            validations.append({"path": expected["path"], "payloadPassed": payload_passed,
                                "classificationPassed": classification_passed,
                                "timestampsPassed": timestamps_passed, "timestampChecks": checks})
            if not payload_passed:
                errors.append("Payload mismatch/missing: " + expected["path"])
            if not classification_passed:
                errors.append("Regular stream classification mismatch: " + expected["path"])
            if not timestamps_passed:
                errors.append("Independent timestamp oracle mismatch: " + expected["path"])
        receipt["validations"] = validations
        receipt["verifiedPayloads"] = sum(item["payloadPassed"] for item in validations)
        receipt["verifiedTimestampSets"] = sum(item["timestampsPassed"] for item in validations)
        if image.startswith("ntfs"):
            directories = [row for row in result["directories"] if row["path"] == "หลักฐาน"]
            child = next((row for row in result["files"] if row["path"] == "หลักฐาน/nested.txt"), {})
            hierarchy_passed = len(directories) == 1 and directories[0]["metaAddress"] == 34 and child.get("parentPath") == "หลักฐาน/"
            receipt["defaultDirectoryHierarchyPassed"] = hierarchy_passed
            if not hierarchy_passed:
                errors.append("Default NTFS directory hierarchy not preserved exactly once")
    receipt["rawSourceSHA256After"] = sha(source)
    if not (receipt["rawSourceSHA256Before"] == receipt["rawSourceSHA256After"] == input_info["sha256"]):
        errors.append("Synthetic source hash changed or differs from manifest")
    receipt["errors"] = errors
    receipt["passed"] = not errors
    write(run / "receipt.json", receipt)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--setup", type=Path, required=True)
    parser.add_argument("--variant", choices=("installed-adapted", "repaired-mac", "both"), default="both")
    parser.add_argument("--output-root", type=Path, default=LOCAL / "repair-controls-20261007")
    parser.add_argument("--host-timezones", nargs="+", choices=ZONES, default=list(ZONES))
    parser.add_argument("--source-timezones", nargs="+", choices=ZONES, default=list(ZONES))
    args = parser.parse_args()
    setup = json.loads(owned(args.setup).read_text())
    variants = ("installed-adapted", "repaired-mac") if args.variant == "both" else (args.variant,)
    for variant in variants:
        if variant not in setup["variants"]:
            raise ValueError("Missing runtime profile: " + variant)
    root = owned(args.output_root) / ("run-" + uuid.uuid4().hex[:10])
    root.mkdir(parents=True)
    classes, probe = prepare_classes(root, setup)
    frozen = {variant: profile_hashes(setup["variants"][variant]) for variant in variants}
    report = {"schemaVersion": 1, "scope": "Untimed old/new JNI correctness and lifetime controls", "frozenProfiles": frozen, "attempts": []}
    report["controlArtifacts"] = {
        "scriptSHA256": sha(Path(__file__)),
        "javaSourceSHA256": sha(REPO / "Benchmarks" / "AutopsyComparison" / "AutopsyRepairProbe.java"),
        "nativeSourceSHA256": sha(REPO / "Benchmarks" / "AutopsyComparison" / "AutopsyEnvironmentProbe.c"),
        "javaClassSHA256": sha(classes / "AutopsyRepairProbe.class"),
        "environmentProbeSHA256": sha(probe),
    }
    for variant in variants:
        for source_zone in args.source_timezones:
            for host_zone in args.host_timezones:
                attempt = run_control(root, setup, variant, "fat16-512.raw", source_zone, host_zone, classes, probe)
                report["attempts"].append(attempt)
                print(f"{variant} FAT16 source={source_zone} host={host_zone}: payloads={attempt.get('verifiedPayloads', 0)}/5 timestamps={attempt.get('verifiedTimestampSets', 0)}/5 stackDefect={attempt.get('stackEnvironmentPointerDefectObserved', False)}", flush=True)
        attempt = run_control(root, setup, variant, "ntfs-streams.raw", "UTC", "Asia/Bangkok", classes, probe)
        report["attempts"].append(attempt)
        print(f"{variant} NTFS: payloads={attempt.get('verifiedPayloads', 0)}/13 hierarchy={attempt.get('defaultDirectoryHierarchyPassed', False)} stackDefect={attempt.get('stackEnvironmentPointerDefectObserved', False)}", flush=True)
    stable = all(profile_hashes(setup["variants"][variant]) == frozen[variant] for variant in variants)
    report["frozenProfilesUnchanged"] = stable
    old = [item for item in report["attempts"] if item["variant"] == "installed-adapted"]
    repaired = [item for item in report["attempts"] if item["variant"] == "repaired-mac"]
    report["oldStackDefectDemonstrated"] = any(item.get("stackEnvironmentPointerDefectObserved") for item in old)
    report["repairedAllControlsPassed"] = bool(repaired) and all(item["passed"] for item in repaired)
    report["passed"] = stable and (report["repairedAllControlsPassed"] if repaired else report["oldStackDefectDemonstrated"])
    write(root / "report.json", report)
    print(str(root / "report.json"), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())

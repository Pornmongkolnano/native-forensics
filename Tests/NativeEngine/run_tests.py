#!/usr/bin/env python3
"""Black-box Phase 1 native helper correctness and safety tests.

Requires a separately built .engine/bin/NFTSKEngine. Uses only Python stdlib.
Generated evidence, exports, and full reports live under ignored local/.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import struct
import subprocess
import sys
import time
import uuid
from pathlib import Path

from fixtures import PAYLOADS, digest, generate


REPO = Path(__file__).resolve().parents[2]
TERMINAL = {"completed", "partial", "failed", "cancelled"}
FRAME_LIMIT = 1024 * 1024
ALLOWED_TYPES = {"hello", "image", "volume", "fileBatch", "progress", "warning", "error", "extracted", *TERMINAL}


def expect(value, message):
    if not value:
        raise AssertionError(message)


class Runner:
    def __init__(self, helper: Path, output: Path, timeout: float):
        self.helper, self.output, self.timeout = helper, output, timeout
        self.helper_sha256 = digest(helper)
        self.tests = []
        self.warnings = []
        self.started = time.time()
        self.fixture_dir = output / "fixtures"
        self.fixtures = generate(self.fixture_dir)
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.run_dir = output / ("run-" + timestamp + "-" + uuid.uuid4().hex[:8])
        self.run_dir.mkdir()
        self.exports = self.run_dir / "exports"
        self.exports.mkdir()
        self.all_source_hashes = {str(path): digest(path) for path in self.fixture_dir.iterdir() if path.is_file()}

    def check(self, label, action):
        start = time.monotonic()
        try:
            detail = action() or {}
            self.tests.append({"name": label, "passed": True, "seconds": round(time.monotonic() - start, 4), "detail": detail})
            print("PASS " + label, flush=True)
        except Exception as error:
            self.tests.append({"name": label, "passed": False, "seconds": round(time.monotonic() - start, 4), "error": str(error)})
            print("FAIL " + label + ": " + str(error), flush=True)
        self.write_report()

    def request(self, fixture, operation="enumerate", timezone="UTC", **extra):
        result = {
            "protocolVersion": 1, "jobID": uuid.uuid4().hex, "operation": operation,
            "imagePaths": [str((self.fixture_dir / name).resolve()) for name in fixture.get("imagePaths", [fixture["path"]])],
            "imageType": fixture.get("imageType", "raw"), "sectorSize": fixture["sectorSize"],
            "timezone": timezone, "maxFiles": 50000, "hashLogicalImage": True,
        }
        result.update(extra)
        return result

    def call(self, request, *, cancel=False, raw_input=None, host_timezone="UTC"):
        payload = (json.dumps(request, ensure_ascii=False) + "\n").encode() if raw_input is None else raw_input
        if cancel:
            payload += (json.dumps({"protocolVersion": 1, "jobID": request["jobID"], "operation": "cancel"}) + "\n").encode()
        start = time.monotonic()
        process = subprocess.run([str(self.helper)], input=payload, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, timeout=self.timeout,
                                 env=dict(os.environ, TZ=host_timezone, LC_ALL="C"))
        lines = process.stdout.splitlines()
        expect(lines, "helper emitted no protocol frames; stderr=" + process.stderr.decode(errors="replace")[:500])
        expect(len(process.stdout) <= 64 * 1024 * 1024, "serialized output exceeded 64 MiB")
        frames = []
        for sequence, line in enumerate(lines):
            expect(len(line) <= FRAME_LIMIT, "output frame exceeded 1 MiB")
            frame = json.loads(line.decode("utf-8", errors="strict"))
            expect(isinstance(frame, dict), "protocol frame must be an object")
            expect(frame.get("protocolVersion") == 1, "wrong response protocol version")
            if raw_input is None:
                expect(frame.get("jobID") == request["jobID"], "response jobID mismatch")
            expect(frame.get("sequence") == sequence, "non-monotonic response sequence")
            expect(frame.get("type") in ALLOWED_TYPES, "unknown response frame type")
            if frame["type"] == "fileBatch":
                expect(isinstance(frame.get("files"), list) and len(frame["files"]) <= 128, "file batch is not bounded")
            if frame["type"] in {"warning", "error"}:
                expect(isinstance(frame.get("code"), str) and isinstance(frame.get("message"), str), "unstructured error or warning")
            frames.append(frame)
        terminals = [frame for frame in frames if frame["type"] in TERMINAL]
        expect(len(terminals) == 1 and frames[-1] is terminals[0], "expected exactly one final terminal frame")
        terminal = terminals[0]
        expected_exit = 0 if terminal["type"] in {"completed", "partial"} else (2 if terminal["type"] == "cancelled" else 1)
        expect(process.returncode == expected_exit, f"exit {process.returncode} does not match {terminal['type']}")
        if terminal["type"] == "completed":
            expect(frames[0]["type"] == "hello", "successful job missing initial hello")
            hello = frames[0]
            expect(isinstance(hello.get("engineVersion"), str) and isinstance(hello.get("patchDigest"), str), "hello missing provenance")
            expect(isinstance(hello.get("capabilities"), list), "hello missing capabilities")
        files = [file for frame in frames if frame["type"] == "fileBatch" for file in frame["files"]]
        expect(terminal.get("fileCount") == len(files), "terminal fileCount differs from emitted rows")
        return {"frames": frames, "files": files, "terminal": terminal, "seconds": time.monotonic() - start,
                "stderr": process.stderr.decode(errors="replace")[:2000]}

    @staticmethod
    def regular(files):
        rows = [row for row in files if not row["isDirectory"] and not row["name"].startswith("$")]
        entries = {row["path"].lstrip("/"): row for row in rows}
        expect(len(entries) == len(rows), "duplicate payload paths must not be hidden by dictionary conversion")
        return entries

    @staticmethod
    def timestamps(fixture, expected_file, timezone):
        matrix = expected_file.get("timestampsByTimezone")
        if matrix is not None:
            expect(timezone in matrix, "fixture lacks independent expected timezone " + timezone)
            return matrix[timezone]
        epoch = fixture["expectedEpochUTC"] - (7 * 3600 if timezone == "Asia/Bangkok" and not fixture.get("validUTCOffset") else 0)
        return {
            "createdEpoch": epoch, "modifiedEpoch": epoch,
            "accessedEpoch": epoch if fixture.get("validUTCOffset") else epoch - 80000,
            "createdNanoseconds": fixture.get("expectedCreatedNanoseconds", 0),
            "modifiedNanoseconds": fixture.get("expectedModifiedNanoseconds", 0),
            "accessedNanoseconds": 0,
        }

    @classmethod
    def check_timestamps(cls, fixture, expected_file, row, timezone):
        expected = cls.timestamps(fixture, expected_file, timezone)
        for prefix in ("created", "modified", "accessed", "changed"):
            epoch_key, nano_key = prefix + "Epoch", prefix + "Nanoseconds"
            if epoch_key in expected:
                expect(row.get(epoch_key) == expected[epoch_key], f"{epoch_key} differs: {expected_file['path']} {row.get(epoch_key)} != {expected[epoch_key]}")
                expect(row.get(nano_key, 0) == expected.get(nano_key, 0), nano_key + " differs: " + expected_file["path"])
            else:
                expect(epoch_key not in row and nano_key not in row, "missing/invalid timestamp must be absent: " + expected_file["path"] + " " + prefix)

    def enumeration(self, fixture, timezone="UTC"):
        request = self.request(fixture, timezone=timezone)
        result = self.call(request)
        expect(result["terminal"]["type"] == "completed", "supported synthetic image was not completed")
        images = [frame for frame in result["frames"] if frame["type"] == "image"]
        expect(len(images) == 1, "one image frame required")
        image = images[0]
        expect(image.get("logicalSize") == fixture["logicalSize"], "logical image size differs")
        expect(image.get("logicalSha256") == fixture["logicalSha256"], "logical image hash differs from concatenated source bytes")
        expect(image.get("sectorSize") == fixture["sectorSize"], "sector size differs")
        expect(image.get("imagePaths") == request["imagePaths"], "opened paths differ from explicit source order")
        volumes = [frame["volume"] for frame in result["frames"] if frame["type"] == "volume"]
        expect(any(volume["offsetBytes"] == fixture["fsOffsetBytes"] for volume in volumes), "filesystem byte offset differs")
        entries = self.regular(result["files"])
        expect(len({row["id"] for row in result["files"]}) == len(result["files"]), "listing contains duplicate stable entry IDs")
        if fixture["filesystem"] == "exFAT":
            # TSK exposes our explicit root volume label as a metadata pseudo-file.
            # Assert its exact name/shape rather than dropping arbitrary extra rows.
            label = entries.pop("NFTK (Volume Label Entry)", None)
            expect(label is not None and label["size"] == 0 and not label["isDeleted"], "exFAT volume-label metadata entry differs")
        expected = {row["path"] for row in fixture["files"]}
        expect(set(entries) == expected, f"file names differ: expected {sorted(expected)}, actual {sorted(entries)}")
        ids = set()
        for file in fixture["files"]:
            row = entries[file["path"]]
            for field in ("id", "path", "name", "fsOffsetBytes", "metaAddress", "size", "isDirectory", "isDeleted"):
                expect(field in row, "missing filesystem field " + field)
            expect(row["id"] not in ids, "duplicate stable entry ID")
            expect(len(row["id"].encode()) <= 128, "entry ID embeds an arbitrarily long path")
            ids.add(row["id"])
            expect(row["size"] == file["size"], "file size differs: " + file["path"])
            expect(row["isDeleted"] == file["isDeleted"], "allocation state differs: " + file["path"])
            self.check_timestamps(fixture, file, row, timezone)
            for field in ("attributeType", "attributeID", "metaAddress"):
                if field in file:
                    expect(row.get(field) == file[field], field + " differs: " + file["path"])
        for file in fixture["files"]:
            row = entries[file["path"]]
            destination = self.exports / (uuid.uuid4().hex + "-" + row["name"])
            locator = {field: row[field] for field in ("fsOffsetBytes", "metaAddress", "attributeType", "attributeID", "size") if field in row}
            extracted = self.call(self.request(fixture, "extract", timezone=timezone, file=locator,
                                                outputPath=str(destination), hashLogicalImage=False))
            expect(extracted["terminal"]["type"] == "completed", "extraction did not complete: " + file["path"])
            receipts = [frame for frame in extracted["frames"] if frame["type"] == "extracted"]
            expect(len(receipts) == 1, "missing extraction receipt")
            expect(destination.read_bytes() == bytes.fromhex(file["payloadHex"]), "extracted bytes differ: " + file["path"])
            expect(receipts[0].get("sha256") == file["sha256"] and digest(destination) == file["sha256"], "extracted digest differs")
            expect(receipts[0].get("byteCount") == file["size"], "extracted byte count differs")
        return {"logicalHashMatched": True, "fileBytesMatched": len(fixture["files"]), "timezone": timezone,
                "rowCount": len(result["files"]), "seconds": round(result["seconds"], 6)}

    def host_timezone_invariance(self, fixture):
        matrix = fixture["timestampMatrix"]
        timezone = matrix["requestTimezones"][0]
        baseline = None
        for host_timezone in matrix["hostTimezones"]:
            result = self.call(self.request(fixture, timezone=timezone, hashLogicalImage=False), host_timezone=host_timezone)
            expect(result["terminal"]["type"] == "completed", "timezone probe was incomplete")
            rows = self.regular(result["files"])
            observed = {}
            for file in fixture["files"]:
                row = rows[file["path"]]
                self.check_timestamps(fixture, file, row, timezone)
                observed[file["path"]] = {key: value for key, value in row.items() if key.endswith("Epoch") or key.endswith("Nanoseconds")}
            if baseline is None:
                baseline = observed
            expect(observed == baseline, "recorded timestamps depend on the ambient host timezone")
        return {"requestTimezone": timezone, "hostTimezones": matrix["hostTimezones"], "fileCount": len(fixture["files"])}

    def fail_request(self, request):
        result = self.call(request)
        expect(result["terminal"]["type"] == "failed", "invalid request must be failed")
        expect(any(frame["type"] == "error" for frame in result["frames"]), "failure missing structured error")
        return {"errorCodes": [frame["code"] for frame in result["frames"] if frame["type"] == "error"]}

    def safety(self):
        fixture = self.fixtures["images"][0]
        rows = self.regular(self.call(self.request(fixture))["files"])
        row = rows["HELLO.TXT"]
        locator = {key: row[key] for key in ("fsOffsetBytes", "metaAddress", "attributeType", "attributeID", "size") if key in row}
        def extract_request(path, **kwargs):
            return self.request(fixture, "extract", file=locator, outputPath=str(path), hashLogicalImage=False, **kwargs)
        preserved = self.exports / "existing.txt"
        preserved.write_bytes(b"PRESERVE")
        self.check("extract refuses existing output", lambda: self._preserved(extract_request(preserved), preserved, b"PRESERVE"))
        source = self.fixture_dir / fixture["path"]
        self.check("extract refuses source as output", lambda: self.fail_request(extract_request(source)))
        link = self.exports / "output-symlink"
        link.symlink_to(preserved)
        self.check("extract refuses output symlink", lambda: self._preserved(extract_request(link), preserved, b"PRESERVE"))
        parent_link = self.exports / "directory-symlink"
        target = self.exports / "symlink-target"
        target.mkdir()
        parent_link.symlink_to(target, target_is_directory=True)
        linked_output = parent_link / "new.txt"
        self.check("extract safely canonicalizes owned symlink parent", lambda: self._canonical_output(extract_request(linked_output), linked_output))
        bad_size_output = self.exports / "invalid-size.txt"
        wrong_size = dict(locator, size=row["size"] + 1)
        self.check("extract rejects stale size locator without output", lambda: self._no_output(
            self.request(fixture, "extract", file=wrong_size, outputPath=str(bad_size_output), hashLogicalImage=False), bad_size_output))
        invalid_meta_output = self.exports / "invalid-meta.txt"
        self.check("extract rejects invalid metadata without output", lambda: self._no_output(
            self.request(fixture, "extract", file=dict(locator, metaAddress=2**63), outputPath=str(invalid_meta_output), hashLogicalImage=False), invalid_meta_output))

    def _preserved(self, request, path, expected):
        result = self.fail_request(request)
        expect(path.read_bytes() == expected, "existing output was modified")
        return result

    def _no_output(self, request, path):
        result = self.fail_request(request)
        expect(not path.exists(), "failed extraction left an output")
        return result

    def _canonical_output(self, request, path):
        result = self.call(request)
        expect(result["terminal"]["type"] == "completed", "owned canonical parent extraction failed")
        expect(path.read_bytes() == PAYLOADS["HELLO.TXT"], "canonical output bytes differ")
        expect(path.resolve().parent.name == "symlink-target", "output escaped the resolved parent")
        self.fail_request(request)
        expect(path.read_bytes() == PAYLOADS["HELLO.TXT"], "repeated canonical extraction overwrote the output")

    def protocol(self):
        fixture = self.fixtures["images"][0]
        for label, extra in [
            ("protocol version", {"protocolVersion": 2}),
            ("unknown operation", {"operation": "modify"}),
            ("invalid timezone", {"timezone": "Not/A-Timezone"}),
            ("invalid image type", {"imageType": "vhd"}),
            ("invalid sector size", {"sectorSize": 1024}),
            ("maxFiles zero", {"maxFiles": 0}),
            ("maxFiles overflow", {"maxFiles": 50001}),
            ("Boolean maxFiles", {"maxFiles": True}),
            ("string logical hash flag", {"hashLogicalImage": "true"}),
            ("missing image", {"imagePaths": [str(self.fixture_dir / "missing.raw")]}),
            ("directory as image", {"imagePaths": [str(self.fixture_dir)]}),
            ("relative image path", {"imagePaths": ["relative.raw"]}),
            ("empty image paths", {"imagePaths": []}),
            ("duplicate RAW segment", {"imagePaths": [str(self.fixture_dir / fixture["path"])] * 2}),
            ("NUL in path", {"imagePaths": [str(self.fixture_dir / fixture["path"]) + "\0"]}),
        ]:
            self.check("reject " + label, lambda extra=extra: self.fail_request(self.request(fixture, **extra)))
        for label, value in [("truncated JSON", b'{"protocolVersion":1\n'), ("non-object JSON", b'[]\n'),
                             ("oversized frame", b" " * (FRAME_LIMIT + 1) + b"\n"),
                             ("request without newline", json.dumps(self.request(fixture)).encode()),
                             ("empty stdin", b""),
                             ("invalid UTF-8", b'\xff\xfe\n')]:
            self.check("reject " + label, lambda value=value: self._malformed(value))
        empty = self.fixture_dir / "invalid-empty.raw"
        empty.touch()
        junk = self.fixture_dir / "invalid-unknown.raw"
        junk.write_bytes(b"NFTK synthetic unsupported format\n" + b"\0" * 8192)
        truncated = self.fixture_dir / "invalid-truncated.raw"
        truncated.write_bytes((self.fixture_dir / fixture["path"]).read_bytes()[:1024])
        for path in (empty, junk):
            self.check("reject " + path.stem, lambda path=path: self.fail_request(self.request(fixture, imagePaths=[str(path)])))
        self.check("truncated image explicitly failed or partial", lambda: self._damaged_image(self.request(fixture, imagePaths=[str(truncated)])))
        # Explicit signatures exercise unsupported claims without representing complete UDF/APFS images.
        udf = self.fixture_dir / "unsupported-udf.raw"
        udf_bytes = bytearray(40 * 2048)
        udf_bytes[16 * 2048:16 * 2048 + 7] = b"\x00BEA01\x01"
        udf_bytes[17 * 2048:17 * 2048 + 7] = b"\x00NSR02\x01"
        udf_bytes[18 * 2048:18 * 2048 + 7] = b"\x00TEA01\x01"
        udf.write_bytes(udf_bytes)
        apfs = self.fixture_dir / "unsupported-apfs.raw"
        apfs_bytes = bytearray(8192)
        apfs_bytes[32:36] = b"NXSB"
        struct.pack_into("<I", apfs_bytes, 36, 4096)
        struct.pack_into("<Q", apfs_bytes, 40, 2)
        apfs.write_bytes(apfs_bytes)
        for path in (udf, apfs):
            self.check("reject synthetic " + path.stem + " signature", lambda path=path: self.fail_request(self.request(fixture, imagePaths=[str(path)])))
        self.check("bounded listing is explicit partial", lambda: self._partial(fixture))
        self.check("inspect completes without file rows or unwanted hash", lambda: self._inspect(fixture))
        self.check("same source has stable IDs", lambda: self._stable_ids(fixture))
        self.check("cancel logical hash job", lambda: self._cancel(self.fixtures["images"][3]))

    def _malformed(self, payload):
        result = self.call({}, raw_input=payload)
        expect(result["terminal"]["type"] == "failed", "malformed request must fail")
        return {"errorCodes": [frame["code"] for frame in result["frames"] if frame["type"] == "error"]}

    def _damaged_image(self, request):
        result = self.call(request)
        expect(result["terminal"]["type"] in {"failed", "partial"}, "truncated image silently completed")
        expect(any(frame["type"] in {"error", "warning"} for frame in result["frames"]), "truncation lacks explicit diagnostic")
        return {"status": result["terminal"]["type"], "diagnostics": [frame["code"] for frame in result["frames"] if frame["type"] in {"error", "warning"}]}

    def _partial(self, fixture):
        result = self.call(self.request(fixture, maxFiles=1))
        expect(result["terminal"]["type"] == "partial", "maxFiles truncation silently completed")
        expect(len(result["files"]) <= 1, "maxFiles limit exceeded")
        expect(any(frame["type"] == "warning" for frame in result["frames"]), "partial listing needs explicit warning")

    def _inspect(self, fixture):
        result = self.call(self.request(fixture, "inspect", imageType="auto", sectorSize=0, hashLogicalImage=False))
        expect(result["terminal"]["type"] == "completed" and not result["files"], "inspect returned a listing or did not complete")
        images = [frame for frame in result["frames"] if frame["type"] == "image"]
        expect(len(images) == 1 and "logicalSha256" not in images[0], "inspect conflated an unrequested hash")
        expect(images[0]["logicalSize"] == fixture["logicalSize"] and images[0]["sectorSize"] == 512, "inspect metadata differs")
        expect(not any(frame["type"] in {"volume", "fileBatch"} for frame in result["frames"]), "inspect emitted listing/volume metadata outside the current contract")

    def _stable_ids(self, fixture):
        first = self.call(self.request(fixture, hashLogicalImage=False))["files"]
        second = self.call(self.request(fixture, hashLogicalImage=False))["files"]
        expect({row["path"]: row["id"] for row in first} == {row["path"]: row["id"] for row in second}, "entry IDs change across requests")

    def _cancel(self, fixture):
        result = self.call(self.request(fixture), cancel=True)
        expect(result["terminal"]["type"] == "cancelled", "cooperative cancellation was not acknowledged")

    def ewf(self, acquire: Path | None):
        if not acquire or not acquire.is_file():
            self.warnings.append("EWF creation was skipped: ewfacquire unavailable; RAW tests do not validate EWF support.")
            return
        source = self.fixtures["images"][0]
        prefix = self.run_dir / "synthetic-ewf"
        command = [str(acquire), "-u", "-c", "none", "-f", "encase6", "-S", "1048576", "-t", str(prefix), str(self.fixture_dir / source["path"])]
        process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=self.timeout)
        expect(process.returncode == 0, "ewfacquire failed: " + process.stderr.decode(errors="replace")[:1000])
        paths = sorted(self.run_dir.glob("synthetic-ewf.E[0-9][0-9]"))
        expect(len(paths) > 1, "split EWF fixture requires multiple segments")
        self.all_source_hashes.update({str(path): digest(path) for path in paths})
        # Requests accept explicit absolute paths, so use fixture-dir-relative .. references resolved before execution.
        fixture = dict(source, path=os.path.relpath(paths[0], self.fixture_dir),
                       imagePaths=[os.path.relpath(path, self.fixture_dir) for path in paths], imageType="ewf")
        self.check("split EWF logical bytes and extraction", lambda: self.enumeration(fixture))
        self.check("split EWF auto detection logical bytes", lambda: self.enumeration(dict(fixture, imageType="auto")))
        explicit_paths = [str(path) for path in paths]
        for label, altered in [("reversed segments", list(reversed(explicit_paths))),
                               ("missing first segment", explicit_paths[1:]),
                               ("missing last segment", explicit_paths[:-1]),
                               ("duplicate segment", explicit_paths + [explicit_paths[-1]]),
                               ("unlisted additional segments", explicit_paths[:1])]:
            self.check("EWF rejects " + label, lambda altered=altered: self.fail_request(self.request(fixture, imagePaths=altered)))
        if len(explicit_paths) > 2:
            self.check("EWF rejects missing middle segment", lambda: self.fail_request(self.request(fixture, imagePaths=explicit_paths[:1] + explicit_paths[2:])))
        self.check("EWF refuses raw interpretation", lambda: self.fail_request(self.request(fixture, imageType="raw")))
        corrupt = self.run_dir / "damaged.E01"
        damaged_bytes = bytearray(paths[0].read_bytes())
        damaged_bytes[:8] = b"BROKEN!!"
        corrupt.write_bytes(damaged_bytes)
        self.check("damaged EWF refuses auto raw fallback", lambda: self.fail_request(self.request(fixture, imageType="auto", imagePaths=[str(corrupt)])))
        raw_container_hash = digest(paths[0])
        expect(raw_container_hash != source["logicalSha256"], "container and logical hash scopes were conflated")
        # A complete singleton is different from the incomplete first segment above.
        # Only declared files may be opened, even when a sibling looks like E02.
        singleton_prefix = self.run_dir / "singleton"
        singleton_command = [str(acquire), "-u", "-c", "none", "-f", "encase6", "-S", "1073741824", "-t", str(singleton_prefix), str(self.fixture_dir / source["path"])]
        singleton_process = subprocess.run(singleton_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=self.timeout)
        expect(singleton_process.returncode == 0, "singleton EWF creation failed")
        singleton = self.run_dir / "singleton.E01"
        expect(singleton.is_file() and not (self.run_dir / "singleton.E02").exists(), "singleton EWF unexpectedly segmented")
        renamed = self.run_dir / "renamed.bin"
        renamed.write_bytes(singleton.read_bytes())
        sibling = self.run_dir / "singleton.E02"
        sibling.write_bytes(paths[1].read_bytes())
        self.all_source_hashes.update({str(path): digest(path) for path in (singleton, renamed, sibling)})
        singleton_fixture = dict(source, path=os.path.relpath(singleton, self.fixture_dir), imageType="ewf")
        self.check("complete singleton EWF ignores undeclared unrelated sibling", lambda: self.enumeration(singleton_fixture))
        renamed_fixture = dict(source, path=os.path.relpath(renamed, self.fixture_dir), imageType="auto")
        self.check("complete singleton EWF renamed .bin keeps logical scope", lambda: self.enumeration(renamed_fixture))

    def source_unchanged(self):
        for path, expected in self.all_source_hashes.items():
            expect(digest(Path(path)) == expected, "fixture source bytes changed: " + Path(path).name)
        expect(digest(self.helper) == self.helper_sha256, "helper binary changed during the suite")
        return {"verifiedSourceFiles": len(self.all_source_hashes), "helperUnchanged": True}

    def write_report(self):
        summary = {
            "schemaVersion": 1, "synthetic": True, "scope": "Native helper only; no GUI, mounted disk, real device, coursework evidence, or full Autopsy module parity.",
            "helper": str(self.helper), "startedUTC": datetime.datetime.fromtimestamp(self.started, datetime.timezone.utc).isoformat(),
            "helperSha256": self.helper_sha256,
            "passed": all(test["passed"] for test in self.tests), "passCount": sum(test["passed"] for test in self.tests),
            "failCount": sum(not test["passed"] for test in self.tests), "warnings": self.warnings, "tests": self.tests,
        }
        (self.run_dir / "report.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n")
        (self.output / "latest-report.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n")

    def run(self, acquire):
        for fixture in self.fixtures["images"]:
            label = "split RAW" if fixture.get("splitRaw") else fixture["path"]
            self.check(label + " enumerate/hash/extract UTC", lambda fixture=fixture: self.enumeration(fixture))
        bangkok_fixtures = [self.fixtures["images"][0], self.fixtures["images"][2], self.fixtures["images"][6]]
        bangkok_fixtures += [fixture for fixture in self.fixtures["images"] if fixture["path"] in {"fat16-year2038.raw", "fat16-year2100.raw"}]
        for fixture in bangkok_fixtures:
            self.check(fixture["path"] + " timestamp Asia/Bangkok", lambda fixture=fixture: self.enumeration(fixture, "Asia/Bangkok"))
        for fixture in self.fixtures["images"]:
            matrix = fixture.get("timestampMatrix", {})
            for timezone in matrix.get("requestTimezones", []):
                if timezone != "UTC":
                    self.check(fixture["path"] + " timestamp " + timezone, lambda fixture=fixture, timezone=timezone: self.enumeration(fixture, timezone))
            if matrix.get("hostTimezones"):
                self.check(fixture["path"] + " host timezone invariance", lambda fixture=fixture: self.host_timezone_invariance(fixture))
        self.safety()
        self.protocol()
        self.check("create EWF fixture", lambda: self.ewf(acquire))
        self.check("all original fixture sources unchanged", self.source_unchanged)
        self.write_report()
        print(str(self.run_dir / "report.json"), flush=True)
        return 0 if all(test["passed"] for test in self.tests) else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helper", type=Path, default=REPO / ".engine/bin/NFTSKEngine")
    parser.add_argument("--output", type=Path, default=REPO / "local/phase1-native-test")
    parser.add_argument("--ewfacquire", type=Path, default=REPO / ".engine/prefix/bin/ewfacquire")
    parser.add_argument("--timeout", type=float, default=45)
    parser.add_argument("--fixtures-only", action="store_true")
    options = parser.parse_args()
    if options.fixtures_only:
        result = generate(options.output / "fixtures")
        print("Generated " + str(len(result["images"])) + " synthetic image configurations")
        return 0
    if not options.helper.is_file():
        parser.error("Build the helper first; this runner never compiles it")
    return Runner(options.helper.resolve(), options.output.resolve(), options.timeout).run(options.ewfacquire)


if __name__ == "__main__":
    sys.exit(main())

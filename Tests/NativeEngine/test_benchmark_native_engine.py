#!/usr/bin/env python3
"""Correctness/safety tests for the measurement harness, not timing assertions."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from benchmark_fixtures import BLOCK_BYTES, LARGE_NAME, large_fat_image, payload_blocks, validate_export


REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("benchmark_native_engine", REPO / "script/benchmark_native_engine.py")
benchmark = importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchmark)


FAKE_HELPER = '''#!/usr/bin/env python3
import json, sys, time
request = json.loads(sys.stdin.readline())
if request.get("hang"):
    time.sleep(60)
body = bytearray(4 * 1024 * 1024)
end = time.monotonic() + 0.03
while time.monotonic() < end:
    body[0] = (body[0] + 1) % 256
time.sleep(0.05)
for sequence, fields in enumerate([
    {"type": "hello", "engineVersion": "synthetic", "patchDigest": "synthetic", "capabilities": []},
    {"type": "completed", "fileCount": 0},
]):
    print(json.dumps({"protocolVersion": 1, "jobID": request["jobID"], "sequence": sequence, **fields}), flush=True)
'''


class BenchmarkHarnessTests(unittest.TestCase):
    def setUp(self):
        (REPO / "local").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="benchmark-unit-", dir=REPO / "local")
        self.directory = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def fake_helper(self):
        path = self.directory / "SyntheticHelper"
        path.write_text(FAKE_HELPER)
        path.chmod(0o755)
        return path

    def test_large_payload_streaming_validation_detects_wrong_byte(self):
        length = BLOCK_BYTES + 17
        target = self.directory / "output.bin"
        sha256 = hashlib.sha256()
        with target.open("xb") as output:
            for block in payload_blocks(length):
                output.write(block)
                sha256.update(block)
        expected = {"size": length, "sha256": sha256.hexdigest(), "recipe": {"byteCount": length}}
        self.assertTrue(validate_export(target, expected)["exactBytesMatched"])
        with target.open("r+b") as output:
            output.seek(BLOCK_BYTES + 10)
            original = output.read(1)
            output.seek(-1, 1)
            output.write(bytes([original[0] ^ 1]))
        with self.assertRaisesRegex(AssertionError, "bytes differ"):
            validate_export(target, expected)

    def test_large_fat_chain_and_root_are_independently_inspectable(self):
        image = self.directory / "large.raw"
        manifest = large_fat_image(image, BLOCK_BYTES)
        file = next(row for row in manifest["files"] if row["path"] == LARGE_NAME)
        self.assertEqual(file["size"], BLOCK_BYTES)
        self.assertEqual(file["onDisk"]["clusterCount"], 256)
        with image.open("rb") as stream:
            boot = stream.read(512)
            reserved = struct.unpack_from("<H", boot, 14)[0]
            sector = struct.unpack_from("<H", boot, 11)[0]
            fat_sectors = struct.unpack_from("<I", boot, 36)[0]
            first = file["onDisk"]["firstCluster"]
            for index in range(2):
                stream.seek((reserved + index * fat_sectors) * sector + first * 4)
                chain = struct.unpack("<256I", stream.read(256 * 4))
                self.assertEqual(chain, tuple(range(first + 1, first + 256)) + (0x0FFFFFFF,))
            stream.seek(file["onDisk"]["rootEntryOffsetBytes"])
            root = stream.read(32)
            self.assertEqual(root[:11], b"BENCH128BIN")
            self.assertEqual(struct.unpack_from("<I", root, 28)[0], BLOCK_BYTES)
            self.assertEqual(struct.unpack_from("<H", root, 26)[0], first)

    def test_export_validation_refuses_symlink_without_reading_or_changing_target(self):
        target = self.directory / "target.bin"
        target.write_bytes(b"PRESERVE")
        link = self.directory / "export.bin"
        link.symlink_to(target)
        expected = {"size": 8, "sha256": hashlib.sha256(b"PRESERVE").hexdigest(), "payloadHex": b"PRESERVE".hex()}
        with self.assertRaises(OSError):
            validate_export(link, expected)
        self.assertEqual(target.read_bytes(), b"PRESERVE")

    def test_exact_owned_child_cpu_receipts_and_worker_bound(self):
        helper = self.fake_helper()
        requests = [{"jobID": str(index)} for index in range(6)]
        result = benchmark.NativeBatch(helper, 2, 5, 0.01).run(requests)
        self.assertEqual(result["maximumLiveHelpers"], 2)
        self.assertEqual(len(result["jobs"]), 6)
        self.assertGreater(result["userCPUSeconds"] + result["systemCPUSeconds"], 0)
        self.assertGreater(result["largestIndividualKernelPeakRSSBytes"], 0)
        self.assertGreater(result["rssSampler"]["sampleCount"], 0)
        self.assertLessEqual(result["rssSampler"]["maximumObservedHelperCount"], 2)
        for request, response in zip(requests, result["jobs"]):
            frames = benchmark.parse_response(request, response)
            self.assertEqual(frames[1]["jobID"], request["jobID"])
            with self.assertRaises(ChildProcessError):
                os.waitpid(response["process"].pid, os.WNOHANG)

    def test_timeout_reaps_only_owned_helpers_and_preserves_input(self):
        helper = self.fake_helper()
        baseline = helper.read_bytes()
        batch = benchmark.NativeBatch(helper, 2, 0.02, 0.01)
        with self.assertRaisesRegex(AssertionError, "timeout"):
            batch.run([{"jobID": "hang", "hang": True}])
        self.assertEqual(helper.read_bytes(), baseline)
        self.assertFalse(batch.sampler.pids)
        for pid, job in batch.owned.items():
            self.assertIsNotNone(job["returncode"])
            with self.assertRaises(ChildProcessError):
                os.waitpid(pid, os.WNOHANG)

    def test_protocol_rejects_partial_instead_of_counting_less_work(self):
        request = {"jobID": "synthetic"}
        frames = [
            {"type": "hello", "engineVersion": "synthetic", "patchDigest": "synthetic"},
            {"type": "partial", "fileCount": 0},
        ]
        output = b"\n".join(json.dumps({"protocolVersion": 1, "jobID": request["jobID"], "sequence": index, **frame}).encode()
                            for index, frame in enumerate(frames))
        with self.assertRaisesRegex(AssertionError, "successfully"):
            benchmark.parse_response(request, {"stdout": output, "returncode": 0})

    def test_pipe_overflow_always_reaps_stops_sampler_and_closes_selector(self):
        helper = self.directory / "FloodHelper"
        for channel in ("stdout", "stderr"):
            with self.subTest(channel=channel):
                helper.write_text("#!/usr/bin/env python3\nimport sys,time\nsys.stdin.readline()\n"
                                  f"sys.{channel}.buffer.write(b'x' * 65536)\nsys.{channel}.flush()\ntime.sleep(60)\n")
                helper.chmod(0o755)
                batch = benchmark.NativeBatch(helper, 1, 5, 0.002)
                with mock.patch.object(benchmark, "RESPONSE_LIMIT", 1024):
                    with self.assertRaisesRegex(AssertionError, "pipe bound"):
                        batch.run([{"jobID": "flood"}])
                self.assertFalse(batch.sampler.thread.is_alive())
                self.assertFalse(batch.sampler.pids)
                self.assertIsNone(batch.selector.get_map())
                for pid, job in batch.owned.items():
                    self.assertIsNotNone(job["returncode"])
                    with self.assertRaises(ChildProcessError):
                        os.waitpid(pid, os.WNOHANG)


if __name__ == "__main__":
    unittest.main()

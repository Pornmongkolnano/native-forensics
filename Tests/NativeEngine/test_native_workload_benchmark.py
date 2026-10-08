#!/usr/bin/env python3
"""Independent fixture/receipt/safety checks; no timing thresholds or builds."""
from __future__ import annotations

import copy
import errno
import hashlib
import importlib.util
import json
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("native_workload_benchmark", REPO / "script/native_workload_benchmark.py")
benchmark = importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchmark)


class WorkloadFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (REPO / "local").mkdir(exist_ok=True)
        cls.temporary = tempfile.TemporaryDirectory(prefix="workload-unit-", dir=REPO / "local")
        cls.directory = Path(cls.temporary.name)
        cls.fixture = cls.directory / "fixture"
        cls.oracle = benchmark.generate(cls.fixture, benchmark.MINIMUM_IMAGE_BYTES)
        cls.output = benchmark.exclusive_directory(cls.directory / "verified")
        cls.receipt = {"schemaVersion": 1, "syntheticOnly": True, "providerExecuted": False,
                       "measurementKind": "ForensicsCore-headless-workflow", "mode": "workflow",
                       "sourceBeforeSHA256": cls.oracle["imageSHA256"], "sourceAfterSHA256": cls.oracle["imageSHA256"],
                       "metadataBeforeSHA256": cls.oracle["metadataSHA256"], "metadataAfterSHA256": cls.oracle["metadataSHA256"],
                       "counts": cls.oracle["expectedCounts"], "missingListingCount": 1,
                       "indexReopened": True, "manifestUnchanged": True, "searchHits": cls.oracle["queries"],
                       "stageSeconds": {"contentIndexBuild": .01}, "verifiedFiles": {}, "batchExportFiles": {},
                       "documents": {}, "decoded": {}}
        for category in ("verifiedFiles", "batchExportFiles"):
            exports = benchmark.exclusive_directory(cls.output / category)
            for path, file in cls.oracle["files"].items():
                target = exports / path[1:]
                with target.open("xb") as stream:
                    for chunk in benchmark.recipe_blocks(file["payloadRecipe"]):
                        stream.write(chunk)
                cls.receipt[category][path] = {"byteCount": file["byteCount"], "sha256": file["sha256"],
                                              "exportFile": category + path}
        for path, file in cls.oracle["files"].items():
            pages = [{"pageNumber": 1, "text": file["text"], "isTruncated": path == "/LARGE.TXT"}] if "text" in file else []
            cls.receipt["documents"][path] = {"status": file["indexStatus"], "reason": file["indexReason"],
                "textPages": pages if file["indexStatus"] == "indexed" else [], "textIsComplete": file["textIsComplete"],
                "contentSHA256": file["sha256"] if file["indexStatus"] == "indexed" else None}
            if path != "/OVER.TXT":
                cls.receipt["decoded"][path] = {"status": "unsupported" if file["indexReason"] == "UNSUPPORTED_CONTENT" else "decoded",
                    "sourceSHA256": file["sha256"], "textPages": pages, "textIsComplete": file["textIsComplete"]}

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.write_receipt(self.receipt)

    def write_receipt(self, value):
        (self.output / "workload-receipt.json").write_text(json.dumps(value, ensure_ascii=False))

    def test_real_fat32_geometry_chain_sparse_size_and_exact_mixed_payloads(self):
        oracle = benchmark.load_fixture(self.fixture)
        self.assertEqual(oracle["imageByteCount"], 256 * 1024 * 1024)
        self.assertGreaterEqual(oracle["geometry"]["clusterCount"], 65525)
        self.assertEqual(oracle["expectedCounts"], {"indexed": 4, "skipped": 6, "pending": 0, "failed": 0})
        with (self.fixture / benchmark.IMAGE_NAME).open("rb") as stream:
            boot = stream.read(512)
            self.assertEqual(struct.unpack_from("<H", boot, 11)[0], 512)
            self.assertEqual(boot[13], 1)
            self.assertEqual(struct.unpack_from("<I", boot, 44)[0], 2)
            self.assertEqual(boot[510:512], b"\x55\xaa")
            file = oracle["files"]["/LARGE.TXT"]
            self.assertEqual(file["byteCount"], 32 * 1024 * 1024)
            self.assertEqual(file["onDisk"]["clusterCount"], 65536)
            first = file["onDisk"]["firstCluster"]
            for copy_index in range(2):
                stream.seek((32 + copy_index * oracle["geometry"]["fatSectors"]) * 512 + first * 4)
                self.assertEqual(struct.unpack("<I", stream.read(4))[0], first + 1)
                stream.seek((32 + copy_index * oracle["geometry"]["fatSectors"]) * 512 + (first + 65535) * 4)
                self.assertEqual(struct.unpack("<I", stream.read(4))[0], 0x0fffffff)
            for path, expected in oracle["files"].items():
                if path in benchmark.VIRTUAL_FILES:
                    continue
                stream.seek(expected["onDisk"]["rootEntryOffsetBytes"])
                row = stream.read(32)
                self.assertEqual(row[:11], path[1:].split(".")[0].ljust(8).encode() + path.split(".")[1].ljust(3).encode())
                self.assertEqual(struct.unpack_from("<I", row, 28)[0], expected["byteCount"])
        self.assertEqual(oracle["files"]["/OVER.TXT"]["byteCount"], 32 * 1024 * 1024 + 1)
        self.assertEqual(len(oracle["files"]["/LARGE.TXT"]["text"].encode()), 1024 * 1024)
        self.assertEqual(oracle["files"]["/LARGE.TXT"]["text"].count("largeNeedle"), 1)
        self.assertFalse(oracle["files"]["/LARGE.TXT"]["textIsComplete"])
        self.assertIn(0, bytes.fromhex(oracle["files"]["/UNKNOWN.BIN"]["payloadRecipe"]["hex"]))

    def test_exact_payload_hash_and_utf16_literal_ranges_including_combining_and_surrogate(self):
        self.assertEqual(self.oracle["files"]["/ALPHA.TXT"]["sha256"], hashlib.sha256(benchmark.ALPHA).hexdigest())
        for query, hits in self.oracle["queries"].items():
            for hit in hits:
                data = self.oracle["files"][hit["path"]]["text"].encode("utf-16le")
                piece = data[hit["utf16Offset"] * 2:(hit["utf16Offset"] + hit["utf16Length"]) * 2].decode("utf-16le")
                self.assertEqual(piece, query)
        self.assertEqual(self.oracle["queries"]["notPresentInAnyPayload"], [])
        self.assertEqual(len(self.oracle["queries"]["้"]), 2)
        files = {"/SYNTH.TXT": {"indexStatus": "indexed", "text": "😀ก้เอกสาร"}}
        self.assertEqual(benchmark.search_oracle(files, ("้", "เอกสาร")), {
            "้": [{"path": "/SYNTH.TXT", "utf16Offset": 3, "utf16Length": 1}],
            "เอกสาร": [{"path": "/SYNTH.TXT", "utf16Offset": 4, "utf16Length": 6}]})

    def test_full_independent_export_and_decode_oracle_passes_and_detects_wrong_export_byte(self):
        self.assertEqual(benchmark.verify(self.fixture, self.output)["independentBytesVerified"], 20)
        target = self.output / self.receipt["batchExportFiles"]["/LARGE.TXT"]["exportFile"]
        with target.open("r+b") as stream:
            stream.seek(1024 * 1024 + 9); original = stream.read(1)
            stream.seek(-1, 1); stream.write(b"Z")
        try:
            with self.assertRaisesRegex(ValueError, "recipe bytes differ"):
                benchmark.verify(self.fixture, self.output)
        finally:
            with target.open("r+b") as stream:
                stream.seek(1024 * 1024 + 9); stream.write(original)

    def test_wrong_search_range_and_fabricated_complete_large_text_are_rejected(self):
        receipt = copy.deepcopy(self.receipt)
        receipt["searchHits"]["้"][0]["utf16Offset"] += 1
        self.write_receipt(receipt)
        with self.assertRaisesRegex(ValueError, "UTF-16 search ranges"):
            benchmark.verify(self.fixture, self.output)
        receipt = copy.deepcopy(self.receipt)
        receipt["decoded"]["/LARGE.TXT"]["textIsComplete"] = True
        self.write_receipt(receipt)
        with self.assertRaisesRegex(ValueError, "decoder hash/coverage"):
            benchmark.verify(self.fixture, self.output)

    def test_no_whole_image_read_bytes_during_source_or_payload_verification(self):
        with mock.patch.object(Path, "read_bytes", side_effect=AssertionError("unbounded read_bytes forbidden")):
            self.assertEqual(benchmark.load_fixture(self.fixture)["imageSHA256"], self.oracle["imageSHA256"])

    def test_reuse_symlink_and_escaping_export_paths_are_rejected_without_target_changes(self):
        with self.assertRaises(FileExistsError):
            benchmark.generate(self.fixture, benchmark.MINIMUM_IMAGE_BYTES)
        real = self.directory / "preserve"
        real.mkdir(exist_ok=True)
        target = real / "target"
        target.write_bytes(b"PRESERVE")
        link = self.directory / "link"
        link.symlink_to(real)
        try:
            with self.assertRaisesRegex(ValueError, "symlinks"):
                benchmark.exclusive_directory(link / "new-output")
            with self.assertRaisesRegex(ValueError, "escaped"):
                benchmark.export_path(self.output, "../preserve/target")
            file_link = self.output / "linked-target"
            file_link.symlink_to(target)
            try:
                with self.assertRaisesRegex(ValueError, "Symlink"):
                    benchmark.export_path(self.output, "linked-target")
            finally:
                file_link.unlink()
            self.assertEqual(target.read_bytes(), b"PRESERVE")
        finally:
            link.unlink()

    def test_cache_advisory_does_not_claim_eviction_and_does_not_change_input(self):
        source = self.fixture / benchmark.METADATA_NAME
        before = benchmark.file_identity(source.stat())
        sha256, advisory = benchmark.hash_file(source, nocache=True)
        self.assertEqual(sha256, self.oracle["metadataSHA256"])
        self.assertTrue(advisory["requested"])
        self.assertFalse(advisory["cacheEvictionVerified"])
        self.assertIn("independent descriptors", advisory["scope"])
        self.assertEqual(before, benchmark.file_identity(source.stat()))
        self.assertEqual(benchmark.REGIMES[1], "cold-requested-OS-cache-uncertain")

    def test_cache_request_uses_darwin_f_nocache_on_read_only_descriptor(self):
        source = self.fixture / benchmark.METADATA_NAME
        with mock.patch.object(benchmark.sys, "platform", "darwin"), mock.patch("fcntl.fcntl") as advisory_call:
            _, advisory = benchmark.hash_file(source, nocache=True)
        self.assertTrue(advisory["applied"])
        self.assertFalse(advisory["cacheEvictionVerified"])
        self.assertEqual(advisory_call.call_args.args[1:], (48, 1))

    def test_listing_oracle_checks_exact_ids_and_distinguishes_derived_million_rows(self):
        rows = 1000000
        expected = hashlib.sha256()
        for offset in range(0, rows, 8):
            expected.update(f"row-{offset}\n".encode())
        receipt = {"schemaVersion": 1, "syntheticOnly": True, "providerExecuted": False, "mode": "listing",
                   "rows": rows, "productionCap": 50000, "productionCount": 50000,
                   "matchingRows": 125000, "matchingIDsSHA256": expected.hexdigest(),
                   "measurementKind": "derived-harness-only", "stageSeconds": {"generation": .1},
                   "searchSamplesSeconds": [.01] * 5}
        self.assertTrue(benchmark.validate_auxiliary_receipt(receipt, "listing", rows)["listingIDsOraclePassed"])
        receipt["matchingIDsSHA256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "independent literal oracle"):
            benchmark.validate_auxiliary_receipt(receipt, "listing", rows)

    def test_cancel_requires_drain_and_source_immutability(self):
        receipt = {key: value for key, value in self.receipt.items() if key in {
            "schemaVersion", "syntheticOnly", "providerExecuted", "stageSeconds", "sourceBeforeSHA256", "sourceAfterSHA256",
            "metadataBeforeSHA256", "metadataAfterSHA256"}}
        receipt.update(mode="cancel", cancelled=True, newScratchRemaining=0)
        self.assertTrue(benchmark.validate_auxiliary_receipt(receipt, "cancel", 50000, self.oracle)["cancellationReceiptPassed"])
        receipt["newScratchRemaining"] = 1
        with self.assertRaisesRegex(ValueError, "drained scratch"):
            benchmark.validate_auxiliary_receipt(receipt, "cancel", 50000, self.oracle)

    def test_failed_measurement_is_durable_before_exit_validation(self):
        probe = self.directory / "failed-probe"
        probe.write_text("#!/usr/bin/env python3\nimport sys\nsys.exit(7)\n")
        probe.chmod(0o755)
        destination = self.directory / "failed-run"
        with self.assertRaisesRegex(ValueError, "Probe failed"):
            benchmark.run(destination, probe, probe, probe, fixture=self.fixture)
        logs = destination / "workflow-warm-prehashed-01-driver"
        process = benchmark.read_json(logs / "process-attempt.json")
        attempt = benchmark.read_json(logs / "measurement-attempt.json")
        failure = benchmark.read_json(logs / "failed-attempt.json")
        self.assertEqual(process["returncode"], 7)
        self.assertEqual(attempt["validationState"], "not-started")
        self.assertEqual(failure["validationState"], "failed")
        self.assertEqual(failure["measurement"]["returncode"], 7)
        self.assertIn("recipeSHA256", failure["provenance"])


class WorkloadMeasurementTests(unittest.TestCase):
    def setUp(self):
        (REPO / "local").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="workload-process-unit-", dir=REPO / "local")
        self.directory = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_descendant_closure_includes_app_helper_grandchild_and_excludes_unrelated(self):
        rows = {11: (1, 100), 12: (11, 200), 13: (12, 300), 14: (1, 999), 15: (14, 999)}
        self.assertEqual(benchmark.descendant_pids(rows, 11), {11, 12, 13})
        self.assertEqual(benchmark.descendant_pids(rows, 99), set())

    def test_exact_wait4_and_timestamped_full_tree_rss_receipts(self):
        source = self.directory / "probe.py"
        source.write_text("import subprocess,sys\n"
                          "p=subprocess.Popen([sys.executable,'-c','import time; data=bytearray(8*1024*1024); time.sleep(.25)'])\n"
                          "p.wait()\n")
        output = benchmark.exclusive_directory(self.directory / "logs")
        receipt = benchmark.launch_probe([sys.executable, str(source)], output, 5, .01)
        self.assertEqual(receipt["returncode"], 0)
        self.assertGreater(receipt["wait4"]["kernelReportedMaximumRSSBytes"], 0)
        self.assertGreaterEqual(receipt["rssSampler"]["maximumObservedProcessCount"], 2)
        self.assertGreater(receipt["rssSampler"]["appPeakRSSSampledBytes"], 0)
        self.assertGreater(receipt["rssSampler"]["helpersPeakRSSSampledBytes"], 0)
        self.assertIsNotNone(receipt["rssSampler"]["firstHelperObservedPID"])
        self.assertTrue(receipt["rssSampler"]["samples"])
        self.assertIsNotNone(receipt["rssSampler"]["actualIntervalMedianSeconds"])
        with self.assertRaises(ChildProcessError):
            os.waitpid(receipt["wait4"]["pid"], os.WNOHANG)

    def test_timeout_reaps_exact_child_and_rejects_bad_interval_before_launch(self):
        output = benchmark.exclusive_directory(self.directory / "timeout")
        with self.assertRaisesRegex(ValueError, "process timeout"):
            benchmark.launch_probe([sys.executable, "-c", "import time; time.sleep(60)"], output, .03, .01)
        attempt = benchmark.read_json(output / "process-attempt.json")
        self.assertTrue(attempt["timedOut"])
        with self.assertRaises(ChildProcessError):
            os.waitpid(attempt["wait4"]["pid"], os.WNOHANG)
        output = benchmark.exclusive_directory(self.directory / "invalid")
        with mock.patch.object(benchmark.subprocess, "Popen") as launch:
            with self.assertRaisesRegex(ValueError, "RSS interval"):
                benchmark.launch_probe([sys.executable], output, 5, 0)
            launch.assert_not_called()

    @staticmethod
    def valid_measurement():
        sample = {"atMonotonicSeconds": 1.0, "rssBytes": 4096, "appRSSBytes": 4096,
                  "helpersRSSBytes": 0, "processCount": 1, "pids": [123]}
        return {"returncode": 0, "terminalExitObserved": True, "lifecycleErrors": [], "wallSeconds": .1,
                "timedOut": False, "wait4": {"pid": 123, "kernelReportedMaximumRSSBytes": 8192},
                "rssSampler": {"available": True, "rootPID": 123, "sampleCount": 1, "samples": [sample],
                    "failedSamples": [], "appPeakRSSSampledBytes": 4096, "helpersPeakRSSSampledBytes": 0,
                    "aggregatePeakRSSSampledBytes": 4096, "maximumObservedProcessCount": 1,
                    "distinctHelperPIDsObserved": 0, "firstHelperObservedPID": None}}

    def test_rss_requires_actual_valid_samples_and_exact_retained_peaks(self):
        benchmark.validate_rss_measurement(self.valid_measurement(), history_only=True)
        changes = [({"sampleCount": 0, "samples": []}, "missing or failed"),
                   ({"failedSamples": ["owned RSS read unavailable"]}, "missing or failed"),
                   ({"appPeakRSSSampledBytes": None}, "peak differs"),
                   ({"aggregatePeakRSSSampledBytes": 9999}, "peak differs")]
        for change, message in changes:
            with self.subTest(change=change):
                receipt = self.valid_measurement()
                receipt["rssSampler"].update(change)
                with self.assertRaisesRegex(ValueError, message):
                    benchmark.validate_rss_measurement(receipt, history_only=True)
        for field, value, message in (("appRSSBytes", float("nan"), "byte values"),
                                      ("atMonotonicSeconds", float("inf"), "timestamp"),
                                      ("pids", [999], "inventory")):
            with self.subTest(field=field):
                receipt = self.valid_measurement()
                receipt["rssSampler"]["samples"][0][field] = value
                with self.assertRaisesRegex(ValueError, message):
                    benchmark.validate_rss_measurement(receipt, history_only=True)

    def test_history_rss_rejects_helpers_but_generic_tree_measurement_accepts_them(self):
        receipt = self.valid_measurement()
        receipt["rssSampler"]["samples"][0].update(pids=[123, 124], processCount=2,
                                                        helpersRSSBytes=2048, rssBytes=6144)
        receipt["rssSampler"].update(helpersPeakRSSSampledBytes=2048, aggregatePeakRSSSampledBytes=6144,
                                      maximumObservedProcessCount=2, distinctHelperPIDsObserved=1,
                                      firstHelperObservedPID=124)
        benchmark.validate_rss_measurement(receipt)
        with self.assertRaisesRegex(ValueError, "spawned descendants"):
            benchmark.validate_rss_measurement(receipt, history_only=True)

    def test_sampler_setup_failure_waits_for_and_retains_natural_exact_exit(self):
        output = benchmark.exclusive_directory(self.directory / "sampler-setup-failure")
        with mock.patch.object(benchmark, "TreeRSSSampler", side_effect=RuntimeError("sampler setup failed")):
            with self.assertRaisesRegex(ValueError, "lifecycle failed"):
                benchmark.launch_probe([sys.executable, "-c", "import time; time.sleep(.05)"], output, 5, .01)
        attempt = benchmark.read_json(output / "process-attempt.json")
        self.assertTrue(attempt["terminalExitObserved"])
        self.assertEqual(attempt["returncode"], 0)
        self.assertFalse(attempt["rssSampler"]["available"])
        self.assertEqual(attempt["lifecycleErrors"][0]["phase"], "sampler-start")
        with self.assertRaises(ChildProcessError):
            os.waitpid(attempt["wait4"]["pid"], os.WNOHANG)

    def test_sampler_stop_failure_does_not_erase_wait4_status(self):
        output = benchmark.exclusive_directory(self.directory / "sampler-stop-failure")
        original_stop = benchmark.TreeRSSSampler.stop
        def failed_stop(sampler):
            original_stop(sampler)
            raise RuntimeError("sampler stop failed after joining")
        with mock.patch.object(benchmark.TreeRSSSampler, "stop", failed_stop):
            with self.assertRaisesRegex(ValueError, "lifecycle failed"):
                benchmark.launch_probe([sys.executable, "-c", "import time; time.sleep(.05)"], output, 5, .01)
        attempt = benchmark.read_json(output / "process-attempt.json")
        self.assertTrue(attempt["terminalExitObserved"])
        self.assertEqual(attempt["returncode"], 0)
        self.assertEqual(attempt["lifecycleErrors"][0]["phase"], "sampler-stop")
        with self.assertRaises(ChildProcessError):
            os.waitpid(attempt["wait4"]["pid"], os.WNOHANG)

    def test_waiter_start_failure_uses_one_fallback_reaper_and_retains_terminal_status(self):
        output = benchmark.exclusive_directory(self.directory / "waiter-start-failure")
        original_start = benchmark.threading.Thread.start
        def failed_waiter_start(thread):
            if thread.name == "workload-exact-wait4":
                raise RuntimeError("waiter start unavailable")
            original_start(thread)
        with mock.patch.object(benchmark.threading.Thread, "start", failed_waiter_start):
            with self.assertRaisesRegex(ValueError, "lifecycle failed"):
                benchmark.launch_probe([sys.executable, "-c", "import time; time.sleep(.05)"], output, 5, .01)
        attempt = benchmark.read_json(output / "process-attempt.json")
        self.assertEqual(attempt["returncode"], 0)
        self.assertTrue(attempt["terminalExitObserved"])
        self.assertIn("fallback", attempt["exitObservation"])
        with self.assertRaises(ChildProcessError):
            os.waitpid(attempt["wait4"]["pid"], os.WNOHANG)

    def test_wait4_failure_hands_off_to_one_bounded_reaper_without_losing_terminal_status(self):
        output = benchmark.exclusive_directory(self.directory / "wait4-once-failure")
        original_wait4, calls = os.wait4, []
        def fail_once(pid, flags):
            calls.append((pid, flags))
            if len(calls) == 1:
                raise OSError(errno.EIO, "injected wait4 failure")
            return original_wait4(pid, flags)
        with mock.patch.object(benchmark.os, "wait4", fail_once):
            with self.assertRaisesRegex(ValueError, "lifecycle failed"):
                benchmark.launch_probe([sys.executable, "-c", "import time; time.sleep(.05)"], output, 5, .01)
        attempt = benchmark.read_json(output / "process-attempt.json")
        self.assertEqual(attempt["returncode"], 0)
        self.assertTrue(attempt["terminalExitObserved"])
        self.assertEqual(attempt["lifecycleErrors"][0]["phase"], "waiter-reap")
        self.assertEqual(calls[0][1], 0)
        self.assertTrue(all(pid == attempt["wait4"]["pid"] and flags == os.WNOHANG for pid, flags in calls[1:]))
        with self.assertRaises(ChildProcessError):
            os.waitpid(attempt["wait4"]["pid"], os.WNOHANG)


FAKE_HISTORY_PROBE = r'''#!/usr/bin/env python3
import argparse,hashlib,json,os,time
from pathlib import Path
p=argparse.ArgumentParser()
p.add_argument('--mode');p.add_argument('--root');p.add_argument('--records',type=int);p.add_argument('--prompt-bytes',type=int)
a=p.parse_args();root=Path(a.root);case=root/'History Benchmark.nativecase';analyses=case/'analyses'
source=b'owned synthetic source\n';request=hashlib.sha256(b'H'*a.prompt_bytes).hexdigest()
ids=[f'00000000-0000-0000-0000-{i:012d}' for i in range(1,a.records+1)]
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
if a.mode=='generate':
    analyses.mkdir(parents=True)
    (root/'synthetic-source.dd').write_bytes(source)
    (case/'manifest.json').write_text(json.dumps({'schemaVersion':1,'syntheticOnly':True}))
    for i,id in enumerate(ids,1):
        record={'schemaVersion':1,'id':id.upper(),'retention':'full','prompt':'H'*a.prompt_bytes,'requestSHA256':request,
                'result':{'requestSHA256':request,'response':{'summary':f'Synthetic local history receipt {i}'}}}
        (analyses/(id+'.json')).write_text(json.dumps(record))
sizes=[(analyses/(id+'.json')).stat().st_size for id in ids]
fixture={'syntheticOnly':True,'providerRequests':0,'recordCount':a.records,'promptBytes':a.prompt_bytes,
         'manifestSHA256':sha(case/'manifest.json'),'sourceSHA256':sha(root/'synthetic-source.dd'),
         'serializedTotalBytes':sum(sizes),'maximumSerializedRecordBytes':max(sizes),'generationSeconds':0}
if a.mode=='generate':
    (root/'history-fixture-receipt.json').write_text(json.dumps(fixture));print(json.dumps(fixture))
else:
    time.sleep(.12)  # Leave an observation window; this fake has no timing assertion.
    newest=list(reversed(ids));pages=[newest[i:i+50] for i in range(0,len(newest),50)]
    print(json.dumps({'schemaVersion':1,'syntheticOnly':True,'providerRequests':0,'processID':os.getpid(),
        'recordCount':a.records,'promptBytes':a.prompt_bytes,'requestSHA256':request,'serializedTotalBytes':sum(sizes),
        'maximumSerializedRecordBytes':max(sizes),'maximumScanSerializedBytes':max(sizes),'historyPages':pages,
        'exactOrderVerified':True,'everyStoredRequestVerified':True,'originalManifestUnchanged':True,
        'originalSourceUnchanged':True,'originalManifestSHA256':fixture['manifestSHA256'],'originalSourceSHA256':fixture['sourceSHA256'],
        'generationSeconds':0,'historyScanSeconds':.001,'verifySeconds':.002}))
'''


class HistoryWorkloadTests(unittest.TestCase):
    def setUp(self):
        (REPO / "local").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="history-workload-unit-", dir=REPO / "local")
        self.directory = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def fixture(self, records=120, prompt_bytes=64):
        fixture = benchmark.exclusive_directory(self.directory / "fixture")
        case = benchmark.exclusive_directory(fixture / benchmark.HISTORY_CASE_NAME)
        analyses = benchmark.exclusive_directory(case / "analyses")
        source = fixture / "synthetic-source.dd"
        source.write_bytes(benchmark.HISTORY_SOURCE_BYTES)
        (case / "manifest.json").write_text(json.dumps({"schemaVersion": 1, "syntheticOnly": True}))
        request = hashlib.sha256(b"H" * prompt_bytes).hexdigest()
        sizes = []
        for index, record_id in enumerate(benchmark.history_ids(records), 1):
            record = {"schemaVersion": 1, "id": record_id.upper(), "retention": "full", "prompt": "H" * prompt_bytes,
                      "requestSHA256": request, "result": {"requestSHA256": request,
                      "response": {"summary": f"Synthetic local history receipt {index}"}}}
            path = analyses / (record_id + ".json")
            path.write_text(json.dumps(record))
            sizes.append(path.stat().st_size)
        benchmark.write_json(fixture / "history-fixture-receipt.json", {
            "syntheticOnly": True, "providerRequests": 0, "recordCount": records, "promptBytes": prompt_bytes,
            "sourceSHA256": benchmark.hash_file(source)[0], "manifestSHA256": benchmark.hash_file(case / "manifest.json")[0],
            "serializedTotalBytes": sum(sizes), "maximumSerializedRecordBytes": max(sizes), "generationSeconds": 0})
        return fixture

    def scan_receipt(self, baseline, pid=123):
        receipt = {key: baseline[key] for key in ("recordCount", "promptBytes", "requestSHA256", "serializedTotalBytes",
                                                   "maximumSerializedRecordBytes", "historyPages")}
        receipt.update(schemaVersion=1, syntheticOnly=True, providerRequests=0, processID=pid,
                       maximumScanSerializedBytes=baseline["maximumSerializedRecordBytes"], exactOrderVerified=True,
                       everyStoredRequestVerified=True, originalManifestUnchanged=True, originalSourceUnchanged=True,
                       originalManifestSHA256=baseline["sourceStates"]["manifest"]["sha256"],
                       originalSourceSHA256=baseline["sourceStates"]["source"]["sha256"], generationSeconds=0,
                       historyScanSeconds=.001, verifySeconds=.002)
        return receipt

    def fake_probe(self):
        probe = self.directory / "fake-history-probe"
        probe.write_text(FAKE_HISTORY_PROBE)
        probe.chmod(0o755)
        return probe

    def test_linked_history_graph_covers_package_core_ipc_sqlite_and_detects_changed_inputs(self):
        root = self.directory / "source-root"
        names = {"Package.swift", "script/native_workload_benchmark.py",
                 "Sources/CaseHistoryWorkloadProbe/CaseHistoryWorkloadProbe.swift",
                 "Sources/ForensicsCore/CaseWork/CaseWorkStore.swift",
                 "Sources/NFDecoderIPC/NFDecoderIPC.m", "Sources/NFDecoderIPC/include/NFDecoderIPC.h",
                 "Sources/CSQLite3/shim.h", "Sources/CSQLite3/module.modulemap"}
        for name in names:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("owned source " + name)
        with mock.patch.object(benchmark, "ROOT", root):
            before = benchmark.history_input_graph()
            self.assertEqual(set(before), names)
            core = root / "Sources/ForensicsCore/CaseWork/CaseWorkStore.swift"
            core.write_text("changed Core bytes")
            self.assertNotEqual(benchmark.history_input_graph()[core.relative_to(root).as_posix()],
                                before[core.relative_to(root).as_posix()])
            extra = root / "Sources/ForensicsCore/Added.swift"
            extra.write_text("new linked input")
            self.assertIn("Sources/ForensicsCore/Added.swift", benchmark.history_input_graph())
            ipc = root / "Sources/NFDecoderIPC/include/NFDecoderIPC.h"
            ipc.unlink()
            with self.assertRaisesRegex(ValueError, "missing linked target"):
                benchmark.history_input_graph()
            ipc.symlink_to(core)
            with self.assertRaisesRegex(ValueError, "Linked history source"):
                benchmark.history_input_graph()

    def test_120_record_oracle_verifies_literal_requests_newest_pages_and_stat_totals(self):
        fixture = self.fixture()
        baseline = benchmark.validate_history_fixture(fixture, 120, 64)
        self.assertEqual([len(page) for page in baseline["historyPages"]], [50, 50, 20])
        self.assertEqual(baseline["historyPages"][0], list(reversed(benchmark.history_ids(120)))[0:50])
        self.assertEqual(baseline["historyPages"][1], list(reversed(benchmark.history_ids(120)))[50:100])
        self.assertEqual(baseline["historyPages"][2], list(reversed(benchmark.history_ids(120)))[100:120])
        self.assertEqual(baseline["requestSHA256"], hashlib.sha256(b"H" * 64).hexdigest())
        self.assertEqual(baseline["serializedTotalBytes"], sum(row["byteCount"] for row in baseline["recordStates"].values()))
        self.assertEqual(len(baseline["recordStates"]), 120)
        self.assertTrue(all(set(row) == {"identity", "sha256", "byteCount"} for row in baseline["recordStates"].values()))
        self.assertEqual(benchmark.validate_history_fixture(fixture, 120, 64), baseline)

    def test_600k_prompt_is_bounded_and_oracle_never_uses_whole_file_read_bytes(self):
        fixture = self.fixture(records=1, prompt_bytes=614400)
        with mock.patch.object(Path, "read_bytes", side_effect=AssertionError("unbounded read_bytes forbidden")):
            baseline = benchmark.validate_history_fixture(fixture, 1, 614400)
        self.assertLessEqual(baseline["maximumSerializedRecordBytes"], 1024 * 1024)
        self.assertEqual(baseline["requestSHA256"], hashlib.sha256(b"H" * 614400).hexdigest())

    def test_wrong_prompt_and_result_summary_are_independently_rejected(self):
        fixture = self.fixture(records=1)
        path = fixture / benchmark.HISTORY_CASE_NAME / "analyses" / (benchmark.history_ids(1)[0] + ".json")
        record = json.loads(path.read_text())
        record["prompt"] = "X" + "H" * 63
        path.write_text(json.dumps(record))
        with self.assertRaisesRegex(ValueError, "stored prompt literal"):
            benchmark.validate_history_fixture(fixture, 1, 64)
        record["prompt"] = "H" * 64
        record["result"]["response"]["summary"] = "Synthetic local history receipt 9"
        path.write_text(json.dumps(record))
        with self.assertRaisesRegex(ValueError, "literal summary"):
            benchmark.validate_history_fixture(fixture, 1, 64)

    def test_wrong_hash_record_id_and_oversize_record_are_rejected(self):
        fixture = self.fixture(records=1)
        path = fixture / benchmark.HISTORY_CASE_NAME / "analyses" / (benchmark.history_ids(1)[0] + ".json")
        record = json.loads(path.read_text())
        record["requestSHA256"] = "0" * 64
        path.write_text(json.dumps(record))
        with self.assertRaisesRegex(ValueError, "stored request hash"):
            benchmark.validate_history_fixture(fixture, 1, 64)
        record["requestSHA256"] = hashlib.sha256(b"H" * 64).hexdigest()
        record["id"] = benchmark.history_ids(2)[1]
        path.write_text(json.dumps(record))
        with self.assertRaisesRegex(ValueError, "ID/schema"):
            benchmark.validate_history_fixture(fixture, 1, 64)
        path.write_bytes(b"H" * (1024 * 1024 + 1))
        with self.assertRaisesRegex(ValueError, "1 MiB serialized cap"):
            benchmark.validate_history_fixture(fixture, 1, 64)

    def test_scan_oracle_rejects_wrong_page_order_provider_requests_and_scan_cap(self):
        baseline = benchmark.validate_history_fixture(self.fixture(), 120, 64)
        receipt = self.scan_receipt(baseline)
        self.assertTrue(benchmark.validate_history_scan(receipt, baseline, 123)["independentHistoryOraclePassed"])
        changed = copy.deepcopy(receipt)
        changed["historyPages"][0].reverse()
        with self.assertRaisesRegex(ValueError, "historyPages"):
            benchmark.validate_history_scan(changed, baseline, 123)
        changed = copy.deepcopy(receipt)
        changed["providerRequests"] = 1
        with self.assertRaisesRegex(ValueError, "zero provider"):
            benchmark.validate_history_scan(changed, baseline, 123)
        changed = copy.deepcopy(receipt)
        changed["maximumScanSerializedBytes"] = 1024 * 1024 + 1
        with self.assertRaisesRegex(ValueError, "working-record cap"):
            benchmark.validate_history_scan(changed, baseline, 123)

    def test_run_history_generates_once_and_retains_five_fresh_stdout_only_scan_receipts(self):
        probe = self.fake_probe()
        destination = self.directory / "measured-fake"
        summary = benchmark.run_history(destination, probe, records=3, prompt_bytes=128, interval=.01)
        self.assertEqual(len(summary["runs"]), 5)
        self.assertEqual(summary["stageSeconds"]["historyScanSeconds"]["samples"], 5)
        self.assertTrue(summary["generationExcludedFromMeasurements"])
        self.assertTrue(summary["provenanceReverifiedAfterRuns"])
        self.assertIn("Sources/CaseHistoryWorkloadProbe/CaseHistoryWorkloadProbe.swift", summary["provenance"]["recipeSHA256"])
        self.assertNotIn("Sources/NativeWorkloadProbe/NativeWorkloadProbe.swift", summary["provenance"]["recipeSHA256"])
        self.assertEqual(set(summary["provenance"]["binarySHA256"]), {"historyProbe"})
        graph = summary["provenance"]["linkedInputSHA256"]
        self.assertIn("Package.swift", graph)
        self.assertIn("Sources/ForensicsCore/CaseWork/CaseWorkStore.swift", graph)
        self.assertIn("Sources/NFDecoderIPC/NFDecoderIPC.m", graph)
        self.assertIn("Sources/CSQLite3/module.modulemap", graph)
        self.assertEqual(summary["kernelReportedMaximumRSSBytes"]["samples"], 5)
        for metric in summary["rssSampledPeakBytes"].values():
            self.assertEqual(metric["samples"], 5)
        pids = set()
        for row in summary["runs"]:
            self.assertTrue(row["freshProcess"])
            self.assertFalse(row["cache"]["cacheVerifiedCold"])
            self.assertEqual(row["cache"]["label"], "warm-preverified")
            self.assertTrue(row["fixtureUnchanged"])
            pids.add(row["measurement"]["wait4"]["pid"])
            raw = benchmark.read_json(destination / row["driverReceipt"])
            self.assertEqual(raw["scanReceipt"]["processID"], row["measurement"]["wait4"]["pid"])
        self.assertEqual(len(pids), 5)
        self.assertTrue((destination / "history-generation-driver/process-attempt.json").is_file())

    def test_missing_history_rss_fails_with_retained_raw_attempt_instead_of_reduced_percentile(self):
        fixture = self.fixture(records=1)
        measurement = WorkloadMeasurementTests.valid_measurement()
        measurement["rssSampler"].update(samples=[], sampleCount=0)
        destination = self.directory / "missing-rss-run"
        with mock.patch.object(benchmark, "launch_probe", return_value=measurement):
            with self.assertRaisesRegex(ValueError, "missing or failed"):
                benchmark.run_history(destination, self.fake_probe(), fixture=fixture, records=1, prompt_bytes=64)
        logs = destination / "history-warm-preverified-01-driver"
        self.assertEqual(benchmark.read_json(logs / "measurement-attempt.json")["measurement"], measurement)
        self.assertEqual(benchmark.read_json(logs / "failed-attempt.json")["validationState"], "failed")
        self.assertFalse((destination / "benchmark-summary.json").exists())

    def test_failed_history_scan_keeps_raw_measurement_before_validation(self):
        fixture = self.fixture(records=1)
        probe = self.directory / "failed-history-probe"
        probe.write_text("#!/usr/bin/env python3\nimport sys\nsys.exit(9)\n")
        probe.chmod(0o755)
        destination = self.directory / "failed-history-run"
        with self.assertRaisesRegex(ValueError, "scan probe failed"):
            benchmark.run_history(destination, probe, fixture=fixture, records=1, prompt_bytes=64)
        logs = destination / "history-warm-preverified-01-driver"
        self.assertEqual(benchmark.read_json(logs / "process-attempt.json")["returncode"], 9)
        self.assertEqual(benchmark.read_json(logs / "measurement-attempt.json")["validationState"], "not-started")
        self.assertEqual(benchmark.read_json(logs / "failed-attempt.json")["validationState"], "failed")
        self.assertFalse((destination / "history-generation-driver").exists())

    def test_history_fixture_preflight_failures_are_retained_without_launching_scan(self):
        fixture = self.fixture(records=1)
        baseline = benchmark.validate_history_fixture(fixture, 1, 64)
        probe = self.fake_probe()
        initial_failure = self.directory / "invalid-fixture-run"
        with mock.patch.object(benchmark, "validate_history_fixture", side_effect=ValueError("literal preflight rejected")), \
             mock.patch.object(benchmark, "launch_probe") as launch:
            with self.assertRaisesRegex(ValueError, "literal preflight"):
                benchmark.run_history(initial_failure, probe, fixture=fixture, records=1, prompt_bytes=64)
            launch.assert_not_called()
        self.assertEqual(benchmark.read_json(initial_failure / "history-fixture-preflight-driver/failed-attempt.json")["validationState"], "failed")
        before_scan = self.directory / "changed-fixture-run"
        with mock.patch.object(benchmark, "validate_history_fixture", side_effect=[baseline, ValueError("changed before scan")]), \
             mock.patch.object(benchmark, "launch_probe") as launch:
            with self.assertRaisesRegex(ValueError, "changed before scan"):
                benchmark.run_history(before_scan, probe, fixture=fixture, records=1, prompt_bytes=64)
            launch.assert_not_called()
        logs = before_scan / "history-warm-preverified-01-driver"
        self.assertEqual(benchmark.read_json(logs / "failed-attempt.json")["validationState"], "preflight-failed")
        self.assertTrue((logs / "attempt-configuration.json").is_file())


if __name__ == "__main__":
    unittest.main()

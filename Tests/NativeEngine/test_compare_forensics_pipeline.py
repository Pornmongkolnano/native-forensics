"""Safety/correctness gates independent of an installed Autopsy runtime."""
import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import zipfile

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "script"))
import compare_forensics_pipeline as benchmark
import benchmark_autopsy_pipeline as autopsy
from fixtures import fat_image


class PipelineComparisonTests(unittest.TestCase):
    def setUp(self):
        benchmark.LOCAL.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="comparison-unit-", dir=benchmark.LOCAL)
        self.directory = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_output_guard_refuses_symlink_escape(self):
        link = self.directory / "outside"
        link.symlink_to(Path("/"), target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "under ignored"):
            benchmark.owned_path(link / "tmp/new-output")

    def test_source_gate_rejects_symlink_without_changing_target(self):
        target = self.directory / "source.raw"
        target.write_bytes(b"immutable synthetic bytes")
        link = self.directory / "link.raw"
        link.symlink_to(target)
        with self.assertRaisesRegex(AssertionError, "regular immutable"):
            benchmark.source_state(link)
        self.assertEqual(target.read_bytes(), b"immutable synthetic bytes")

    def test_partial_native_cache_cannot_enter_payload_gate(self):
        cache = self.directory / "partial.json"
        cache.write_text(json.dumps({"status": "partial", "warnings": []}))
        with self.assertRaisesRegex(AssertionError, "partial or warned"):
            benchmark.native_readback({"core": {"cachePath": str(cache)}},
                                      Path("/unused-helper"), {}, Path("/unused-source"))

    def test_missing_payload_cannot_produce_a_speed_ratio(self):
        resources = {"sampledAggregatePeakRSSBytes": 1024**2,
                     "sampledUserCPULowerBoundSeconds": 1,
                     "sampledSystemCPULowerBoundSeconds": 0}
        pair = {"native": {"wallSeconds": 1, "resources": resources,
                           "validation": {"passed": True, "verifiedPayloads": 13}},
                "autopsy": {"wallSeconds": 2, "resources": resources,
                            "validation": {"passed": False, "verifiedPayloads": 12}}}
        with self.assertRaisesRegex(AssertionError, "all expected payloads"):
            benchmark.summarize([copy.deepcopy(pair) for _ in range(5)])
        with self.assertRaisesRegex(AssertionError, "five measured pairs"):
            benchmark.summarize([copy.deepcopy(pair) for _ in range(4)])

    def test_timestamp_gap_remains_visible_despite_payload_pass(self):
        pair = {"native": {"validation": {"files": [
            {"path": "/FILE.TXT", "createdEpoch": 1700000000}]}},
                "autopsy": {"validation": {"files": [
            {"path": "FILE.TXT", "passed": True, "createdEpoch": 1699974800,
             "changedEpoch": 0}]}}}
        result = benchmark.metadata_comparison(pair)
        self.assertFalse(result["knownPayloadMetadataParity"])
        self.assertEqual(len(result["differences"]), 1)
        self.assertEqual(result["differences"][0]["autopsyMinusNativeSeconds"], -25200)

    def test_fat_oracle_reads_date_only_access_from_disk(self):
        image = self.directory / "fat.raw"
        expected = fat_image(image, 16, 512)
        oracles = benchmark.fat_timestamp_oracle(image, expected)
        for oracle in oracles.values():
            self.assertEqual(oracle["createdEpoch"], 1700000000)
            self.assertEqual(oracle["modifiedEpoch"], 1700000000)
            self.assertEqual(oracle["accessedEpoch"], 1699920000)
            self.assertNotIn("changedEpoch", oracle)
        rows = [{"path": path, **oracle} for path, oracle in oracles.items()]
        self.assertTrue(benchmark.timestamp_gate(rows, expected, image, native=True)["passed"])
        rows[0]["accessedEpoch"] = 1700000000
        self.assertFalse(benchmark.timestamp_gate(rows, expected, image, native=True)["passed"])

    def test_shared_wrong_epochs_and_lost_native_fractions_fail_oracle(self):
        expected = {"filesystem": "NTFS", "files": [{"path": "stream", "timestampsByTimezone": {
            "UTC": {"createdEpoch": 1704164646, "createdNanoseconds": 123456700}}}]}
        wrong = [{"path": "stream", "createdEpoch": 1704164645, "createdNanoseconds": 123456700}]
        for native in (True, False):
            result = benchmark.timestamp_gate(wrong, expected, Path("/unused"), native=native)
            self.assertFalse(result["passed"])
        seconds_only = [{"path": "stream", "createdEpoch": 1704164646, "changedEpoch": 0}]
        self.assertFalse(benchmark.timestamp_gate(seconds_only, expected, Path("/unused"), native=True)["passed"])
        java = benchmark.timestamp_gate(seconds_only, expected, Path("/unused"), native=False)
        self.assertTrue(java["passed"])
        self.assertIn("Whole epoch seconds", java["precision"])
        self.assertFalse(java["fullFractionalMetadataParityClaimed"])

    def test_directory_ads_requires_regular_stream_classification(self):
        row = {"path": "หลักฐาน:directory-note", "attributeType": 128, "isDirectory": False, "isFile": True}
        benchmark.require_regular_directory_ads(row, native=True)
        benchmark.require_regular_directory_ads(row, native=False)
        for changed in ({"isDirectory": True}, {"isFile": False}):
            with self.assertRaisesRegex(AssertionError, "regular DATA"):
                benchmark.require_regular_directory_ads({**row, **changed}, native=False)

    def test_readback_failure_preserves_timing_resources_and_partial_validation(self):
        journal = self.directory / "pair.json"
        pair = {"iteration": 1, "order": ["native", "autopsy"]}
        record = {"pipelineCompleted": True, "wallSeconds": 0.125, "resources": {"sampleCount": 2}}
        def failed_readback(value):
            snapshot = json.loads(journal.read_text())
            self.assertEqual(snapshot["native"]["wallSeconds"], 0.125)
            value["validation"] = {"passed": True, "files": [{"path": "first-export", "passed": True}]}
            raise AssertionError("second export mismatched")
        benchmark.journal_attempt(pair, "native", lambda: record, failed_readback, journal)
        saved = json.loads(journal.read_text())["native"]
        self.assertEqual(saved["wallSeconds"], 0.125)
        self.assertEqual(saved["resources"]["sampleCount"], 2)
        self.assertEqual(len(saved["validation"]["files"]), 1)
        self.assertFalse(saved["validation"]["passed"])
        self.assertEqual(saved["status"], "failed")

    def test_launcher_failure_has_retained_attempt_before_other_application(self):
        journal = self.directory / "failed-launch.json"
        pair = {"iteration": 2, "order": ["autopsy", "native"]}
        def failed_launch():
            self.assertEqual(json.loads(journal.read_text())["autopsy"]["phase"], "launch")
            raise OSError("launcher refused")
        result = benchmark.journal_attempt(pair, "autopsy", failed_launch, lambda _: None, journal)
        self.assertEqual(result["status"], "failed")
        self.assertIn("launcher refused", json.loads(journal.read_text())["autopsy"]["error"])

    def test_final_integrity_failure_invalidates_precomputed_ratios(self):
        report = {"workloads": [{"performanceRatioAllowed": True,
                  "summary": {"pairedWallRatioMedian": 2},
                  "pairs": [{"performanceRatioAllowed": True, "native": {"wallSeconds": 1}}]}]}
        benchmark.invalidate_performance(report, "recipe changed")
        workload = report["workloads"][0]
        self.assertFalse(report["performanceRatioAllowed"])
        self.assertFalse(workload["performanceRatioAllowed"])
        self.assertFalse(workload["pairs"][0]["performanceRatioAllowed"])
        self.assertNotIn("summary", workload)
        self.assertFalse(workload["invalidatedDiagnosticSummary"]["validForPerformanceClaim"])
        self.assertEqual(workload["pairs"][0]["native"]["wallSeconds"], 1)

    def make_jni_profile(self):
        runtime = self.directory / "runtime"
        ext = runtime / "autopsy/modules/ext"
        ext.mkdir(parents=True)
        jar = ext / "sleuthkit-4.15.0.jar"
        with zipfile.ZipFile(jar, "w") as archive:
            archive.writestr(autopsy.JNI_RESOURCE, b"synthetic JNI resource")
        profile = {"runtime": str(runtime), "jdk": str(self.directory / "jdk"),
                   "nativeDirectory": str(self.directory / "native"), "modules": [], "nativeFiles": []}
        resource = autopsy.jni_resource_receipt(profile)
        profile.update(tskJarSHA256=resource["jarSHA256"], jniResourceEntry=resource["resourceEntry"],
                       jniResourceSHA256=resource["sha256"])
        owned = self.directory / "jni"
        owned.mkdir()
        loaded = owned / "libtsk_jni_test.dylib"
        loaded.write_bytes(b"synthetic JNI resource")
        return profile, owned, loaded

    def test_extracted_jni_must_match_effective_jar_and_owned_directory(self):
        profile, owned, loaded = self.make_jni_profile()
        trace = "dyld[123]: <UUID> " + str(loaded)
        self.assertTrue(autopsy.loaded_jni_receipt(trace, profile, [owned])["passed"])
        loaded.write_bytes(b"wrong JNI")
        with self.assertRaisesRegex(AssertionError, "hash differs"):
            autopsy.loaded_jni_receipt(trace, profile, [owned])
        with self.assertRaisesRegex(AssertionError, "outside"):
            autopsy.loaded_jni_receipt(trace, profile, [self.directory / "elsewhere"])

    def test_effective_copied_launcher_change_is_detected(self):
        profile, _, _ = self.make_jni_profile()
        runtime, jdk = Path(profile["runtime"]), Path(profile["jdk"])
        (runtime / "bin").mkdir()
        (runtime / "etc").mkdir()
        (jdk / "bin").mkdir(parents=True)
        launcher = runtime / "bin/autopsy"
        launcher.write_text("synthetic launcher")
        (runtime / "etc/autopsy.conf").write_text("synthetic configuration")
        (jdk / "bin/java").write_text("synthetic wrapper")
        profile["effectiveFiles"] = autopsy.effective_runtime_files(runtime, jdk)
        setup = {"protectedFiles": [], "commonJars": [], "inputs": {}, "variants": {"repaired-mac": profile}}
        autopsy.verify_setup(setup)
        launcher.write_text("changed staged launcher")
        with self.assertRaisesRegex(ValueError, "Effective staged"):
            autopsy.verify_setup(setup)

    def test_autopsy_receipt_survives_pipeline_cleanup_and_port_failures(self):
        profile = {"runtime": str(self.directory / "runtime"), "jdk": str(self.directory / "jdk"),
                   "nativeDirectory": str(self.directory / "native")}
        setup = {"variants": {"repaired-mac": profile}, "inputs": {"synthetic.raw": {"path": "/unused-source"}},
                 "privateSolrPorts": {"http": 41137, "stop": 41138, "rmi": 41139},
                 "privateSolrStopKey": "nf-test", "javaHome": "/unused-jdk", "scope": "unit test"}
        process = SimpleNamespace(pid=123, returncode=7)
        sampler = Mock()
        sampler.receipt.return_value = {"sampleCount": 1}
        sampler.cleanup_remaining.side_effect = RuntimeError("cleanup refused")
        observer = Mock()
        observer.wait.return_value = SimpleNamespace(returncode=7, exit_monotonic=100.125, method="fake blocking waiter")
        with patch.object(autopsy, "verify_setup"), patch.object(autopsy, "free_ports", side_effect=[None, OSError("port still occupied")]), \
                patch.object(autopsy, "solr_snapshot", return_value={"available": False}), \
                patch.object(autopsy.subprocess, "Popen", return_value=process), \
                patch.object(autopsy, "ProcessExitObserver", return_value=observer), \
                patch.object(autopsy, "OwnedGroupSampler", return_value=sampler), \
                patch.object(autopsy, "stop_owned_group"), patch.object(autopsy.time, "monotonic", return_value=100), \
                patch.object(autopsy, "loaded_jni_receipt", return_value={"passed": True}):
            result = autopsy.run_pipeline(setup, self.directory, "repaired-mac", "synthetic.raw")
        saved = json.loads((Path(result["runDirectory"]) / "receipt.json").read_text())
        self.assertEqual(saved["wallSeconds"], 0.125)
        self.assertFalse(saved["structuralGatePassed"])
        self.assertEqual({row["phase"] for row in saved["errors"]}, {"pipeline", "dependencyCleanup", "portsAfterCleanup"})
        self.assertEqual(saved["resources"]["sampleCount"], 1)

    @unittest.skipUnless(sys.platform == "darwin", "macOS libproc receipt")
    def test_error_free_sampler_with_no_processes_does_not_claim_full_coverage(self):
        sampler = benchmark.OwnedGroupSampler(2147483647)
        receipt = sampler.receipt()  # No process was started or sampled.
        self.assertTrue(receipt["noSamplerErrors"])
        self.assertIsNone(receipt["sampledAggregatePeakRSSBytes"])
        self.assertNotIn("resourceCoverageComplete", receipt)
        self.assertTrue(receipt["observedProcessCoverage"].startswith("Unproven"))


if __name__ == "__main__":
    unittest.main()

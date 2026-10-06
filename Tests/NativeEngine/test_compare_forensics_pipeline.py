"""Safety/correctness gates independent of an installed Autopsy runtime."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "script"))
import compare_forensics_pipeline as benchmark


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


if __name__ == "__main__":
    unittest.main()

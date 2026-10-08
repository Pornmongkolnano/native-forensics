#!/usr/bin/env python3
"""Pure semantic/protocol/pinned-namespace regressions; no native app/build/UI."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import signal
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
import uuid
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("content_index_runtime_gate", ROOT / "Tests/Runtime/run_content_index_runtime_gates.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def h(value):
    return hashlib.sha256(value.encode()).hexdigest()


def signed_inputs():
    return {role: {"sha256": h(role), "codeSigningCDHash": h(role)[:40]} for role in ("host", "broker", "worker")}


def decoder(signed, pages=None):
    result = {"schemaVersion": 1, "decoderIdentifier": "NativeForensics.document-decoder", "decoderVersion": "2.1.0",
              "isolation": "appSandboxXPC", "decoderExecutableSHA256": signed["worker"]["sha256"],
              "decoderCodeSigningCDHash": signed["worker"]["codeSigningCDHash"],
              "brokerExecutableSHA256": signed["broker"]["sha256"], "brokerCodeSigningCDHash": signed["broker"]["codeSigningCDHash"],
              "options": gate.expected_options(), "optionsSHA256": gate.runtime.document_receipt_digest(gate.expected_options())}
    if pages is None:
        result["ipcProtocolVersion"] = 2
    else:
        result["derivedTextSHA256"] = gate.runtime.document_receipt_digest(pages)
    return result


def oracles():
    result = {}
    for label in gate.LABELS:
        texts = {"/ALPHA.TXT": "Alpha\nneedleOnlyInPayload\nภาษาไทย เอกสาร ก้\n", "/THAI.TXT": "เอกสารก้\n",
                 "/BETA.TXT": "Beta plain text\n", "/LARGE.TXT": "largeNeedle\n"}
        if label == "replacement":
            texts["/ALPHA.TXT"] = texts["/ALPHA.TXT"].replace("needleOnlyInPayload", "needleAfterReplacement")
        reasons = {"/OVER.TXT": "FILE_BYTE_LIMIT", "/UNKNOWN.BIN": "UNSUPPORTED_CONTENT", "/EMPTY.TXT": "NO_TEXT_LAYER_OR_BODY",
                   "/$MBR": "UNSUPPORTED_CONTENT", "/$FAT1": "UNSUPPORTED_CONTENT", "/$FAT2": "UNSUPPORTED_CONTENT"}
        files = {}
        for path in sorted(set(texts) | set(reasons)):
            complete = path in texts and path != "/LARGE.TXT"
            files[path] = {"byteCount": len(texts[path].encode()) if path in texts else 0,
                           "sha256": h("logical:" + path + ":" + texts.get(path, "")),
                           "indexStatus": "indexed" if path in texts else "skipped",
                           "indexReason": reasons.get(path, None if complete else "PARTIAL_DECODER_COVERAGE"),
                           "textIsComplete": complete}
            if path in texts:
                files[path]["text"] = texts[path]
        query_files = {path: dict(row) for path, row in files.items()}
        result[label] = {"imageSHA256": h("source:" + ("original" if label == "stable" else label)),
                         "imageByteCount": 256 * gate.MIB, "files": files,
                         "queries": gate.workload.search_oracle(query_files, (*gate.workload.QUERIES, "needleAfterReplacement"))}
    return result


def sources(fixture, oracle):
    return {label: {"label": label, "evidenceID": str(uuid.uuid4()).upper(),
                   "path": str(fixture / label / gate.workload.IMAGE_NAME), "sha256": oracle[label]["imageSHA256"],
                   "byteCount": oracle[label]["imageByteCount"]} for label in gate.LABELS}


def snapshot(labels, source, oracle, signed, case_id):
    documents, source_rows = [], []
    for label in labels:
        source_rows.append({"evidenceID": source[label]["evidenceID"], "selectedContainerSHA256": oracle[label]["imageSHA256"],
                            "selectedContainerByteCount": oracle[label]["imageByteCount"],
                            "orderedContainerSHA256": [oracle[label]["imageSHA256"]], "listingSHA256": h("listing:" + label),
                            "listingEntryCount": 10, "listingIsPartial": False})
        for number, (path, expected) in enumerate(oracle[label]["files"].items(), 1):
            file = {"id": str(number), "path": path, "name": path[1:], "fsOffsetBytes": 0, "metaAddress": number,
                    "size": expected["byteCount"], "isDirectory": False, "isDeleted": False}
            address = {key: file[key] for key in ("id", "path", "fsOffsetBytes", "metaAddress")}
            row = {"evidenceID": source[label]["evidenceID"], "file": file,
                   "locatorSHA256": gate.runtime.document_receipt_digest(address), "status": expected["indexStatus"],
                   "textPages": [], "textIsComplete": expected["textIsComplete"]}
            if expected["indexReason"] is not None:
                row["reason"] = expected["indexReason"]
            if row["status"] == "indexed":
                pages = [{"pageNumber": 1, "text": expected["text"], "isTruncated": not expected["textIsComplete"],
                          "referenceKind": "document", "referenceLabel": "Text document"}]
                row.update(textPages=pages, contentSHA256=expected["sha256"],
                           derivedTextSHA256=gate.runtime.document_receipt_digest(pages), decoderProvenance=decoder(signed, pages))
            documents.append(row)
    return {"schemaVersion": 1, "id": str(uuid.uuid4()).upper(), "caseID": case_id, "builtAt": 813150755.456666,
            "decoderContract": "NativeForensics.document-decoder@2.1.0", "decoderBinarySHA256": signed["worker"]["sha256"],
            "decoderIdentity": decoder(signed), "limits": {"maximumFiles": 512, "maximumFileBytes": 32 * gate.MIB,
            "maximumInputBytes": 256 * gate.MIB, "maximumTextBytes": 16 * gate.MIB, "timeoutSeconds": 600},
            "sources": source_rows, "documents": documents, "omittedRegularFiles": 0, "skippedDirectories": 0}


def completed_ledger():
    ledger, stamp, pid = gate.EventLedger(), 100, 1000
    for stage in gate.STAGES:
        ledger.accept({"schemaVersion": 1, "kind": "stageStarted", "stage": stage, "uptimeNanoseconds": stamp}); stamp += 100
        count = 1 if stage == "cancel" else gate.COUNTS[stage][1]
        for _ in range(count):
            pid += 1
            for kind in ("decoderStarted", "decoderExited"):
                ledger.accept({"schemaVersion": 1, "kind": kind, "stage": stage, "processIdentifier": pid,
                               "uptimeNanoseconds": stamp}); stamp += 100
        ledger.accept({"schemaVersion": 1, "kind": "stageCompleted", "stage": stage, "uptimeNanoseconds": stamp}); stamp += 100
    ledger.accept({"schemaVersion": 1, "kind": "complete", "stage": "", "receipt": "receipt.json", "uptimeNanoseconds": stamp})
    return ledger


class ProtocolTests(unittest.TestCase):
    def test_complete_fixed_stage_order_has57_fresh_sequential_worker_pairs(self):
        ledger = completed_ledger()
        ledger.validate_complete()
        self.assertEqual([len(ledger.started[stage]) for stage in gate.STAGES], [18, 10, 14, 1, 14])
        self.assertEqual(sum(map(len, ledger.started.values())), 57)

    def test_premature_completion_wrong_stage_unmatched_exit_and_overlap_fail(self):
        for events, message in [([{"kind": "complete", "receipt": "receipt.json", "stage": ""}], "Premature"),
                                ([{"kind": "stageStarted", "stage": "changed"}], "Stage order"),
                                ([{"kind": "stageStarted", "stage": "rebuild"}, {"kind": "decoderExited", "stage": "rebuild", "processIdentifier": 11}], "lacks accepted"),
                                ([{"kind": "stageStarted", "stage": "rebuild"}, {"kind": "decoderStarted", "stage": "rebuild", "processIdentifier": 11},
                                  {"kind": "decoderStarted", "stage": "rebuild", "processIdentifier": 12}], "Overlapping")]:
            with self.subTest(message=message):
                ledger = gate.EventLedger()
                with self.assertRaisesRegex(AssertionError, message):
                    for number, event in enumerate(events):
                        ledger.accept(dict(event, schemaVersion=1, uptimeNanoseconds=number + 1))

    def test_events_after_completion_and_backward_clock_are_rejected(self):
        ledger = completed_ledger()
        with self.assertRaises(AssertionError):
            ledger.accept(dict(ledger.events[-1]))
        ledger = gate.EventLedger()
        ledger.accept({"schemaVersion": 1, "kind": "stageStarted", "stage": "rebuild", "uptimeNanoseconds": 10})
        with self.assertRaisesRegex(AssertionError, "timestamps"):
            ledger.accept({"schemaVersion": 1, "kind": "stageCompleted", "stage": "rebuild", "uptimeNanoseconds": 9})

    def test_duplicate_json_keys_and_nonfinite_constants_fail_closed(self):
        for data in (b'{"schemaVersion":1,"schemaVersion":2}', b'{"value":NaN}', b'{"value":Infinity}'):
            with self.subTest(data=data), self.assertRaises(AssertionError):
                gate.decode(data)

    def test_nearest_rank_n5_p95_is_maximum_without_population_omission(self):
        self.assertEqual(gate.distribution([5, 1, 4, 2, 3]), {"samples": 5, "minimum": 1, "p50": 3, "p95": 5, "maximum": 5})
        for values in ([], [1, None], [float("nan")], [-1]):
            with self.subTest(values=values), self.assertRaises(AssertionError):
                gate.distribution(values)

    def test_exact_reaper_retries_eintr_and_retains_one_pid_and_wnohang(self):
        with mock.patch.object(gate.os, "wait4", side_effect=[InterruptedError(), (123, 0, "usage")]) as wait:
            self.assertEqual(gate.wait4_nonblocking(123, time.monotonic() + 1), (123, 0, "usage"))
            self.assertEqual(wait.call_args_list, [mock.call(123, os.WNOHANG), mock.call(123, os.WNOHANG)])
        with mock.patch.object(gate.os, "wait4", side_effect=InterruptedError()):
            with self.assertRaisesRegex(AssertionError, "deadline"):
                gate.wait4_nonblocking(123, time.monotonic() - 1)

    def test_signal_raced_natural_exit_returns_unsent_and_eintr_retries_one_group(self):
        with mock.patch.object(gate.os, "killpg", side_effect=ProcessLookupError()):
            self.assertFalse(gate.signal_owned_group(123, signal.SIGTERM, time.monotonic() + 1))
        with mock.patch.object(gate.os, "killpg", side_effect=[InterruptedError(), None]) as send:
            self.assertTrue(gate.signal_owned_group(123, signal.SIGTERM, time.monotonic() + 1))
            self.assertEqual(send.call_args_list, [mock.call(123, signal.SIGTERM), mock.call(123, signal.SIGTERM)])


class OwnedHostDrainTests(unittest.TestCase):
    def setUp(self):
        self.process = SimpleNamespace(pid=123, returncode=None)
        self.usage = SimpleNamespace(ru_utime=.1, ru_stime=.2, ru_maxrss=4096)

    def test_zero_wait_then_signal_esrch_continues_exact_reaping_and_reports_natural_exit(self):
        errors = []
        with mock.patch.object(gate.os, "wait4", side_effect=[(0, 0, None), (0, 0, None), (123, 0, self.usage)]) as wait, \
                mock.patch.object(gate.os, "killpg", side_effect=ProcessLookupError()) as send, \
                mock.patch.object(gate.time, "sleep"):
            receipt, sent = gate.drain_owned_host(self.process, errors)
        self.assertEqual(wait.call_args_list, [mock.call(123, os.WNOHANG)] * 3)
        send.assert_called_once_with(123, signal.SIGTERM)
        self.assertEqual((receipt["pid"], receipt["returncode"], self.process.returncode), (123, 0, 0))
        self.assertTrue(receipt["terminalExitObserved"])
        self.assertNotIn("driverTerminationSignalsSent", receipt)
        self.assertEqual((sent, errors), ([], []))

    def test_already_terminal_exact_child_is_reaped_without_any_signal(self):
        errors = []
        with mock.patch.object(gate.os, "wait4", return_value=(123, 0, self.usage)) as wait, \
                mock.patch.object(gate.os, "killpg") as send:
            receipt, sent = gate.drain_owned_host(self.process, errors)
        wait.assert_called_once_with(123, os.WNOHANG)
        send.assert_not_called()
        self.assertEqual((receipt["returncode"], sent, errors), (0, [], []))
        self.assertNotIn("driverTerminationSignalsSent", receipt)

    def test_successful_group_signal_is_the_only_sent_signal_in_terminal_receipt(self):
        errors = []
        with mock.patch.object(gate.os, "wait4", side_effect=[(0, 0, None), (123, signal.SIGTERM, self.usage)]), \
                mock.patch.object(gate.os, "killpg") as send, mock.patch.object(gate.time, "sleep"):
            receipt, sent = gate.drain_owned_host(self.process, errors)
        send.assert_called_once_with(123, signal.SIGTERM)
        self.assertEqual(receipt["returncode"], -signal.SIGTERM)
        self.assertEqual(receipt["driverTerminationSignalsSent"], [int(signal.SIGTERM)])
        self.assertEqual((sent, errors), ([int(signal.SIGTERM)], []))

    def test_reaping_ownership_error_stops_without_kill_fallback_or_fabricated_exit(self):
        for response in (ChildProcessError("not this parent's child"), (456, 0, self.usage)):
            with self.subTest(response=response):
                errors = []
                with mock.patch.object(gate.os, "wait4", side_effect=[response]) as wait, \
                        mock.patch.object(gate.os, "killpg") as send:
                    receipt, sent = gate.drain_owned_host(self.process, errors)
                wait.assert_called_once_with(123, os.WNOHANG)
                send.assert_not_called()
                self.assertIsNone(receipt)
                self.assertEqual(sent, [])
                self.assertEqual(len(errors), 1)
                self.assertEqual(errors[0]["phase"], "owned-host-drain")
                self.assertIsNone(self.process.returncode)

    def test_successfully_sent_signal_survives_a_later_unconfirmed_reap(self):
        errors = []
        with mock.patch.object(gate.os, "wait4", side_effect=[(0, 0, None), ChildProcessError("lost ownership")]), \
                mock.patch.object(gate.os, "killpg") as send, mock.patch.object(gate.time, "sleep"):
            receipt, sent = gate.drain_owned_host(self.process, errors)
        send.assert_called_once_with(123, signal.SIGTERM)
        self.assertIsNone(receipt)
        self.assertEqual(sent, [int(signal.SIGTERM)])
        self.assertEqual(len(errors), 1)
        self.assertIsNone(self.process.returncode)

    def test_persistent_zero_wait_and_esrch_are_bounded_without_false_signal_telemetry(self):
        clock, errors = [0.0], []
        def advance(_):
            clock[0] += .25
        with mock.patch.object(gate.time, "monotonic", side_effect=lambda: clock[0]), \
                mock.patch.object(gate.time, "sleep", side_effect=advance), \
                mock.patch.object(gate.os, "wait4", return_value=(0, 0, None)) as wait, \
                mock.patch.object(gate.os, "killpg", side_effect=ProcessLookupError()) as send:
            receipt, sent = gate.drain_owned_host(self.process, errors)
        self.assertIsNone(receipt)
        self.assertEqual((sent, errors, self.process.returncode), ([], [], None))
        self.assertEqual(send.call_args_list, [mock.call(123, signal.SIGTERM), mock.call(123, signal.SIGKILL)])
        self.assertTrue(all(call == mock.call(123, os.WNOHANG) for call in wait.call_args_list))
        self.assertEqual(clock[0], 5.0)

    def test_session_failure_retains_natural_esrch_race_terminal_and_original_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / "nf-index-fixture-mocked.noindex").mkdir()
            self.process.stdin, self.process.stdout, self.process.stderr = (mock.Mock() for _ in range(3))
            monitor = mock.Mock()
            monitor.track.side_effect = AssertionError("mocked failure after owned launch")
            monitor.summary.return_value = {}
            with mock.patch.object(gate, "require_no_existing_host"), \
                    mock.patch.object(gate, "IndexProcesses", return_value=monitor), \
                    mock.patch.object(gate.subprocess, "Popen", return_value=self.process), \
                    mock.patch.object(gate.os, "wait4", side_effect=[(0, 0, None), (123, 0, self.usage)]), \
                    mock.patch.object(gate.os, "killpg", side_effect=ProcessLookupError()) as send, \
                    mock.patch.object(gate.time, "sleep"):
                with self.assertRaisesRegex(AssertionError, "retained raw receipts"):
                    gate.run_session(root / "NativeForensics.app", root, 1, {})
            attempt = gate.read_json(root / "session-01-driver/process-attempt.json")
            self.assertEqual(attempt["failure"]["message"], "mocked failure after owned launch")
            self.assertTrue(attempt["terminalExitObserved"])
            self.assertEqual(attempt["wait4"]["returncode"], 0)
            self.assertEqual(attempt["memory"]["driverObservationErrors"], [])
            self.assertNotIn("driverTerminationSignalsSent", attempt)
            self.assertNotIn("driverTerminationSignalsSent", attempt["wait4"])
            send.assert_called_once_with(123, signal.SIGTERM)
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                stream.close.assert_called_once()


class HostPreflightTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.app = self.root / "NativeForensics.app"
        self.app.mkdir()
        host = self.app / gate.runtime.HOST
        host.parent.mkdir(parents=True)
        host.write_bytes(b"mocked file, never executed")
        self.receipt = self.root / "preflight.json"
        self.monitor = mock.Mock()
        self.monitor.sample.return_value = []
        self.monitor.summary.return_value = {
            "lastPIDInventory": {"requestedBytes": 8192, "returnedBytes": 1024, "errno": 0},
            "ownedOrKnownPIDQueryFailures": [], "ownedOrKnownPIDQueryFailuresOmitted": 0}
        self.host = {"role": "host", "path": str(self.app / gate.runtime.HOST), "processIdentifier": 987,
                     "parentProcessIdentifier": 1, "startSeconds": 1234, "startMicroseconds": 567,
                     "residentBytes": 4096}

    def tearDown(self):
        self.tmp.cleanup()

    def preflight(self):
        with mock.patch.object(gate, "IndexProcesses", return_value=self.monitor), \
                mock.patch.object(gate.os, "killpg") as send, mock.patch.object(gate.subprocess, "Popen") as launch:
            try:
                return gate.require_no_existing_host(self.app, self.receipt)
            finally:
                send.assert_not_called()
                launch.assert_not_called()

    def test_exact_existing_host_refuses_without_signal_and_retains_its_birth(self):
        self.monitor.sample.return_value = [self.host]
        with self.assertRaisesRegex(AssertionError, "already running"):
            self.preflight()
        saved = gate.read_json(self.receipt)
        self.assertEqual(saved["existingHosts"], [self.host])
        self.assertEqual(saved["processes"], [self.host])
        self.assertIsNone(saved["failure"])

    def test_linked_host_path_is_rejected_before_inventory_or_signal(self):
        host = self.app / gate.runtime.HOST
        target = self.root / "other-executable"
        target.write_bytes(b"mocked file, never executed")
        host.unlink()
        host.symlink_to(target)
        with mock.patch.object(gate, "IndexProcesses") as inventory, mock.patch.object(gate.os, "killpg") as send, \
                mock.patch.object(gate.subprocess, "Popen") as launch:
            with self.assertRaisesRegex(AssertionError, "canonical regular host executable"):
                gate.require_no_existing_host(self.app, self.receipt)
        inventory.assert_not_called()
        send.assert_not_called()
        launch.assert_not_called()
        self.assertFalse(self.receipt.exists())
        self.assertEqual(target.read_bytes(), b"mocked file, never executed")

    def test_quiet_exact_app_path_does_not_reject_a_different_copy_or_helper(self):
        other_host = dict(self.host, path=str(self.root / "Different Copy.app" / gate.runtime.HOST))
        broker = dict(self.host, role="broker", path=str(self.app / gate.runtime.BROKER))
        self.monitor.sample.return_value = [other_host, broker]
        self.preflight()
        saved = gate.read_json(self.receipt)
        self.assertEqual(saved["existingHosts"], [])
        self.assertEqual(saved["processes"], [other_host, broker])

    def test_preflight_query_failures_and_omissions_are_retained_and_fail_closed(self):
        for failures, omitted in ([{"phase": "owned-path-bsd-info", "processIdentifier": 987, "errno": 3}], 0), ([], 1):
            with self.subTest(failures=failures, omitted=omitted):
                self.monitor.summary.return_value["ownedOrKnownPIDQueryFailures"] = failures
                self.monitor.summary.return_value["ownedOrKnownPIDQueryFailuresOmitted"] = omitted
                self.receipt = self.root / (str(uuid.uuid4()) + ".json")
                with self.assertRaisesRegex(AssertionError, "identity queries failed"):
                    self.preflight()
                saved = gate.read_json(self.receipt)["memory"]
                self.assertEqual(saved["ownedOrKnownPIDQueryFailures"], failures)
                self.assertEqual(saved["ownedOrKnownPIDQueryFailuresOmitted"], omitted)

    def test_preflight_unavailable_or_potentially_truncated_inventory_is_rejected(self):
        for inventory in (None, {"requestedBytes": 4096, "returnedBytes": 4096},
                          {"requestedBytes": 4096, "returnedBytes": 0}):
            with self.subTest(inventory=inventory):
                self.monitor.summary.return_value["lastPIDInventory"] = inventory
                self.receipt = self.root / (str(uuid.uuid4()) + ".json")
                with self.assertRaisesRegex(AssertionError, "unavailable or potentially truncated"):
                    self.preflight()
                self.assertEqual(gate.read_json(self.receipt)["memory"]["lastPIDInventory"], inventory)

    def test_preflight_sampling_exception_is_retained_before_refusal(self):
        self.monitor.sample.side_effect = AssertionError("mocked inventory failure")
        with self.assertRaisesRegex(AssertionError, "inventory is unavailable"):
            self.preflight()
        saved = gate.read_json(self.receipt)
        self.assertEqual(saved["failure"], {"type": "AssertionError", "message": "mocked inventory failure"})
        self.assertEqual(saved["processes"], [])

    def test_existing_host_initial_preflight_prevents_fixture_creation(self):
        self.monitor.sample.return_value = [self.host]
        output = self.root / "owned-output"
        output.mkdir()
        with mock.patch.object(gate.sys, "platform", "darwin"), \
                mock.patch.object(gate.time, "get_clock_info", return_value=SimpleNamespace(implementation="mach_absolute_time")), \
                mock.patch.object(gate.runtime, "signed_identity", return_value={}), \
                mock.patch.object(gate, "signed_engine_identity", return_value={}), \
                mock.patch.object(gate, "fresh_root", return_value=output), \
                mock.patch.object(gate, "IndexProcesses", return_value=self.monitor), \
                mock.patch.object(gate, "prepare_fixture") as prepare, \
                mock.patch.object(gate, "run_session") as run, \
                mock.patch.object(gate.os, "killpg") as send, mock.patch("builtins.print"):
            with self.assertRaisesRegex(AssertionError, "already running"):
                gate.execute(self.app, self.root)
        prepare.assert_not_called()
        run.assert_not_called()
        send.assert_not_called()
        self.assertEqual(gate.read_json(output / "initial-host-preflight.json")["existingHosts"], [self.host])

    def test_session_preflight_refusal_prevents_launch_and_retains_failed_attempt(self):
        self.monitor.sample.return_value = [self.host]
        (self.root / "nf-index-fixture-mocked.noindex").mkdir()
        with mock.patch.object(gate, "IndexProcesses", return_value=self.monitor), \
                mock.patch.object(gate.subprocess, "Popen") as launch, mock.patch.object(gate.os, "killpg") as send:
            with self.assertRaisesRegex(AssertionError, "retained raw receipts"):
                gate.run_session(self.app, self.root, 1, {})
        launch.assert_not_called()
        send.assert_not_called()
        logs = self.root / "session-01-driver"
        self.assertEqual(gate.read_json(logs / "host-preflight.json")["existingHosts"], [self.host])
        attempt = gate.read_json(logs / "process-attempt.json")
        self.assertIn("already running", attempt["failure"]["message"])
        self.assertIsNone(attempt["wait4"])
        self.assertFalse(attempt["terminalExitObserved"])
        self.assertNotIn("driverTerminationSignalsSent", attempt)


class NamespaceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve() / "private"
        self.root.mkdir(mode=0o700)
        self.source = self.root / "source.raw"
        self.source.write_bytes(b"owned synthetic source")

    def tearDown(self):
        self.tmp.cleanup()

    def test_full_held_bytes_and_namespace_are_unchanged_without_read_bytes(self):
        (self.root / "nested").mkdir(mode=0o700)
        (self.root / "nested/marker.json").write_text("{}")
        with mock.patch.object(Path, "read_bytes", side_effect=AssertionError("whole-file reads forbidden")):
            pinned = gate.PinnedNamespace(self.root)
            try:
                before = copy.deepcopy(pinned.baseline)
                self.assertEqual(pinned.verify(), before)
                self.assertEqual(before["source.raw"]["sha256"], hashlib.sha256(b"owned synthetic source").hexdigest())
                self.assertEqual(set(before), {".", "source.raw", "nested", "nested/marker.json"})
            finally:
                pinned.close()

    def test_replacement_bytes_or_added_namespace_fail_without_touching_foreign_canary(self):
        pinned = gate.PinnedNamespace(self.root)
        try:
            foreign = self.root.parent / "canary"
            foreign.write_bytes(b"PRESERVE")
            self.source.unlink(); self.source.symlink_to(foreign)
            with self.assertRaisesRegex(AssertionError, "Linked"):
                pinned.verify()
            self.assertEqual(foreign.read_bytes(), b"PRESERVE")
        finally:
            pinned.close()
        self.source.unlink(); self.source.write_bytes(b"owned synthetic source")
        pinned = gate.PinnedNamespace(self.root)
        try:
            (self.root / "extra").write_bytes(b"new namespace")
            with self.assertRaisesRegex(AssertionError, "inventory changed"):
                pinned.verify()
        finally:
            pinned.close()

    def test_same_name_replacement_and_in_place_byte_changes_are_detected(self):
        pinned = gate.PinnedNamespace(self.root)
        try:
            self.source.write_bytes(b"Owned synthetic source")
            with self.assertRaisesRegex(AssertionError, "changed"):
                pinned.verify()
        finally:
            pinned.close()
        pinned = gate.PinnedNamespace(self.root)
        try:
            replacement = self.root.parent / "candidate"
            replacement.write_bytes(self.source.read_bytes()); replacement.replace(self.source)
            with self.assertRaisesRegex(AssertionError, "identity changed"):
                pinned.verify()
        finally:
            pinned.close()

    def test_linked_and_oversized_json_receipts_are_rejected(self):
        target = self.root / "receipt.json"
        target.write_text('{"ok":true}')
        link = self.root / "linked.json"; link.symlink_to(target)
        with self.assertRaisesRegex(AssertionError, "canonical"):
            gate.read_json(link)
        with self.assertRaisesRegex(AssertionError, "oversized"):
            gate.read_json(target, maximum=2)


class MemoryTests(unittest.TestCase):
    @staticmethod
    def attempt():
        signed = {role: {"path": "/owned/" + role} for role in ("host", "broker", "worker", "engine")}
        processes = []
        for pid, role, parent, resident in ((11, "host", 999, 10), (12, "broker", 1, 20),
                                           (13, "worker", 12, 30), (14, "engine", 11, 40)):
            processes.append({"processIdentifier": pid, "parentProcessIdentifier": parent, "startSeconds": 123,
                              "startMicroseconds": pid, "role": role, "path": signed[role]["path"], "residentBytes": resident})
        identities = [{key: value for key, value in row.items() if key != "residentBytes"} for row in processes]
        worker, broker = identities[2], identities[1]
        physical = dict(worker, physicalExitObserved=True, physicalExitUptimeNanoseconds=100, stage="rebuild",
                        acceptedEvent={"processIdentifier": 13, "stage": "rebuild", "uptimeNanoseconds": 80},
                        exitedEvent={"processIdentifier": 13, "stage": "rebuild", "uptimeNanoseconds": 95}, brokerIdentity=broker)
        return {"wait4": {"pid": 11}, "signedExecutables": signed, "physicalObservers": [physical],
                "memory": {"driverObservationErrors": [], "ownedOrKnownPIDQueryFailuresOmitted": 0,
                "ownedOrKnownPIDQueryFailures": [], "samples": 1,
                "samplesRaw": [{"uptimeNanoseconds": 90, "stage": "rebuild", "processes": processes}],
                "validResidentSamplesByRole": {role: 1 for role in signed},
                "failedResidentSamplesByRole": {role: 0 for role in signed},
                "peakResidentBytesByRole": {"host": 10, "broker": 20, "worker": 30, "engine": 40},
                "completeFamilySamplingPasses": 1, "incompleteFamilySamplingPasses": 0,
                "peakSimultaneousFamilyResidentBytes": 100, "peakKnownResidentBytesInIncompleteFamilyPass": None,
                "observedProcesses": identities}}

    def test_all_owned_role_peaks_and_family_sum_recompute_from_whole_raw_population(self):
        value = self.attempt()
        result = gate.audit_memory(value)
        self.assertTrue(result["physicalWorkerExitOraclePassed"])
        self.assertTrue(result["rssEvidenceComplete"])
        self.assertEqual(result["acceptedWorkers"], 1)

    def test_missing_engine_is_explicitly_unavailable_not_a_zero_peak(self):
        value = self.attempt(); memory = value["memory"]
        memory["samplesRaw"][0]["processes"].pop()
        memory["observedProcesses"].pop()
        memory["validResidentSamplesByRole"]["engine"] = 0
        memory["peakResidentBytesByRole"]["engine"] = None
        memory["peakSimultaneousFamilyResidentBytes"] = 60
        result = gate.audit_memory(value)
        self.assertFalse(result["rssEvidenceComplete"])
        self.assertIn("unobserved", result["rssUnavailability"])

    def test_false_peak_omitted_population_or_unrelated_host_fail(self):
        for name, mutate in [("peak", lambda a: a["memory"]["peakResidentBytesByRole"].update(host=999)),
                             ("population", lambda a: a["memory"].update(samples=2)),
                             ("same bundle GUI", lambda a: a["memory"]["samplesRaw"][0]["processes"][0].update(processIdentifier=999)),
                             ("other engine", lambda a: a["memory"]["samplesRaw"][0]["processes"][3].update(parentProcessIdentifier=999)),
                             ("post exit", lambda a: a["memory"]["samplesRaw"][0].update(uptimeNanoseconds=101))]:
            with self.subTest(name=name):
                value = self.attempt(); mutate(value)
                with self.assertRaises(AssertionError):
                    gate.audit_memory(value)

    def test_missing_physical_exit_wrong_parent_and_query_cap_fail(self):
        for name, mutate in [("exit", lambda a: a["physicalObservers"][0].update(physicalExitObserved=False)),
                             ("parent", lambda a: a["physicalObservers"][0].update(parentProcessIdentifier=999)),
                             ("query cap", lambda a: a["memory"].update(ownedOrKnownPIDQueryFailuresOmitted=1))]:
            with self.subTest(name=name):
                value = self.attempt(); mutate(value)
                with self.assertRaises(AssertionError):
                    gate.audit_memory(value)


class SemanticTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.output = Path(self.tmp.name).resolve()
        self.fixture = self.output / "fixture"
        self.oracle, self.signed = oracles(), signed_inputs()
        self.sources = sources(self.fixture, self.oracle)
        self.case_id = str(uuid.uuid4()).upper()
        self.value = snapshot(("stable", "original"), self.sources, self.oracle, self.signed, self.case_id)

    def tearDown(self):
        self.tmp.cleanup()

    def validate(self, value):
        return gate.validate_snapshot(value, ("stable", "original"), self.sources, self.oracle, self.signed)

    def test_full_actual_xpc_source_status_text_hash_and_locator_oracle(self):
        result = self.validate(self.value)
        self.assertEqual(result["documentCounts"], {"indexed": 8, "skipped": 12, "failed": 0, "pending": 0})
        self.assertTrue(result["partialCoverage"])

    def test_wrong_source_full_content_hash_text_or_source_unit_fails(self):
        changes = [("source hash", lambda s: s["sources"][0].update(selectedContainerSHA256=h("wrong"))),
                   ("content hash", lambda s: next(d for d in s["documents"] if d["status"] == "indexed").update(contentSHA256=h("wrong"))),
                   ("text", lambda s: next(d for d in s["documents"] if d["status"] == "indexed")["textPages"][0].update(text="fabricated")),
                   ("source unit", lambda s: next(d for d in s["documents"] if d["status"] == "indexed")["textPages"][0].update(referenceLabel="Page 1"))]
        for name, mutate in changes:
            with self.subTest(name=name):
                value = copy.deepcopy(self.value); mutate(value)
                with self.assertRaises(AssertionError):
                    self.validate(value)

    def test_relaxed_cap_missing_sandbox_wrong_signature_or_option_digest_fail(self):
        for name, mutate in [("cap", lambda s: s["limits"].update(maximumFiles=513)),
                             ("isolation", lambda s: s["decoderIdentity"].update(isolation="testFixture")),
                             ("signature", lambda s: s["decoderIdentity"].update(decoderCodeSigningCDHash=h("wrong")[:40])),
                             ("option digest", lambda s: s["decoderIdentity"].update(optionsSHA256=h("wrong")))]:
            with self.subTest(name=name):
                value = copy.deepcopy(self.value); mutate(value)
                with self.assertRaises(AssertionError):
                    self.validate(value)

    def test_skipped_body_duplicate_document_or_complete_large_prefix_fail(self):
        for name, mutate in [("skipped body", lambda s: next(d for d in s["documents"] if d["status"] == "skipped").update(contentSHA256=h("wrong"))),
                             ("duplicate", lambda s: s["documents"].__setitem__(1, copy.deepcopy(s["documents"][0]))),
                             ("false completeness", lambda s: next(d for d in s["documents"] if d["file"]["path"] == "/LARGE.TXT").update(textIsComplete=True))]:
            with self.subTest(name=name):
                value = copy.deepcopy(self.value); mutate(value)
                with self.assertRaises(AssertionError):
                    self.validate(value)

    def test_literal_utf16_queries_distinguish_stable_replacement_and_combining_marks(self):
        old = gate.expected_search(("stable", "original"), self.oracle)
        new = gate.expected_search(("stable", "replacement"), self.oracle)
        self.assertEqual({x["label"] for x in old["needleOnlyInPayload"]}, {"stable", "original"})
        self.assertEqual({x["label"] for x in new["needleOnlyInPayload"]}, {"stable"})
        self.assertEqual({x["label"] for x in new["needleAfterReplacement"]}, {"replacement"})
        self.assertTrue(new["้"])
        self.assertEqual(old["needleAfterReplacement"], [])
        bad = copy.deepcopy(self.oracle); bad["stable"]["queries"]["เอกสาร"][0]["utf16Offset"] += 1
        with self.assertRaisesRegex(AssertionError, "UTF-16"):
            gate.expected_search(("stable", "original"), bad)

    def full_report(self):
        ledger, snaps = completed_ledger(), {}
        stages, searches = [], {}
        for stage in gate.COMPLETED_STAGES:
            labels = ("stable", "original") if stage in ("rebuild", "unchanged") else ("stable", "replacement")
            value = snapshot(labels, self.sources, self.oracle, self.signed, self.case_id)
            if stage == "unchanged":
                value["documents"] = copy.deepcopy(snaps["rebuild"]["documents"])
                value["sources"] = copy.deepcopy(snaps["rebuild"]["sources"])
            snaps[stage] = value
            gate.write_json(self.output / (stage + "-index.json"), value)
            reused, rebuilt = gate.COUNTS[stage]
            stages.append({"stage": stage, "durationNanoseconds": 100, "previewCount": rebuilt, "reusedFiles": reused,
                           "rebuiltFiles": rebuilt, "sourceIDs": [self.sources[label]["evidenceID"] for label in labels],
                           "snapshotID": value["id"], "serializedFilename": stage + "-index.json"})
            searches[stage] = gate.expected_search(labels, self.oracle)
        case = self.output / "Content Index Probe.nativecase"; case.mkdir()
        manifest = {"schemaVersion": 1, "id": self.case_id,
                    "evidence": [{"id": self.sources[label]["evidenceID"], "sourcePath": self.sources[label]["path"],
                                  "sha256": self.sources[label]["sha256"], "byteCount": self.sources[label]["byteCount"],
                                  "hashScope": "selected-file-bytes"}
                                 for label in ("stable", "original")]}
        gate.write_json(case / "manifest.json", manifest)
        gate.write_json(case / "derived-content-index.json", snaps["unchanged"])
        replacement_case = self.output / "Replacement Source Record.nativecase"; replacement_case.mkdir()
        replacement = self.sources["replacement"]
        gate.write_json(replacement_case / "manifest.json", {"schemaVersion": 1, "id": str(uuid.uuid4()).upper(),
                        "evidence": [{"id": replacement["evidenceID"], "sourcePath": replacement["path"],
                                      "sha256": replacement["sha256"], "byteCount": replacement["byteCount"],
                                      "hashScope": "selected-file-bytes"}]})
        cancel = [event for event in ledger.events if event["stage"] == "cancel"]
        requested = next(event["uptimeNanoseconds"] for event in cancel if event["kind"] == "decoderStarted")
        returned = next(event["uptimeNanoseconds"] for event in cancel if event["kind"] == "decoderExited")
        return {"schemaVersion": 1, "syntheticOnly": True, "backend": "actual-bundled-app-sandbox-xpc",
                "providerExecuted": False, "guiMeasured": False, "sources": list(self.sources.values()), "stages": stages,
                "searchHits": searches, "publicationRefused": True, "cancellationRequested": True, "cancellationReturned": True,
                "cancellationDurationNanoseconds": 200, "cancellationRequestedUptimeNanoseconds": requested,
                "cancellationReturnedUptimeNanoseconds": returned, "cancellationDrainNanoseconds": returned - requested,
                "measurementScope": "explicit diagnostic; no scheduler/GUI; retained oracles/snapshots in RSS",
                "cancellationScope": "accepted worker after ACK; external physical exit observed separately",
                "priorGenerationUnchanged": True, "newScratchRemaining": 0}, ledger, snaps

    def test_completed_pipeline_keeps_prior_durable_generation_and_changed_source_unpublished(self):
        report, ledger, _ = self.full_report()
        result = gate.validate_report(self.output, report, ledger, self.fixture, self.oracle, self.signed)
        self.assertTrue(result["semanticOraclePassed"])

    def test_wrong_progress_changed_search_or_manifest_scope_fail(self):
        report, ledger, _ = self.full_report()
        for name, mutate in [("reuse", lambda r: r["stages"][2].update(reusedFiles=8)),
                             ("preview", lambda r: r["stages"][0].update(previewCount=20)),
                             ("sourceID", lambda r: r["stages"][2]["sourceIDs"].__setitem__(1, self.sources["original"]["evidenceID"])),
                             ("search", lambda r: r["searchHits"]["changed"].update(needleAfterReplacement=[])),
                             ("cancellation", lambda r: r.update(cancellationReturned=False)),
                             ("drain subtraction", lambda r: r.update(cancellationDrainNanoseconds=1)),
                             ("request clock", lambda r: r.update(cancellationRequestedUptimeNanoseconds=1)),
                             ("publication", lambda r: r.update(publicationRefused=False))]:
            with self.subTest(name=name):
                value = copy.deepcopy(report); mutate(value)
                with self.assertRaises(AssertionError):
                    gate.validate_report(self.output, value, ledger, self.fixture, self.oracle, self.signed)

    def test_persisted_changed_generation_or_only_whitespace_rewrite_fails(self):
        report, ledger, snaps = self.full_report()
        persisted = self.output / "Content Index Probe.nativecase/derived-content-index.json"
        persisted.write_text(json.dumps(snaps["changed"], sort_keys=True))
        with self.assertRaisesRegex(AssertionError, "prior durable generation"):
            gate.validate_report(self.output, report, ledger, self.fixture, self.oracle, self.signed)
        persisted.write_text(json.dumps(snaps["unchanged"], separators=(",", ":"), sort_keys=True))
        with self.assertRaisesRegex(AssertionError, "prior durable generation"):
            gate.validate_report(self.output, report, ledger, self.fixture, self.oracle, self.signed)

    def test_replacement_id_must_be_normally_recorded_in_its_distinct_case(self):
        report, ledger, _ = self.full_report()
        path = self.output / "Replacement Source Record.nativecase/manifest.json"
        value = json.loads(path.read_text())
        value["evidence"][0]["id"] = self.sources["original"]["evidenceID"]
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(AssertionError, "not normally recorded"):
            gate.validate_report(self.output, report, ledger, self.fixture, self.oracle, self.signed)


if __name__ == "__main__":
    unittest.main()

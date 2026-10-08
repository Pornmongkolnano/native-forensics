"""Compiler-free regressions for runtime evidence oracles, not parser tests."""
import copy
import errno
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import subprocess

import run_document_runtime_gates as gates
import prepare_and_run_document_runtime_gates as prepare


class HelperReceiptPipeTests(unittest.TestCase):
    class Pipe:
        def __init__(self, blocking):
            read, write = os.pipe()
            self.stdout = os.fdopen(read, "rb")
            self.writer = write
            os.set_blocking(read, blocking)

        def close_writer(self):
            if self.writer is not None:
                descriptor, self.writer = self.writer, None
                os.close(descriptor)

        def close(self):
            try:
                self.close_writer()
            finally:
                self.stdout.close()

    def pipe(self, blocking=True):
        value = self.Pipe(blocking)
        self.addCleanup(value.close)
        return value

    def close_writer_later(self, value):
        # A regression must fail the test, never hang the test runner forever.
        stop = threading.Event()
        worker = threading.Thread(target=lambda: (stop.wait(0.3), value.close_writer()), daemon=True)
        worker.start()
        def finish():
            stop.set()
            worker.join(0.5)
            self.assertFalse(worker.is_alive())
        self.addCleanup(finish)

    def test_valid_fragmented_receipt_and_following_line_are_preserved(self):
        value = self.pipe()
        def emit():
            for fragment in (b'{"sta', b'tus":"armed"}', b'\n{"status":"terminated"}\n'):
                os.write(value.writer, fragment)
                time.sleep(0.005)
        worker = threading.Thread(target=emit, daemon=True)
        worker.start()
        try:
            self.assertEqual(gates.wait_json_line(value, 0.5), {"status": "armed"})
            self.assertEqual(gates.wait_json_line(value, 0.5), {"status": "terminated"})
            self.assertTrue(os.get_blocking(value.stdout.fileno()))
            self.assertFalse(value.stdout.closed)
        finally:
            worker.join(0.5)
            self.assertFalse(worker.is_alive())

    def test_partial_receipt_without_newline_has_absolute_deadline(self):
        value = self.pipe()
        os.write(value.writer, b'{"status":"armed"}')
        self.close_writer_later(value)
        started = time.monotonic()
        with self.assertRaisesRegex(AssertionError, "bounded deadline"):
            gates.wait_json_line(value, 0.03)
        self.assertLess(time.monotonic() - started, 0.2)
        self.assertTrue(os.get_blocking(value.stdout.fileno()))

    def test_deadline_does_not_restart_after_each_fragment(self):
        value = self.pipe()
        os.write(value.writer, b"{")
        stop = threading.Event()
        def emit():
            for _ in range(10):
                if stop.wait(0.01):
                    break
                os.write(value.writer, b" ")
        worker = threading.Thread(target=emit, daemon=True)
        worker.start()
        self.close_writer_later(value)
        try:
            started = time.monotonic()
            with self.assertRaisesRegex(AssertionError, "bounded deadline"):
                gates.wait_json_line(value, 0.03)
            self.assertLess(time.monotonic() - started, 0.2)
        finally:
            stop.set()
            worker.join(0.5)
            self.assertFalse(worker.is_alive())

    def test_no_output_and_expired_deadline_fail_without_closing_stream(self):
        value = self.pipe(blocking=False)
        self.close_writer_later(value)
        for timeout in (0.03, 0):
            with self.assertRaisesRegex(AssertionError, "bounded deadline"):
                gates.wait_json_line(value, timeout)
        self.assertFalse(os.get_blocking(value.stdout.fileno()))
        self.assertFalse(value.stdout.closed)

    def test_cap_accepts_exact_line_and_rejects_one_overflow_byte(self):
        value = self.pipe()
        exact = b'{"x":"' + b"a" * (4096 - len(b'{"x":""}\n')) + b'"}\n'
        self.assertEqual(len(exact), 4096)
        os.write(value.writer, exact)
        self.assertEqual(len(gates.wait_json_line(value, 0.5)["x"]), 4087)
        # 4096 JSON bytes plus newline is one byte beyond the total line cap.
        os.write(value.writer, exact[:-1] + b" \n")
        with self.assertRaisesRegex(AssertionError, "byte cap"):
            gates.wait_json_line(value, 0.5)
        self.assertTrue(os.get_blocking(value.stdout.fileno()))

    def test_malformed_nonobject_and_eof_fail_closed(self):
        for body, error, message in ((b"{bad-json}\n", json.JSONDecodeError, None),
                                     (b"[]\n", AssertionError, "not an object"),
                                     (b'{"x":1}', AssertionError, "ended before"),
                                     (b"", AssertionError, "ended before")):
            value = self.pipe()
            os.write(value.writer, body)
            value.close_writer()
            if message:
                with self.assertRaisesRegex(error, message):
                    gates.wait_json_line(value, 0.5)
            else:
                with self.assertRaises(error):
                    gates.wait_json_line(value, 0.5)
            self.assertTrue(os.get_blocking(value.stdout.fileno()))
            self.assertFalse(value.stdout.closed)


class RuntimeEvidenceOracleTests(unittest.TestCase):
    def boundary(self):
        operations = {name: {"allowed": False, "errno": errno.EPERM, "stage": stage}
                      for name, stage in (("outsideRead", "open"), ("outsideWritableOpen", "open"),
                                          ("outsideCreate", "open"), ("ipv4LoopbackConnect", "connect"),
                                          ("ipv4LoopbackBind", "bind"), ("unixOutsideBind", "bind"))}
        operations.update({name: {"allowed": True, "errno": 0}
                           for name in ("ipv4Socket", "inheritedContainerWrite", "systemTrueExecution")})
        operations["ownContainerWrite"] = {"allowed": False, "errno": errno.EPERM}
        return {"textPages": [{"text": json.dumps(operations), "isTruncated": False}]}

    def report(self, count=2):
        events = []
        for ordinal in range(1, count + 1):
            events += [{"ordinal": ordinal, "kind": kind, "processIdentifier": 100 + ordinal,
                        "uptimeNanoseconds": ordinal * 1000 + offset}
                       for kind, offset in (("started", 0), ("exited", 100))]
        return {"available": True, "attempts": [{"ordinal": ordinal, "analysis": {"schemaVersion": 2}}
                for ordinal in range(1, count + 1)], "events": events}

    def test_all_accepted_workers_need_physical_exit(self):
        report = self.report()
        gates.validate_lifecycle(report, 2)
        report["events"].pop()
        with self.assertRaisesRegex(AssertionError, "lacks physical exit"):
            gates.validate_lifecycle(report, 2)

    def test_shared_or_overlapping_parser_is_rejected(self):
        report = self.report()
        report["events"][1], report["events"][2] = report["events"][2], report["events"][1]
        with self.assertRaisesRegex(AssertionError, "overlapping"):
            gates.validate_lifecycle(report, 2)
        report = self.report()
        report["events"][2]["processIdentifier"] = report["events"][3]["processIdentifier"] = 101
        with self.assertRaisesRegex(AssertionError, "reused a parser PID"):
            gates.validate_lifecycle(report, 2)

    def test_early_cancel_is_not_relabelled_after_trust(self):
        report = {"available": True, "attempts": [{"ordinal": 1, "errorCode": "cancelled"}],
                  "events": [{"ordinal": 1, "kind": "cancelRequested", "processIdentifier": 0}]}
        gates.validate_lifecycle(report, 1, expect_error="cancelled", no_trusted_start=True)
        report["events"] += self.report(1)["events"]
        with self.assertRaisesRegex(AssertionError, "after trusted peer"):
            gates.validate_lifecycle(report, 1, expect_error="cancelled", no_trusted_start=True)

    def test_duplicate_attempt_start_cannot_cover_missing_attempt(self):
        report = self.report()
        report["events"][2]["ordinal"] = report["events"][3]["ordinal"] = 1
        with self.assertRaisesRegex(AssertionError, "each attempt ordinal"):
            gates.validate_lifecycle(report, 2)

    def test_same_host_early_cancel_recovery_requires_only_second_attempt_start(self):
        report = self.report()
        report["attempts"][0] = {"ordinal": 1, "errorCode": "cancelled"}
        report["events"] = [{"ordinal": 1, "kind": "cancelRequested", "processIdentifier": 0}] + report["events"][2:]
        gates.validate_lifecycle(report, 2, start_ordinals=[2], expected_errors=["cancelled", None])
        report["events"] += self.report(1)["events"]
        with self.assertRaisesRegex(AssertionError, "each attempt ordinal"):
            gates.validate_lifecycle(report, 2, start_ordinals=[2], expected_errors=["cancelled", None])

    def test_source_receipt_detects_same_length_change(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "synthetic"
            path.write_bytes(b"old")
            before = gates.receipt(path)
            path.write_bytes(b"new")
            self.assertNotEqual(gates.receipt(path), before)

    def test_actual_parser_and_broker_and_whole_text_are_bound(self):
        identities = {role: {"sha256": value * 64, "codeSigningCDHash": value * 40}
                      for role, value in (("worker", "1"), ("broker", "2"))}
        source = {"sha256": "3" * 64, "bytes": 8}
        options = {"timeoutSeconds": 12.0, "maximumInputBytes": 128 * gates.MIB,
                   "maximumResponseBytes": 2 * gates.MIB, "maximumTextBytes": gates.MIB}
        pages = [{"pageNumber": 1, "text": "ข้อความไทย", "isTruncated": False}]
        provenance = {"schemaVersion": 1, "decoderIdentifier": "NativeForensics.document-decoder",
                      "decoderVersion": "2.1.0", "isolation": "appSandboxXPC", "options": options,
                      "decoderExecutableSHA256": "1" * 64, "decoderCodeSigningCDHash": "1" * 40,
                      "brokerExecutableSHA256": "2" * 64, "brokerCodeSigningCDHash": "2" * 40,
                      "optionsSHA256": gates.document_receipt_digest(options),
                      "derivedTextSHA256": gates.document_receipt_digest(pages)}
        analysis = {"schemaVersion": 2, "status": "decoded", "sourceSHA256": source["sha256"],
                    "sourceByteCount": 8, "provenance": provenance, "textPages": pages}
        gates.validate_attempt(analysis, source, identities, 12.0)
        bad = copy.deepcopy(analysis)
        bad["provenance"]["brokerExecutableSHA256"] = "4" * 64
        with self.assertRaisesRegex(AssertionError, "executable provenance"):
            gates.validate_attempt(bad, source, identities, 12.0)
        bad = copy.deepcopy(analysis)
        bad["textPages"][0]["text"] += " altered"
        with self.assertRaisesRegex(AssertionError, "derived-text digest"):
            gates.validate_attempt(bad, source, identities, 12.0)

    def test_narrowed_input_policy_cannot_pass_runtime_oracle(self):
        # Cap checking happens before receipt digest comparison. This prevents
        # a newly rehashed smaller policy from becoming a performance pass.
        identities = {role: {"sha256": value * 64, "codeSigningCDHash": value * 40}
                      for role, value in (("worker", "1"), ("broker", "2"))}
        analysis = {"schemaVersion": 2, "status": "decoded", "sourceSHA256": "3" * 64,
                    "sourceByteCount": 8, "provenance": {
                        "schemaVersion": 1, "decoderIdentifier": "NativeForensics.document-decoder", "decoderVersion": "2.1.0",
                        "isolation": "appSandboxXPC", "decoderExecutableSHA256": "1" * 64,
                        "decoderCodeSigningCDHash": "1" * 40, "brokerExecutableSHA256": "2" * 64,
                        "brokerCodeSigningCDHash": "2" * 40,
                        "options": {"timeoutSeconds": 12.0, "maximumInputBytes": 32 * gates.MIB,
                                    "maximumResponseBytes": 2 * gates.MIB, "maximumTextBytes": gates.MIB}}}
        with self.assertRaisesRegex(AssertionError, "cap/timeout changed"):
            gates.validate_attempt(analysis, {"sha256": "3" * 64, "bytes": 8}, identities, 12.0)

    def test_preparation_refuses_unhandled_production_signing_restriction(self):
        result = subprocess.CompletedProcess([], 0, "", "CodeDirectory v=20400 flags=0x100(hard)\nExecutable Segment flags=0x1\n")
        with patch.object(prepare.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(AssertionError, "unhandled production signing flags"):
                prepare.signing_flags(Path("synthetic-worker"))

    def test_preparation_reads_code_directory_flags_from_current_sdk_display(self):
        # Actual current SDK field structure; omit executable paths and hashes.
        display = ("Format=app bundle with Mach-O thin (arm64)\n"
                   "CodeDirectory v=20400 size=34658 flags=0x2(adhoc) hashes=1076+3 location=embedded\n"
                   "Executable Segment base=0\nExecutable Segment limit=7962624\n"
                   "Executable Segment flags=0x1\nTotal signatures=1\nChosen signature=1\n")
        result = subprocess.CompletedProcess([], 0, "", display)
        with patch.object(prepare.subprocess, "run", return_value=result):
            self.assertEqual(prepare.signing_flags(Path("synthetic-host")), 0x2)

    def test_preparation_rejects_missing_or_multiple_code_directory_records(self):
        for display in ("Executable Segment flags=0x1\n",
                        "CodeDirectory v=20400 flags=0x2(adhoc)\nCodeDirectory v=20400 flags=0x2(adhoc)\n"):
            result = subprocess.CompletedProcess([], 0, "", display)
            with patch.object(prepare.subprocess, "run", return_value=result):
                with self.assertRaisesRegex(AssertionError, "source signing flags unavailable"):
                    prepare.signing_flags(Path("synthetic-ambiguous"))

    def test_zero_broker_observations_are_unproven_and_failure_keeps_raw_evidence(self):
        gate = {"name": "synthetic-sustained", "memory": {"observedProcesses": []},
                "gateStatus": "observed; semantic oracle pending"}
        records = []
        with tempfile.TemporaryDirectory() as root:
            gates.record_gate(Path(root), records, gate, 64)
            with self.assertRaisesRegex(AssertionError, "criterion is unproven"):
                gates.require_one_broker(gate)
            self.assertEqual(len(records), 1)
            raw = Path(root) / "synthetic-sustained.driver.json"
            self.assertTrue(raw.is_file())
            self.assertIn('"observedProcesses":[]', raw.read_text())
            self.assertEqual(gate["observedBrokerBirthCount"], 0)

    def test_multiple_broker_births_fail_even_when_pid_is_reused(self):
        gate = {"memory": {"observedProcesses": [
            {"role": "broker", "processIdentifier": 100, "startSeconds": 1000, "startMicroseconds": 1},
            {"role": "broker", "processIdentifier": 100, "startSeconds": 1001, "startMicroseconds": 2}]}}
        with self.assertRaisesRegex(AssertionError, "multiple exact-owned broker births observed: 2"):
            gates.require_one_broker(gate)

    def test_preparation_keeps_hardened_runtime_and_disables_timestamp_request(self):
        with patch.object(prepare.subprocess, "run") as command:
            prepare.sign(Path("synthetic-worker"), "-", "org.nativeforensics.NFDocumentDecoderWorker",
                         Path("synthetic-exact-entitlements.plist"), 0x10002)
        arguments = command.call_args.args[0]
        self.assertIn("--timestamp=none", arguments)
        self.assertEqual(arguments[arguments.index("--options") + 1], "runtime")
        self.assertEqual(arguments[arguments.index("--entitlements") + 1], "synthetic-exact-entitlements.plist")

    def test_boundary_denials_require_permission_error_at_the_attempted_operation(self):
        gates.validate_boundary(self.boundary())
        for operation in ("outsideRead", "outsideWritableOpen", "outsideCreate", "ipv4LoopbackConnect",
                          "ipv4LoopbackBind", "unixOutsideBind"):
            for error in (errno.ENOENT, errno.ENAMETOOLONG, errno.ECONNREFUSED, True):
                value = self.boundary()
                operations = json.loads(value["textPages"][0]["text"])
                operations[operation]["errno"] = error
                value["textPages"][0]["text"] = json.dumps(operations)
                with self.assertRaisesRegex(AssertionError, "actual stage"):
                    gates.validate_boundary(value)

    def test_socket_creation_denial_cannot_be_labelled_connect_or_bind_denial(self):
        for operation in ("ipv4LoopbackConnect", "ipv4LoopbackBind", "unixOutsideBind"):
            value = self.boundary()
            operations = json.loads(value["textPages"][0]["text"])
            operations[operation]["stage"] = "socket"
            value["textPages"][0]["text"] = json.dumps(operations)
            with self.assertRaisesRegex(AssertionError, "actual stage"):
                gates.validate_boundary(value)

    def test_container_and_owned_child_spawn_are_required_positive_controls(self):
        for operation in ("inheritedContainerWrite", "systemTrueExecution"):
            value = self.boundary()
            operations = json.loads(value["textPages"][0]["text"])
            operations[operation] = {"allowed": False, "errno": errno.EPERM}
            value["textPages"][0]["text"] = json.dumps(operations)
            with self.assertRaisesRegex(AssertionError, "positive control"):
                gates.validate_boundary(value)
        self.assertFalse(gates.validate_boundary(self.boundary())["operations"]["ownContainerWrite"]["allowed"])

    def test_control_receipt_rejects_same_size_wrong_contents_hardlinks_and_fifo(self):
        with tempfile.TemporaryDirectory() as root:
            directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                path = Path(root) / "marker"
                path.write_bytes(b"N")
                path.chmod(0o600)
                self.assertEqual(prepare.regular_receipt(directory, "marker", b"N")["bytes"], 1)
                with self.assertRaisesRegex(AssertionError, "contents changed"):
                    prepare.regular_receipt(directory, "marker", b"C")
                os.link(path, Path(root) / "alias")
                with self.assertRaisesRegex(AssertionError, "shape changed"):
                    prepare.regular_receipt(directory, "marker", b"N")
                path.unlink()
                os.mkfifo(path, 0o600)
                with self.assertRaisesRegex(AssertionError, "shape changed"):
                    prepare.regular_receipt(directory, "marker", b"N")
            finally:
                os.close(directory)

    def test_owned_private_directory_identity_is_checked_and_cleaned(self):
        with tempfile.TemporaryDirectory() as parent:
            directory = prepare.PrivateDirectory(Path(parent).resolve(), "synthetic-")
            path = directory.path
            descriptor = os.open("one", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600, dir_fd=directory.descriptor)
            os.close(descriptor)
            directory.check()
            directory.close({"one"})
            self.assertFalse(path.exists())

    def test_failure_recovery_requires_mixed_error_success_and_physical_order(self):
        report = self.report()
        report["attempts"][0] = {"ordinal": 1, "errorCode": "timeout"}
        gates.validate_lifecycle(report, 2, expected_errors=["timeout", None])
        report["attempts"][1] = {"ordinal": 2, "errorCode": "timeout"}
        with self.assertRaisesRegex(AssertionError, "unexpected attempt"):
            gates.validate_lifecycle(report, 2, expected_errors=["timeout", None])
        report = self.report()
        report["attempts"][0] = {"ordinal": 1, "errorCode": "timeout"}
        report["events"].pop(1)
        with self.assertRaisesRegex(AssertionError, "overlapping"):
            gates.validate_lifecycle(report, 2, expected_errors=["timeout", None])

    def test_same_broker_recovery_requires_independent_birth_bound_observers(self):
        identities = {role: {"sha256": value * 64, "codeSigningCDHash": value * 40}
                      for role, value in (("worker", "1"), ("broker", "2"))}
        options = {"timeoutSeconds": 2.0, "maximumInputBytes": 128 * gates.MIB,
                   "maximumResponseBytes": 2 * gates.MIB, "maximumTextBytes": gates.MIB}
        pages = [{"pageNumber": 1, "text": "synthetic parser worker fixture response", "isTruncated": False,
                  "referenceLabel": "Synthetic worker fixture", "referenceKind": "document"}]
        provenance = {"schemaVersion": 1, "decoderIdentifier": "NativeForensics.document-decoder", "decoderVersion": "2.1.0",
                      "isolation": "appSandboxXPC", "options": options, "decoderExecutableSHA256": "1" * 64,
                      "decoderCodeSigningCDHash": "1" * 40, "brokerExecutableSHA256": "2" * 64,
                      "brokerCodeSigningCDHash": "2" * 40, "optionsSHA256": gates.document_receipt_digest(options),
                      "derivedTextSHA256": gates.document_receipt_digest(pages)}
        analysis = {"schemaVersion": 2, "status": "decoded", "sourceSHA256": "3" * 64, "sourceByteCount": 8,
                    "provenance": provenance, "textPages": pages}
        report = self.report()
        report["attempts"] = [{"ordinal": 1, "errorCode": "timeout"}, {"ordinal": 2, "analysis": analysis}]
        def birth(pid, role):
            return {"processIdentifier": pid, "parentProcessIdentifier": 90, "role": role, "path": "/owned/" + role,
                    "startSeconds": 1000, "startMicroseconds": pid}
        first, broker, second = birth(101, "worker"), birth(90, "broker"), birth(102, "worker")
        gate = {"report": report, "sourceReceipt": {"sha256": "3" * 64, "bytes": 8},
                "memory": {"observedProcesses": [broker]}, "intervention": {
                    "phase": "registered-broker-and-failed-worker", "worker": first, "broker": broker,
                    "recoveryWorker": second, "brokerLiveAtRecoveryWorkerObservation": True},
                "physicalObservers": [dict(row, physicalExitObserved=position != 1) for position, row in enumerate((first, broker, second))]}
        gates.validate_failure_recovery(gate, "timeout", identities, 2.0)
        bad = copy.deepcopy(gate)
        bad["intervention"].pop("recoveryWorker")
        with self.assertRaisesRegex(AssertionError, "continuity is unproven"):
            gates.validate_failure_recovery(bad, "timeout", identities, 2.0)
        bad = copy.deepcopy(gate)
        bad["physicalObservers"][2]["startMicroseconds"] += 1
        with self.assertRaisesRegex(AssertionError, "sampled birth/path"):
            gates.validate_failure_recovery(bad, "timeout", identities, 2.0)
        bad = copy.deepcopy(gate)
        bad["intervention"]["recoveryWorker"]["parentProcessIdentifier"] += 1
        with self.assertRaisesRegex(AssertionError, "changed broker parent"):
            gates.validate_failure_recovery(bad, "timeout", identities, 2.0)
        bad = copy.deepcopy(gate)
        bad["intervention"]["brokerLiveAtRecoveryWorkerObservation"] = False
        with self.assertRaisesRegex(AssertionError, "was not alive"):
            gates.validate_failure_recovery(bad, "timeout", identities, 2.0)
        bad = copy.deepcopy(gate)
        bad["physicalObservers"].pop()
        with self.assertRaisesRegex(AssertionError, "independent physical exit"):
            gates.validate_failure_recovery(bad, "timeout", identities, 2.0)

    def test_listener_accept_or_error_cannot_support_network_denial(self):
        valid = {"address": "127.0.0.1", "acceptTimeoutSeconds": 0.1, "applicationDataTransferred": False,
                 "acceptedConnections": 0, "errors": []}
        prepare.validate_listener_receipt(valid)
        for change in ({"acceptedConnections": 1}, {"errors": [errno.EIO]}, {"applicationDataTransferred": True}):
            with self.assertRaisesRegex(AssertionError, "no network-denial pass"):
                prepare.validate_listener_receipt({**valid, **change})

    def test_directory_rollback_closes_both_fds_if_removal_fails(self):
        with tempfile.TemporaryDirectory() as parent:
            original_close = prepare.os.close
            with patch.object(prepare.PrivateDirectory, "check", side_effect=AssertionError("original setup failure")), \
                 patch.object(prepare.os, "rmdir", side_effect=OSError(errno.EIO, "synthetic rollback failure")), \
                 patch.object(prepare.os, "close", wraps=original_close) as closed:
                with self.assertRaisesRegex(AssertionError, "original setup failure") as failure:
                    prepare.PrivateDirectory(Path(parent).resolve(), "synthetic-")
                self.assertEqual(closed.call_count, 2)
                self.assertIn("synthetic rollback failure", failure.exception.ownedRollbackFailure["details"][0])

    def test_listener_thread_start_failure_closes_allocated_socket(self):
        with patch.object(prepare.socket, "socket") as allocated, patch.object(prepare.threading, "Thread") as thread:
            allocated.return_value.getsockname.return_value = ("127.0.0.1", 12345)
            thread.return_value.start.side_effect = RuntimeError("synthetic startup failure")
            with self.assertRaisesRegex(RuntimeError, "synthetic startup failure"):
                prepare.LoopbackListener()
            allocated.return_value.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()

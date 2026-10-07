#!/usr/bin/env python3
"""Synchronized fake-process tests; no subprocess or benchmark is executed."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import threading
import time
import types
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest import mock


REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("benchmark_process_timing", REPO / "script/benchmark_process_timing.py")
timing = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = timing
spec.loader.exec_module(timing)


class ControlledProcess:
    """Expose only the blocking wait contract, gated by test-owned events."""

    def __init__(self, returncode=0, error=None):
        self.args = ["synthetic-owned-process"]
        self.returncode = returncode
        self.error = error
        self.entered = threading.Event()
        self.release = threading.Event()
        self.left = threading.Event()
        self.wait_calls = 0
        self.wait_thread = None

    def wait(self):
        self.wait_calls += 1
        self.wait_thread = threading.current_thread()
        self.entered.set()
        try:
            if not self.release.wait(2):
                raise AssertionError("test did not release its fake process")
            if self.error is not None:
                raise self.error
            return self.returncode
        finally:
            self.left.set()

    def poll(self):
        raise AssertionError("process polling is forbidden")

    def terminate(self):
        raise AssertionError("the waiter must not terminate processes")

    def kill(self):
        raise AssertionError("the waiter must not kill processes")


class ProcessTimingTests(unittest.TestCase):
    def released_process(self, **kwargs):
        process = ControlledProcess(**kwargs)
        process.release.set()
        return process

    def test_exit_is_observed_once_by_a_daemon_worker_without_polling(self):
        process = self.released_process(returncode=-15)
        before = time.monotonic()
        result = timing.wait_for_process(process, 1)
        after = time.monotonic()
        self.assertEqual(result.returncode, -15)
        self.assertLessEqual(before, result.exit_monotonic)
        self.assertLessEqual(result.exit_monotonic, after)
        self.assertEqual(result.method, timing.EXIT_OBSERVATION_METHOD)
        self.assertEqual(process.wait_calls, 1)
        self.assertIsNot(process.wait_thread, threading.current_thread())
        self.assertTrue(process.wait_thread.daemon)
        with self.assertRaises(FrozenInstanceError):
            result.returncode = 99

    def test_caller_blocks_until_the_controlled_process_exits(self):
        process = ControlledProcess(returncode=7)
        caller_done = threading.Event()
        outcome = {}

        def call_waiter():
            try:
                outcome["result"] = timing.wait_for_process(process, 1)
            except BaseException as error:
                outcome["error"] = error
            finally:
                caller_done.set()

        caller = threading.Thread(target=call_waiter, daemon=True)
        caller.start()
        try:
            self.assertTrue(process.entered.wait(1))
            self.assertFalse(caller_done.is_set())
            process.release.set()
            self.assertTrue(caller_done.wait(1))
            self.assertNotIn("error", outcome)
            self.assertEqual(outcome["result"].returncode, 7)
            self.assertEqual(process.wait_calls, 1)
        finally:
            process.release.set()
            caller.join(timeout=1)
        self.assertFalse(caller.is_alive())

    def test_exit_timestamp_precedes_delayed_parent_delivery(self):
        process = self.released_process()
        caller = threading.current_thread()
        caller_time = [10.0]

        def monotonic():
            return caller_time[0] if threading.current_thread() is caller else 10.25

        class DelayedDeliveryEvent:
            def __init__(self):
                self.event = threading.Event()

            def set(self):
                self.event.set()

            def wait(self, timeout):
                ready = self.event.wait(timeout)
                caller_time[0] = 100.0  # Parent resumes well after the exit.
                return ready

        thread_api = types.SimpleNamespace(Event=DelayedDeliveryEvent, Thread=threading.Thread,
                                           TIMEOUT_MAX=threading.TIMEOUT_MAX)
        with mock.patch.object(timing, "time", types.SimpleNamespace(monotonic=monotonic)), \
                mock.patch.object(timing, "threading", thread_api):
            result = timing.wait_for_process(process, 1)
        self.assertEqual(result.exit_monotonic, 10.25)
        self.assertEqual(caller_time[0], 100.0)

    def test_timeout_returns_while_worker_is_blocked_and_leaves_cleanup_to_caller(self):
        process = ControlledProcess()
        before = time.monotonic()
        try:
            with self.assertRaises(subprocess.TimeoutExpired) as raised:
                timing.wait_for_process(process, 0.02)
            after = time.monotonic()
            self.assertEqual(raised.exception.cmd, process.args)
            self.assertEqual(raised.exception.timeout, 0.02)
            self.assertLessEqual(before + 0.02, raised.exception.observed_monotonic)
            self.assertLessEqual(raised.exception.observed_monotonic, after)
            self.assertLess(after - before, 1)
            self.assertTrue(process.entered.is_set())
            self.assertFalse(process.release.is_set())
            self.assertFalse(process.left.is_set())
            self.assertEqual(process.wait_calls, 1)
        finally:
            process.release.set()
            self.assertTrue(process.left.wait(1))

    def test_worker_error_is_reraised_unchanged_with_worker_traceback(self):
        failure = OSError("synthetic wait failure")
        process = self.released_process(error=failure)
        try:
            timing.wait_for_process(process, 1)
        except OSError as raised:
            self.assertIs(raised, failure)
            frames = []
            traceback = raised.__traceback__
            while traceback is not None:
                frames.append(traceback.tb_frame.f_code.co_name)
                traceback = traceback.tb_next
        else:
            self.fail("worker error was not propagated")
        self.assertIn("_observe_exit", frames)
        self.assertIn("wait", frames)
        self.assertEqual(process.wait_calls, 1)

    def test_base_exception_in_worker_does_not_turn_into_a_timeout(self):
        failure = KeyboardInterrupt("synthetic worker interruption")
        process = self.released_process(error=failure)
        with self.assertRaises(KeyboardInterrupt) as raised:
            timing.wait_for_process(process, 1)
        self.assertIs(raised.exception, failure)

    def test_exit_observed_after_deadline_is_timeout_even_if_event_is_ready(self):
        process = self.released_process()
        caller = threading.current_thread()
        caller_times = iter((10.0, 10.0, 12.0))

        def monotonic():
            return next(caller_times) if threading.current_thread() is caller else 11.5

        with mock.patch.object(timing, "time", types.SimpleNamespace(monotonic=monotonic)):
            with self.assertRaises(subprocess.TimeoutExpired) as raised:
                timing.wait_for_process(process, 1)
        self.assertEqual(raised.exception.observed_monotonic, 12.0)
        self.assertEqual(process.wait_calls, 1)

    def test_observer_starts_immediately_and_retains_ontime_exit_before_delayed_wait(self):
        process = self.released_process(returncode=8)
        caller = threading.current_thread()
        caller_time = [10.0]

        def monotonic():
            return caller_time[0] if threading.current_thread() is caller else 10.25

        with mock.patch.object(timing, "time", types.SimpleNamespace(monotonic=monotonic)):
            observer = timing.ProcessExitObserver(process, 1)
            self.assertTrue(process.entered.wait(1))
            self.assertTrue(observer._finished.wait(1))  # Synchronize receipt publication.
            caller_time[0] = 100.0  # Simulate slow sampler initialization.
            result = observer.wait()
        self.assertEqual(result.returncode, 8)
        self.assertEqual(result.exit_monotonic, 10.25)
        self.assertEqual(process.wait_calls, 1)

    def test_observer_delayed_wait_does_not_accept_a_late_exit(self):
        process = self.released_process()
        caller = threading.current_thread()
        caller_time = [10.0]

        def monotonic():
            return caller_time[0] if threading.current_thread() is caller else 11.5

        with mock.patch.object(timing, "time", types.SimpleNamespace(monotonic=monotonic)):
            observer = timing.ProcessExitObserver(process, 1)
            self.assertTrue(observer._finished.wait(1))
            caller_time[0] = 12.0
            with self.assertRaises(subprocess.TimeoutExpired) as raised:
                observer.wait()
        self.assertEqual(raised.exception.observed_monotonic, 12.0)
        self.assertEqual(raised.exception.timeout, 1)
        self.assertEqual(process.wait_calls, 1)

    def test_observer_deadline_includes_initialization_before_wait(self):
        process = ControlledProcess()
        observed_time = [10.0]
        observer = None
        with mock.patch.object(timing, "time", types.SimpleNamespace(monotonic=lambda: observed_time[0])):
            try:
                observer = timing.ProcessExitObserver(process, 1)
                self.assertTrue(process.entered.wait(1))
                observed_time[0] = 12.0  # Initialization used the entire deadline.
                before_wait = time.monotonic()
                with self.assertRaises(subprocess.TimeoutExpired) as raised:
                    observer.wait()
                self.assertLess(time.monotonic() - before_wait, 1)
                self.assertEqual(raised.exception.observed_monotonic, 12.0)
                self.assertFalse(process.left.is_set())
            finally:
                process.release.set()
                if observer is not None:
                    self.assertTrue(observer._finished.wait(1))

    def test_invalid_timeout_is_rejected_before_starting_worker(self):
        process = ControlledProcess()
        for timeout in (-1, float("nan"), float("inf"), -float("inf"), threading.TIMEOUT_MAX * 2):
            with self.subTest(timeout=timeout), self.assertRaisesRegex(ValueError, "timeout must be"):
                timing.wait_for_process(process, timeout)
        self.assertEqual(process.wait_calls, 0)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Bounded observation of a Popen exit without timeout-based wait polling.

The worker timestamps immediately after a blocking ``process.wait()`` returns.
That is an observation of the exit, not the kernel's exact exit timestamp. The
calling thread's scheduling and later runner cleanup do not move this endpoint.
Callers must drain redirected pipes independently and own process-group cleanup.
"""

from __future__ import annotations

import math
import subprocess
import threading
import time
from dataclasses import dataclass


EXIT_OBSERVATION_METHOD = "blocking Popen.wait() worker with immediate time.monotonic() observation"


@dataclass(frozen=True)
class ProcessExit:
    returncode: int
    exit_monotonic: float
    method: str = EXIT_OBSERVATION_METHOD


class ProcessExitObserver:
    """Start observing an exact process immediately, then deliver its receipt.

    ``process.wait()`` is called once with no timeout, in a daemon worker. The
    deadline starts at construction, so callers should construct this directly
    after Popen, before sampler initialization. ``wait()`` waits on a bounded
    event only for the remaining deadline. A receipt observed by the worker by
    the deadline is retained even if the caller begins ``wait()`` later. Worker
    exceptions before that deadline are re-raised with their worker traceback.

    On timeout, ``subprocess.TimeoutExpired.observed_monotonic`` records when
    the parent detected failure. No signal, join, pipe operation, or cleanup is
    performed here. The daemon worker remains blocked until the caller's exact
    owned-process cleanup makes the wait return, so cleanup must stay bounded.
    """
    def __init__(self, process: subprocess.Popen, timeout: float):
        if not math.isfinite(timeout) or not 0 <= timeout <= threading.TIMEOUT_MAX:
            raise ValueError("timeout must be finite, nonnegative, and within threading.TIMEOUT_MAX")

        self._process = process
        self._timeout = timeout
        self._deadline = time.monotonic() + timeout
        self._finished = threading.Event()
        self._observation: ProcessExit | None = None
        self._wait_error: BaseException | None = None
        self._completed_monotonic: float | None = None
        threading.Thread(target=self._observe_exit, name="benchmark-process-waiter", daemon=True).start()

    def _observe_exit(self) -> None:
        try:
            returncode = self._process.wait()
            self._completed_monotonic = time.monotonic()
            self._observation = ProcessExit(returncode, self._completed_monotonic)
        except BaseException as error:
            self._completed_monotonic = time.monotonic()
            self._wait_error = error
        finally:
            self._finished.set()

    def wait(self) -> ProcessExit:
        """Deliver an on-time observation, or record bounded timeout detection."""
        ready = self._finished.wait(max(0.0, self._deadline - time.monotonic()))
        if ready and self._completed_monotonic is not None and self._completed_monotonic <= self._deadline:
            if self._wait_error is not None:
                raise self._wait_error
            if self._observation is not None:
                return self._observation

        observed_monotonic = time.monotonic()
        error = subprocess.TimeoutExpired(self._process.args, self._timeout)
        error.observed_monotonic = observed_monotonic
        raise error


def wait_for_process(process: subprocess.Popen, timeout: float) -> ProcessExit:
    """Construct an immediate observer and wait for its bounded exit receipt."""
    return ProcessExitObserver(process, timeout).wait()

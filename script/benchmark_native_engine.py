#!/usr/bin/env python3
"""Reproducible worker 1/2/4 extraction experiment for the pinned native helper.

Run after other NativeForensics jobs stop. This is a warmed-cache, instrumented
native-helper batch experiment, NOT an Autopsy comparison or Swift/UI benchmark.
No production worker default is changed. Only newly generated synthetic inputs
and exports under ignored local/ are used. Python standard library only.

Normal: python3 script/benchmark_native_engine.py
Smoke:  python3 script/benchmark_native_engine.py --smoke

Each block uses the SAME ordered jobs at all three concurrency limits. One warmup
block is excluded, then at least five paired blocks run in seeded, interleaved
worker order. Independent byte/hash validation and source hashing occur OUTSIDE
timed intervals. Verified exports are deleted individually after each batch.
"""

from __future__ import annotations

import argparse
import ctypes
import datetime
import errno
import hashlib
import json
import os
import platform
import plistlib
import random
import selectors
import signal
import statistics
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "Tests/NativeEngine"))
from benchmark_fixtures import BLOCK_BYTES, LARGE_NAME, generate_benchmark_fixtures, validate_export
from fixtures import digest


WORKERS = (1, 2, 4)
FRAME_LIMIT = 1024 * 1024
RESPONSE_LIMIT = 2 * 1024 * 1024  # These extraction jobs emit no listing rows.
TERMINALS = {"completed", "partial", "failed", "cancelled"}
ALLOWED_TYPES = {"hello", "image", "volume", "fileBatch", "progress", "warning", "error", "extracted", *TERMINALS}


def require(value, message):
    if not value:
        raise AssertionError(message)


def input_state(paths: list[Path]) -> list[dict]:
    result = []
    for path in paths:
        require(path.is_file() and not path.is_symlink(), "Inputs must be regular, non-symlink files")
        before = path.stat()
        sha256 = digest(path)
        after = path.stat()
        identity = lambda state: (state.st_dev, state.st_ino, state.st_size, state.st_mtime_ns, state.st_ctime_ns)
        require(identity(before) == identity(after), "Input changed while hashing")
        result.append({"name": path.name, "size": after.st_size, "sha256": sha256,
                       "identity": list(identity(after))})
    return result


def parse_response(request: dict, result: dict) -> list[dict]:
    lines = result["stdout"].splitlines()
    require(lines, "Native helper emitted no response")
    frames = []
    for sequence, line in enumerate(lines):
        require(len(line) <= FRAME_LIMIT, "Response frame exceeded 1 MiB")
        frame = json.loads(line.decode("utf-8", errors="strict"))
        require(isinstance(frame, dict), "Response frame was not an object")
        require(frame.get("protocolVersion") == 1 and frame.get("jobID") == request["jobID"], "Response contract mismatch")
        require(frame.get("sequence") == sequence and frame.get("type") in ALLOWED_TYPES, "Response sequence/type mismatch")
        if frame["type"] == "fileBatch":
            require(isinstance(frame.get("files"), list) and len(frame["files"]) <= 128, "Unbounded listing batch")
        frames.append(frame)
    require(frames[0]["type"] == "hello", "Missing hello provenance")
    require(isinstance(frames[0].get("engineVersion"), str) and isinstance(frames[0].get("patchDigest"), str), "Missing engine provenance")
    terminals = [frame for frame in frames if frame["type"] in TERMINALS]
    require(len(terminals) == 1 and frames[-1] is terminals[0], "Missing unique final terminal")
    require(terminals[0]["type"] == "completed" and result["returncode"] == 0, "Job did not complete successfully")
    require(not any(frame["type"] in {"warning", "error"} for frame in frames), "Benchmark work emitted a warning/error")
    emitted_files = sum(len(frame["files"]) for frame in frames if frame["type"] == "fileBatch")
    require(terminals[0].get("fileCount") == emitted_files, "Terminal/listing row counts differ")
    return frames


class RSSSampler:
    """Sample simultaneous RSS only for the exact still-owned helper PID set.

    Direct libproc calls on macOS and /proc reads on Linux avoid spawning a
    profiler process per sample. Sampling still adds scheduling overhead and
    can miss short-lived processes or between-sample peaks. wait4 separately
    provides every helper's kernel maximum; the sum of the largest N individual
    maxima bounds aggregate RSS with a concurrency limit N, but is NOT a sample.
    """
    def __init__(self, interval: float):
        self.interval = interval
        self.lock = threading.Lock()
        self.pids = set()
        self.stop_event = threading.Event()
        self.samples = []
        self.sample_seconds = []
        self.failures = []
        self.libproc = None
        if sys.platform == "darwin":
            self.libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
            self.libproc.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
            self.libproc.proc_pidinfo.restype = ctypes.c_int
        self.page_bytes = os.sysconf("SC_PAGE_SIZE")
        self.thread = threading.Thread(target=self._sample, daemon=True)

    def add(self, pid):
        with self.lock:
            self.pids.add(pid)

    def remove(self, pid):
        with self.lock:
            self.pids.discard(pid)

    def start(self):
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        self.thread.join(timeout=3)
        require(not self.thread.is_alive(), "RSS sampler did not stop")

    def _sample(self):
        while not self.stop_event.is_set():
            with self.lock:
                pids = sorted(self.pids)
            if pids:
                start = time.perf_counter()
                try:
                    entries = []
                    for pid in pids:
                        rss = self._rss(pid)
                        if rss is not None:
                            entries.append((pid, rss))
                    # Discard PIDs already reaped while the syscalls ran. This
                    # avoids adding an exited helper's stale row to a new set.
                    with self.lock:
                        entries = [(pid, rss) for pid, rss in entries if pid in self.pids]
                    if entries:
                        self.samples.append({"at": time.perf_counter(), "bytes": sum(rss for _, rss in entries),
                                             "helperCount": len(entries)})
                except Exception as error:
                    self.failures.append(str(error))
                self.sample_seconds.append(time.perf_counter() - start)
            self.stop_event.wait(self.interval)

    def _rss(self, pid):
        if self.libproc:
            # Public sys/proc_info.h: proc_taskinfo has six uint64_t fields then
            # twelve int32_t fields (96 bytes). pti_resident_size is field two
            # in BYTES. PROC_PIDTASKINFO = 4. Verified against the Xcode SDK;
            # reject a short/unrecognized structure rather than report zero.
            buffer = ctypes.create_string_buffer(96)
            ctypes.set_errno(0)
            count = self.libproc.proc_pidinfo(pid, 4, 0, buffer, len(buffer))
            if count == 0 and ctypes.get_errno() == errno.ESRCH:
                return None  # An exact owned helper exited between observations.
            require(count == len(buffer), "libproc returned an unavailable/unknown taskinfo structure")
            return int(ctypes.c_uint64.from_buffer(buffer, 8).value)
        try:
            fields = Path(f"/proc/{pid}/statm").read_text().split()
        except FileNotFoundError:
            return None
        require(len(fields) >= 2, "Malformed owned helper /proc statm")
        return int(fields[1]) * self.page_bytes

    def receipt(self):
        intervals = [second["at"] - first["at"] for first, second in zip(self.samples, self.samples[1:])]
        return {"method": "macOS libproc PROC_PIDTASKINFO resident bytes" if self.libproc else "Linux /proc/PID/statm resident pages × page size",
                "requestedIntervalSeconds": self.interval, "sampleCount": len(self.samples),
                "aggregatePeakRSSSampledBytes": max((sample["bytes"] for sample in self.samples), default=None),
                "maximumObservedHelperCount": max((sample["helperCount"] for sample in self.samples), default=0),
                "actualIntervalMedianSeconds": statistics.median(intervals) if intervals else None,
                "actualIntervalMaximumSeconds": max(intervals) if intervals else None,
                "rssSampleReadWallSeconds": sum(self.sample_seconds), "failedSamples": self.failures,
                "limitations": "RSS summed across exact live owned helper PIDs. Samples read PIDs sequentially, not atomically; short jobs/peaks can be missed. Sampler/queue overhead is present in all instrumented batches. Parent, GUI and non-owned processes are excluded."}


class NativeBatch:
    """Bounded queue with exact-PID wait4 CPU/kernel peaks and bounded pipes."""
    def __init__(self, helper: Path, workers: int, timeout: float, sample_interval: float):
        require(workers in WORKERS, "Workers must be 1, 2 or 4")
        require(timeout > 0 and 0.001 <= sample_interval <= 1, "Invalid timeout or sample interval")
        self.helper, self.workers, self.timeout = helper, workers, timeout
        self.sampler = RSSSampler(sample_interval)
        self.selector = selectors.DefaultSelector()
        self.owned = {}

    def _spawn(self, index: int, request: dict):
        process = subprocess.Popen([str(self.helper)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True,
                                   env=dict(os.environ, TZ="UTC", LC_ALL="C"))
        job = {"index": index, "request": request, "process": process, "started": time.perf_counter(),
               "stdout": bytearray(), "stderr": bytearray(), "openPipes": 2, "returncode": None}
        self.owned[process.pid] = job
        self.sampler.add(process.pid)
        for label, pipe in (("stdout", process.stdout), ("stderr", process.stderr)):
            os.set_blocking(pipe.fileno(), False)
            self.selector.register(pipe, selectors.EVENT_READ, (job, label))
        try:
            process.stdin.write((json.dumps(request, ensure_ascii=False) + "\n").encode())
        finally:
            process.stdin.close()

    def _reap(self, pid, job):
        finished, status, usage = os.wait4(pid, os.WNOHANG)
        if not finished:
            return False
        job["returncode"] = os.waitstatus_to_exitcode(status)
        # Popen must know we already reaped its exact child; it must not waitpid
        # again or accidentally claim an unrelated process's resource receipt.
        job["process"].returncode = job["returncode"]
        job["exited"] = time.perf_counter()
        self.sampler.remove(pid)
        rss_multiplier = 1 if sys.platform == "darwin" else 1024
        job["resource"] = {"userCPUSeconds": usage.ru_utime, "systemCPUSeconds": usage.ru_stime,
                           "kernelPeakRSSBytes": usage.ru_maxrss * rss_multiplier,
                           "blockInputOperations": usage.ru_inblock, "blockOutputOperations": usage.ru_oublock,
                           "majorFaults": usage.ru_majflt, "minorFaults": usage.ru_minflt,
                           "voluntaryContextSwitches": usage.ru_nvcsw, "involuntaryContextSwitches": usage.ru_nivcsw}
        return True

    def _drain(self, timeout=0.005, *, discard=False):
        for key, _ in self.selector.select(timeout):
            job, label = key.data
            try:
                chunk = os.read(key.fileobj.fileno(), 65536)
            except BlockingIOError:
                continue
            if not chunk:
                self.selector.unregister(key.fileobj)
                key.fileobj.close()
                job["openPipes"] -= 1
            elif not discard:
                job[label].extend(chunk)
                require(len(job[label]) <= RESPONSE_LIMIT, "Helper stdout/stderr exceeded benchmark pipe bound")

    def _stop_owned(self):
        # Only exact children of this queue; never pkill a name or touch Autopsy.
        for pid, job in list(self.owned.items()):
            if job["returncode"] is None:
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        deadline = time.perf_counter() + 1
        while any(job["returncode"] is None for job in self.owned.values()) and time.perf_counter() < deadline:
            # Error/cancel cleanup must not rethrow the original pipe-bound
            # failure before reaping. Discard new bytes instead of buffering.
            self._drain(discard=True)
            for pid, job in self.owned.items():
                if job["returncode"] is None:
                    self._reap(pid, job)
        for pid, job in self.owned.items():
            if job["returncode"] is None:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                finished, status, _usage = os.wait4(pid, 0)
                require(finished == pid, "Owned child cleanup reaped a different PID")
                job["returncode"] = os.waitstatus_to_exitcode(status)
                job["process"].returncode = job["returncode"]
                self.sampler.remove(pid)

    def run(self, requests: list[dict]) -> dict:
        require(requests, "Batch requires a nonempty fixed job list")
        results, cursor, maximum_live = [], 0, 0
        self.sampler.start()
        started = time.perf_counter()
        try:
            while len(results) < len(requests):
                live = sum(job["returncode"] is None for job in self.owned.values())
                while cursor < len(requests) and live < self.workers:
                    self._spawn(cursor, requests[cursor])
                    cursor += 1
                    live += 1
                    maximum_live = max(maximum_live, live)
                self._drain()
                now = time.perf_counter()
                for pid, job in list(self.owned.items()):
                    if job["returncode"] is None:
                        self._reap(pid, job)
                    require(now - job["started"] <= self.timeout or job["returncode"] is not None,
                            "Owned helper exceeded per-job timeout")
                    require(job["returncode"] is None or not job["openPipes"] or now - job["exited"] <= 2,
                            "Helper exited without bounded pipe EOF; unexpected descendants are outside this benchmark")
                    if job["returncode"] is not None and not job["openPipes"]:
                        results.append(job)
                        del self.owned[pid]
            # Include the final pipe pump/EOF observation in queue wall time.
            # Independent response/export validation still happens in main(),
            # after this timed batch has returned.
            ended = time.perf_counter()
        finally:
            try:
                self._stop_owned()
            finally:
                try:
                    self.sampler.stop()
                finally:
                    for key in list(self.selector.get_map().values()):
                        self.selector.unregister(key.fileobj)
                        key.fileobj.close()
                    self.selector.close()
        results.sort(key=lambda item: item["index"])
        usage = [job["resource"] for job in results]
        return {"jobs": results, "wallSeconds": ended - started, "maximumLiveHelpers": maximum_live,
                "userCPUSeconds": sum(item["userCPUSeconds"] for item in usage),
                "systemCPUSeconds": sum(item["systemCPUSeconds"] for item in usage),
                "largestIndividualKernelPeakRSSBytes": max(item["kernelPeakRSSBytes"] for item in usage),
                "sumIndividualKernelPeaksUpperBoundBytes": sum(item["kernelPeakRSSBytes"] for item in usage),
                "sumLargestWorkerCountKernelPeaksUpperBoundBytes": sum(sorted(
                    (item["kernelPeakRSSBytes"] for item in usage), reverse=True)[:self.workers]),
                "ioCounters": {name: sum(item[name] for item in usage) for name in
                               ("blockInputOperations", "blockOutputOperations", "majorFaults", "minorFaults",
                                "voluntaryContextSwitches", "involuntaryContextSwitches")},
                "rssSampler": self.sampler.receipt()}


def request_for(image: dict, fixture_dir: Path, operation="enumerate", **extra) -> dict:
    return {"protocolVersion": 1, "jobID": uuid.uuid4().hex, "operation": operation,
            "imagePaths": [str((fixture_dir / name).resolve()) for name in image.get("imagePaths", [image["path"]])],
            "imageType": "raw", "sectorSize": image["sectorSize"], "timezone": "UTC",
            "maxFiles": 50000, "hashLogicalImage": operation == "enumerate", **extra}


def prepare_workloads(helper: Path, fixture_dir: Path, manifest: dict, timeout, interval,
                      small_rounds: int, large_jobs: int) -> tuple[list[dict], dict]:
    workloads, provenance = [], None
    for image in manifest["images"]:
        request = request_for(image, fixture_dir)
        result = NativeBatch(helper, 1, timeout, interval).run([request])["jobs"][0]
        frames = parse_response(request, result)
        hello = {key: frames[0][key] for key in ("engineVersion", "patchDigest", "capabilities")}
        require(provenance is None or provenance == hello, "Helper provenance changed during setup")
        provenance = hello
        images = [frame for frame in frames if frame["type"] == "image"]
        require(len(images) == 1 and images[0].get("logicalSha256") == image["logicalSha256"], "Generated logical hash differs")
        require(images[0].get("imagePaths") == request["imagePaths"] and images[0].get("logicalSize") == image["logicalSize"], "Opened image scope differs")
        rows = {row["path"].lstrip("/"): row for frame in frames if frame["type"] == "fileBatch" for row in frame["files"]}
        expected = image["files"] if image["filesystem"] == "NTFS" else [row for row in image["files"] if row["path"] == LARGE_NAME]
        jobs = []
        for item in expected:
            require(item["path"] in rows, "Synthetic payload missing from enumeration")
            row = rows[item["path"]]
            require(row["size"] == item["size"] and row["isDeleted"] == item["isDeleted"] and not row["isDirectory"], "Payload metadata differs")
            locator = {key: row[key] for key in ("fsOffsetBytes", "metaAddress", "attributeType", "attributeID", "size") if key in row}
            for key in ("metaAddress", "attributeType", "attributeID"):
                if key in item:
                    require(locator.get(key) == item[key], "Independent expected locator differs")
            jobs.append({"file": locator, "expected": item})
        if image["filesystem"] == "NTFS":
            name, jobs = "small-ntfs-streams", jobs * small_rounds
        else:
            name, jobs = "large-fat32-extraction", jobs * large_jobs
        workloads.append({"name": name, "image": image, "jobs": jobs,
                          "jobCount": len(jobs), "byteCount": sum(job["expected"]["size"] for job in jobs)})
    return workloads, provenance


def environment_receipt() -> dict:
    def read(args):
        try:
            result = subprocess.run(args, capture_output=True, text=True, timeout=5)
            return result.stdout.strip() if result.returncode == 0 else "unavailable"
        except (OSError, subprocess.SubprocessError):
            return "unavailable"
    result = {"architecture": platform.machine(), "system": platform.system(),
              "kernel": platform.release(), "python": platform.python_version(),
              "backgroundLoadAverage1m5m15m": list(os.getloadavg())}
    if sys.platform == "darwin":
        result.update(macOS=read(["/usr/bin/sw_vers", "-productVersion"]),
                      osBuild=read(["/usr/bin/sw_vers", "-buildVersion"]),
                      machineClass=read(["/usr/sbin/sysctl", "-n", "hw.model"]),
                      ramBytes=read(["/usr/sbin/sysctl", "-n", "hw.memsize"]),
                      cpuClass=read(["/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"]),
                      logicalCPUCount=read(["/usr/sbin/sysctl", "-n", "hw.logicalcpu"]),
                      physicalCPUCount=read(["/usr/sbin/sysctl", "-n", "hw.physicalcpu"]))
        battery = read(["/usr/bin/pmset", "-g", "batt"])
        # Retain only power-source/state fields, not machine-specific device IDs.
        result["powerSource"] = "AC" if "'AC Power'" in battery else "battery" if "'Battery Power'" in battery else "unavailable"
        result["batteryState"] = ";".join(part.strip() for line in battery.splitlines() if "%" in line for part in line.split(";")[1:]) or "unavailable"
        settings = read(["/usr/bin/pmset", "-g", "custom"])
        result["lowPowerModeSettings"] = [line.strip() for line in settings.splitlines() if "lowpowermode" in line] or ["unavailable"]
        result["thermalStatus"] = read(["/usr/bin/pmset", "-g", "therm"])
        mount_rows = read(["/bin/df", "-P", str(REPO / "local")]).splitlines()
        device = mount_rows[1].split()[0] if len(mount_rows) >= 2 else "unavailable"
        filesystem = read(["/usr/sbin/diskutil", "info", "-plist", device]) if device.startswith("/dev/") else "unavailable"
        try:
            disk_info = plistlib.loads(filesystem.encode())
            result["sourceOutputFilesystem"] = disk_info.get("FilesystemType", "unavailable")
            result["sourceOutputSolidState"] = disk_info.get("SolidState", "unavailable")
        except (ValueError, plistlib.InvalidFileException):
            result["sourceOutputFilesystem"] = "unavailable"
    return result


def summary(report: dict) -> dict:
    result = {}
    for workload in report["workloads"]:
        runs = [run for run in report["batches"] if run["phase"] == "measured" and run["workload"] == workload["name"]]
        counts = {}
        for workers in WORKERS:
            samples = [run for run in runs if run["workers"] == workers]
            if not samples:
                continue
            walls = [run["wallSeconds"] for run in samples]
            rss = [run["rssSampler"]["aggregatePeakRSSSampledBytes"] for run in samples if run["rssSampler"]["aggregatePeakRSSSampledBytes"] is not None]
            counts[str(workers)] = {"sampleCount": len(samples), "wallMedianSeconds": statistics.median(walls),
                "wallMinimumSeconds": min(walls), "wallMaximumSeconds": max(walls), "wallSamplesSeconds": walls,
                "userCPUMedianSeconds": statistics.median(run["userCPUSeconds"] for run in samples),
                "systemCPUMedianSeconds": statistics.median(run["systemCPUSeconds"] for run in samples),
                "sampledAggregateRSSMaximumBytes": max(rss) if rss else None,
                "individualKernelRSSMaximumBytes": max(run["largestIndividualKernelPeakRSSBytes"] for run in samples),
                "aggregateRSSKernelUpperBoundMaximumBytes": max(run["sumLargestWorkerCountKernelPeaksUpperBoundBytes"] for run in samples),
                "jobsPerSecondAtMedian": workload["jobCount"] / statistics.median(walls),
                "throughputMiBPerSecondAtMedian": workload["byteCount"] / BLOCK_BYTES / statistics.median(walls)}
        paired = {}
        for workers in (2, 4):
            pairs = []
            for block in sorted({run["block"] for run in runs}):
                group = {run["workers"]: run for run in runs if run["block"] == block}
                if 1 in group and workers in group:
                    pairs.append({"block": block, "differenceSeconds": group[workers]["wallSeconds"] - group[1]["wallSeconds"],
                                  "ratioToOneWorker": group[workers]["wallSeconds"] / group[1]["wallSeconds"]})
            paired[str(workers)] = {"pairs": pairs, "ratioMedian": statistics.median(pair["ratioToOneWorker"] for pair in pairs) if pairs else None}
        result[workload["name"]] = {"workers": counts, "pairedWithOneWorker": paired}
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helper", type=Path, default=REPO / ".engine/bin/NFTSKEngine")
    parser.add_argument("--output", type=Path, default=REPO / "local/worker-benchmark")
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--seed", type=int, default=20261006)
    parser.add_argument("--timeout", type=float, default=180)
    parser.add_argument("--sample-interval", type=float, default=0.002)
    parser.add_argument("--smoke", action="store_true", help="One correctness-only block, 1 MiB large file; no performance claim")
    parser.add_argument("--keep-exports", action="store_true", help="Keep verified synthetic outputs; normal experiment uses ~18 GiB")
    args = parser.parse_args(argv)
    require(args.smoke or args.runs >= 5, "Measured experiment requires at least five paired blocks")
    require(args.smoke or args.warmups >= 1, "Measured experiment requires a separate warmup block")
    require(args.timeout > 0 and 0.001 <= args.sample_interval <= 1, "Invalid timeout/sampler interval")
    require(sys.platform in ("darwin", "linux") and hasattr(os, "wait4"), "Profiler requires wait4 resource receipts")
    helper = args.helper.absolute()
    require(helper.is_file() and not helper.is_symlink() and os.access(helper, os.X_OK), "Pinned helper must be a regular executable; build it first")
    output = args.output.resolve()
    require(output.is_relative_to((REPO / "local").resolve()), "Reports/fixtures must stay under ignored repository local/")
    output.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = output / ("run-" + timestamp + "-" + uuid.uuid4().hex[:8])
    run_dir.mkdir()
    report = {"schemaVersion": 1, "status": "running", "smokeOnly": args.smoke,
              "startedUTC": timestamp, "environmentBefore": environment_receipt(), "batches": [],
              "method": {"scope": "instrumented native-helper extraction queue including helper startup, filesystem reads, content SHA-256, writes, fsync and Python queue dispatch/pipe-pump overhead",
                "excluded": ["Swift selected-container prehash", "Swift client staging/publication", "GUI", "case/cache/index", "independent export validation", "setup enumeration/logical-image hash", "before/after source hashes"],
                "cacheRegime": "warmed OS/filesystem caches; before-batch streaming input prehash warms all source bytes. No global purge or cold-cache claim",
                "cpu": "sum of exact owned helper wait4 user/system CPU", "diskCounters": "wait4 block operations, NOT byte counts; unavailable/zero counters do not imply zero disk I/O",
                "workerMeaning": "maximum concurrent single-job helper processes, not threads or production app policy",
                "seed": args.seed, "workers": list(WORKERS), "runsPerCount": 1 if args.smoke else args.runs,
                "warmupsPerCount": 0 if args.smoke else args.warmups, "maximumBufferBytesPerPipe": RESPONSE_LIMIT,
                "samplingSeconds": args.sample_interval, "perJobTimeoutSeconds": args.timeout,
                "retention": "keep verified exports" if args.keep_exports else "delete only exact newly created, independently verified export files after each batch"}}
    report_path = run_dir / "report.json"
    def write():
        report["comparisonEligible"] = report["status"] == "completed" and not args.smoke
        report["summary"] = summary(report) if "workloads" in report else {}
        report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    try:
        manifest = generate_benchmark_fixtures(run_dir / "fixtures", (1 if args.smoke else 128) * BLOCK_BYTES)
        (run_dir / "fixture-manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
        inputs = [helper, *(run_dir / "fixtures" / image["path"] for image in manifest["images"])]
        baseline = input_state(inputs)
        report["inputHashes"] = [{key: row[key] for key in ("name", "size", "sha256")} for row in baseline]
        report["sourceRevision"] = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True, check=True).stdout.strip()
        report["recipeDigests"] = {str(path.relative_to(REPO)): digest(path) for path in
                                  (Path(__file__), REPO / "Tests/NativeEngine/benchmark_fixtures.py", REPO / "Tests/NativeEngine/fixtures.py", REPO / "Tests/NativeEngine/ntfs_fixtures.py")}
        receipt = REPO / ".engine/manifest.json"
        require(receipt.is_file(), "Pinned native build receipt is required; build helper first")
        build = json.loads(receipt.read_text())
        require(build.get("engineSha256") == baseline[0]["sha256"], "Helper does not match pinned build receipt")
        report["buildReceiptSHA256"] = digest(receipt)
        report["nativeBuild"] = {key: build.get(key) for key in
                                 ("engineSha256", "engineVersion", "patchDigest", "architecture", "buildFingerprint", "toolchain", "compiledImageCapabilities", "linking")}
        workloads, report["helperProvenance"] = prepare_workloads(helper, run_dir / "fixtures", manifest, args.timeout,
                                                   args.sample_interval, 1 if args.smoke else 4, 4 if args.smoke else 8)
        require(all(report["helperProvenance"][key] == build[key] for key in ("engineVersion", "patchDigest")),
                "Helper protocol provenance does not match pinned build receipt")
        report["workloads"] = [{"name": work["name"], "jobCount": work["jobCount"], "byteCount": work["byteCount"],
                                "imageName": work["image"]["path"], "logicalSize": work["image"]["logicalSize"],
                                "logicalSHA256": work["image"]["logicalSha256"]} for work in workloads]
        rng = random.Random(args.seed)
        phases = [("warmup", 0 if args.smoke else args.warmups), ("measured", 1 if args.smoke else args.runs)]
        for phase, block_count in phases:
            for block in range(block_count):
                work_order = list(workloads)
                rng.shuffle(work_order)
                for work in work_order:
                    worker_order = list(WORKERS)
                    rng.shuffle(worker_order)
                    for workers in worker_order:
                        require(input_state(inputs) == baseline, "Ordered source/helper inputs changed before batch")
                        directory = run_dir / (f"{phase}-{block:02d}-{work['name']}-workers-{workers}")
                        directory.mkdir()
                        requests = [request_for(work["image"], run_dir / "fixtures", "extract", file=job["file"],
                                               outputPath=str((directory / f"export-{index:04d}.bin").resolve()), hashLogicalImage=False)
                                    for index, job in enumerate(work["jobs"])]
                        report["activeBatch"] = {"phase": phase, "block": block, "workload": work["name"],
                            "workers": workers, "jobCount": len(requests), "byteCount": work["byteCount"],
                            "ownedOutputDirectory": str(directory.relative_to(REPO)),
                            "note": "Failed/interrupted work is retained for diagnostics and excluded from successful throughput"}
                        print(f"RUN {phase} block={block} {work['name']} workers={workers} jobs={len(requests)}", flush=True)
                        batch = NativeBatch(helper, workers, args.timeout, args.sample_interval).run(requests)
                        require(batch["maximumLiveHelpers"] <= workers, "Worker concurrency cap was exceeded")
                        validated, resources = [], []
                        for index, (job, result) in enumerate(zip(work["jobs"], batch.pop("jobs"))):
                            frames = parse_response(requests[index], result)
                            provenance = {key: frames[0][key] for key in ("engineVersion", "patchDigest", "capabilities")}
                            require(provenance == report["helperProvenance"], "Helper provenance drifted between jobs")
                            receipts = [frame for frame in frames if frame["type"] == "extracted"]
                            require(len(receipts) == 1, "Missing unique extraction receipt")
                            receipt = receipts[0]
                            require(receipt.get("byteCount") == job["expected"]["size"] and receipt.get("sha256") == job["expected"]["sha256"], "Helper size/hash differs from independent expected content")
                            require(receipt.get("outputPath") == requests[index]["outputPath"], "Helper output path differs from owned export")
                            export = directory / f"export-{index:04d}.bin"
                            verified = validate_export(export, job["expected"])
                            validated.append({"index": index, "syntheticPath": job["expected"]["path"], **verified})
                            resources.append(result["resource"])
                            if not args.keep_exports:
                                state = export.stat(follow_symlinks=False)
                                require([state.st_dev, state.st_ino, state.st_size, state.st_mtime_ns, state.st_ctime_ns] == verified["fileIdentity"],
                                        "Owned output changed before individual cleanup; preserve it")
                                export.unlink()
                        require(len(validated) == work["jobCount"], "Fewer jobs were validated than the fixed workload")
                        require(input_state(inputs) == baseline, "Ordered source/helper inputs changed after batch")
                        batch.update(phase=phase, block=block, workload=work["name"], workers=workers,
                                     jobCount=len(validated), byteCount=sum(item["byteCount"] for item in validated),
                                     verified=validated, perJobResources=resources, sourceHashesBeforeAfterMatched=True,
                                     helperHashBeforeAfterMatched=True, validationOutsideTimedInterval=True)
                        report["batches"].append(batch)
                        report.pop("activeBatch")
                        write()
                        print(f"PASS wall={batch['wallSeconds']:.6f}s cpu={batch['userCPUSeconds'] + batch['systemCPUSeconds']:.6f}s verified={len(validated)}", flush=True)
                        if not args.keep_exports:
                            directory.rmdir()  # Refuse recursive cleanup of unexpected content.
        report["finalInputHashesMatched"] = input_state(inputs) == baseline
        require(report["finalInputHashesMatched"], "Final input hashes changed")
        report["status"] = "completed"
    except KeyboardInterrupt:
        report.update(status="cancelled", error="User interrupted; owned helper queue stopped")
    except Exception as error:
        report.update(status="failed", error=str(error))
    report["environmentAfter"] = environment_receipt()
    report["finishedUTC"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    write()
    print(str(report_path.relative_to(REPO)), flush=True)
    print(json.dumps({"status": report["status"], "smokeOnly": args.smoke, "summary": report["summary"]}, indent=2), flush=True)
    return 0 if report["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())

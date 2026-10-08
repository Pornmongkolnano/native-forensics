#!/usr/bin/env python3
"""Run owned synthetic gates against already-built/signed app copies.

No compiler, signer, GUI, provider request, arbitrary-process signal, or
production protocol bypass is used. Reports are local diagnostic evidence.
"""
from __future__ import annotations

import argparse
import base64
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time

MIB = 1024 * 1024
HOST = "Contents/MacOS/NativeForensics"
BROKER = "Contents/XPCServices/NFDocumentDecoderXPC.xpc/Contents/MacOS/NFDocumentDecoderXPC"
WORKER = "Contents/XPCServices/NFDocumentDecoderXPC.xpc/Contents/Helpers/NFDocumentDecoderWorker"
MARKER = b"NF_RUNTIME_ASCII_ORACLE_20261008\n"
POLICY_GATES = ["fixture-boundary", "fixture-crash-same-host-recovery", "fixture-malformed-same-host-recovery",
                "fixture-hang-same-host-recovery"]
OTHER_GATES = ["production-sustained", "fixture-sustained", "production-32MiB", "production-64MiB", "production-128MiB",
               "fixture-response-cap", "fixture-flood", "early-cancel-same-host-recovery", "early-cancel-cross-host-availability",
               "bad-hello", "broker-death"]


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(128 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def receipt(path):
    identity = Path(path).lstat()
    require(stat.S_ISREG(identity.st_mode), "source is not a regular file")
    return {"device": identity.st_dev, "inode": identity.st_ino,
            "bytes": identity.st_size, "mtimeNanoseconds": identity.st_mtime_ns,
            "ctimeNanoseconds": identity.st_ctime_ns, "sha256": digest(path)}


def document_receipt_digest(value):
    # The fixed document receipt has no dates or nonintegral floating-point
    # values in these gates. Swift JSONEncoder emits integral Double timeouts
    # as integers. Match sorted UTF-8 JSON with unescaped slashes explicitly.
    def normalize(item):
        if isinstance(item, float) and item.is_integer():
            return int(item)
        if isinstance(item, dict):
            return {key: normalize(child) for key, child in item.items()}
        if isinstance(item, list):
            return [normalize(child) for child in item]
        return item
    data = json.dumps(normalize(value), sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode()
    return hashlib.sha256(data).hexdigest()


def signing_normalized_digest(path):
    """Remove only an EOF code-signature blob and its allocation metadata.

    The full signed digest is separately retained. This comparator detects a
    changed code/data/load command/link-edit payload after fixture re-signing;
    it does not assert that two signed executables are byte-identical.
    """
    data = bytearray(Path(path).read_bytes())
    require(len(data) >= 32 and struct.unpack_from("<I", data)[0] == 0xFEEDFACF,
            "expected a single little-endian 64-bit Mach-O")
    count, commands_size = struct.unpack_from("<II", data, 16)
    require(count <= 4096 and 32 + commands_size <= len(data), "invalid Mach-O commands")
    cursor, signature, linkedit = 32, None, None
    for _ in range(count):
        command, size = struct.unpack_from("<II", data, cursor)
        require(size >= 8 and cursor + size <= 32 + commands_size, "invalid Mach-O command size")
        if command == 0x1D:
            require(size == 16 and signature is None, "invalid code-signature command")
            offset, length = struct.unpack_from("<II", data, cursor + 8)
            signature = (cursor, offset, length)
        if command == 0x19 and data[cursor + 8:cursor + 24].rstrip(b"\0") == b"__LINKEDIT":
            require(size >= 72 and linkedit is None, "invalid link-edit segment")
            linkedit = cursor
        cursor += size
    require(cursor == 32 + commands_size and signature is not None and linkedit is not None,
            "missing signature/link-edit command")
    command, offset, length = signature
    require(length > 0 and offset >= cursor and offset + length == len(data), "signature must be the exact EOF blob")
    file_offset = struct.unpack_from("<Q", data, linkedit + 40)[0]
    require(file_offset <= offset, "invalid link-edit file offset")
    struct.pack_into("<I", data, command + 12, 0)  # signature allocation length
    struct.pack_into("<Q", data, linkedit + 32, 0)  # allocation-dependent VM size
    struct.pack_into("<Q", data, linkedit + 48, offset - file_offset)
    return hashlib.sha256(data[:offset]).hexdigest()


def signed_identity(app):
    subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(app)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    identities = {}
    for role, relative in (("host", HOST), ("broker", BROKER), ("worker", WORKER)):
        path = app / relative
        require(path.is_file() and not path.is_symlink() and path.resolve(strict=True) == path,
                "missing regular executable or executable ancestor escapes owned app")
        result = subprocess.run(["/usr/bin/codesign", "-d", "--verbose=4", str(path)],
                                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        display = result.stderr + result.stdout
        hashes = re.findall(r"^CDHash=([0-9a-f]{40}|[0-9a-f]{64})$", display, re.M)
        require(len(hashes) == 1, "missing signing CDHash")
        identities[role] = {"path": str(path), "sha256": digest(path), "codeSigningCDHash": hashes[0],
                            "signatureNormalizedPayloadSHA256": signing_normalized_digest(path)}
    return identities


class BsdInfo(ctypes.Structure):
    _fields_ = [("flags", ctypes.c_uint32), ("status", ctypes.c_uint32),
                ("xstatus", ctypes.c_uint32), ("pid", ctypes.c_uint32),
                ("ppid", ctypes.c_uint32), ("uid", ctypes.c_uint32),
                ("gid", ctypes.c_uint32), ("ruid", ctypes.c_uint32),
                ("rgid", ctypes.c_uint32), ("svuid", ctypes.c_uint32),
                ("svgid", ctypes.c_uint32), ("reserved", ctypes.c_uint32),
                ("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32),
                ("nfiles", ctypes.c_uint32), ("pgid", ctypes.c_uint32),
                ("jobc", ctypes.c_uint32), ("tdev", ctypes.c_uint32),
                ("tpgid", ctypes.c_uint32), ("nice", ctypes.c_int32),
                ("startSeconds", ctypes.c_uint64), ("startMicroseconds", ctypes.c_uint64)]


class TaskInfo(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in
                ("virtual", "resident", "totalUser", "totalSystem", "threadsUser", "threadsSystem")] + [
        (name, ctypes.c_int32) for name in ("policy", "faults", "pageins", "cowFaults", "messagesSent",
        "messagesReceived", "machCalls", "unixCalls", "switches", "threads", "running", "priority")]


class OwnedProcesses:
    def __init__(self, app):
        self.paths = {str(app / path): role for role, path in (("host", HOST), ("broker", BROKER), ("worker", WORKER))}
        self.lib = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        self.lib.proc_pidpath.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32)
        self.lib.proc_pidinfo.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int)
        self.lib.proc_listpids.argtypes = (ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_int)
        self.peaks = {role: 0 for role in ("host", "broker", "worker")}
        self.valid_rss = {role: 0 for role in self.peaks}
        self.failed_rss = {role: 0 for role in self.peaks}
        self.family_peak, self.partial_family_peak, self.samples, self.observed = 0, 0, 0, {}
        self.complete_family_samples, self.partial_family_samples = 0, 0
        self.known_pids = {}
        self.query_failures, self.query_failures_omitted = [], 0
        self.last_inventory = None

    def track(self, pid, role):
        self.known_pids[pid] = {"role": role, "expectedPath": next(path for path, value in self.paths.items() if value == role)}

    def failed_query(self, phase, pid, result, error, **details):
        if len(self.query_failures) < 256:
            self.query_failures.append({"phase": phase, "processIdentifier": pid,
                                        "returnValue": result, "errno": error, **details})
        else:
            self.query_failures_omitted += 1

    def identity(self, pid):
        name, info = ctypes.create_string_buffer(4096), BsdInfo()
        ctypes.set_errno(0)
        result = self.lib.proc_pidpath(pid, name, len(name))
        error = ctypes.get_errno()
        if result <= 0:
            if pid in self.known_pids:
                self.failed_query("pidpath", pid, result, error, **self.known_pids[pid])
            return None
        path = os.fsdecode(name.value)
        if path not in self.paths:
            if pid in self.known_pids:
                self.failed_query("known-pid-path-mismatch", pid, result, error,
                                  actualPath=path, **self.known_pids[pid])
            return None
        ctypes.set_errno(0)
        result = self.lib.proc_pidinfo(pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info))
        error = ctypes.get_errno()
        if result != ctypes.sizeof(info):
            self.failed_query("owned-path-bsd-info", pid, result, error,
                              actualPath=path, expectedBytes=ctypes.sizeof(info))
            return None
        if info.pid != pid or info.uid != os.geteuid():
            self.failed_query("owned-path-bsd-identity", pid, result, error,
                              actualPath=path, actualPID=info.pid, actualUID=info.uid, expectedUID=os.geteuid())
            return None
        return {"processIdentifier": pid, "parentProcessIdentifier": info.ppid,
                "startSeconds": info.startSeconds, "startMicroseconds": info.startMicroseconds,
                "role": self.paths[path], "path": path}

    def sample(self):
        size = self.lib.proc_listpids(1, 0, None, 0)
        require(0 < size <= 16 * MIB, "unavailable bounded process inventory")
        array = (ctypes.c_int * ((size + 4096) // ctypes.sizeof(ctypes.c_int)))()
        ctypes.set_errno(0)
        received = self.lib.proc_listpids(1, 0, array, ctypes.sizeof(array))
        self.last_inventory = {"requestedBytes": ctypes.sizeof(array), "returnedBytes": received,
                               "errno": ctypes.get_errno()}
        require(0 < received <= ctypes.sizeof(array) and received % ctypes.sizeof(ctypes.c_int) == 0,
                "PID inventory collection failed: " + json.dumps(self.last_inventory, sort_keys=True))
        inventory = set(array[:received // ctypes.sizeof(ctypes.c_int)])
        self.last_inventory["knownPIDPresence"] = {str(pid): pid in inventory for pid in self.known_pids}
        rows, family, complete_family = [], 0, True
        # The host is an independently owned, unreaped Popen child while the
        # loop runs. Query it even if inventory coverage omitted it; exact
        # path/UID/birth requirements still apply to every accepted row.
        for pid in inventory | set(self.known_pids):
            if not pid:
                continue
            identity = self.identity(pid)
            if identity is None:
                continue
            usage = TaskInfo()
            valid_rss = (self.lib.proc_pidinfo(pid, 4, 0, ctypes.byref(usage), ctypes.sizeof(usage)) == ctypes.sizeof(usage)
                         and self.identity(pid) == identity)
            row = dict(identity, residentBytes=usage.resident if valid_rss else None)
            rows.append(row)
            birth = f"{pid}:{identity['startSeconds']}:{identity['startMicroseconds']}"
            self.observed.setdefault(birth, identity)
            if valid_rss:
                self.valid_rss[identity["role"]] += 1
                family += usage.resident
                self.peaks[identity["role"]] = max(self.peaks[identity["role"]], usage.resident)
            else:
                self.failed_rss[identity["role"]] += 1
                complete_family = False
        self.samples += 1
        if rows and complete_family:
            self.complete_family_samples += 1
            self.family_peak = max(self.family_peak, family)
        elif rows:
            self.partial_family_samples += 1
            self.partial_family_peak = max(self.partial_family_peak, family)
        return rows

    def summary(self):
        return {"samplingPeriodMilliseconds": 20, "samples": self.samples,
                "method": "SDK-visible libproc diagnostic metadata; exact owned-copy executable paths; sampled RSS, not an OS hard memory limit",
                "peakResidentBytesByRole": {role: self.peaks[role] if self.valid_rss[role] else None for role in self.peaks},
                "validResidentSamplesByRole": self.valid_rss, "failedResidentSamplesByRole": self.failed_rss,
                "completeFamilySamplingPasses": self.complete_family_samples,
                "incompleteFamilySamplingPasses": self.partial_family_samples,
                "peakSimultaneousFamilyResidentBytes": self.family_peak if self.complete_family_samples else None,
                "peakKnownResidentBytesInIncompleteFamilyPass": self.partial_family_peak if self.partial_family_samples else None,
                "familySamplingScope": "RSS sum within one sampling pass; per-process kernel queries are sequential",
                "lastPIDInventory": self.last_inventory,
                "ownedOrKnownPIDQueryFailures": self.query_failures,
                "ownedOrKnownPIDQueryFailuresOmitted": self.query_failures_omitted,
                "observedProcesses": list(self.observed.values())}


class PhysicalExit:
    def __init__(self, monitor, pid):
        self.identity = monitor.identity(pid)
        require(self.identity is not None, "cannot register an already absent/unowned process")
        self.queue = select.kqueue()
        self.closed = False
        try:
            event = select.kevent(pid, filter=select.KQ_FILTER_PROC,
                                 flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE | select.KQ_EV_ONESHOT,
                                 fflags=select.KQ_NOTE_EXIT)
            result = self.queue.control([event], 1, 0)
            require(not result, "process exited before observer trust")
            require(monitor.identity(pid) == self.identity, "process birth identity changed during observer registration")
        except BaseException:
            self.close()
            raise
        self.observed = False
        self.observed_uptime = None

    def poll(self):
        if not self.observed:
            for event in self.queue.control(None, 1, 0):
                require(event.ident == self.identity["processIdentifier"] and event.fflags & select.KQ_NOTE_EXIT,
                        "unexpected physical-exit kernel event")
                self.observed = True
                self.observed_uptime = time.monotonic_ns()
        return self.observed

    def report(self):
        return dict(self.identity, physicalExitObserved=self.poll(), physicalExitUptimeNanoseconds=self.observed_uptime)

    def close(self):
        if not self.closed:
            self.closed = True
            self.queue.close()


def validate_attempt(analysis, source, identities, timeout):
    require(analysis.get("schemaVersion") == 2 and analysis.get("status") == "decoded", "expected current decoded analysis")
    require(analysis.get("sourceSHA256") == source["sha256"] and analysis.get("sourceByteCount") == source["bytes"],
            "analysis source receipt mismatch")
    provenance = analysis.get("provenance", {})
    require(provenance.get("schemaVersion") == 1 and
            provenance.get("decoderIdentifier") == "NativeForensics.document-decoder" and
            provenance.get("decoderVersion") == "2.1.0", "wrong decoder contract receipt")
    require(provenance.get("isolation") == "appSandboxXPC", "wrong runtime isolation receipt")
    for field, role, identity_field in (("decoderExecutableSHA256", "worker", "sha256"),
        ("decoderCodeSigningCDHash", "worker", "codeSigningCDHash"),
        ("brokerExecutableSHA256", "broker", "sha256"), ("brokerCodeSigningCDHash", "broker", "codeSigningCDHash")):
        require(provenance.get(field) == identities[role][identity_field], "signed executable provenance mismatch: " + field)
    options = provenance.get("options", {})
    require(options.get("maximumInputBytes") == 128 * MIB and options.get("maximumResponseBytes") == 2 * MIB
            and options.get("maximumTextBytes") == MIB and options.get("timeoutSeconds") == timeout,
            "runtime cap/timeout changed")
    for field in ("optionsSHA256", "derivedTextSHA256"):
        require(re.fullmatch("[0-9a-f]{64}", provenance.get(field, "")) is not None, "missing receipt digest")
    require(provenance["optionsSHA256"] == document_receipt_digest(options), "options digest oracle mismatch")
    require(provenance["derivedTextSHA256"] == document_receipt_digest(analysis.get("textPages", [])),
            "whole derived-text digest oracle mismatch")
    require(sum(len(page["text"].encode()) for page in analysis.get("textPages", [])) <= MIB, "derived text cap exceeded")


def validate_lifecycle(report, count, expect_error=None, no_trusted_start=False,
                       start_ordinals=None, expected_errors=None):
    attempts, events = report.get("attempts", []), report.get("events", [])
    require(len(attempts) == count and report.get("available") is True, "attempt count/backend unavailable")
    require([attempt.get("ordinal") for attempt in attempts] == list(range(1, count + 1)), "attempt ordinals changed")
    started = [event for event in events if event["kind"] == "started"]
    expected_starts = start_ordinals if start_ordinals is not None else ([] if no_trusted_start else list(range(1, count + 1)))
    require(sorted(event["ordinal"] for event in started) == expected_starts,
            "early failure occurred after trusted peer startup" if no_trusted_start else
            "accepted startup inventory does not match each attempt ordinal")
    if expected_errors is not None:
        require(len(expected_errors) == count, "wrong expected error inventory")
    accepted_pids = []
    active = set()
    for event in events:
        if event["kind"] == "cancelRequested":
            continue
        key = (event["ordinal"], event["processIdentifier"])
        if event["kind"] == "started":
            require(not active and key not in accepted_pids, "overlapping/shared worker ownership")
            active.add(key); accepted_pids.append(key)
        elif event["kind"] == "exited":
            require(key in active, "exit event has no owned startup")
            active.remove(key)
        else:
            raise AssertionError("unknown lifecycle event")
    require(not active, "accepted parser lacks physical exit")
    require(len({pid for _, pid in accepted_pids}) == len(accepted_pids), "test reused a parser PID")
    for position, attempt in enumerate(attempts):
        expected = expected_errors[position] if expected_errors is not None else (
            "invalidResponse" if expect_error == "invalidResponse-before-start" else expect_error)
        require(attempt.get("errorCode") == expected, "unexpected attempt result/error")
        if expected is None:
            require(attempt.get("analysis") is not None, "missing successful analysis")


def lifecycle_gaps(report):
    previous_exit, gaps = None, []
    for event in report.get("events", []):
        if event["kind"] == "started" and previous_exit is not None:
            gaps.append((event["uptimeNanoseconds"] - previous_exit) / 1_000_000)
        elif event["kind"] == "exited":
            previous_exit = event["uptimeNanoseconds"]
    return {"interWorkerGapMilliseconds": gaps, "maximumInterWorkerGapMilliseconds": max(gaps, default=None)}


def require_rss_evidence(gate):
    gate["rssEvidenceComplete"] = all(gate["memory"]["validResidentSamplesByRole"][role] > 0
                                      for role in ("host", "broker", "worker"))
    if not gate["rssEvidenceComplete"]:
        gate["gateStatus"] = "unavailable: required role RSS was not observed; no zero-peak memory claim"


def require_one_broker(gate):
    births = {(row["processIdentifier"], row["startSeconds"], row["startMicroseconds"])
              for row in gate["memory"]["observedProcesses"] if row["role"] == "broker"}
    gate["observedBrokerBirthCount"] = len(births)
    require(births, "no exact-owned broker birth was observed; same-broker criterion is unproven")
    require(len(births) == 1, "multiple exact-owned broker births observed: " + str(len(births)))


def validate_boundary(analysis):
    pages = analysis.get("textPages", [])
    require(len(pages) == 1 and pages[0].get("isTruncated") is False, "boundary result page was incomplete")
    value = json.loads(pages[0]["text"])
    expected = {"outsideRead", "outsideWritableOpen", "outsideCreate", "ipv4Socket", "ipv4LoopbackConnect",
                "ipv4LoopbackBind", "unixOutsideBind", "ownContainerWrite", "inheritedContainerWrite", "systemTrueExecution"}
    require(isinstance(value, dict) and set(value) == expected, "boundary operation inventory changed")
    for operation, stages in (("outsideRead", {"open", "read"}), ("outsideWritableOpen", {"open"}),
                              ("outsideCreate", {"open"}), ("ipv4LoopbackConnect", {"connect"}),
                              ("ipv4LoopbackBind", {"bind"}), ("unixOutsideBind", {"bind"})):
        result = value[operation]
        require(isinstance(result, dict) and result.get("allowed") is False and
                type(result.get("errno")) is int and result["errno"] in (errno.EPERM, errno.EACCES) and
                result.get("stage") in stages, "boundary operation lacks permission denial at its actual stage: " + operation)
    for operation in ("ipv4Socket", "ownContainerWrite", "inheritedContainerWrite", "systemTrueExecution"):
        result = value[operation]
        require(isinstance(result, dict) and type(result.get("allowed")) is bool and
                type(result.get("errno")) is int and ((result["allowed"] and result["errno"] == 0) or
                (not result["allowed"] and result["errno"] > 0)), "invalid observed boundary outcome: " + operation)
    for operation in ("inheritedContainerWrite", "systemTrueExecution"):
        require(value[operation]["allowed"] is True and value[operation]["errno"] == 0,
                "boundary positive control failed: " + operation)
    return {"operations": value, "positiveControls": ["owned compiled broker-container child write", "/usr/bin/true own child spawn/reap"],
            "scope": "exact signed production host/broker payload with signed inheriting synthetic worker; legacy ownContainerWrite is NSHomeDirectory only"}


def validate_failure_recovery(gate, error, identities, timeout):
    validate_lifecycle(gate["report"], 2, expected_errors=[error, None])
    require_one_broker(gate)
    analysis = gate["report"]["attempts"][1]["analysis"]
    validate_attempt(analysis, gate["sourceReceipt"], identities, timeout)
    pages = analysis["textPages"]
    require(len(pages) == 1 and pages[0]["pageNumber"] == 1 and pages[0]["isTruncated"] is False and
            pages[0]["text"] == "synthetic parser worker fixture response",
            "same-host failure recovery normal text oracle mismatch")
    accepted = [event for event in gate["report"]["events"] if event["kind"] == "started"]
    ended = [event for event in gate["report"]["events"] if event["kind"] == "exited"]
    require(ended[0]["uptimeNanoseconds"] < accepted[1]["uptimeNanoseconds"],
            "recovery accepted a worker before failed worker physically drained")
    action, observers = gate.get("intervention") or {}, gate.get("physicalObservers", [])
    require(action.get("phase") == "registered-broker-and-failed-worker" and action.get("recoveryWorker") is not None,
            "same physical broker continuity is unproven: required worker-parent observations missing")
    require(len(observers) == 3 and observers[0]["processIdentifier"] == accepted[0]["processIdentifier"] and
            observers[2]["processIdentifier"] == accepted[1]["processIdentifier"] and
            observers[0]["physicalExitObserved"] and observers[2]["physicalExitObserved"],
            "recovery lacks independent physical exit for both exact workers")
    for observed, sampled, role in ((observers[0], action["worker"], "worker"),
                                     (observers[1], action["broker"], "broker"),
                                     (observers[2], action["recoveryWorker"], "worker")):
        require(observed.get("role") == role and all(observed.get(field) is not None and
                observed[field] == sampled.get(field) for field in
                ("processIdentifier", "startSeconds", "startMicroseconds", "path")),
                "recovery kernel observer identity differs from its sampled birth/path")
    require(action["worker"]["parentProcessIdentifier"] == action["recoveryWorker"]["parentProcessIdentifier"] ==
            action["broker"]["processIdentifier"] == observers[1]["processIdentifier"], "recovery workers changed broker parent")
    require(action.get("brokerLiveAtRecoveryWorkerObservation") is True,
            "original registered broker was not alive at recovery worker observation")
    gate["recoveryScope"] = "same host/client; exact broker birth/path revalidated as live parent of both workers; public-client decoded terminal response after owned reap; both workers independently physically exited"
    gate["brokerExitObservationScope"] = "registered through both attempts; final host exit may end its application-service broker; polling observation times do not establish kernel exit order"


def record_gate(root, records, gate, count=1):
    # Preserve raw driver evidence before semantic oracles can throw. A failed
    # criterion must not erase PID/path/RSS observations or imply a restart.
    gate["oracleStatus"] = "pending"
    path = root / (gate["name"] + ".driver.json")
    gate["driverReceiptPath"] = str(path)
    records.append(gate)
    encoded = json.dumps({"driverReceiptSchemaVersion": 1, **gate}, sort_keys=True,
                         ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
    require(len(encoded) <= 2 * MIB * count + 4 * MIB, "bounded raw driver receipt exceeded its observation budget")
    with path.open("xb") as output:
        output.write(encoded + b"\n")


def write_source(root, name, body=None, size=None):
    path = root / (name + ".input")
    with path.open("xb") as destination:
        if size is None:
            destination.write(body)
        else:
            chunk = (MARKER * (MIB // len(MARKER) + 1))[:MIB]
            remaining = size
            while remaining:
                value = chunk[:min(remaining, len(chunk))]
                destination.write(value); remaining -= len(value)
    os.chmod(path, 0o400)
    return path


def wait_json_line(process, timeout):
    require(process.stdout is not None, "missing helper stdout")
    descriptor = process.stdout.fileno()
    original_blocking = os.get_blocking(descriptor)
    deadline = time.monotonic() + timeout
    line = bytearray()
    try:
        os.set_blocking(descriptor, False)
        while True:
            remaining = deadline - time.monotonic()
            require(remaining > 0, "broker helper did not complete its receipt before the bounded deadline")
            try:
                ready, _, _ = select.select([descriptor], [], [], remaining)
                require(ready, "broker helper did not complete its receipt before the bounded deadline")
                # Reading exactly one byte leaves every subsequent receipt in
                # the pipe for the next call; the BufferedReader never prefetches.
                # At most 4096 bytes plus one overflow-detection byte are held.
                chunk = os.read(descriptor, 1)
            except (BlockingIOError, InterruptedError):
                continue
            require(chunk, "broker helper stdout ended before a complete newline receipt")
            line.extend(chunk)
            require(len(line) <= 4096, "broker helper receipt exceeds its byte cap")
            if chunk == b"\n":
                receipt = json.loads(line)
                require(isinstance(receipt, dict), "broker helper receipt is not an object")
                return receipt
    finally:
        os.set_blocking(descriptor, original_blocking)


def run_probe(root, name, app, identities, source_path, mode="analyze", count=1,
              timeout=12.0, intervention=None, death_helper=None):
    source = receipt(source_path)
    stdout_path, stderr_path = root / (name + ".json"), root / (name + ".stderr")
    marker = root / (".nativeforensics-xpc-cancel-" + name + ".marker")
    require(not marker.exists(), "cancel marker must be absent before probe starts")
    arguments = [str(app / HOST), "--document-xpc-probe", "--input", str(source_path),
                 "--sha256", source["sha256"], "--bytes", str(source["bytes"]),
                 "--timeout", str(timeout), "--mode", mode]
    if mode == "sustained":
        arguments += ["--repeat", str(count)]
    if intervention == "early-cancel":
        arguments += ["--cancel-marker", str(marker)]
    monitor, watches, helper, action = OwnedProcesses(app), [], None, None
    deadline = time.monotonic() + (timeout + 8) * count
    started_at = time.monotonic_ns()
    process = None
    try:
        with stdout_path.open("xb") as out, stderr_path.open("xb") as err:
            process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=out, stderr=err)
            monitor.track(process.pid, "host")
            while process.poll() is None:
                require(time.monotonic() < deadline, "owned host exceeded outer watchdog")
                rows = monitor.sample()
                if intervention and action is None:
                    workers = [row for row in rows if row["role"] == "worker"]
                    if workers:
                        require(len(workers) == 1, "more than one worker in one owned app")
                        worker = workers[0]
                        broker = monitor.identity(worker["parentProcessIdentifier"])
                        require(broker and broker["role"] == "broker", "worker parent is not the exact owned broker")
                        watches.append(PhysicalExit(monitor, worker["processIdentifier"]))
                        if intervention == "early-cancel":
                            marker_fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                                os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                            try:
                                identity = os.fstat(marker_fd)
                                require(stat.S_ISREG(identity.st_mode) and identity.st_uid == os.geteuid()
                                        and identity.st_size == 0 and identity.st_nlink == 1, "cancel marker inode changed")
                                require(os.write(marker_fd, b"1") == 1, "cancel marker write failed")
                            finally:
                                os.close(marker_fd)
                            action = {"phase": "registered-worker-birth-before-host-trust",
                                      "markerWrittenUptimeNanoseconds": time.monotonic_ns(), "broker": broker}
                        elif intervention == "broker-death":
                            watches.append(PhysicalExit(monitor, broker["processIdentifier"]))
                            require(death_helper is not None, "missing prepared broker-death helper")
                            helper = subprocess.Popen([str(death_helper), str(broker["processIdentifier"]), str(app)],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                            armed = wait_json_line(helper, 3)
                            action = {"phase": "task-control-helper-replied", "helperReceipt": armed, "broker": broker}
                            require(armed.get("status") in ("armed", "unavailable"),
                                    "broker helper refused to arm: " + json.dumps(armed, sort_keys=True))
                            if armed.get("status") == "armed":
                                require(armed.get("processIdentifier") == broker["processIdentifier"] and
                                        armed.get("executable") == str(app / BROKER) and
                                        base64.b64decode(armed.get("codeSigningCDHash", ""), validate=True).hex() ==
                                        identities["broker"]["codeSigningCDHash"], "broker helper identity receipt mismatch")
                                action["phase"] = "verified-kernel-task-right"
                                # The host emits accepted start before sending
                                # content. Give the tiny body a settling period;
                                # final evidence proves accepted ownership,
                                # not a separate parser-body acknowledgement.
                                time.sleep(0.1)
                                require(not watches[0].poll() and not watches[1].poll(), "owned work exited before broker death")
                                clock = time.get_clock_info("monotonic")
                                require("mach_absolute_time" in clock.implementation,
                                        "cannot compare Python trigger and DispatchTime uptime epochs")
                                action["triggerClockImplementation"] = clock.implementation
                                action["terminationTriggeredUptimeNanoseconds"] = time.monotonic_ns()
                                helper.stdin.write(b"T"); helper.stdin.flush(); helper.stdin.close()
                                action["terminationReceipt"] = wait_json_line(helper, 3)
                            else:
                                action["phase"] = "task-control-unavailable"
                                helper.stdin.close()
                        elif intervention == "bad-hello":
                            action = {"phase": "independently-observed-worker-before-handshake-refusal", "broker": broker}
                        elif intervention == "observe-recovery":
                            watches.append(PhysicalExit(monitor, broker["processIdentifier"]))
                            action = {"phase": "registered-broker-and-failed-worker", "broker": broker, "worker": worker}
                if intervention == "observe-recovery" and action is not None and "recoveryWorker" not in action:
                    fresh = [row for row in rows if row["role"] == "worker" and
                             row["processIdentifier"] != action["worker"]["processIdentifier"]]
                    if fresh:
                        current = monitor.identity(action["broker"]["processIdentifier"])
                        require(len(fresh) == 1 and current == action["broker"] and not watches[1].poll() and
                                fresh[0]["parentProcessIdentifier"] == current["processIdentifier"],
                                "recovery parent differs from the exact retained live broker")
                        watches.append(PhysicalExit(monitor, fresh[0]["processIdentifier"]))
                        action["recoveryWorker"] = fresh[0]
                        action["brokerLiveAtRecoveryWorkerObservation"] = True
                for watch in watches:
                    watch.poll()
                time.sleep(0.02)
            require(process.returncode == 0, "bundled probe failed; see bounded stderr artifact")
        monitor.known_pids.pop(process.pid, None)  # poll reaped it; never diagnose a reused unrelated PID
        monitor.sample()
        require(receipt(source_path) == source, "synthetic source changed during analysis")
        require(stdout_path.stat().st_size <= 2 * MIB * count + 65536, "host report cap exceeded")
        report = json.loads(stdout_path.read_bytes())
        unavailable_intervention = (intervention == "broker-death" and action is not None
                                   and action["helperReceipt"].get("status") == "unavailable")
        if intervention:
            require(action is not None or intervention == "observe-recovery", "intervention never observed actual owned worker birth")
            if not unavailable_intervention and intervention != "observe-recovery":
                require(all(watch.poll() for watch in watches), "missing independent physical-exit kernel event")
        result = {"name": name, "reportPath": str(stdout_path), "sourceReceipt": source,
                  "signedExecutables": identities, "memory": monitor.summary(), "intervention": action,
                  "physicalObservers": [watch.report() for watch in watches],
                  "lifecycleTiming": lifecycle_gaps(report),
                  "wallDurationNanoseconds": time.monotonic_ns() - started_at, "report": report}
        if unavailable_intervention:
            result["gateStatus"] = "unavailable: macOS denied task_for_pid; no privilege or signal fallback"
            return result
        result["gateStatus"] = "observed; semantic oracle applied by caller"
        return result
    finally:
        if helper is not None:
            if helper.stdin and not helper.stdin.closed:
                try:
                    helper.stdin.close()  # releases retained right without termination if no T was sent
                except OSError:
                    pass  # a dead helper may have closed its read end; still reap it and close all other fds
            try:
                helper.wait(timeout=4)
            except subprocess.TimeoutExpired:
                helper.kill(); helper.wait()  # own unreaped helper child only
            if helper.stdout:
                try:
                    helper.stdout.close()
                except OSError:
                    pass
            if helper.stderr:
                try:
                    helper.stderr.close()
                except OSError:
                    pass
        if process is not None and process.poll() is None:
            process.terminate()  # own unreaped host child; worker has independent broker-pipe/deadline watch
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait()
        for watch in watches:
            watch.close()
        marker.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--production-app", required=True, type=Path)
    parser.add_argument("--fixture-app", required=True, type=Path)
    parser.add_argument("--early-app", required=True, type=Path)
    parser.add_argument("--bad-hello-app", required=True, type=Path)
    parser.add_argument("--death-helper", type=Path)
    parser.add_argument("--output-parent", required=True, type=Path)
    parser.add_argument("--repeat", type=int, default=64)
    parser.add_argument("--retain-apps", action="store_true")
    parser.add_argument("--only-policy-recovery", action="store_true")
    args = parser.parse_args()
    require(sys.platform == "darwin", "runtime gates require macOS")
    require(2 <= args.repeat <= 64, "repeat must be 2...64")
    args.output_parent.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix="nf-xpc-runtime-", dir=args.output_parent)).resolve()
    os.chmod(root, 0o700)
    apps, app_paths, inputs, gates = {}, [], [], []
    summary = {"schemaVersion": 1, "evidenceScope": "owned signed local app runtime; synthetic worker variants explicitly separated",
               "root": str(root), "gates": gates, "complete": False, "fullSuiteComplete": False,
               "selectedScope": "policy-and-failure-recovery-only" if args.only_policy_recovery else "full-runtime-suite",
               "requiredGateNames": POLICY_GATES if args.only_policy_recovery else POLICY_GATES + OTHER_GATES}
    try:
        def owned_source(name, **kwargs):
            inputs.append(root / (name + ".input"))
            return write_source(root, name, **kwargs)

        for role in ("production", "fixture", "early", "bad_hello"):
            source = getattr(args, role + "_app").resolve(strict=True)
            require(source.suffix == ".app", "expected prepared app bundle")
            app = root / (role + ".app")
            app_paths.append(app)
            shutil.copytree(source, app, symlinks=True)
            identities = signed_identity(app)
            apps[role] = (app, identities)
        for variant in ("fixture", "early", "bad_hello"):
            for role in ("host", "broker"):
                require(apps[variant][1][role]["signatureNormalizedPayloadSHA256"] ==
                        apps["production"][1][role]["signatureNormalizedPayloadSHA256"],
                        "fixture changed production executable payload: " + variant + "/" + role)
        small = owned_source("small", body=MARKER + "ข้อความไทย synthetic only\n".encode())
        normal = owned_source("fixture-normal", body=b"NF_TEST_NORMAL")
        hang = owned_source("fixture-hang", body=b"NF_TEST_HANG")
        cap = owned_source("fixture-response-cap", body=b"NF_TEST_RESPONSE_CAP")
        flood = owned_source("fixture-flood", body=b"NF_TEST_FLOOD")
        boundary = owned_source("fixture-boundary", body=b"NF_TEST_BOUNDARY")
        app, identities = apps["fixture"]
        gate = run_probe(root, "fixture-boundary", app, identities, boundary)
        record_gate(root, gates, gate)
        validate_lifecycle(gate["report"], 1)
        analysis = gate["report"]["attempts"][0]["analysis"]
        validate_attempt(analysis, gate["sourceReceipt"], identities, 12.0)
        gate["boundaryEvidence"] = validate_boundary(analysis)
        gate["externalControlsRequired"] = "preparation.json must separately confirm unchanged short outside canary, zero live loopback accepts, and owned one-byte write-control"
        gate["oracleStatus"] = "passed"
        for fault, error, timeout in (("crash", "invalidResponse", 12.0), ("malformed", "invalidResponse", 12.0),
                                      ("hang", "timeout", 2.0)):
            source_path = owned_source("fixture-" + fault + "-once", body=("NF_TEST_" + fault.upper() + "_ONCE").encode())
            gate = run_probe(root, "fixture-" + fault + "-same-host-recovery", app, identities, source_path,
                             mode="sustained", count=2, timeout=timeout, intervention="observe-recovery")
            record_gate(root, gates, gate, 2)
            validate_failure_recovery(gate, error, identities, timeout)
            gate["oracleStatus"] = "passed"
        if not args.only_policy_recovery:
            for label, source_path in (("production", small), ("fixture", normal)):
                app, identities = apps[label]
                gate = run_probe(root, label + "-sustained", app, identities, source_path,
                                 mode="sustained", count=args.repeat)
                record_gate(root, gates, gate, args.repeat)
                validate_lifecycle(gate["report"], args.repeat)
                for attempt in gate["report"]["attempts"]:
                    validate_attempt(attempt["analysis"], gate["sourceReceipt"], identities, 12.0)
                require_one_broker(gate)
                if label == "production":
                    for attempt in gate["report"]["attempts"]:
                        require(attempt["analysis"]["textPages"][0]["text"] == small.read_text(), "small text oracle mismatch")
                gate["oracleStatus"] = "passed"
            for size in (32 * MIB, 64 * MIB, 128 * MIB):
                source_path = owned_source("ascii-" + str(size // MIB) + "MiB", size=size)
                app, identities = apps["production"]
                gate = run_probe(root, "production-" + str(size // MIB) + "MiB", app, identities, source_path)
                record_gate(root, gates, gate)
                validate_lifecycle(gate["report"], 1)
                analysis = gate["report"]["attempts"][0]["analysis"]
                validate_attempt(analysis, gate["sourceReceipt"], identities, 12.0)
                page = analysis["textPages"][0]
                require(page["isTruncated"] is True and len(page["text"].encode()) == MIB,
                        "large text omitted its exact truncation/coverage disclosure")
                with source_path.open("rb") as source_file:
                    require(page["text"].encode() == source_file.read(MIB), "large text prefix oracle mismatch")
                require_rss_evidence(gate)
                gate["oracleStatus"] = "passed"
            app, identities = apps["fixture"]
            gate = run_probe(root, "fixture-response-cap", app, identities, cap)
            record_gate(root, gates, gate)
            validate_lifecycle(gate["report"], 1)
            analysis = gate["report"]["attempts"][0]["analysis"]
            validate_attempt(analysis, gate["sourceReceipt"], identities, 12.0)
            framed = [int(value.rsplit("=", 1)[1]) for value in analysis["warnings"]
                      if value.startswith("Synthetic framed response byte count=")]
            require(len(framed) == 1 and 2 * MIB - 6 <= framed[0] <= 2 * MIB,
                    "response-cap fixture was not near the actual frame cap")
            require(set(analysis["textPages"][0]["text"]) == {"\x01"}, "response-cap text oracle mismatch")
            require_rss_evidence(gate)
            gate["oracleStatus"] = "passed"
            gate = run_probe(root, "fixture-flood", app, identities, flood)
            record_gate(root, gates, gate)
            validate_lifecycle(gate["report"], 1, expect_error="outputLimit")
            gate["oracleStatus"] = "passed"
            app, identities = apps["early"]
            gate = run_probe(root, "early-cancel-same-host-recovery", app, identities, normal,
                             mode="cancel-early-recover", count=2, intervention="early-cancel")
            record_gate(root, gates, gate, 2)
            validate_lifecycle(gate["report"], 2, start_ordinals=[2], expected_errors=["cancelled", None])
            require(any(event["kind"] == "cancelRequested" for event in gate["report"]["events"]), "missing host cancel phase receipt")
            require_one_broker(gate)
            validate_attempt(gate["report"]["attempts"][1]["analysis"], gate["sourceReceipt"], identities, 12.0)
            original = gate["intervention"]["broker"]
            original_worker = gate["physicalObservers"][0]
            accepted = next(event for event in gate["report"]["events"] if event["kind"] == "started")
            require(accepted["processIdentifier"] != original_worker["processIdentifier"], "recovery reused cancelled worker")
            require(original_worker["physicalExitObserved"] and original_worker["physicalExitUptimeNanoseconds"] <
                    accepted["uptimeNanoseconds"], "recovery startup preceded independently observed cancelled-worker exit")
            require(any(row["role"] == "worker" and row["processIdentifier"] == accepted["processIdentifier"]
                        and row["parentProcessIdentifier"] == original["processIdentifier"]
                        for row in gate["memory"]["observedProcesses"]), "recovery worker lacks original broker ownership")
            gate["recoveryScope"] = "same host/client; exact original broker PID/birth/path; first worker physically drained before fresh accepted worker"
            gate["oracleStatus"] = "passed"
            recovery = run_probe(root, "early-cancel-cross-host-availability", app, identities, normal)
            record_gate(root, gates, recovery)
            validate_lifecycle(recovery["report"], 1)
            validate_attempt(recovery["report"]["attempts"][0]["analysis"], recovery["sourceReceipt"], identities, 12.0)
            require_one_broker(recovery)
            recovery["recoveryScope"] = "new host invocation; usable independently authenticated application-service broker; no same-process claim"
            recovery["oracleStatus"] = "passed"
            app, identities = apps["bad_hello"]
            gate = run_probe(root, "bad-hello", app, identities, normal, intervention="bad-hello")
            record_gate(root, gates, gate)
            validate_lifecycle(gate["report"], 1, expect_error="invalidResponse-before-start", no_trusted_start=True)
            gate["oracleStatus"] = "passed"
            if args.death_helper:
                app, identities = apps["fixture"]
                gate = run_probe(root, "broker-death", app, identities, hang, timeout=2.0,
                                 intervention="broker-death", death_helper=args.death_helper.resolve(strict=True))
                record_gate(root, gates, gate)
                if not gate["gateStatus"].startswith("unavailable"):
                    validate_lifecycle(gate["report"], 1, expect_error="invalidResponse")
                    require(gate["intervention"]["terminationReceipt"]["status"] == "terminated", "broker was not terminated")
                    accepted = [event for event in gate["report"]["events"] if event["kind"] == "started"]
                    require(len(accepted) == 1 and accepted[0]["uptimeNanoseconds"] <
                            gate["intervention"]["terminationTriggeredUptimeNanoseconds"],
                            "broker termination preceded accepted decode ownership")
                    require(accepted[0]["processIdentifier"] ==
                            gate["physicalObservers"][0]["processIdentifier"],
                            "accepted worker differs from independently watched worker")
                gate["oracleStatus"] = "unavailable" if gate["gateStatus"].startswith("unavailable") else "passed"
            else:
                gates.append({"name": "broker-death", "gateStatus": "unavailable: no prepared Mach task-right helper"})
        require([gate["name"] for gate in gates] == summary["requiredGateNames"], "requested gate inventory changed")
        summary["complete"] = not any(gate["gateStatus"].startswith("unavailable") for gate in gates)
        summary["fullSuiteComplete"] = summary["complete"] and not args.only_policy_recovery
    except BaseException as error:
        summary["failure"] = {"type": type(error).__name__, "message": str(error)}
        for gate in gates:
            if gate.get("oracleStatus") == "pending":
                gate["oracleStatus"] = "failed"
                gate["oracleFailure"] = summary["failure"]
        raise
    finally:
        summary["appsRetained"] = args.retain_apps
        summary["cleanupScope"] = "owned host/helper children and fds reaped/closed; no shared broker PID signals; source apps untouched"
        cleanup_failures = []
        for path in inputs:
            try:
                path.unlink(missing_ok=True)
            except OSError as error:
                cleanup_failures.append({"artifact": str(path), "operation": "unlink-owned-input", "errno": error.errno})
        if not args.retain_apps:
            for app in app_paths:
                try:
                    if app.exists():
                        shutil.rmtree(app)
                except OSError as error:
                    cleanup_failures.append({"artifact": str(app), "operation": "remove-owned-app-copy", "errno": error.errno})
        summary["cleanupFailures"] = cleanup_failures
        if cleanup_failures or "failure" in summary:
            summary["complete"] = False
            summary["fullSuiteComplete"] = False
        (root / "summary.json").write_text(json.dumps(summary, sort_keys=True, indent=2) + "\n")
        print(root / "summary.json", flush=True)
    return 1 if summary["cleanupFailures"] else (0 if summary["complete"] else 77)


if __name__ == "__main__":
    sys.exit(main())

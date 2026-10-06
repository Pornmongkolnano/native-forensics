#!/usr/bin/env python3
"""Prepare and run an isolated *full NetBeans* Autopsy image-import pipeline.

This is not a desktop responsiveness test. No ingest modules are requested and
verification/export belongs outside its timed interval. Runtime staging uses
fresh directories and read-only references; installed cases/settings are never
selected. The upstream three-module baseline still needs the Mac ARM64 adapters.
Only local/autopsy-comparison is writable. Standard library, macOS only.
"""
from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import socket
import sqlite3
import statistics
import struct
import subprocess
import threading
import time
import urllib.request
import uuid
import zipfile

REPO = Path(__file__).resolve().parents[1]
LOCAL = REPO / "local/autopsy-comparison"
SETUP_VERSION = 2
VARIANTS = ("original-mac-compatible", "installed-adapted")
MODULES = ("org-sleuthkit-autopsy-core.jar", "org-sleuthkit-autopsy-keywordsearch.jar",
           "org-sleuthkit-autopsy-recentactivity.jar")
ARM64_TSK_JAR_SHA = "9e888f8dfb14eb9e5ebce8f8199f550d149615ac2a7002df3fabbf5b24f69b3b"


def digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            sha.update(block)
    return sha.hexdigest()


def write_json(path: Path, data):
    with path.open("x") as stream:
        json.dump(data, stream, indent=2, ensure_ascii=False)
        stream.write("\n")


def owned_path(path: Path) -> Path:
    resolved = path.resolve()
    if not resolved.is_relative_to(LOCAL.resolve()):
        raise ValueError("Output must be under ignored local/autopsy-comparison")
    return resolved


def symlink_tree(source: Path, destination: Path, overrides: dict[str, Path]):
    """All directories are owned. Bin/nbexec/configs and overrides are copies.

    Symlinking bin/autopsy itself would resolve back to the installed runtime.
    No updater directories from the installed runtime are selected.
    """
    destination.mkdir()
    for current, directories, files in os.walk(source, followlinks=False):
        relative = Path(current).relative_to(source)
        target = destination / relative
        directories[:] = [name for name in directories if name not in ("update", "logs")]
        for name in directories:
            original = Path(current) / name
            if original.is_symlink():
                (target / name).symlink_to(original.resolve(), target_is_directory=True)
            else:
                (target / name).mkdir()
        for name in files:
            original = Path(current) / name
            key = (relative / name).as_posix()
            if name.endswith((".log", ".pid")) or ".log." in name:
                continue
            if key in overrides:
                shutil.copy2(overrides[key], target / name)
            elif key.startswith(("bin/", "etc/", "autopsy/solr/")) or key == "platform/lib/nbexec":
                shutil.copy2(original, target / name)
            else:
                (target / name).symlink_to(original.resolve())


def private_solr_key(jar: Path, key: str) -> dict:
    """Safety-only adapter isolates upstream's process-matching STOP.KEY.

    Both variants receive the same equal-length constant substitution. No Java
    method bytecode or filesystem enumeration logic is changed. A read-only
    source symlink is detached before writing the task-owned replacement JAR.
    """
    original = jar.read_bytes()
    previous_hash = hashlib.sha256(original).hexdigest()
    temporary = jar.with_name(jar.name + ".private-key")
    changed = []
    with zipfile.ZipFile(jar) as source, zipfile.ZipFile(temporary, "x") as target:
        for info in source.infolist():
            data = source.read(info.filename)
            if info.filename.endswith(".class") and b"jjk#09s" in data:
                count = data.count(b"jjk#09s")
                data = data.replace(b"jjk#09s", key.encode("ascii"))
                changed.append({"entry": info.filename, "occurrences": count})
            target.writestr(info, data)
    if len(changed) != 1 or changed[0]["entry"] != "org/sleuthkit/autopsy/keywordsearch/Server.class" or not (1 <= changed[0]["occurrences"] <= 10):
        temporary.unlink()
        raise ValueError("Unexpected STOP.KEY constant locations; adapter refused")
    jar.unlink()  # Only this task-owned link or copy, never the source target.
    temporary.rename(jar)
    return {"originalJarSHA256": previous_hash, "effectiveJarSHA256": digest(jar),
            "privateStopKey": key, "changedEntries": changed,
            "purpose": "Prevent upstream fallback process queries from matching unrelated Solr instances"}


def free_ports(ports):
    ports = tuple(ports)
    if not ports or any(not isinstance(port, int) or not (1 <= port <= 65535) for port in ports):
        raise ValueError("Supply valid TCP/UDP port numbers")
    # BSD permits a wildcard SO_REUSEADDR listener to coexist with a listener
    # on an explicit local interface. Detect all live listeners first; socket
    # binding alone cannot prove the absence of a loopback listener on macOS.
    listeners = subprocess.run(["/usr/sbin/lsof", "-nP", "-t",
        "-iTCP:" + ",".join(str(port) for port in ports), "-sTCP:LISTEN"],
        capture_output=True, text=True, timeout=5)
    if listeners.returncode == 0 and listeners.stdout.strip():
        raise OSError(errno.EADDRINUSE, "An actual TCP listener occupies a private benchmark port")
    if listeners.returncode != 1 or listeners.stderr.strip():
        raise RuntimeError("Could not establish private listener absence: " + listeners.stderr.strip())
    held = []
    try:
        for port in ports:
            for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                descriptor = socket.socket(socket.AF_INET, kind)
                held.append(descriptor)
                if kind == socket.SOCK_STREAM:
                    # A just-closed owned Solr connection can leave TIME_WAIT.
                    # Reuse the local address, then listen to reject any actual
                    # live listener; SO_REUSEPORT is deliberately never enabled.
                    descriptor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                descriptor.bind(("0.0.0.0", port))
                if kind == socket.SOCK_STREAM:
                    descriptor.listen(1)
    finally:
        for descriptor in held:
            descriptor.close()


def solr_snapshot():
    """Read-only identity/core inventory, never starts/stops/unloads anything."""
    root = "http://127.0.0.1:23232/solr/"
    try:
        def read(suffix):
            with urllib.request.urlopen(root + suffix, timeout=3) as response:
                return json.load(response)
        info = read("admin/info/system?wt=json")
        cores = read("admin/cores?action=STATUS&wt=json")
        return {"available": True, "home": info.get("solr_home"),
                "startTime": info["jvm"]["jmx"]["startTime"],
                "cores": sorted(cores.get("status", {}))}
    except Exception as error:
        return {"available": False, "reason": type(error).__name__}


def prepare(output: Path, runtime: Path, installer: Path, java_home: Path,
            fixtures: Path) -> dict:
    output = owned_path(output)
    output.mkdir(parents=True, exist_ok=True)
    metadata_path = output / "setup.json"
    if metadata_path.exists():
        setup = json.loads(metadata_path.read_text())
        if setup.get("schemaVersion") != SETUP_VERSION:
            raise ValueError("Old unsafe setup retained as diagnostic; prepare in a new output directory")
        verify_setup(setup)
        return setup
    runtime = runtime.resolve()
    installer = installer.resolve()
    java_home = java_home.resolve()
    fixtures = fixtures.resolve()
    if not (runtime / "bin/autopsy").is_file():
        raise ValueError("Autopsy runtime is missing bin/autopsy")
    variant_info = json.loads((installer / "audit-probes/version-benchmark-20261006/variants.json").read_text())
    backup_root = installer / "audit-probes/safe-improvements-20261005/backups"
    backup_info = json.loads((backup_root / "backup-manifest.json").read_text())
    tsk_jar = runtime / "autopsy/modules/ext/sleuthkit-4.15.0.jar"
    if digest(tsk_jar) != ARM64_TSK_JAR_SHA:
        raise ValueError("Expected verified Java 17 ARM64-compatible TSK jar")
    image_manifest = json.loads((fixtures / "manifest.json").read_text())
    if image_manifest.get("synthetic") is not True:
        raise ValueError("Only explicitly synthetic manifests are accepted")
    inputs = {}
    for name in ("fat16-512.raw", "ntfs-streams.raw"):
        item = next(row for row in image_manifest["images"] if row["path"] == name)
        path = fixtures / name
        if path.is_symlink() or not path.is_file() or digest(path) != item["logicalSha256"]:
            raise ValueError("Synthetic image hash does not match its manifest")
        inputs[name] = {"path": str(path), "sha256": item["logicalSha256"],
                        "size": path.stat().st_size, "facts": item}
    common = []
    for path in sorted(runtime.rglob("*.jar")):
        common.append({"path": str(path), "relativePath": path.relative_to(runtime).as_posix(),
                       "sha256": digest(path)})
    tracked = [runtime / "bin/autopsy", runtime / "platform/lib/nbexec",
               runtime / "etc/autopsy.conf", runtime / "etc/autopsy.clusters", java_home / "bin/java"]
    private_key = "nf" + uuid.uuid4().hex[:5]
    setup = {"schemaVersion": SETUP_VERSION, "scope": "Full NetBeans CLI createCase/addDataSource; no runIngest or GUI; fresh owned Solr bootstrap",
             "baselineScope": "Original upstream three Autopsy JARs plus unpatched TSK native backup; common Mac ARM64 dependencies remain adapted",
             "runtime": str(runtime), "javaHome": str(java_home), "inputs": inputs,
             "commonJars": common, "protectedFiles": [], "variants": {},
             "timezone": "UTC", "sectorSize": "auto", "orphanFiles": "included",
             "ingestModules": [], "verificationOutsideTiming": True,
             "privateSolrPorts": {"http": 41137, "stop": 41138, "rmi": 41139},
             "privateSolrStopKey": private_key}
    for variant in VARIANTS:
        tree = output / ("runtime-" + variant)
        native = output / ("native-" + variant)
        native.mkdir()
        overrides = {}
        if variant == "original-mac-compatible":
            for item in variant_info["components"]:
                source = Path(item["original_path"])
                if digest(source) != item["original_sha256"]:
                    raise ValueError("Original upstream module baseline hash mismatch")
                overrides["autopsy/modules/" + item["name"]] = source
                tracked.append(source)
        for key in ("tsk_native", "tsk_jni"):
            item = backup_info[key]
            source = Path(item["backup"] if variant == "original-mac-compatible" else item["source"])
            if variant == "original-mac-compatible" and digest(source) != item["sha256"]:
                raise ValueError("Unpatched native backup hash mismatch")
            shutil.copy2(source, native / source.name)
            tracked.append(source)
        symlink_tree(runtime, tree, overrides)
        key_adapter = private_solr_key(tree / "autopsy/modules/org-sleuthkit-autopsy-keywordsearch.jar", private_key)
        # nbexec invokes a Java child through /bin/sh (SIP strips inherited DYLD
        # vars). A task-local JDK wrapper sets them *after* that boundary.
        jdk = output / ("jdk-" + variant)
        jdk.mkdir()
        for source in java_home.iterdir():
            if source.name != "bin":
                (jdk / source.name).symlink_to(source.resolve(), target_is_directory=source.is_dir())
        (jdk / "bin").mkdir()
        for source in (java_home / "bin").iterdir():
            if source.name != "java":
                (jdk / "bin" / source.name).symlink_to(source.resolve())
        wrapper = jdk / "bin/java"
        wrapper.write_text("#!/bin/sh\nexport DYLD_LIBRARY_PATH=" + shlex.quote(str(native)) +
                           "\nexport DYLD_PRINT_LIBRARIES=1\nexec " +
                           shlex.quote(str(java_home / "bin/java")) + ' "$@"\n')
        wrapper.chmod(0o755)
        setup["variants"][variant] = {"runtime": str(tree), "jdk": str(jdk),
            "safetyAdapter": key_adapter,
            "nativeDirectory": str(native), "modules": [
                {"name": name, "sha256": digest(tree / "autopsy/modules" / name)} for name in MODULES],
            "nativeFiles": [{"path": str(p), "sha256": digest(p)} for p in sorted(native.iterdir())]}
    setup["protectedFiles"] = [{"path": str(p), "sha256": digest(p)} for p in sorted(set(tracked))]
    write_json(metadata_path, setup)
    return setup


def verify_setup(setup: dict):
    for row in setup["protectedFiles"] + setup["commonJars"]:
        if digest(Path(row["path"])) != row["sha256"]:
            raise ValueError("Runtime baseline changed: " + row["path"])
    for row in setup["inputs"].values():
        if digest(Path(row["path"])) != row["sha256"]:
            raise ValueError("Synthetic source changed")
    for variant in setup["variants"].values():
        for row in variant["modules"]:
            if digest(Path(variant["runtime"]) / "autopsy/modules" / row["name"]) != row["sha256"]:
                raise ValueError("Staged module changed")
        for row in variant["nativeFiles"]:
            if digest(Path(row["path"])) != row["sha256"]:
                raise ValueError("Staged native library changed")


def stop_owned_group(process: subprocess.Popen):
    if process.poll() is not None:
        return
    if os.getpgid(process.pid) != process.pid:
        raise RuntimeError("Refusing signal outside exact task-owned process group")
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=3)


class OwnedGroupSampler:
    """Sample only a new-session process group, including orphaned Solr children.

    macOS rusage_info_v2 CPU times are Mach absolute ticks (not nanoseconds).
    Convert using mach_timebase_info. CPU sums retain each process's last live
    sample, so they are lower bounds when short-lived children/exit tails vanish.
    RSS sums are sequential, non-atomic estimates and may miss between-sample peaks.
    """
    def __init__(self, pgid: int, interval: float = .005):
        self.pgid = pgid
        self.interval = interval
        self.records = {}
        self.samples = []
        self.errors = []
        self.failure_counts = {}
        self.failure_overflow_count = 0
        self.stop_event = threading.Event()
        self.libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        self.libproc.proc_listpids.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_int]
        self.libproc.proc_listpids.restype = ctypes.c_int
        self.libproc.proc_pid_rusage.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
        self.libproc.proc_pid_rusage.restype = ctypes.c_int
        self.libproc.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        self.libproc.proc_pidpath.restype = ctypes.c_int
        system = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
        ratio = (ctypes.c_uint32 * 2)()
        if system.mach_timebase_info(ctypes.byref(ratio)) != 0 or not ratio[1]:
            raise RuntimeError("Could not read Mach absolute CPU timebase")
        self.timebase = {"numer": ratio[0], "denom": ratio[1]}
        self.tick_seconds = ratio[0] / ratio[1] / 1e9
        self.thread = threading.Thread(target=self._loop, daemon=True)

    def group_pids(self):
        buffer = (ctypes.c_int * 4096)()
        size = self.libproc.proc_listpids(2, self.pgid, buffer, ctypes.sizeof(buffer))
        if size <= 0:
            return []
        if size >= ctypes.sizeof(buffer) or size % ctypes.sizeof(ctypes.c_int):
            raise RuntimeError("Owned process group enumeration exceeded its bound")
        return sorted(pid for pid in buffer[:size // ctypes.sizeof(ctypes.c_int)] if pid > 0)

    def usage(self, pid):
        buffer = ctypes.create_string_buffer(160)  # public rusage_info_v2, 16 UUID bytes + 18 uint64_t
        ctypes.set_errno(0)
        status = self.libproc.proc_pid_rusage(pid, 2, buffer)
        if status != 0:
            if ctypes.get_errno() in (errno.ESRCH, errno.EINVAL):
                return None
            raise OSError(ctypes.get_errno(), "Owned process rusage unavailable")
        values = struct.unpack_from("18Q", buffer, 16)
        if values[9]:
            return None  # Exited/zombie process; it owns no runnable task/socket.
        return {"startAbsoluteTicks": values[8], "residentBytes": values[6],
                "userAbsoluteTicks": values[0], "systemAbsoluteTicks": values[1],
                "diskBytesRead": values[16], "diskBytesWritten": values[17]}

    def sample(self):
        entries = []
        for pid in self.group_pids():
            try:
                usage = self.usage(pid)
            except OSError as error:
                # Some short-lived platform helpers deny rusage even to their
                # owner. Keep sampling the other owned PIDs rather than lose
                # this complete aggregate sample, and retain honest coverage.
                self.record_failure(pid, error)
                continue
            if usage is None:
                continue
            key = (pid, usage["startAbsoluteTicks"])
            executable = ctypes.create_string_buffer(4096)
            self.libproc.proc_pidpath(pid, executable, len(executable))
            if key not in self.records:
                self.records[key] = {"pid": pid, "firstSampleMonotonic": time.monotonic(),
                    "rssPeakSampledBytes": 0}
            record = self.records[key]
            record["executable"] = executable.value.decode(errors="replace")
            record.update(usage)
            record["rssPeakSampledBytes"] = max(record["rssPeakSampledBytes"], usage["residentBytes"])
            if os.getpgid(pid) == self.pgid:
                entries.append(usage["residentBytes"])
        if entries:
            self.samples.append({"monotonic": time.monotonic(), "aggregateRSSBytes": sum(entries),
                                 "processCount": len(entries)})

    def record_failure(self, pid, error):
        key = (pid, getattr(error, "errno", None), type(error).__name__)
        if key in self.failure_counts:
            self.failure_counts[key]["count"] += 1
            self.failure_counts[key]["lastMonotonic"] = time.monotonic()
            return
        if len(self.failure_counts) >= 128:
            self.failure_overflow_count += 1
            return
        executable = ctypes.create_string_buffer(4096)
        if pid is not None:
            self.libproc.proc_pidpath(pid, executable, len(executable))
        now = time.monotonic()
        self.failure_counts[key] = {"pid": pid, "errno": getattr(error, "errno", None),
            "type": type(error).__name__, "message": str(error),
            "executable": executable.value.decode(errors="replace"),
            "count": 1, "firstMonotonic": now, "lastMonotonic": now}

    def _loop(self):
        while not self.stop_event.is_set():
            try:
                self.sample()
            except (ProcessLookupError, OSError) as error:
                if getattr(error, "errno", None) != errno.ESRCH:
                    self.record_failure(None, error)
            except Exception as error:
                self.record_failure(None, error)
            self.stop_event.wait(self.interval)

    def start(self):
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        self.thread.join(timeout=3)
        if self.thread.is_alive():
            raise RuntimeError("Owned process sampler did not stop")

    def cleanup_remaining(self):
        """Parent may have exited while task-owned detached Solr is still alive."""
        remaining = []
        for pid in self.group_pids():
            usage = self.usage(pid)
            if usage is None:
                continue
            if (pid, usage["startAbsoluteTicks"]) not in self.records:
                raise RuntimeError("Refusing cleanup of an unregistered process or reused PID")
            if os.getpgid(pid) != self.pgid:
                raise RuntimeError("Refusing cleanup after process group identity changed")
            remaining.append(pid)
        if remaining:
            try:
                os.killpg(self.pgid, signal.SIGTERM)
            except ProcessLookupError:
                return remaining
            end = time.monotonic() + 3
            while any(self.usage(pid) is not None for pid in self.group_pids()) and time.monotonic() < end:
                time.sleep(.02)
            if any(self.usage(pid) is not None for pid in self.group_pids()):
                try:
                    os.killpg(self.pgid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        return remaining

    def receipt(self):
        rows = sorted(self.records.values(), key=lambda row: row["firstSampleMonotonic"])
        intervals = [b["monotonic"] - a["monotonic"] for a, b in zip(self.samples, self.samples[1:])]
        return {"method": "libproc PROC_PGRP_ONLY/rusage_info_v2; exact new-session group and PID creation identities",
            "machTimebase": self.timebase, "requestedIntervalSeconds": self.interval,
            "actualIntervalMedianSeconds": statistics.median(intervals) if intervals else None,
            "sampleCount": len(self.samples), "sampledAggregatePeakRSSBytes": max((r["aggregateRSSBytes"] for r in self.samples), default=None),
            "sampledUserCPULowerBoundSeconds": sum(r["userAbsoluteTicks"] for r in rows) * self.tick_seconds,
            "sampledSystemCPULowerBoundSeconds": sum(r["systemAbsoluteTicks"] for r in rows) * self.tick_seconds,
            "sampledDiskReadLowerBoundBytes": sum(r["diskBytesRead"] for r in rows),
            "sampledDiskWriteLowerBoundBytes": sum(r["diskBytesWritten"] for r in rows),
            "ownedProcesses": rows, "failedSamples": list(self.failure_counts.values()),
            "failedSampleCount": sum(row["count"] for row in self.failure_counts.values()) + self.failure_overflow_count,
            "failureRecordsTruncatedCount": self.failure_overflow_count,
            "resourceCoverageComplete": not self.failure_counts and not self.failure_overflow_count,
            "limitations": "Includes successfully sampled owned main JVM, Solr and shell children; Python and GUI excluded. Denied/unavailable PIDs are retained as bounded failure receipts and excluded from sums, making coverage partial. Sequential RSS samples can miss peaks. Last-live CPU/disk samples omit exit tails and unseen short processes; they are lower bounds, not wait4 kernel totals."}
def sqlite_receipt(case_db: Path, expected: dict) -> dict:
    connection = sqlite3.connect(case_db.as_uri() + "?mode=ro", uri=True)
    try:
        images = [dict(zip(("id", "type", "sectorSize", "timezone", "size"), row))
                  for row in connection.execute("SELECT obj_id,type,ssize,tzone,size FROM tsk_image_info")]
        files = [dict(zip(("name", "size", "metaAddress", "attributeType", "attributeID", "parentPath", "metaFlags", "nameFlags", "filesystemID"), row))
                 for row in connection.execute("SELECT name,size,meta_addr,attr_type,attr_id,parent_path,meta_flags,dir_flags,fs_obj_id FROM tsk_files WHERE type=0")]
        filesystems = [dict(zip(("id", "offset", "type", "blockSize", "blockCount"), row))
                       for row in connection.execute("SELECT obj_id,img_offset,fs_type,block_size,block_count FROM tsk_fs_info")]
        if len(images) != 1 or images[0]["timezone"] != "UTC" or images[0]["size"] != expected["size"]:
            raise AssertionError("Effective image timezone/size did not match fixed workload")
        if not filesystems:
            raise AssertionError("CLI produced no supported filesystem")
        return {"images": images, "filesystems": filesystems, "filesystemEntries": files,
                "filesystemEntryCount": len(files), "effectiveTimezone": "UTC"}
    finally:
        connection.close()


def run_pipeline(setup: dict, output: Path, variant: str, image: str,
                 label: str = "smoke", timeout: float = 120) -> dict:
    """One bounded isolated run; call serially inside root's paired experiment."""
    if variant not in VARIANTS or image not in setup["inputs"] or not (0 < timeout <= 120):
        raise ValueError("Invalid fixed workload/variant/timeout")
    if not label or len(label) > 64 or not all(c.isascii() and (c.isalnum() or c in "-_") for c in label):
        raise ValueError("Run label must contain only ASCII letters, numbers, hyphens or underscores")
    verify_setup(setup)  # Outside timing, necessarily warms filesystem caches.
    run = owned_path(output) / (label + "-" + uuid.uuid4().hex[:12])
    run.mkdir()
    for name in ("user", "cache", "cases", "home", "tmp", "prefs", "jni"):
        (run / name).mkdir()
    selected = setup["variants"][variant]
    tree = Path(selected["runtime"])
    jdk = Path(selected["jdk"])
    ports = setup["privateSolrPorts"]
    free_ports(ports.values())
    (run / "user/config").mkdir()
    (run / "user/config/KeywordSearch.properties").write_text(
        "IndexingServerPort=" + str(ports["http"]) + "\nIndexingServerStopPort=" + str(ports["stop"]) + "\n")
    (run / "solr-pids").mkdir()
    (run / "solr-logs").mkdir()
    include = run / "solr-include.sh"
    include.write_text("\n".join("export " + key + "=" + shlex.quote(str(value)) for key, value in {
        "SOLR_HOME": run / "user/solr", "SOLR_PID_DIR": run / "solr-pids",
        "SOLR_LOGS_DIR": run / "solr-logs", "SOLR_STOP_WAIT": 15,
        "SOLR_PORT": ports["http"], "STOP_PORT": ports["stop"], "RMI_PORT": ports["rmi"],
        "STOP_KEY": setup["privateSolrStopKey"], "SOLR_OPTS": "-Djetty.host=127.0.0.1",
        "SOLR_JAVA_HOME": setup["javaHome"]}.items()) + "\n")
    case_name = "SyntheticComparison"
    command = [str(tree / "bin/autopsy"), "--jdkhome", str(jdk),
        "--userdir", str(run / "user"), "--cachedir", str(run / "cache"),
        "--nogui", "--nosplash", "-J-Xmx4G", "-J-Djava.awt.headless=true",
        "-J-Duser.timezone=UTC", "-J-Duser.home=" + str(run / "home"),
        "-J-Djava.io.tmpdir=" + str(run / "tmp"), "-J-Djava.util.prefs.userRoot=" + str(run / "prefs"),
        "-J-Dtsk.tmpdir=" + str(run / "jni"), "-J-Djna.library.path=/opt/homebrew/lib",
        "-J-Djava.library.path=" + selected["nativeDirectory"] + ":/opt/homebrew/lib",
        "--createCase", "--caseName", case_name, "--caseType", "single",
        "--caseBaseDir", str(run / "cases"), "--addDataSource", "--dataSourcePath", setup["inputs"][image]["path"]]
    write_json(run / "command.json", command)
    solr_before = solr_snapshot()
    environment = os.environ.copy()
    environment["TZ"] = "UTC"
    environment["SOLR_INCLUDE"] = str(include)
    for name in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"):
        environment.pop(name, None)
    record = {"schemaVersion": 1, "variant": variant, "image": image,
        "scope": setup["scope"], "runDirectory": str(run), "command": command,
        "warmCache": True, "verificationIncludedInTiming": False, "solrBefore": solr_before}
    process = None
    sampler = None
    started = time.monotonic()
    try:
        with (run / "stdout.log").open("xb") as log:
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                cwd=run, env=environment, start_new_session=True, stdin=subprocess.DEVNULL)
            record["ownedProcessGroup"] = process.pid
            sampler = OwnedGroupSampler(process.pid)
            sampler.start()
            try:
                code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                record["timedOut"] = True
                stop_owned_group(process)
                code = process.returncode
            record["wallSeconds"] = time.monotonic() - started
            record["exitCode"] = code
            sampler.stop()
            record["resources"] = sampler.receipt()
        trace = (run / "stdout.log").read_text(errors="replace")
        native_path = str(Path(selected["nativeDirectory"]) / "libtsk.23.dylib")
        record["nativeLoadedTrace"] = [line for line in trace.splitlines() if native_path in line and "dyld[" in line]
        record["unintendedInstalledNativeTrace"] = [line for line in trace.splitlines()
            if "dyld[" in line and "/libtsk.23.dylib" in line and native_path not in line]
        databases = list((run / "cases").rglob("autopsy.db"))
        record["caseDatabases"] = [str(path) for path in databases]
        if code != 0 or not record["nativeLoadedTrace"] or record["unintendedInstalledNativeTrace"] or len(databases) != 1:
            raise AssertionError("Full NetBeans run failed or exact native baseline was not loaded; inspect stdout.log")
        record["sqlite"] = sqlite_receipt(databases[0], setup["inputs"][image])
        record["structuralGatePassed"] = True
        record["exactExportsVerified"] = False
    except Exception as error:
        record["error"] = type(error).__name__ + ": " + str(error)
        record["structuralGatePassed"] = False
    finally:
        if process is not None:
            stop_owned_group(process)
        if sampler is not None:
            sampler.stop()
            record["forcedCleanupRemainingPIDs"] = sampler.cleanup_remaining()
            record["resources"] = sampler.receipt()
            if record["forcedCleanupRemainingPIDs"]:
                record["ownedServicePersistedAfterAppExit"] = True
                record["serviceCleanupScope"] = "Exact registered owned process identities/group, outside app wall interval"
        record["solrAfter"] = solr_snapshot()
        record["existingSolrUnchanged"] = record["solrAfter"] == solr_before
        free_ports(ports.values())
        record["ownedSolrPortsFreeAfterCleanup"] = True
        verify_setup(setup)
        record["protectedFilesAndSourcesUnchanged"] = True
        write_json(run / "receipt.json", record)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=LOCAL / "prepared-v3")
    parser.add_argument("--runtime", type=Path, default=Path.home() / "Library/Application Support/Autopsy/autopsy-4.23.1")
    parser.add_argument("--installer", type=Path, default=Path.home() / "Downloads/Autopsy-Install")
    parser.add_argument("--java-home", type=Path, default=Path("/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home"))
    parser.add_argument("--fixtures", type=Path, default=REPO / "local/phase1-corpus-verified/fixtures")
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--variant", choices=VARIANTS, default=VARIANTS[0])
    parser.add_argument("--image", choices=("fat16-512.raw", "ntfs-streams.raw"), default="fat16-512.raw")
    args = parser.parse_args()
    setup = prepare(args.output, args.runtime, args.installer, args.java_home, args.fixtures)
    if args.smoke:
        record = run_pipeline(setup, args.output, args.variant, args.image)
        print(json.dumps({key: record.get(key) for key in ("runDirectory", "exitCode", "wallSeconds", "structuralGatePassed", "error")}))
        return 0 if record["structuralGatePassed"] and record["existingSolrUnchanged"] else 1
    print(json.dumps({"prepared": str(args.output), "variants": list(setup["variants"]), "smokeExecuted": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

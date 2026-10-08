#!/usr/bin/env python3
"""Root-coordinated local test preparation: compile/sign owned fixtures, then gates.

Invoke only after the coordinator releases its compiler/performance window.
No SwiftPM build, production bundle mutation, timestamp request or provider call.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import uuid

import run_document_runtime_gates as gates

CANARY = b"NativeForensics owned synthetic outside canary\n"
CONTROL_FILES = {"write-control": b"N", "crash-once": b"C", "malformed-once": b"M", "hang-once": b"H"}


def validate_listener_receipt(value):
    gates.require(value.get("address") == "127.0.0.1" and value.get("acceptTimeoutSeconds") == 0.1 and
                  value.get("applicationDataTransferred") is False and type(value.get("acceptedConnections")) is int and
                  value["acceptedConnections"] == 0 and value.get("errors") == [],
                  "owned live listener observed a connection or failed; no network-denial pass")


def directory_identity(descriptor):
    value = os.fstat(descriptor)
    gates.require(stat.S_ISDIR(value.st_mode), "owned artifact parent is not a directory")
    return {"device": value.st_dev, "inode": value.st_ino, "uid": value.st_uid,
            "permissions": stat.S_IMODE(value.st_mode)}


def regular_receipt(directory, leaf, expected):
    descriptor = os.open(leaf, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
    try:
        before = os.fstat(descriptor)
        gates.require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and
                      before.st_nlink == 1 and before.st_size == len(expected) and
                      stat.S_IMODE(before.st_mode) == 0o600, "owned control file shape changed")
        contents = os.read(descriptor, len(expected) + 1)
        after = os.fstat(descriptor)
        linked = os.stat(leaf, dir_fd=directory, follow_symlinks=False)
        fields = ("st_dev", "st_ino", "st_uid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode")
        gates.require(all(getattr(before, field) == getattr(after, field) == getattr(linked, field) for field in fields),
                      "owned control file identity changed during read")
        gates.require(contents == expected, "owned control file contents changed")
        return {"device": before.st_dev, "inode": before.st_ino, "uid": before.st_uid, "links": before.st_nlink,
                "bytes": before.st_size, "permissions": stat.S_IMODE(before.st_mode),
                "mtimeNanoseconds": before.st_mtime_ns, "ctimeNanoseconds": before.st_ctime_ns,
                "sha256": gates.hashlib.sha256(contents).hexdigest()}
    finally:
        os.close(descriptor)


class PrivateDirectory:
    """A newly created exclusive directory, accessed through pinned parent/fds."""
    def __init__(self, parent, prefix, require_owned_parent=True):
        gates.require(parent.is_absolute() and parent.resolve(strict=True) == parent, "artifact parent is not canonical")
        self.parent = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.descriptor, self.leaf, self.path = None, prefix + uuid.uuid4().hex[:12], None
        try:
            parent_identity = directory_identity(self.parent)
            gates.require(not require_owned_parent or parent_identity["uid"] == os.geteuid(), "container parent UID changed")
            os.mkdir(self.leaf, 0o700, dir_fd=self.parent)
            self.path = parent / self.leaf
            self.descriptor = os.open(self.leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                      dir_fd=self.parent)
            self.identity = directory_identity(self.descriptor)
            gates.require(self.identity["uid"] == os.geteuid() and self.identity["permissions"] == 0o700,
                          "new artifact directory is not private and owned")
            self.check()
        except BaseException as original:
            rollback = []
            try:
                # Without a validated held inode, leave the partial directory
                # in place rather than adopting a replacement during rollback.
                if self.descriptor is not None and hasattr(self, "identity"):
                    value = os.stat(self.leaf, dir_fd=self.parent, follow_symlinks=False)
                    gates.require(stat.S_ISDIR(value.st_mode) and value.st_uid == os.geteuid() and
                                  value.st_dev == self.identity["device"] and value.st_ino == self.identity["inode"],
                                  "construction rollback leaf identity changed")
                    os.rmdir(self.leaf, dir_fd=self.parent)
                elif self.path is not None:
                    rollback.append("partial directory retained: validated held inode unavailable")
            except BaseException as error:
                rollback.append(str(error))
            finally:
                if self.descriptor is not None:
                    os.close(self.descriptor)
                os.close(self.parent)
            if rollback:
                original.ownedRollbackFailure = {"path": str(self.path), "details": rollback}
            raise

    def check(self):
        value = os.stat(self.leaf, dir_fd=self.parent, follow_symlinks=False)
        gates.require(self.path.resolve(strict=True) == self.path and self.path.lstat().st_dev == value.st_dev and
                      self.path.lstat().st_ino == value.st_ino, "owned artifact absolute path changed")
        gates.require(stat.S_ISDIR(value.st_mode) and
                      {"device": value.st_dev, "inode": value.st_ino, "uid": value.st_uid,
                       "permissions": stat.S_IMODE(value.st_mode)} == self.identity == directory_identity(self.descriptor),
                      "owned artifact directory was replaced")

    def close(self, allowed_leaves):
        try:
            self.check()
            leaves = os.listdir(self.descriptor)
            gates.require(set(leaves) <= set(allowed_leaves), "unexpected artifact in private control directory")
            for leaf in leaves:
                os.unlink(leaf, dir_fd=self.descriptor)
            os.rmdir(self.leaf, dir_fd=self.parent)
        finally:
            os.close(self.descriptor)
            os.close(self.parent)


class LoopbackListener:
    """Accept and immediately close synthetic connections; never send/read data."""
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.socket.bind(("127.0.0.1", 0))
            self.socket.listen(8)
            self.socket.settimeout(0.1)
        except BaseException:
            self.socket.close()
            raise
        self.port, self.accepted, self.errors = self.socket.getsockname()[1], 0, []
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.consume, name="owned-loopback-canary", daemon=True)
        try:
            self.thread.start()
        except BaseException:
            self.socket.close()
            raise

    def consume(self):
        while not self.stop.is_set():
            try:
                connection, _ = self.socket.accept()
                self.accepted += 1
                connection.close()
            except socket.timeout:
                continue
            except OSError as error:
                self.errors.append(error.errno)
                return

    def close(self):
        # One complete accept interval drains any already queued connection.
        self.stop.wait(0.12)
        self.stop.set()
        self.thread.join(0.5)
        try:
            gates.require(not self.thread.is_alive(), "owned listener did not stop within its deadline")
            return {"address": "127.0.0.1", "port": self.port, "acceptTimeoutSeconds": 0.1,
                    "acceptedConnections": self.accepted, "errors": self.errors, "applicationDataTransferred": False}
        finally:
            self.socket.close()


def signing_flags(path):
    result = subprocess.run(["/usr/bin/codesign", "-d", "--verbose=4", str(path)],
                            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    # The SDK's display also emits `Executable Segment flags=...`, which is
    # a different namespace. Select exactly one signed CodeDirectory record.
    matches = re.findall(r"^CodeDirectory\b[^\r\n]*?\bflags=(0x[0-9a-fA-F]+)\b",
                         result.stdout + result.stderr, re.MULTILINE)
    gates.require(len(matches) == 1, "source signing flags unavailable")
    flags = int(matches[0], 16)
    # Current staged products use ad-hoc/linker signature metadata and optional
    # hardened runtime. Refuse additional security options rather than dropping
    # an unhandled production restriction during fixture preparation.
    gates.require(flags & ~(0x2 | 0x10000 | 0x20000) == 0,
                  "unhandled production signing flags; explicit preservation required")
    return flags


def run_logged(arguments, log, timeout=60):
    with log.open("xb") as output:
        subprocess.run(arguments, check=True, stdout=output, stderr=subprocess.STDOUT, timeout=timeout)


def sign(path, identity, identifier, entitlements, flags):
    arguments = ["/usr/bin/codesign", "--force", "--sign", identity, "--timestamp=none"]
    if flags & 0x10000:
        arguments += ["--options", "runtime"]
    if identifier:
        arguments += ["--identifier", identifier]
    if entitlements:
        arguments += ["--entitlements", str(entitlements)]
    else:
        # Preserve the original parent app's identifier and entitlement grants.
        arguments += ["--preserve-metadata=identifier,entitlements"]
    arguments.append(str(path))
    subprocess.run(arguments, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--production-app", required=True, type=Path)
    parser.add_argument("--output-parent", required=True, type=Path)
    parser.add_argument("--sign-identity", default="-")
    parser.add_argument("--repeat", default=64, type=int)
    parser.add_argument("--retain-apps", action="store_true", help="retain final runtime copies, not preparation resources")
    parser.add_argument("--only-policy-recovery", action="store_true",
                        help="run the missing boundary and crash/malformed/hang recovery scopes only")
    args = parser.parse_args()
    gates.require(sys.platform == "darwin" and 2 <= args.repeat <= 64, "requires macOS and repeat 2...64")
    repository = Path(__file__).resolve().parents[2]
    source = args.production_app.resolve(strict=True)
    gates.require(source.suffix == ".app", "expected a current signed production app")
    source_receipt = gates.signed_identity(source)
    flags = {role: signing_flags(source / relative) for role, relative in
             (("host", gates.HOST), ("broker", gates.BROKER), ("worker", gates.WORKER))}
    worker_entitlements = repository / "script/specs/document_worker_entitlements.plist"
    broker_entitlements = repository / "script/specs/document_xpc_entitlements.plist"
    for path, expected in ((worker_entitlements, {"com.apple.security.app-sandbox": True, "com.apple.security.inherit": True}),
                           (broker_entitlements, {"com.apple.security.app-sandbox": True})):
        value = plistlib.loads(path.read_bytes())
        gates.require(value.keys() == expected.keys() and all(value[key] is True for key in expected),
                      "fixture preparation requires exact production Boolean entitlements")
    args.output_parent.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix="nf-xpc-preparation-", dir=args.output_parent)).resolve()
    os.chmod(root, 0o700)
    paths, listener, outside, control = [], None, None, None
    exit_code = 1
    report = {"schemaVersion": 1, "evidenceScope": "synthetic fixture preparation; not release packaging",
              "sourceSignedExecutables": source_receipt, "sourceSigningFlags": flags, "complete": False,
              "selectedScope": "policy-and-failure-recovery-only" if args.only_policy_recovery else "full-runtime-suite",
              "fullSuiteComplete": False}
    try:
        inputs = [repository / path for path in ("Tests/Runtime/NFDocumentDecoderWorkerFixture.m",
                  "Tests/Runtime/NFBrokerDeathProbe.m", "Sources/NFDecoderIPC/NFDecoderIPC.m",
                  "Sources/NFDecoderIPC/include/NFDecoderIPC.h")]
        inputs += [worker_entitlements, broker_entitlements]
        report["buildInputsSHA256"] = {str(path.relative_to(repository)): gates.digest(path) for path in inputs}
        # Keep the UNIX socket pathname below macOS sun_path[104], regardless
        # of the caller's output-parent length. This owned directory alone is
        # outside the broker container; no user-selected path reaches the RPC.
        outside = PrivateDirectory(Path("/private/tmp"), "nf-xpc-can-", require_owned_parent=False)
        canary = outside.path / "c"
        gates.require(len(os.fsencode(str(canary) + ".socket")) < 104, "synthetic UNIX path exceeds sun_path")
        descriptor = os.open("c", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=outside.descriptor)
        try:
            gates.require(os.write(descriptor, CANARY) == len(CANARY), "short canary write")
        finally:
            os.close(descriptor)
        report["outsideDirectory"] = {"path": str(outside.path), **outside.identity}
        report["canaryReceipt"] = regular_receipt(outside.descriptor, "c", CANARY)
        container = Path.home().resolve(strict=True) / "Library/Containers/org.nativeforensics.NFDocumentDecoderXPC/Data"
        gates.require(container.is_dir(), "expected broker container Data directory must already exist")
        control = PrivateDirectory(container, "nf-xpc-test-")
        report["inheritedControlDirectory"] = {"path": str(control.path), **control.identity,
                                               "scope": "new owned child of the broker's existing sandbox container Data"}
        gates.require(os.listdir(control.descriptor) == [], "owned control directory was not empty")
        listener = LoopbackListener()
        port = listener.port
        variants = {}
        compiler = ["xcrun", "clang", "-fobjc-arc", "-fblocks", "-std=gnu11", "-arch", "arm64",
                    "-mmacosx-version-min=14.0", "-I", str(repository / "Sources/NFDecoderIPC/include"),
                    "-DNF_XPC_CANARY_PATH=" + json.dumps(str(canary), ensure_ascii=False),
                    "-DNF_XPC_INHERITED_CONTROL_DIRECTORY=" + json.dumps(str(control.path), ensure_ascii=False),
                    "-DNF_XPC_LOOPBACK_PORT=" + str(port)]
        for name, macros in (("fixture", []), ("early", ["-DNF_TEST_HELLO_DELAY_MS=1500"]),
                             ("bad-hello", ["-DNF_TEST_HELLO_DELAY_MS=500", "-DNF_TEST_BAD_HELLO_VERSION=1"])):
            app = root / (name + ".app")
            paths.append(app)
            shutil.copytree(source, app, symlinks=True)
            worker = app / gates.WORKER
            gates.require(worker.resolve(strict=True) == worker, "worker path escapes owned preparation app")
            command = compiler + macros + [str(inputs[0]), str(inputs[2]), "-framework", "Foundation",
                      "-framework", "Security", "-lbsm", "-o", str(worker)]
            run_logged(command, root / (name + ".clang.log"))
            sign(worker, args.sign_identity, "org.nativeforensics.NFDocumentDecoderWorker", worker_entitlements, flags["worker"])
            broker = app / "Contents/XPCServices/NFDocumentDecoderXPC.xpc"
            sign(broker, args.sign_identity, "org.nativeforensics.NFDocumentDecoderXPC", broker_entitlements, flags["broker"])
            sign(app, args.sign_identity, None, None, flags["host"])
            receipt = gates.signed_identity(app)
            for role in ("host", "broker"):
                gates.require(receipt[role]["signatureNormalizedPayloadSHA256"] ==
                              source_receipt[role]["signatureNormalizedPayloadSHA256"], "fixture changed production payload")
            report.setdefault("preparedSignedExecutables", {})[name] = receipt
            variants[name] = app
        helper = root / "NFBrokerDeathProbe"
        paths.append(helper)
        run_logged(["xcrun", "clang", "-fobjc-arc", "-std=gnu11", "-arch", "arm64", "-mmacosx-version-min=14.0",
                    str(inputs[1]), "-framework", "Foundation", "-framework", "Security", "-lbsm", "-o", str(helper)],
                   root / "broker-death-helper.clang.log")
        subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none", str(helper)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        command = [sys.executable, str(repository / "Tests/Runtime/run_document_runtime_gates.py"),
                   "--production-app", str(source), "--fixture-app", str(variants["fixture"]),
                   "--early-app", str(variants["early"]), "--bad-hello-app", str(variants["bad-hello"]),
                   "--death-helper", str(helper), "--output-parent", str(args.output_parent.resolve()), "--repeat", str(args.repeat)]
        if args.retain_apps:
            command += ["--retain-apps"]
        if args.only_policy_recovery:
            command += ["--only-policy-recovery"]
        with (root / "runtime.stdout").open("xb") as output, (root / "runtime.stderr").open("xb") as error:
            completed = subprocess.run(command, stdout=output, stderr=error)
        report["runtimeExitCode"] = completed.returncode
        report["runtimeSummaryPath"] = (root / "runtime.stdout").read_text().strip()
        outside.check()
        report["canaryReceiptAfter"] = regular_receipt(outside.descriptor, "c", CANARY)
        gates.require(report["canaryReceiptAfter"] == report["canaryReceipt"], "owned canary changed during preparation/gates")
        gates.require(os.listdir(outside.descriptor) == ["c"], "outside boundary attempt left an unexpected artifact")
        control.check()
        report["controlFileReceipts"] = {leaf: regular_receipt(control.descriptor, leaf, value)
                                         for leaf, value in CONTROL_FILES.items() if leaf in os.listdir(control.descriptor)}
        runtime_summary = json.loads(Path(report["runtimeSummaryPath"]).read_text())
        report["requiredGateNames"] = runtime_summary["requiredGateNames"]
        passed = {gate["name"] for gate in runtime_summary["gates"] if gate.get("oracleStatus") == "passed"}
        for gate_name, leaf in (("fixture-boundary", "write-control"), ("fixture-crash-same-host-recovery", "crash-once"),
                                ("fixture-malformed-same-host-recovery", "malformed-once"),
                                ("fixture-hang-same-host-recovery", "hang-once")):
            gates.require(gate_name not in passed or leaf in report["controlFileReceipts"], "successful gate lacks owned control marker")
        report["complete"] = completed.returncode == 0
        report["fullSuiteComplete"] = report["complete"] and not args.only_policy_recovery
        exit_code = completed.returncode
    except BaseException as error:
        report["failure"] = {"type": type(error).__name__, "message": str(error)}
        if hasattr(error, "ownedRollbackFailure"):
            report["constructionRollbackFailure"] = error.ownedRollbackFailure
        raise
    finally:
        cleanup = []
        if listener is not None:
            try:
                report["loopbackListener"] = listener.close()
                validate_listener_receipt(report["loopbackListener"])
            except BaseException as error:
                report["listenerFailure"] = {"type": type(error).__name__, "message": str(error)}
                cleanup.append({"artifact": "owned loopback listener", "operation": "validate-and-close"})
        for resource, leaves in ((control, CONTROL_FILES), (outside, {"c", "c.created", "c.socket"})):
            if resource is not None:
                try:
                    resource.close(leaves)
                except BaseException as error:
                    cleanup.append({"artifact": str(resource.path), "operation": "remove-owned-private-directory",
                                    "type": type(error).__name__, "message": str(error)})
        for path in reversed(paths):
            try:
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink(missing_ok=True)
            except OSError as error:
                cleanup.append({"artifact": str(path), "errno": error.errno})
        report["cleanupFailures"] = cleanup
        if cleanup:
            report["complete"] = False
            report["fullSuiteComplete"] = False
            exit_code = 1
        (root / "preparation.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
        print(root / "preparation.json", flush=True)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())

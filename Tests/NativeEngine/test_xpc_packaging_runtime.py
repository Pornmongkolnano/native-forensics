"""Fail-closed XPC runtime checks use synthetic files and mocked macOS tools."""
from pathlib import Path
import copy
import hashlib
import json
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from xml.parsers.expat import ExpatError

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "script"))
import validate_app_bundle as bundle_validator
import source_provenance


SANDBOX = "com.apple.security.app-sandbox"
INHERIT = "com.apple.security.inherit"


class XPCEntitlementTests(unittest.TestCase):
    def test_exact_boolean_sandbox_grant_is_accepted(self):
        bundle_validator.validate_xpc_entitlements({SANDBOX: True})

    def test_sandbox_grant_must_be_boolean_true(self):
        for value in (False, 0, 1, "true", "True", None, [], {}):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "exactly the App Sandbox"):
                bundle_validator.validate_xpc_entitlements({SANDBOX: value})

    def test_missing_sandbox_or_non_dictionary_is_rejected(self):
        for value in (None, True, [], {}, {"com.apple.security.inherit": True}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                bundle_validator.validate_xpc_entitlements(value)

    def test_additional_grants_are_rejected_even_when_false(self):
        for key, value in (("com.apple.security.network.client", True),
                           ("com.apple.security.files.user-selected.read-only", True),
                           ("com.apple.security.inherit", False),
                           ("com.apple.security.application-groups", ["synthetic.group"])):
            with self.subTest(key=key), self.assertRaises(ValueError):
                bundle_validator.validate_xpc_entitlements({SANDBOX: True, key: value})


class WorkerEntitlementTests(unittest.TestCase):
    def test_worker_requires_exact_boolean_sandbox_and_inherit(self):
        bundle_validator.validate_worker_entitlements({SANDBOX: True, INHERIT: True})
        for key in (SANDBOX, INHERIT):
            for value in (False, 0, 1, "true", None):
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    bundle_validator.validate_worker_entitlements({SANDBOX: True, INHERIT: True, key: value})

    def test_missing_or_additional_worker_entitlements_are_rejected(self):
        for value in (None, [], {}, {SANDBOX: True}, {INHERIT: True},
                      {SANDBOX: True, INHERIT: True, "com.apple.security.network.client": True},
                      {SANDBOX: True, INHERIT: True, "com.apple.security.network.client": False}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                bundle_validator.validate_worker_entitlements(value)

    def test_broker_cannot_acquire_worker_inheritance_entitlement(self):
        with self.assertRaises(ValueError):
            bundle_validator.validate_xpc_entitlements({SANDBOX: True, INHERIT: True})


class BinaryRuntimeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.binary = self.root / "NFDocumentDecoderXPC"
        self.binary.write_bytes(b"synthetic executable; tools are mocked")
        self.binary.chmod(0o755)
        self.architectures = "arm64"
        self.dependencies = (f"{self.binary}:\n"
            "\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1.0.0)\n"
            "\t/System/Library/Frameworks/Security.framework/Versions/A/Security "
            "(compatibility version 1.0.0, current version 1.0.0)\n")
        self.loads = self.build_version()

    @staticmethod
    def build_version(minimum="14.0", platform="1"):
        return ("Load command 0\n"
                "      cmd LC_BUILD_VERSION\n"
                "  cmdsize 32\n"
                f" platform {platform}\n"
                f"    minos {minimum}\n"
                "      sdk 26.0\n"
                "   ntools 1\n")

    @staticmethod
    def legacy_version(minimum="14"):
        return ("Load command 0\n"
                "      cmd LC_VERSION_MIN_MACOSX\n"
                "  cmdsize 16\n"
                f"  version {minimum}\n"
                "      sdk 26.0\n")

    def tool_output(self, argv):
        outputs = {
            ("/usr/bin/lipo", "-archs", str(self.binary)): self.architectures,
            ("/usr/bin/otool", "-L", str(self.binary)): self.dependencies,
            ("/usr/bin/otool", "-l", str(self.binary)): self.loads,
        }
        self.assertIn(tuple(argv), outputs, "Runtime validation invoked an unexpected tool.")
        return outputs[tuple(argv)]

    def validate(self, minimum="14.0"):
        with patch.object(bundle_validator, "command", side_effect=self.tool_output) as command:
            bundle_validator.validate_binary_runtime(self.binary, "arm64", minimum)
        return command

    def test_build_version_and_macOS_version_normalization_are_accepted(self):
        for deployment, declared, platform in (("14.0", "14", "1"),
                                                ("14.0.0", "14.0", "macos"),
                                                ("14", "14.0.0", "MACOS")):
            with self.subTest(deployment=deployment, declared=declared, platform=platform):
                self.loads = self.build_version(deployment, platform)
                self.assertEqual(self.validate(declared).call_count, 3)

    def test_legacy_version_min_macOS_14_is_normalized(self):
        self.loads = self.legacy_version("14")
        self.validate("14.0")

    def test_mismatched_empty_duplicate_or_extra_architecture_slices_are_rejected(self):
        for architectures in ("", "x86_64", "arm64 x86_64", "x86_64 arm64", "arm64 arm64"):
            with self.subTest(architectures=architectures):
                self.architectures = architectures
                with self.assertRaisesRegex(ValueError, "single-architecture receipt"):
                    self.validate()

    def test_non_system_dynamic_dependencies_are_rejected(self):
        for dependency in ("@rpath/private.dylib", "@loader_path/private.dylib",
                           "/Library/Frameworks/Private.framework/Private", "relative.dylib",
                           "/usr/lib/../../tmp/private.dylib",
                           "/System/Library/../../tmp/private.dylib"):
            with self.subTest(dependency=dependency):
                self.dependencies = (f"{self.binary}:\n\t{dependency} "
                                     "(compatibility version 1.0.0, current version 1.0.0)\n")
                with self.assertRaisesRegex(ValueError, "outside macOS system libraries"):
                    self.validate()

    def test_missing_dynamic_dependency_inventory_is_rejected(self):
        self.dependencies = f"{self.binary}:\n"
        with self.assertRaisesRegex(ValueError, "outside macOS system libraries"):
            self.validate()

    def test_missing_deployment_command_or_minimum_field_is_rejected(self):
        for loads in ("", "Load command 0\n cmd LC_UUID\n uuid synthetic\n",
                      self.build_version().replace("    minos 14.0\n", ""),
                      self.legacy_version().replace("  version 14\n", "")):
            with self.subTest(loads=loads):
                self.loads = loads
                with self.assertRaises(ValueError):
                    self.validate()

    def test_non_macOS_deployment_targets_are_rejected(self):
        for platform in ("2", "ios", "6", "maccatalyst", ""):
            with self.subTest(platform=platform):
                self.loads = self.build_version(platform=platform)
                with self.assertRaisesRegex(ValueError, "not macOS"):
                    self.validate()
        self.loads = self.legacy_version().replace("LC_VERSION_MIN_MACOSX", "LC_VERSION_MIN_IPHONEOS")
        with self.assertRaises(ValueError):
            self.validate()

    def test_new_and_legacy_deployment_mismatches_are_rejected(self):
        for loads in (self.build_version("15.0"), self.legacy_version("13.0")):
            with self.subTest(loads=loads):
                self.loads = loads
                with self.assertRaisesRegex(ValueError, "minimum macOS differs"):
                    self.validate()

    def test_duplicate_deployment_commands_are_rejected(self):
        for second in (self.build_version(), self.legacy_version()):
            with self.subTest(second=second):
                self.loads = self.build_version() + second.replace("Load command 0", "Load command 1")
                with self.assertRaisesRegex(ValueError, "minimum macOS differs"):
                    self.validate()

    def test_malformed_deployment_or_declared_versions_are_rejected(self):
        for minimum in ("14..0", "14.0.0.1"):
            with self.subTest(deployment=minimum):
                self.loads = self.build_version(minimum)
                with self.assertRaises(ValueError):
                    self.validate()
        self.loads = self.build_version()
        for minimum in (None, 14, "", "14.0-beta", "14.0.0.1"):
            with self.subTest(declared=minimum), self.assertRaises(ValueError):
                self.validate(minimum)

    def test_missing_or_symlinked_binary_is_rejected_before_tools(self):
        self.binary.unlink()
        with patch.object(bundle_validator, "command") as command:
            with self.assertRaisesRegex(ValueError, "absent or a symlink"):
                bundle_validator.validate_binary_runtime(self.binary, "arm64", "14.0")
            command.assert_not_called()
        target = self.root / "other"
        target.write_bytes(b"synthetic target")
        self.binary.symlink_to(target)
        with patch.object(bundle_validator, "command") as command:
            with self.assertRaisesRegex(ValueError, "absent or a symlink"):
                bundle_validator.validate_binary_runtime(self.binary, "arm64", "14.0")
            command.assert_not_called()

    def test_system_tool_failure_is_propagated(self):
        failure = subprocess.CalledProcessError(1, ["/usr/bin/lipo", "-archs", str(self.binary)])
        with patch.object(bundle_validator, "command", side_effect=failure), self.assertRaises(subprocess.CalledProcessError):
            bundle_validator.validate_binary_runtime(self.binary, "arm64", "14.0")


class SignedEntitlementTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "NFDocumentDecoderXPC.xpc"
        self.path.mkdir()

    def extract(self, stdout=b"", stderr=b""):
        result = subprocess.CompletedProcess([], 0, stdout, stderr)
        with patch.object(bundle_validator.subprocess, "run", return_value=result) as run:
            value = bundle_validator.signed_entitlements(self.path)
        run.assert_called_once_with(["/usr/bin/codesign", "-d", "--entitlements", ":-", str(self.path)],
                                    capture_output=True, check=True)
        return value

    def test_entitlement_plist_is_extracted_from_either_stream_with_diagnostics(self):
        xml = plistlib.dumps({SANDBOX: True})
        for stdout, stderr in ((xml, b"Executable=synthetic\n"),
                               (b"", b"Executable=synthetic\n" + xml + b"warning: synthetic diagnostic\n")):
            with self.subTest(stream="stdout" if stdout else "stderr"):
                value = self.extract(stdout, stderr)
                self.assertEqual(value, {SANDBOX: True})
                bundle_validator.validate_xpc_entitlements(value)

    def test_absent_entitlements_cannot_satisfy_sandbox_requirement(self):
        for data in (b"", b"Executable=synthetic\n"):
            with self.subTest(data=data):
                value = self.extract(stderr=data)
                self.assertEqual(value, {})
                with self.assertRaises(ValueError):
                    bundle_validator.validate_xpc_entitlements(value)

    def test_truncated_entitlement_xml_cannot_satisfy_sandbox_requirement(self):
        for data in (b"<?xml version=\"1.0\"?><plist><dict>", b"</plist>"):
            with self.subTest(data=data), self.assertRaises(ValueError):
                bundle_validator.validate_xpc_entitlements(self.extract(stderr=data))

    def test_non_dictionary_entitlement_plist_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "malformed entitlements"):
            self.extract(stdout=plistlib.dumps([SANDBOX]))

    def test_malformed_entitlement_plist_is_rejected(self):
        malformed = b'<?xml version="1.0"?><plist version="1.0"><dict><key>sandbox</key><true></dict></plist>'
        with self.assertRaises((plistlib.InvalidFileException, ExpatError, ValueError)):
            self.extract(stdout=malformed)

    def test_extracted_integer_or_extra_grant_does_not_satisfy_xpc_policy(self):
        for value in ({SANDBOX: 1}, {SANDBOX: True, "com.apple.security.network.client": True}):
            with self.subTest(value=value):
                extracted = self.extract(stdout=plistlib.dumps(value))
                with self.assertRaises(ValueError):
                    bundle_validator.validate_xpc_entitlements(extracted)

    def test_codesign_extraction_failure_is_propagated(self):
        failure = subprocess.CalledProcessError(1, ["/usr/bin/codesign", "-d"])
        with patch.object(bundle_validator.subprocess, "run", side_effect=failure), self.assertRaises(subprocess.CalledProcessError):
            bundle_validator.signed_entitlements(self.path)


class _WorkerBundleFixture:
    """Only synthetic source/bundle bytes; no compiler or Apple tools are invoked."""
    @staticmethod
    def digest(data):
        return hashlib.sha256(data).hexdigest()

    def write(self, path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source_root = self.root / "Source"
        self.app = self.root / "NativeForensics.app"
        self.worker_binary = self.app / bundle_validator.WORKER_EXECUTABLE_PATH
        self.xpc_bundle = self.app / bundle_validator.XPC_BUNDLE_PATH
        self.broker_binary = self.app / bundle_validator.XPC_EXECUTABLE_PATH
        self.products = ("NativeForensics", "NFDocumentDecoder", "NFDocumentDecoderXPC", "NFDocumentDecoderWorker")
        for product in self.products:
            for name in source_provenance.required_inputs(product):
                self.write(self.source_root / name, b"synthetic required input")
            for directory in source_provenance.product_directories(product):
                extension = ".m" if directory.endswith("/NFDecoderIPC") else ".h" if directory.endswith("/CSQLite3") else ".swift"
                self.write(self.source_root / directory / ("Synthetic" + extension), b"synthetic target input")
        self.info = {"CFBundleExecutable": "NativeForensics", "CFBundlePackageType": "APPL",
            "CFBundleIdentifier": "io.github.pornmongkolnano.nativeforensics", "CFBundleShortVersionString": "0.7.0",
            "CFBundleVersion": "16", "LSMinimumSystemVersion": "14.0"}
        self.xpc_info = {"CFBundleExecutable": "NFDocumentDecoderXPC", "CFBundlePackageType": "XPC!",
            "CFBundleIdentifier": bundle_validator.XPC_IDENTIFIER, "CFBundleShortVersionString": "0.7.0",
            "CFBundleVersion": "16", "LSMinimumSystemVersion": "14.0", "XPCService": {"ServiceType": "Application"}}
        self.write(self.source_root / source_provenance.XPC_INFO_INPUT, plistlib.dumps(self.xpc_info))
        self.write(self.source_root / source_provenance.XPC_ENTITLEMENTS_INPUT, plistlib.dumps({SANDBOX: True}))
        self.write(self.source_root / source_provenance.WORKER_ENTITLEMENTS_INPUT, plistlib.dumps({SANDBOX: True, INHERIT: True}))
        self.write(self.app / "Contents/Info.plist", plistlib.dumps(self.info))
        self.write(self.xpc_bundle / "Contents/Info.plist", plistlib.dumps(self.xpc_info))
        self.write(self.app / "Contents/MacOS/NativeForensics", b"synthetic app")
        self.write(self.app / "Contents/Helpers/NFTSKEngine", b"synthetic engine")
        self.write(self.app / "Contents/Helpers/NFDocumentDecoder", b"synthetic CLI")
        self.write(self.broker_binary, b"synthetic broker")
        self.write(self.worker_binary, b"synthetic worker")
        self.write(self.app / "Contents/Resources/AppIcon.icns", (self.source_root / "Assets/AppIcon/AppIcon.icns").read_bytes())
        self.write(self.app / "Contents/Resources/EngineLicenses/synthetic/LICENSE", b"synthetic license")
        self.write(self.app / "Contents/Resources/EngineLicenses/THIRD_PARTY_NOTICES.md", b"synthetic notices")
        engine = {"schemaVersion": 1, "protocolVersion": 1, "engineVersion": "synthetic", "architecture": "arm64",
            "toolchain": {"minimumMacOS": "14.0"}, "engineSha256": self.digest(b"synthetic engine"),
            "licenses": "Contents/Resources/EngineLicenses/", "distributionArtifactsBundled": False,
            "licenseSha256": {"NativeEngine/licenses/synthetic/LICENSE": self.digest(b"synthetic license")},
            "noticesSha256": self.digest(b"synthetic notices")}
        self.write(self.app / "Contents/Resources/engine-manifest.json", json.dumps(engine).encode())
        policy = {"buildConfiguration": "release", "buildPathPolicy": source_provenance.BUILD_PATH_POLICY,
                  "packagingTransform": "strip-S-on-staged-release-copy"}
        self.app_receipt = {"schemaVersion": 1, "path": "Contents/MacOS/NativeForensics", "appVersion": "0.7.0", "appBuild": "16",
            "compiledBinarySha256": self.digest(b"synthetic app"), **policy,
            **source_provenance.make_source_receipt(self.source_root, "NativeForensics")}
        self.decoder_receipt = {"schemaVersion": 2, "protocolVersion": 1, "path": "Contents/Helpers/NFDocumentDecoder",
            "architecture": "arm64", "minimumMacOS": "14.0", "sha256": self.digest(b"synthetic CLI"),
            "compiledBinarySha256": self.digest(b"synthetic CLI"), **policy,
            **source_provenance.make_source_receipt(self.source_root, "NFDocumentDecoder")}
        self.worker_receipt = {"path": bundle_validator.WORKER_EXECUTABLE_PATH, "identifier": bundle_validator.WORKER_IDENTIFIER,
            "architecture": "arm64", "minimumMacOS": "14.0", "sha256": self.digest(b"synthetic worker"),
            "compiledBinarySha256": self.digest(b"synthetic worker"), "entitlements": {SANDBOX: True, INHERIT: True},
            "entitlementsSourceSha256": bundle_validator.sha256(self.source_root / source_provenance.WORKER_ENTITLEMENTS_INPUT),
            **policy, **source_provenance.make_source_receipt(self.source_root, "NFDocumentDecoderWorker")}
        self.xpc_receipt = {"schemaVersion": 2, "protocolVersion": 2, "path": bundle_validator.XPC_BUNDLE_PATH,
            "executablePath": bundle_validator.XPC_EXECUTABLE_PATH, "bundleIdentifier": bundle_validator.XPC_IDENTIFIER,
            "architecture": "arm64", "minimumMacOS": "14.0", "sha256": self.digest(b"synthetic broker"),
            "compiledBinarySha256": self.digest(b"synthetic broker"), "entitlements": {SANDBOX: True},
            "infoPlistSha256": bundle_validator.sha256(self.source_root / source_provenance.XPC_INFO_INPUT),
            "entitlementsSourceSha256": bundle_validator.sha256(self.source_root / source_provenance.XPC_ENTITLEMENTS_INPUT),
            **policy, **source_provenance.make_source_receipt(self.source_root, "NFDocumentDecoderXPC"), "worker": self.worker_receipt}
        self.write_receipts()

    def write_receipts(self):
        for name, value in (("app-source-manifest.json", self.app_receipt), ("document-decoder-manifest.json", self.decoder_receipt),
                            ("document-xpc-manifest.json", self.xpc_receipt)):
            self.write(self.app / "Contents/Resources" / name, json.dumps(value).encode())

    def metadata(self, source_root=None):
        return bundle_validator.validate_metadata(self.app, source_root=source_root)


class NestedWorkerMetadataTests(_WorkerBundleFixture, unittest.TestCase):
    def test_nested_worker_hash_graph_and_current_source_scope_are_recorded(self):
        result = self.metadata(self.source_root)
        self.assertEqual(result["workerDecoderSha256"], self.worker_receipt["sha256"])
        self.assertEqual(result["workerSourceGraphSha256"], self.worker_receipt["sourceGraphSha256"])
        self.assertFalse((self.worker_binary.parent / "Info.plist").exists())

    def test_missing_or_malformed_worker_receipt_is_rejected(self):
        for worker in (None, [], {}, {**self.worker_receipt, "path": "../worker"},
                       {**self.worker_receipt, "identifier": "other.worker"},
                       {**self.worker_receipt, "architecture": "x86_64"},
                       {**self.worker_receipt, "minimumMacOS": "15.0"},
                       {**self.worker_receipt, "sourceGraphSchemaVersion": 2},
                       {**self.worker_receipt, "product": "NFDocumentDecoder"},
                       {**self.worker_receipt, "compiledBinarySha256": None}):
            with self.subTest(worker=worker):
                self.xpc_receipt["worker"] = worker
                self.write_receipts()
                with self.assertRaises(ValueError):
                    self.metadata()

    def test_worker_declarations_cannot_gain_extra_or_non_boolean_entitlements(self):
        for value in ({SANDBOX: True}, {SANDBOX: True, INHERIT: 1},
                      {SANDBOX: True, INHERIT: True, "com.apple.security.network.client": True}):
            with self.subTest(value=value):
                self.worker_receipt["entitlements"] = value
                self.write_receipts()
                with self.assertRaises(ValueError):
                    self.metadata()

    def test_worker_binary_missing_changed_or_symlinked_is_rejected(self):
        self.worker_binary.write_bytes(b"changed worker")
        with self.assertRaisesRegex(ValueError, "worker differs"):
            self.metadata()
        self.worker_binary.unlink()
        with self.assertRaises(ValueError):
            self.metadata()
        self.worker_binary.symlink_to(self.broker_binary)
        with self.assertRaises(ValueError):
            self.metadata()

    def test_worker_is_checked_before_broker_binary(self):
        self.worker_binary.write_bytes(b"changed worker")
        self.broker_binary.write_bytes(b"changed broker")
        with self.assertRaisesRegex(ValueError, "worker differs"):
            self.metadata()

    def test_worker_entitlement_source_and_build_policy_bindings_are_required(self):
        original = copy.deepcopy(self.worker_receipt)
        for key, value in (("entitlementsSourceSha256", "f" * 64), ("buildConfiguration", "debug"),
                           ("buildPathPolicy", "unrecorded"), ("packagingTransform", "unstripped-local-debug-copy")):
            with self.subTest(key=key):
                self.worker_receipt = {**original, key: value}
                self.xpc_receipt["worker"] = self.worker_receipt
                self.write_receipts()
                with self.assertRaises(ValueError):
                    self.metadata()

    def test_offline_worker_graph_cannot_disagree_with_shared_inputs(self):
        name = next(name for name in self.worker_receipt["sourceSha256"] if name.startswith("Sources/ForensicsCore/"))
        self.worker_receipt["sourceSha256"][name] = "f" * 64
        self.worker_receipt["sourceGraphSha256"] = source_provenance.graph_digest("NFDocumentDecoderWorker", self.worker_receipt["sourceSha256"])
        self.write_receipts()
        with self.assertRaisesRegex(ValueError, "shared inputs"):
            self.metadata()

    def test_current_source_entitlement_spec_must_also_have_exact_boolean_grants(self):
        self.write(self.source_root / source_provenance.WORKER_ENTITLEMENTS_INPUT, plistlib.dumps({SANDBOX: True, INHERIT: 1}))
        for product, receipt in zip(self.products, (self.app_receipt, self.decoder_receipt, self.xpc_receipt, self.worker_receipt)):
            receipt.update(source_provenance.make_source_receipt(self.source_root, product))
        self.worker_receipt["entitlementsSourceSha256"] = bundle_validator.sha256(self.source_root / source_provenance.WORKER_ENTITLEMENTS_INPUT)
        self.write_receipts()
        with self.assertRaisesRegex(ValueError, "worker requires exactly"):
            self.metadata(self.source_root)

    def test_current_broker_requires_manifest_and_protocol_version_two(self):
        for field in ("schemaVersion", "protocolVersion"):
            with self.subTest(field=field):
                self.xpc_receipt[field] = 1
                self.write_receipts()
                with self.assertRaises(ValueError):
                    self.metadata()
                self.xpc_receipt[field] = 2

    def test_historical_zero_six_without_xpc_worker_remains_readable(self):
        self.info.update(CFBundleShortVersionString="0.6.0", CFBundleVersion="15")
        self.write(self.app / "Contents/Info.plist", plistlib.dumps(self.info))
        self.app_receipt.update(appVersion="0.6.0", appBuild="15")
        for product, receipt in (("NativeForensics", self.app_receipt), ("NFDocumentDecoder", self.decoder_receipt)):
            files = source_provenance.source_graph(self.source_root, product, 2)
            receipt.update(sourceGraphSchemaVersion=2, product=product, sourceSha256=files,
                           sourceGraphSha256=source_provenance.graph_digest(product, files))
        self.write_receipts()
        (self.app / "Contents/Resources/document-xpc-manifest.json").unlink()
        shutil.rmtree(self.app / "Contents/XPCServices")
        result = self.metadata()
        self.assertIsNone(result["workerDecoderSha256"])
        self.assertIsNone(result["workerSourceGraphSha256"])


class WorkerBundleRuntimeTests(_WorkerBundleFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.worker_architecture = "arm64"
        self.worker_minimum = "14.0"
        self.worker_dylib = "/usr/lib/libSystem.B.dylib"
        self.worker_identifier = bundle_validator.WORKER_IDENTIFIER
        self.worker_entitlements = {SANDBOX: True, INHERIT: True}
        self.broker_entitlements = {SANDBOX: True}
        self.worker_signature_failure = False
        self.worker_extraction_failure = False

    def tool_output(self, argv):
        path = Path(argv[-1])
        if argv[:2] == ["/usr/bin/lipo", "-archs"]:
            return self.worker_architecture if path == self.worker_binary else "arm64"
        if argv[:2] == ["/usr/bin/otool", "-L"]:
            dylib = self.worker_dylib if path == self.worker_binary else "/usr/lib/libSystem.B.dylib"
            return f"{path}:\n\t{dylib} (compatibility version 1.0.0, current version 1.0.0)\n"
        if argv[:2] == ["/usr/bin/otool", "-l"]:
            return BinaryRuntimeTests.build_version(self.worker_minimum if path == self.worker_binary else "14.0")
        if argv[:3] == ["/usr/bin/codesign", "--verify", "--strict"]:
            if path == self.worker_binary and self.worker_signature_failure:
                raise subprocess.CalledProcessError(1, argv)
            return ""
        if argv == ["/usr/bin/codesign", "--verify", "--deep", "--strict", str(self.app)]:
            return ""
        self.fail("Unexpected system tool call: " + repr(argv))

    def codesign_output(self, argv, **kwargs):
        path = Path(argv[-1])
        if argv[:2] == ["/usr/bin/codesign", "-dvvv"]:
            identifier = self.worker_identifier if path == self.worker_binary else bundle_validator.XPC_IDENTIFIER
            return subprocess.CompletedProcess(argv, 0, "", f"Identifier={identifier}\n" if identifier is not None else "")
        if argv[:4] == ["/usr/bin/codesign", "-d", "--entitlements", ":-"]:
            if path == self.worker_binary and self.worker_extraction_failure:
                raise subprocess.CalledProcessError(1, argv)
            value = self.worker_entitlements if path == self.worker_binary else self.broker_entitlements if path == self.xpc_bundle else {}
            return subprocess.CompletedProcess(argv, 0, plistlib.dumps(value), b"")
        self.fail("Unexpected direct subprocess call: " + repr(argv))

    def validate(self):
        result = self.metadata()
        with patch.object(bundle_validator, "validate_metadata", return_value=result), \
             patch.object(bundle_validator, "command", side_effect=self.tool_output) as commands, \
             patch.object(bundle_validator.subprocess, "run", side_effect=self.codesign_output) as signing:
            validated = bundle_validator.validate_bundle(self.app)
        return validated, commands.call_args_list, signing.call_args_list

    def test_worker_runtime_and_signature_are_validated_before_broker(self):
        result, commands, signing = self.validate()
        self.assertEqual(result["validation"], "passed-local-artifact-checks")
        argv = [call.args[0] for call in commands]
        self.assertLess(argv.index(["/usr/bin/lipo", "-archs", str(self.worker_binary)]),
                        argv.index(["/usr/bin/lipo", "-archs", str(self.broker_binary)]))
        self.assertLess(argv.index(["/usr/bin/codesign", "--verify", "--strict", str(self.worker_binary)]),
                        argv.index(["/usr/bin/codesign", "--verify", "--strict", str(self.xpc_bundle)]))
        signature_argv = [call.args[0] for call in signing]
        self.assertLess(signature_argv.index(["/usr/bin/codesign", "-dvvv", str(self.worker_binary)]),
                        signature_argv.index(["/usr/bin/codesign", "-dvvv", str(self.xpc_bundle)]))

    def test_worker_actual_architecture_deployment_and_runtime_closure_are_checked(self):
        for field, value in (("worker_architecture", "x86_64"), ("worker_architecture", "arm64 x86_64"),
                             ("worker_minimum", "15.0"), ("worker_dylib", "@rpath/private.dylib"),
                             ("worker_dylib", "/usr/lib/../../tmp/private.dylib")):
            with self.subTest(field=field, value=value):
                before = getattr(self, field)
                setattr(self, field, value)
                with self.assertRaises(ValueError):
                    self.validate()
                setattr(self, field, before)

    def test_worker_signed_identity_and_exact_entitlements_are_checked(self):
        for identifier in ("other.worker", None, bundle_validator.WORKER_IDENTIFIER + "\nIdentifier=other.worker"):
            with self.subTest(identifier=identifier):
                self.worker_identifier = identifier
                with self.assertRaisesRegex(ValueError, "Worker code signature identifier"):
                    self.validate()
        self.worker_identifier = bundle_validator.WORKER_IDENTIFIER
        for entitlements in ({}, {SANDBOX: True}, {SANDBOX: True, INHERIT: 1},
                             {SANDBOX: True, INHERIT: True, "com.apple.security.network.client": True}):
            with self.subTest(entitlements=entitlements):
                self.worker_entitlements = entitlements
                with self.assertRaises(ValueError):
                    self.validate()

    def test_worker_signature_and_entitlement_extraction_failures_propagate(self):
        self.worker_signature_failure = True
        with self.assertRaises(subprocess.CalledProcessError):
            self.validate()
        self.worker_signature_failure = False
        self.worker_extraction_failure = True
        with self.assertRaises(subprocess.CalledProcessError):
            self.validate()

    def test_broker_cannot_inherit_even_when_nested_worker_is_valid(self):
        self.broker_entitlements[INHERIT] = True
        with self.assertRaises(ValueError):
            self.validate()

    def test_worker_release_privacy_scan_is_enforced(self):
        result = self.metadata()
        self.worker_binary.write_bytes(b"/Users/synthetic-private/worker.o\0")
        with patch.object(bundle_validator, "validate_metadata", return_value=result), \
             patch.object(bundle_validator, "command", side_effect=self.tool_output), \
             patch.object(bundle_validator.subprocess, "run", side_effect=self.codesign_output), \
             self.assertRaisesRegex(ValueError, "privacy blocker"):
            bundle_validator.validate_bundle(self.app)


if __name__ == "__main__":
    unittest.main()

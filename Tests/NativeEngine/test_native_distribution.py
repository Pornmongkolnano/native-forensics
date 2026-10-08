"""Synthetic source-compliance, archive and installer publication regressions."""
from pathlib import Path
import hashlib
import io
import json
import os
import plistlib
import shutil
import shlex
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "script"))
import package_native_distribution as distribution
import package_app
import source_provenance
import build_native_engine as native_builder

ROOT = Path(__file__).resolve().parents[2]


class DistributionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.app = self.root / "dist/NativeForensics.app"
        self.spec = {"schemaVersion": 1, "engineVersion": "synthetic", "minimumMacOS": "14.0", "dependencies": [
            {"name": "example", "version": "1", "archive": "example.tar.gz", "sha256": self.digest(b"source archive"),
             "patches": [{"path": "NativeEngine/patches/example.patch", "sha256": self.digest(b"source patch")}]}]}
        self.create(".engine/downloads/example.tar.gz", b"source archive")
        self.create("NativeEngine/patches/example.patch", b"source patch")
        self.create("NativeEngine/licenses/example/LICENSE", b"source license")
        self.create("THIRD_PARTY_NOTICES.md", b"notices")
        self.create("NativeEngine/NFTSKEngine.cpp", b"int main() {}")
        self.create("NativeEngine/dependencies.json", json.dumps(self.spec).encode())
        self.create("script/build_native_engine.py", b"# original builder")
        for name in ("package_app.py", "validate_app_bundle.py", "build_and_run.sh", "package_native_distribution.py"):
            self.create("script/" + name, b"# synthetic recipe")
        self.create("script/source_provenance.py", b"# synthetic source graph recipe")
        self.create("script/native_install_publish.c", b"/* publisher */")
        self.create("script/templates/native_install.command", b"#!/bin/zsh\nexit 0\n", 0o755)
        self.create("Sources/ForensicsCore/Example.swift", b"// original core")
        self.create("Sources/NFDocumentDecoder/Example.swift", b"// original decoder")
        self.create("Sources/NFDocumentDecoding/Example.swift", b"// isolated format parser")
        self.create("Sources/NFDocumentDecoderXPC/Example.swift", b"// isolated XPC service")
        self.create("Sources/NFDocumentDecoderWorker/Example.swift", b"// fresh inheriting parser worker")
        self.create("Sources/NFDecoderIPC/NFDecoderIPC.m", b"// original ObjC protocol")
        self.create("Sources/NFDecoderIPC/include/NFDecoderIPC.h", b"// original ObjC protocol declaration")
        for name in source_provenance.XPC_INPUTS:
            self.create(name, (ROOT / name).read_bytes())
        self.create("Sources/NativeForensics/Example.swift", b"// original UI")
        self.create("Sources/CSQLite3/module.modulemap", b"// synthetic system module")
        self.create("Sources/CSQLite3/shim.h", b"// synthetic system header")
        self.create("Tests/ForensicsCoreTests/ExampleTests.swift", b"// synthetic regression")
        for name in ("AppIcon.png", "AppIcon.icns", "README.md"):
            self.create("Assets/AppIcon/" + name, b"original icon materials")
        self.create("Package.swift", b"// synthetic package")
        self.create("docs/DISTRIBUTION.md", b"Distribution instructions")
        self.create("docs/XPC-PACKAGING.md", b"XPC packaging contract")
        self.create("docs/XPC-DECODE.md", b"XPC runtime contract")
        self.create("local/real-case/secret.txt", b"NEVER PACKAGE THIS")
        self.create(".engine/dependencies-build.json", json.dumps({"fingerprint": "synthetic-dependencies"}).encode())
        relink = {}
        for name in distribution.RELINK_NAMES:
            relink[name] = self.digest(name.encode())
            self.create(".engine/relink/" + name, name.encode(), 0o755 if name.endswith(".command") else 0o644)
        patches = [{"path": "NativeEngine/patches/example.patch", "sha256": self.digest(b"source patch")}]
        self.receipt = {"schemaVersion": 1, "protocolVersion": 1, "engineVersion": "synthetic", "architecture": "arm64",
            "toolchain": {"minimumMacOS": "14.0"}, "dependencies": self.spec["dependencies"],
            "appliedPatches": patches, "patchDigest": self.digest(distribution.canonical(patches)),
            "engineSha256": self.digest(b"synthetic helper"), "relinkSha256": relink,
            "licenseSha256": {"NativeEngine/licenses/example/LICENSE": self.digest(b"source license")},
            "noticesSha256": self.digest(b"notices")}
        fingerprint = {"dependencyFingerprint": "synthetic-dependencies", "source": self.digest(b"int main() {}"),
            "script": self.digest(b"# original builder"), "spec": distribution.sha(self.root / "NativeEngine/dependencies.json"),
            "notices": self.digest(b"notices"), "licenses": self.receipt["licenseSha256"]}
        self.receipt["buildFingerprint"] = self.digest(distribution.canonical(fingerprint))
        self.create(".engine/manifest.json", json.dumps(self.receipt).encode())
        bundled = {**self.receipt, "licenses": "Contents/Resources/EngineLicenses/", "distributionArtifactsBundled": False}
        self.create_app("Contents/Resources/engine-manifest.json", json.dumps(bundled).encode())
        self.create_app("Contents/Helpers/NFTSKEngine", b"synthetic helper", 0o755)
        self.create_app("Contents/MacOS/NativeForensics", b"synthetic app", 0o755)
        self.create_app("Contents/Resources/AppIcon.icns", b"original icon materials")
        self.create_app("Contents/Resources/EngineLicenses/example/LICENSE", b"source license")
        self.create_app("Contents/Resources/EngineLicenses/THIRD_PARTY_NOTICES.md", b"notices")
        info = {"CFBundleExecutable": "NativeForensics", "CFBundlePackageType": "APPL",
            "CFBundleIdentifier": "io.github.pornmongkolnano.nativeforensics", "CFBundleShortVersionString": "0.7.0",
            "CFBundleVersion": "16", "LSMinimumSystemVersion": "14.0"}
        self.create_app("Contents/Info.plist", plistlib.dumps(info))
        self.create_app("Contents/Helpers/NFDocumentDecoder", b"synthetic decoder", 0o755)
        self.decoder = {"schemaVersion": 2, "protocolVersion": 1, "architecture": "arm64", "minimumMacOS": "14.0",
            "path": "Contents/Helpers/NFDocumentDecoder", "sha256": self.digest(b"synthetic decoder"),
            "compiledBinarySha256": self.digest(b"synthetic decoder"),
            "buildConfiguration": "release", "buildPathPolicy": source_provenance.BUILD_PATH_POLICY,
            "packagingTransform": "strip-S-on-staged-release-copy",
            **source_provenance.make_source_receipt(self.root, "NFDocumentDecoder")}
        self.create_app("Contents/Resources/document-decoder-manifest.json", json.dumps(self.decoder).encode())
        self.app_source = {"schemaVersion": 1, "path": "Contents/MacOS/NativeForensics", "appVersion": "0.7.0", "appBuild": "16",
            "compiledBinarySha256": self.digest(b"synthetic app"),
            "buildConfiguration": "release", "buildPathPolicy": source_provenance.BUILD_PATH_POLICY,
            "packagingTransform": "strip-S-on-staged-release-copy",
            **source_provenance.make_source_receipt(self.root, "NativeForensics")}
        self.create_app("Contents/Resources/app-source-manifest.json", json.dumps(self.app_source).encode())
        self.create_app(distribution.XPC_BUNDLE_PATH + "/Contents/Info.plist", (self.root / source_provenance.XPC_INFO_INPUT).read_bytes())
        self.create_app(distribution.XPC_BUNDLE_PATH + "/Contents/MacOS/NFDocumentDecoderXPC", b"synthetic XPC decoder", 0o755)
        self.create_app(distribution.WORKER_EXECUTABLE_PATH, b"synthetic parser worker", 0o755)
        self.worker = {"path": distribution.WORKER_EXECUTABLE_PATH, "identifier": package_app.WORKER_IDENTIFIER,
            "sha256": self.digest(b"synthetic parser worker"), "compiledBinarySha256": self.digest(b"synthetic parser worker"),
            "architecture": "arm64", "minimumMacOS": "14.0",
            "entitlementsSourceSha256": distribution.sha(self.root / source_provenance.WORKER_ENTITLEMENTS_INPUT),
            "entitlements": {"com.apple.security.app-sandbox": True, "com.apple.security.inherit": True},
            "buildConfiguration": "release", "buildPathPolicy": source_provenance.BUILD_PATH_POLICY,
            "packagingTransform": "strip-S-on-staged-release-copy",
            **source_provenance.make_source_receipt(self.root, "NFDocumentDecoderWorker")}
        self.xpc = {"schemaVersion": 2, "protocolVersion": 2, "architecture": "arm64", "minimumMacOS": "14.0",
            "path": distribution.XPC_BUNDLE_PATH, "executablePath": distribution.XPC_BUNDLE_PATH + "/Contents/MacOS/NFDocumentDecoderXPC",
            "bundleIdentifier": "org.nativeforensics.NFDocumentDecoderXPC", "sha256": self.digest(b"synthetic XPC decoder"),
            "compiledBinarySha256": self.digest(b"synthetic XPC decoder"),
            "infoPlistSha256": distribution.sha(self.root / source_provenance.XPC_INFO_INPUT),
            "entitlementsSourceSha256": distribution.sha(self.root / source_provenance.XPC_ENTITLEMENTS_INPUT),
            "entitlements": {"com.apple.security.app-sandbox": True}, "buildConfiguration": "release",
            "buildPathPolicy": source_provenance.BUILD_PATH_POLICY, "packagingTransform": "strip-S-on-staged-release-copy",
            **source_provenance.make_source_receipt(self.root, "NFDocumentDecoderXPC"), "worker": self.worker}
        self.create_app("Contents/Resources/document-xpc-manifest.json", json.dumps(self.xpc).encode())
        self.support = self.create("support", b"synthetic publisher", 0o755)

    @staticmethod
    def digest(data):
        return hashlib.sha256(data).hexdigest()

    def create(self, name, data, mode=0o644):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)
        return path

    def create_app(self, name, data, mode=0o644):
        return self.create("dist/NativeForensics.app/" + name, data, mode)

    def stage(self):
        stage = self.root / "stage"
        stage.mkdir()
        materials = distribution.verify_materials(self.root, self.app)
        materials["installSupportBuildReceipt"] = self.support_receipt()
        manifest = distribution.stage_distribution(self.root, self.app, stage, self.support,
            {"mode": "development", "notarization": "not-verified"}, materials)
        return stage, manifest

    def support_receipt(self):
        return {"schemaVersion": 1, "product": "InstallSupport", "sourcePath": distribution.SUPPORT_SOURCE,
            "sourceSha256": distribution.sha(self.root / distribution.SUPPORT_SOURCE),
            "builderSourceSha256": distribution.sha(self.root / distribution.SUPPORT_BUILDER),
            "architecture": "arm64", "minimumMacOS": "14.0", "buildConfiguration": "release",
            "compileRecipe": distribution.support_compile_recipe("arm64", "14.0"),
            "compilerInput": "captured-complete-source-bytes-on-stdin",
            "compiledBinarySha256": distribution.sha(self.support), "signedBinarySha256": distribution.sha(self.support),
            "signing": "ad-hoc", "hardenedRuntime": False,
            "scope": "captured source compiled before signing; raw and signed output hashes recorded"}

    @staticmethod
    def reinventory(stage, manifest):
        manifest["files"] = {name: facts for name, facts in distribution.inventory(stage).items()
                             if name not in {"SHA256SUMS", "distribution-manifest.json"}}
        (stage / "distribution-manifest.json").write_text(json.dumps(manifest))
        (stage / "SHA256SUMS").write_text("".join(f'{facts["sha256"]}  {name}\n'
            for name, facts in distribution.inventory(stage).items() if name != "SHA256SUMS"))

    def add_native_header_receipt(self):
        self.spec["engineVersion"] = "0.1.5-tsk4.15.0"
        self.spec["protocolVersion"] = 1
        self.create("NativeEngine/dependencies.json", json.dumps(self.spec).encode())
        for name in distribution.NATIVE_HEADERS:
            self.create(name, ("// public original header " + name).encode())
        self.receipt.update({"engineVersion": self.spec["engineVersion"],
            "nativeHeaderSha256": {name: distribution.sha(self.root / name) for name in distribution.NATIVE_HEADERS},
            "compiledInputSha256": {name: distribution.sha(self.root / name) for name in distribution.NATIVE_HEADERS | {"NativeEngine/NFTSKEngine.cpp"}},
            "buildInputCapture": distribution.NATIVE_CAPTURE_SCOPE})
        fingerprint, _ = distribution.engine_input_fingerprint(self.root, self.receipt, "synthetic-dependencies", self.receipt["licenseSha256"])
        self.receipt["buildFingerprint"] = fingerprint
        self.create(".engine/manifest.json", json.dumps(self.receipt).encode())
        self.create_app("Contents/Resources/engine-manifest.json", json.dumps({**self.receipt,
            "licenses": "Contents/Resources/EngineLicenses/", "distributionArtifactsBundled": False}).encode())

    def test_complete_source_static_relink_inventory_and_no_local_data(self):
        stage, manifest = self.stage()
        self.assertEqual(distribution.validate_distribution(stage), manifest)
        names = set(manifest["files"])
        self.assertIn("Source/Dependencies/example.tar.gz", names)
        self.assertIn("Relink/NFTSKEngine.o", names)
        self.assertIn("Relink/libewf.a", names)
        self.assertIn("Source/NativeEngine/patches/example.patch", names)
        self.assertIn("Source/script/build_native_engine.py", names)
        self.assertIn("Source/NativeEngine/licenses/example/LICENSE", names)
        self.assertIn("Source/Sources/CSQLite3/module.modulemap", names)
        self.assertIn("Source/Sources/NFDecoderIPC/NFDecoderIPC.m", names)
        self.assertIn("Source/Sources/NFDocumentDecoding/Example.swift", names)
        self.assertIn("Source/Sources/NFDocumentDecoderXPC/Example.swift", names)
        self.assertIn("Source/Sources/NFDocumentDecoderWorker/Example.swift", names)
        self.assertIn("Source/" + source_provenance.XPC_ENTITLEMENTS_INPUT, names)
        self.assertIn("Source/" + source_provenance.WORKER_ENTITLEMENTS_INPUT, names)
        self.assertIn("Source/script/package_native_distribution.py", names)
        self.assertIn("Source/Repack.command", names)
        self.assertIn(distribution.SUPPORT_RECEIPT_NAME, names)
        self.assertFalse(any(name.startswith(("local/", ".engine/")) for name in names))
        self.assertNotIn(str(self.root), (stage / "Relink/link-command.json").read_text())
        self.assertFalse(any(b"NEVER PACKAGE THIS" in path.read_bytes() for path in stage.rglob("*") if path.is_file()))

    def test_missing_changed_source_patch_object_and_recipe_rejected(self):
        for name in (".engine/downloads/example.tar.gz", "NativeEngine/patches/example.patch",
                     ".engine/relink/NFTSKEngine.o", "script/build_native_engine.py"):
            with self.subTest(name=name):
                path = self.root / name
                original = path.read_bytes()
                path.write_bytes(b"changed")
                with self.assertRaises(ValueError):
                    distribution.verify_materials(self.root, self.app)
                path.write_bytes(original)

    def test_dependency_and_app_receipt_disagreement_rejected(self):
        self.receipt["dependencies"] = []
        (self.root / ".engine/manifest.json").write_text(json.dumps(self.receipt))
        with self.assertRaises(ValueError):
            distribution.verify_materials(self.root, self.app)

    def test_changed_decoder_source_rejected_before_archive(self):
        self.create("Sources/ForensicsCore/Example.swift", b"changed source")
        with self.assertRaisesRegex(ValueError, "source graph changed"):
            self.stage()

    def test_symlink_material_directory_and_unsafe_archive_path_rejected(self):
        path = self.root / ".engine/downloads/example.tar.gz"
        path.unlink()
        path.symlink_to(self.root / "THIRD_PARTY_NOTICES.md")
        with self.assertRaises(ValueError):
            distribution.verify_materials(self.root, self.app)
        for name in ("../outside", "/absolute", "bad\nname", "a//b", "a/./b", "a space"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                distribution.relative_name(name)

    def test_complete_manifest_detects_missing_extra_and_changed_files(self):
        stage, _ = self.stage()
        path = stage / "README.md"
        original = path.read_bytes()
        path.write_bytes(b"different")
        with self.assertRaises(ValueError):
            distribution.validate_distribution(stage)
        path.write_bytes(original)
        (stage / "extra.txt").write_bytes(b"unlisted")
        with self.assertRaises(ValueError):
            distribution.validate_distribution(stage)
        (stage / "extra.txt").unlink()
        path.unlink()
        with self.assertRaises(ValueError):
            distribution.validate_distribution(stage)

    def test_deterministic_zip_and_executable_permissions(self):
        stage, _ = self.stage()
        one, two = self.root / "one.zip", self.root / "two.zip"
        first = distribution.deterministic_zip(stage, one)
        for path in stage.rglob("*"):
            os.utime(path, (1700000000, 1700000000))
        second = distribution.deterministic_zip(stage, two)
        self.assertEqual(first, second)
        with zipfile.ZipFile(one) as archive:
            self.assertEqual(archive.namelist(), sorted(archive.namelist()))
            self.assertEqual((archive.getinfo("Install.command").external_attr >> 16) & 0o777, 0o755)
            self.assertEqual((archive.getinfo("README.md").external_attr >> 16) & 0o777, 0o644)
            self.assertTrue(all(item.date_time == distribution.FIXED_TIME for item in archive.infolist()))

    def test_output_preserved_and_input_overlap_rejected(self):
        stage, _ = self.stage()
        output = self.create("existing.zip", b"previous output")
        with self.assertRaises(ValueError):
            distribution.deterministic_zip(stage, output)
        self.assertEqual(output.read_bytes(), b"previous output")
        with self.assertRaises(ValueError):
            distribution.deterministic_zip(stage, stage / "overlap.zip")

    @staticmethod
    def filesystem_identity(path):
        identity = path.stat(follow_symlinks=False)
        return identity.st_dev, identity.st_ino

    def package_fixture(self, output):
        # Filesystem/source/ZIP validation is real; synthetic bytes cannot be
        # assessed as native executables or receive a measured Apple trust claim.
        receipt = self.create("support-receipt.json", json.dumps(self.support_receipt()).encode())
        trust = {"mode": "development", "notarization": "not-verified"}
        with patch.object(distribution, "validate_bundle", return_value={}), \
             patch.object(distribution, "validate_binary_runtime"), \
             patch.object(distribution, "signing_details", return_value="Signature=adhoc\nflags=0x2(adhoc)"), \
             patch.object(distribution, "verify_trust", return_value=trust), \
             patch.object(distribution.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)):
            return distribution.package(self.app, output, install_support=self.support,
                                        install_support_receipt=receipt, root=self.root)

    def test_package_failure_retains_substituted_work_or_output_ancestor(self):
        actual_stage = distribution.stage_distribution
        for variant in ("work", "ancestor"):
            with self.subTest(variant=variant):
                parent = self.root / ("package-output-" + variant)
                parent.mkdir()
                output = parent / "package.zip"
                failure = OSError("owned distribution staging fault")
                observed = {}
                def substitute_after_staging(root, app, stage, support, trust, materials):
                    actual_stage(root, app, stage, support, trust, materials)
                    work = stage.parent
                    observed.update(work=work, inventory=distribution.inventory(work),
                                    originalIdentity=self.filesystem_identity(work))
                    if variant == "work":
                        displaced = self.root / "displaced-distribution-work"
                        work.rename(displaced)
                    else:
                        displaced_parent = self.root / "displaced-package-output"
                        parent.rename(displaced_parent)
                        parent.mkdir()
                        displaced = displaced_parent / work.name
                    work.mkdir()
                    canary = work / "foreign-canary"
                    canary.write_bytes(b"foreign distribution work")
                    observed.update(displaced=displaced, canary=canary,
                                    canaryIdentity=self.filesystem_identity(canary))
                    raise failure
                diagnostics = io.StringIO()
                with patch.object(distribution, "stage_distribution", side_effect=substitute_after_staging), \
                     patch.object(distribution.sys, "stderr", diagnostics):
                    with self.assertRaises(OSError) as caught:
                        self.package_fixture(output)
                self.assertIs(caught.exception, failure)
                self.assertFalse(output.exists())
                self.assertTrue(observed["work"].name.endswith(".noindex"))
                self.assertEqual(self.filesystem_identity(observed["displaced"]), observed["originalIdentity"])
                self.assertEqual(distribution.inventory(observed["displaced"]), observed["inventory"])
                self.assertEqual(self.filesystem_identity(observed["canary"]), observed["canaryIdentity"])
                self.assertEqual(observed["canary"].read_bytes(), b"foreign distribution work")
                self.assertIn("Distribution work directory path candidate for manual review (no automatic cleanup): " + str(observed["work"]), diagnostics.getvalue())

    def test_zip_publication_failure_retains_substituted_temporary_or_output_ancestor(self):
        stage = self.root / "zip-input"
        stage.mkdir()
        (stage / "marker").write_bytes(b"owned ZIP payload")
        for variant in ("temporary", "ancestor"):
            with self.subTest(variant=variant):
                parent = self.root / ("zip-output-" + variant)
                parent.mkdir()
                output = parent / "package.zip"
                failure = OSError("owned exclusive ZIP publication fault")
                observed = {}
                def substitute_and_refuse(temporary, target):
                    self.assertEqual(target, output)
                    observed.update(temporary=temporary, originalBytes=temporary.read_bytes(),
                                    originalIdentity=self.filesystem_identity(temporary))
                    if variant == "temporary":
                        displaced = self.root / "displaced-temporary-archive"
                        temporary.rename(displaced)
                    else:
                        displaced_parent = self.root / "displaced-zip-output"
                        parent.rename(displaced_parent)
                        parent.mkdir()
                        displaced = displaced_parent / temporary.name
                    temporary.write_bytes(b"foreign temporary ZIP canary")
                    observed.update(displaced=displaced, canaryIdentity=self.filesystem_identity(temporary))
                    raise failure
                diagnostics = io.StringIO()
                with patch.object(distribution.os, "link", side_effect=substitute_and_refuse), \
                     patch.object(distribution.sys, "stderr", diagnostics):
                    with self.assertRaises(OSError) as caught:
                        distribution.deterministic_zip(stage, output)
                self.assertIs(caught.exception, failure)
                self.assertFalse(output.exists())
                self.assertEqual(self.filesystem_identity(observed["displaced"]), observed["originalIdentity"])
                self.assertEqual(observed["displaced"].read_bytes(), observed["originalBytes"])
                with zipfile.ZipFile(observed["displaced"]) as archive:
                    self.assertEqual(archive.read("marker"), b"owned ZIP payload")
                self.assertEqual(self.filesystem_identity(observed["temporary"]), observed["canaryIdentity"])
                self.assertEqual(observed["temporary"].read_bytes(), b"foreign temporary ZIP canary")
                self.assertIn("Temporary ZIP path candidate for manual review (no automatic cleanup): " + str(observed["temporary"]), diagnostics.getvalue())

    def test_package_success_retains_validated_work_and_original_zip_hardlink(self):
        parent = self.root / "successful-output"
        parent.mkdir()
        output = parent / "package.zip"
        before = distribution.inventory(self.app)
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(distribution.sys, "stdout", stdout), patch.object(distribution.sys, "stderr", stderr):
            result = self.package_fixture(output)
        work = list(parent.glob(".nativeforensics-distribution-*"))
        archives = list(parent.glob(".nativeforensics-zip-*"))
        self.assertEqual(len(work), 1)
        self.assertTrue(work[0].name.endswith(".noindex"))
        manifest = distribution.validate_distribution(work[0] / "package")
        self.assertEqual(result["fileCount"], len(manifest["files"]))
        self.assertEqual(result["zipSha256"], distribution.sha(output))
        self.assertEqual(distribution.inventory(self.app), before)
        self.assertEqual(len(archives), 1)
        self.assertEqual(self.filesystem_identity(archives[0]), self.filesystem_identity(output))
        self.assertEqual(archives[0].stat().st_nlink, 2)
        self.assertEqual(output.stat().st_nlink, 2)
        self.assertEqual(archives[0].read_bytes(), output.read_bytes())
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn(str(work[0]), stderr.getvalue())
        self.assertIn(str(archives[0]), stderr.getvalue())

    def test_diagnostic_failures_preserve_original_package_and_zip_errors(self):
        class BrokenDiagnosticStream:
            def write(self, text):
                raise BrokenPipeError("owned diagnostic pipe closed")
        closed = io.StringIO()
        closed.close()
        stage = self.root / "diagnostic-zip-input"
        stage.mkdir()
        (stage / "marker").write_bytes(b"owned diagnostic ZIP payload")
        for ordinal, stream in enumerate((closed, BrokenDiagnosticStream())):
            for operation in ("package", "zip"):
                with self.subTest(stream=type(stream).__name__, operation=operation):
                    parent = self.root / f"diagnostic-output-{ordinal}-{operation}"
                    parent.mkdir()
                    output = parent / "package.zip"
                    failure = OSError("original owned " + operation + " failure")
                    with patch.object(distribution.sys, "stderr", stream):
                        with self.assertRaises(OSError) as caught:
                            if operation == "package":
                                with patch.object(distribution, "verify_install_support_receipt", side_effect=failure):
                                    self.package_fixture(output)
                            else:
                                with patch.object(distribution.os, "link", side_effect=failure):
                                    distribution.deterministic_zip(stage, output)
                    self.assertIs(caught.exception, failure)
                    self.assertFalse(output.exists())
                    if operation == "package":
                        retained = list(parent.glob(".nativeforensics-distribution-*"))
                        self.assertEqual(len(retained), 1)
                        self.assertTrue(retained[0].name.endswith(".noindex"))
                        self.assertEqual(list(retained[0].iterdir()), [])
                    else:
                        retained = list(parent.glob(".nativeforensics-zip-*"))
                        self.assertEqual(len(retained), 1)
                        with zipfile.ZipFile(retained[0]) as archive:
                            self.assertEqual(archive.read("marker"), b"owned diagnostic ZIP payload")

    def test_release_cannot_claim_ad_hoc_trust(self):
        command_result = subprocess.CompletedProcess([], 0, "", "Signature=adhoc\nTeamIdentifier=not set\n")
        with patch.object(distribution.subprocess, "run", return_value=command_result):
            self.assertEqual(distribution.verify_trust(self.app, self.support, "development")["notarization"], "not-verified")
            with self.assertRaisesRegex(ValueError, "Developer ID"):
                distribution.verify_trust(self.app, self.support, "release")

    def test_full_app_sqlite_package_recipe_and_asset_changes_rejected(self):
        for name in ("Sources/NativeForensics/Example.swift", "Sources/CSQLite3/shim.h",
                     "Sources/CSQLite3/module.modulemap", "Package.swift", "script/package_app.py",
                     "script/build_and_run.sh", "Assets/AppIcon/AppIcon.icns", "Assets/AppIcon/AppIcon.png"):
            with self.subTest(name=name):
                path = self.root / name
                original = path.read_bytes()
                path.write_bytes(b"changed graph input")
                with self.assertRaisesRegex(ValueError, "source graph changed"):
                    distribution.verify_materials(self.root, self.app)
                path.write_bytes(original)

    def test_added_missing_relevant_source_graph_inputs_rejected(self):
        extra = self.create("Sources/ForensicsCore/Extra.swift", b"// unexpected compiled source")
        with self.assertRaisesRegex(ValueError, "extra inputs"):
            distribution.verify_materials(self.root, self.app)
        extra.unlink()
        path = self.root / "Sources/NativeForensics/Example.swift"
        path.unlink()
        with self.assertRaises(ValueError):
            distribution.verify_materials(self.root, self.app)

    def test_receipt_missing_required_graph_cannot_use_legacy_bypass(self):
        path = self.app / "Contents/Resources/app-source-manifest.json"
        changed = {**self.app_source, "sourceSha256": {key: value for key, value in self.app_source["sourceSha256"].items()
                                                      if key != "Sources/CSQLite3/shim.h"}}
        changed["sourceGraphSha256"] = source_provenance.graph_digest("NativeForensics", changed["sourceSha256"])
        path.write_text(json.dumps(changed))
        with self.assertRaisesRegex(ValueError, "missing required"):
            distribution.validate_metadata(self.app, allow_legacy_development=True)

    def test_shared_decoder_app_graph_disagreement_rejected_without_source_root(self):
        path = self.app / "Contents/Resources/app-source-manifest.json"
        files = {**self.app_source["sourceSha256"], "Package.swift": "a" * 64}
        path.write_text(json.dumps({**self.app_source, "sourceSha256": files,
                                   "sourceGraphSha256": source_provenance.graph_digest("NativeForensics", files)}))
        with self.assertRaisesRegex(ValueError, "disagree"):
            distribution.validate_metadata(self.app)

    def test_precompile_snapshot_rejects_changed_source_and_postcompile_binary(self):
        binaries = self.root / "compiled"
        binaries.mkdir()
        for product in source_provenance.PRODUCT_DIRECTORIES:
            (binaries / product).write_bytes(product.encode())
        snapshot = source_provenance.snapshot_products(self.root)
        receipt = source_provenance.seal_build(self.root, binaries, snapshot)
        source_provenance.verify_build_receipt(self.root, binaries, receipt)
        (binaries / "NativeForensics").write_bytes(b"changed compiled binary")
        with self.assertRaisesRegex(ValueError, "Compiled binary differs"):
            source_provenance.verify_build_receipt(self.root, binaries, receipt)
        (binaries / "NativeForensics").write_bytes(b"NativeForensics")
        (self.root / "Sources/CSQLite3/shim.h").write_bytes(b"changed during compilation")
        with self.assertRaisesRegex(ValueError, "source graph changed"):
            source_provenance.seal_build(self.root, binaries, snapshot)

    def test_malformed_absolute_and_digest_graph_receipts_rejected(self):
        for invalid in ("/Users/example/secret", "../escape", "Sources/NativeForensics/../secret.swift"):
            files = {**self.app_source["sourceSha256"], invalid: "a" * 64}
            changed = {**self.app_source, "sourceSha256": files,
                       "sourceGraphSha256": source_provenance.graph_digest("NativeForensics", files)}
            with self.subTest(path=invalid), self.assertRaises(ValueError):
                source_provenance.validate_source_receipt(changed, "NativeForensics")
        with self.assertRaisesRegex(ValueError, "digest differs"):
            source_provenance.validate_source_receipt({**self.app_source, "sourceGraphSha256": "f" * 64}, "NativeForensics")

    def test_engine_source_edit_after_preflight_cannot_be_copied(self):
        materials = distribution.verify_materials(self.root, self.app)
        materials["installSupportBuildReceipt"] = self.support_receipt()
        (self.root / "NativeEngine/NFTSKEngine.cpp").write_bytes(b"edited after preflight")
        stage = self.root / "stage"
        stage.mkdir()
        with self.assertRaisesRegex(ValueError, "hash differs"):
            distribution.stage_distribution(self.root, self.app, stage, self.support, {"mode": "development"}, materials)

    def test_installer_source_edit_after_build_pin_cannot_be_copied(self):
        materials = distribution.verify_materials(self.root, self.app)
        materials["installSupportBuildReceipt"] = self.support_receipt()
        (self.root / "script/native_install_publish.c").write_bytes(b"edited after publisher build")
        stage = self.root / "stage"
        stage.mkdir()
        with self.assertRaisesRegex(ValueError, "source/build recipe differs"):
            distribution.stage_distribution(self.root, self.app, stage, self.support, {"mode": "development"}, materials)

    def test_extra_dependency_license_input_cannot_be_omitted(self):
        self.create("NativeEngine/licenses/example/EXTRA-LICENSE", b"additional required notice")
        with self.assertRaisesRegex(ValueError, "extra inputs"):
            distribution.verify_materials(self.root, self.app)

    def test_private_path_byte_scan_catches_linker_strings_across_chunks(self):
        path = self.create("raw-binary", b"x" * (1024 * 1024 - 3) + b"/Users/synthetic-build/Private.o\0")
        with self.assertRaisesRegex(ValueError, "privacy blocker"):
            source_provenance.check_binary_privacy(path)
        for marker in (b"/private/var/folders/synthetic/object.o\0", b"/var/folders/synthetic/object.o\0"):
            path.write_bytes(marker)
            with self.assertRaises(ValueError):
                source_provenance.check_binary_privacy(path)
        path.write_bytes(b"/NativeForensicsBuild/Sources/Example.swift\0")
        source_provenance.check_binary_privacy(path)

    def test_debug_bundle_cannot_become_distribution(self):
        for filename, receipt in (("app-source-manifest.json", self.app_source), ("document-decoder-manifest.json", self.decoder),
                                  ("document-xpc-manifest.json", self.xpc)):
            changed = {**receipt, "buildConfiguration": "debug", "packagingTransform": "unstripped-local-debug-copy"}
            if "worker" in receipt:
                changed["worker"] = {**receipt["worker"], "buildConfiguration": "debug", "packagingTransform": "unstripped-local-debug-copy"}
            (self.app / "Contents/Resources" / filename).write_text(json.dumps(changed))
        with self.assertRaisesRegex(ValueError, "optimized release configuration"):
            distribution.verify_materials(self.root, self.app)

    def test_xpc_bundle_and_receipt_are_required_for_current_app(self):
        receipt = self.app / "Contents/Resources/document-xpc-manifest.json"
        original = receipt.read_bytes()
        receipt.unlink()
        with self.assertRaises(ValueError):
            distribution.validate_metadata(self.app)
        receipt.write_bytes(original)
        shutil.rmtree(self.app / distribution.XPC_BUNDLE_PATH)
        with self.assertRaises(ValueError):
            distribution.validate_metadata(self.app)

    def test_xpc_identity_metadata_and_executable_tampering_are_rejected(self):
        info_path = self.app / distribution.XPC_BUNDLE_PATH / "Contents/Info.plist"
        original = info_path.read_bytes()
        info = plistlib.loads(original)
        for key, value in (("CFBundleIdentifier", "org.example.other"), ("CFBundlePackageType", "APPL"),
                           ("CFBundleExecutable", "OtherDecoder"), ("LSMinimumSystemVersion", "15.0"),
                           ("CFBundleName", "changed signed metadata")):
            with self.subTest(key=key):
                info_path.write_bytes(plistlib.dumps({**info, key: value}))
                with self.assertRaises(ValueError):
                    distribution.validate_metadata(self.app)
                info_path.write_bytes(original)
        binary = self.app / distribution.XPC_BUNDLE_PATH / "Contents/MacOS/NFDocumentDecoderXPC"
        binary.write_bytes(b"changed service")
        with self.assertRaisesRegex(ValueError, "XPC decoder differs"):
            distribution.validate_metadata(self.app)

    def test_xpc_graph_requires_every_target_and_binds_shared_inputs_offline(self):
        for prefix in ("Sources/ForensicsCore/", "Sources/NFDocumentDecoderXPC/", "Sources/NFDecoderIPC/"):
            files = {key: value for key, value in self.xpc["sourceSha256"].items() if not key.startswith(prefix)}
            changed = {**self.xpc, "sourceSha256": files,
                       "sourceGraphSha256": source_provenance.graph_digest("NFDocumentDecoderXPC", files)}
            with self.subTest(prefix=prefix), self.assertRaises(ValueError):
                source_provenance.validate_source_receipt(changed, "NFDocumentDecoderXPC")
        files = {**self.xpc["sourceSha256"], "Sources/ForensicsCore/Example.swift": "a" * 64}
        changed = {**self.xpc, "sourceSha256": files,
                   "sourceGraphSha256": source_provenance.graph_digest("NFDocumentDecoderXPC", files)}
        (self.app / "Contents/Resources/document-xpc-manifest.json").write_text(json.dumps(changed))
        with self.assertRaisesRegex(ValueError, "graphs disagree"):
            distribution.validate_metadata(self.app)

    def test_worker_receipt_path_identity_policy_and_raw_binding_cannot_be_forged(self):
        path = self.app / "Contents/Resources/document-xpc-manifest.json"
        changes = (("path", "Contents/Helpers/OtherWorker"), ("identifier", "org.example.other"),
                   ("architecture", "x86_64"), ("minimumMacOS", "15.0"), ("compiledBinarySha256", "bad"),
                   ("buildConfiguration", "debug"), ("packagingTransform", "unknown"),
                   ("entitlementsSourceSha256", "f" * 64),
                   ("entitlements", {"com.apple.security.app-sandbox": True, "com.apple.security.inherit": 1}),
                   ("entitlements", {**self.worker["entitlements"], "com.apple.security.network.client": True}))
        for key, value in changes:
            with self.subTest(key=key, value=value):
                path.write_text(json.dumps({**self.xpc, "worker": {**self.worker, key: value}}))
                with self.assertRaises(ValueError):
                    distribution.validate_metadata(self.app)
        path.write_text(json.dumps(self.xpc))
        self.assertEqual(distribution.validate_metadata(self.app)["workerDecoderSha256"], self.worker["sha256"])

    def test_worker_executable_and_nested_receipt_are_mandatory_and_hash_bound(self):
        path = self.app / "Contents/Resources/document-xpc-manifest.json"
        path.write_text(json.dumps({key: value for key, value in self.xpc.items() if key != "worker"}))
        with self.assertRaises(ValueError):
            distribution.validate_metadata(self.app)
        path.write_text(json.dumps(self.xpc))
        binary = self.app / distribution.WORKER_EXECUTABLE_PATH
        original = binary.read_bytes()
        binary.unlink()
        with self.assertRaises(ValueError):
            distribution.validate_metadata(self.app)
        binary.write_bytes(b"changed parser worker")
        with self.assertRaises(ValueError):
            distribution.validate_metadata(self.app)
        binary.write_bytes(original)
        self.assertEqual(distribution.validate_metadata(self.app)["workerSourceGraphSha256"], self.worker["sourceGraphSha256"])

    def test_worker_graph_requires_parser_target_and_its_entitlement_specification(self):
        for prefix in ("Sources/NFDocumentDecoderWorker/", "Sources/NFDocumentDecoding/", "Sources/NFDecoderIPC/",
                       source_provenance.WORKER_ENTITLEMENTS_INPUT):
            with self.subTest(prefix=prefix):
                files = {name: digest for name, digest in self.worker["sourceSha256"].items() if not name.startswith(prefix)}
                changed = {**self.worker, "sourceSha256": files,
                    "sourceGraphSha256": source_provenance.graph_digest("NFDocumentDecoderWorker", files)}
                with self.assertRaises(ValueError):
                    source_provenance.validate_source_receipt(changed, "NFDocumentDecoderWorker")

    def test_worker_signature_is_required_by_release_trust_team_and_runtime_gate(self):
        trusted = "Authority=Developer ID Application: Synthetic\nTeamIdentifier=TEAM123\nflags=0x10000(runtime)\n"
        for worker_details in ("Signature=adhoc\nTeamIdentifier=not set\n", trusted.replace("TEAM123", "OTHERTEAM"),
                               trusted.replace("flags=0x10000(runtime)", "flags=0x0(none)")):
            def result(args, **kwargs):
                details = worker_details if args[-1].endswith(distribution.WORKER_EXECUTABLE_PATH) else trusted
                return subprocess.CompletedProcess(args, 0, "", details)
            with self.subTest(worker_details=worker_details), patch.object(distribution.subprocess, "run", side_effect=result) as calls:
                with self.assertRaises(ValueError):
                    distribution.verify_trust(self.app, self.support, "release")
                self.assertTrue(any(call.args[0][-1].endswith(distribution.WORKER_EXECUTABLE_PATH) for call in calls.call_args_list))

    def test_historical_graph_schemas_remain_inspectable_without_worker_inputs(self):
        for schema in (1, 2):
            files = source_provenance.source_graph(self.root, "NativeForensics", schema)
            receipt = {"sourceGraphSchemaVersion": schema, "product": "NativeForensics", "sourceSha256": files,
                "sourceGraphSha256": source_provenance.graph_digest("NativeForensics", files)}
            self.assertEqual(source_provenance.validate_source_receipt(receipt, "NativeForensics", self.root), files)
            self.assertNotIn(source_provenance.WORKER_ENTITLEMENTS_INPUT, files)

    def test_native_header_only_changes_missing_and_links_cannot_reuse_source_binding(self):
        self.add_native_header_receipt()
        distribution.verify_materials(self.root, self.app)
        for name in distribution.NATIVE_HEADERS:
            path = self.root / name
            original = path.read_bytes()
            for fault in ("changed", "missing", "linked"):
                with self.subTest(name=name, fault=fault):
                    path.unlink()
                    if fault == "changed": path.write_bytes(b"header-only source change")
                    elif fault == "linked": path.symlink_to(self.root / "NativeEngine/NFTSKEngine.cpp")
                    with self.assertRaises(ValueError): distribution.verify_materials(self.root, self.app)
                    if path.exists() or path.is_symlink(): path.unlink()
                    path.write_bytes(original)

    def test_current_header_inventory_is_exact_and_legacy_headerless_fingerprint_unchanged(self):
        legacy = self.receipt["buildFingerprint"]
        actual, _ = distribution.engine_input_fingerprint(self.root, self.receipt, "synthetic-dependencies", self.receipt["licenseSha256"])
        self.assertEqual(actual, legacy)
        self.add_native_header_receipt()
        current = dict(self.receipt)
        for fields in ({}, {"nativeHeaderSha256": {}}, {"nativeHeaderSha256": {**current["nativeHeaderSha256"], "NativeEngine/keys/private.pem": "a" * 64}},
                       {"compiledInputSha256": {}}, {"buildInputCapture": "claimed-current-source"}):
            changed = {key: value for key, value in current.items() if key not in {"nativeHeaderSha256", "compiledInputSha256", "buildInputCapture"}} if not fields else {**current, **fields}
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                distribution.engine_input_fingerprint(self.root, changed, "synthetic-dependencies", current["licenseSha256"])

    def test_native_headers_ship_and_copied_header_changes_break_recomputed_fingerprint(self):
        self.add_native_header_receipt()
        stage, manifest = self.stage()
        for name in distribution.NATIVE_HEADERS:
            self.assertIn("Source/" + name, manifest["files"])
            self.assertEqual((stage / "Source" / name).read_bytes(), (self.root / name).read_bytes())
        header = next(iter(distribution.NATIVE_HEADERS))
        (stage / "Source" / header).write_bytes(b"altered corresponding header")
        with self.assertRaisesRegex(ValueError, "captured compiler inputs"):
            distribution.engine_input_fingerprint(stage / "Source", self.receipt, "synthetic-dependencies", self.receipt["licenseSha256"])

    def test_three_link_recipes_keep_system_security_framework_without_host_paths(self):
        actual = native_builder.helper_link_args("clang++", "arm64", "/synthetic-sdk", "14.0", Path("NFTSKEngine.o"),
            [Path("libtsk.a"), Path("libewf.a")], Path("NFTSKEngine"))
        recipe = native_builder.portable_relink_command("arm64", "14.0")
        stage, _ = self.stage()
        portable = json.loads((stage / "Relink/link-command.json").read_text())
        self.assertEqual([actual[i + 1] for i, arg in enumerate(actual) if arg == "-framework"], ["CoreFoundation", "Security"])
        self.assertEqual([portable[i + 1] for i, arg in enumerate(portable) if arg == "-framework"], ["CoreFoundation", "Security"])
        self.assertIn("-framework CoreFoundation -framework Security", recipe)
        self.assertNotIn(str(self.root), recipe)
        self.assertNotIn(str(self.root), json.dumps(portable))

    def test_cpp_header_snapshot_is_complete_and_rejects_original_or_captured_drift(self):
        self.add_native_header_receipt()
        captured = native_builder.capture_helper_inputs(self.root, "synthetic-dependencies")
        self.assertEqual(set(captured["sources"]), distribution.NATIVE_HEADERS | {"NativeEngine/NFTSKEngine.cpp"})
        snapshot = self.root / "captured"
        cpp = native_builder.write_captured_sources(snapshot, captured)
        self.assertEqual(cpp, snapshot / "NativeEngine/NFTSKEngine.cpp")
        for name, data in captured["sources"].items(): self.assertEqual((snapshot / name).read_bytes(), data)
        native_builder.verify_helper_inputs(self.root, captured)
        native_builder.verify_captured_sources(snapshot, captured)
        header = next(iter(distribution.NATIVE_HEADERS))
        for name in distribution.NATIVE_HEADERS | {"NativeEngine/NFTSKEngine.cpp", "NativeEngine/dependencies.json",
                    "script/build_native_engine.py", "THIRD_PARTY_NOTICES.md", "NativeEngine/licenses/example/LICENSE"}:
            path = self.root / name
            original = path.read_bytes()
            with self.subTest(name=name):
                path.write_bytes(original + b"\nchanged after input capture")
                with self.assertRaises(RuntimeError): native_builder.verify_helper_inputs(self.root, captured)
                path.write_bytes(original)
        (snapshot / header).chmod(0o600); (snapshot / header).write_bytes(b"captured compiler header altered")
        with self.assertRaises(RuntimeError): native_builder.verify_captured_sources(snapshot, captured)

    def test_native_publication_failure_restores_helper_relink_licenses_and_manifest(self):
        self.create(".engine/bin/NFTSKEngine", b"previous helper", 0o755)
        self.create(".engine/licenses/NOTICE", b"previous notices")
        before = distribution.inventory(self.root / ".engine")
        stage = self.root / "native-stage"
        self.create("native-stage/NFTSKEngine", b"new helper", 0o755)
        self.create("native-stage/relink/NFTSKEngine.o", b"new object")
        self.create("native-stage/licenses/NOTICE", b"new notices")
        self.create("native-stage/manifest.json", b"new receipt")
        def fail_manifest(source, target):
            if source == stage / "manifest.json": raise OSError("synthetic publication failure")
            return source.rename(target)
        with self.assertRaises(OSError): native_builder.publish_helper_stage(stage, self.root / ".engine", rename=fail_manifest)
        self.assertEqual(distribution.inventory(self.root / ".engine"), before)

    def test_prebuilt_publisher_cannot_infer_source_without_captured_receipt(self):
        output = self.root / "prebuilt.zip"
        with patch.object(distribution, "validate_bundle", return_value={}):
            with self.assertRaisesRegex(ValueError, "requires its captured"):
                distribution.package(self.app, output, install_support=self.support, root=self.root)
        self.assertFalse(output.exists())

    def test_publisher_receipt_rejects_mutated_shape_source_recipe_and_binary(self):
        receipt = self.support_receipt()
        distribution.verify_install_support_receipt(self.root, self.support, receipt, "arm64", "14.0", verify_runtime=False)
        changes = (("schemaVersion", 2), ("architecture", "x86_64"), ("minimumMacOS", "15.0"),
                   ("buildConfiguration", "debug"), ("compiledBinarySha256", "bad"), ("sourceSha256", "a" * 64),
                   ("builderSourceSha256", "a" * 64), ("compileRecipe", ["clang", "unrecorded.c"]),
                   ("compilerInput", "claimed-current-source"), ("hardenedRuntime", 1),
                   ("privateBuildDirectory", "/Users/synthetic-private/build"))
        for key, value in changes:
            with self.subTest(key=key), self.assertRaises(ValueError):
                distribution.verify_install_support_receipt(self.root, self.support, {**receipt, key: value},
                                                            "arm64", "14.0", verify_runtime=False)
        self.support.write_bytes(b"replaced signed publisher")
        with self.assertRaisesRegex(ValueError, "signed binary differs"):
            distribution.verify_install_support_receipt(self.root, self.support, receipt, "arm64", "14.0", verify_runtime=False)

    def test_support_replacement_after_preflight_cannot_retain_old_source_binding(self):
        materials = distribution.verify_materials(self.root, self.app)
        materials["installSupportBuildReceipt"] = self.support_receipt()
        self.support.write_bytes(b"replaced after compiler receipt")
        stage = self.root / "stage"
        stage.mkdir()
        with self.assertRaisesRegex(ValueError, "signed binary differs"):
            distribution.stage_distribution(self.root, self.app, stage, self.support, {"mode": "development"}, materials)

    def test_repack_uses_only_included_source_materials_and_preserves_archive_bytes(self):
        stage, _ = self.stage()
        expected = self.root / "expected.zip"
        distribution.deterministic_zip(stage, expected)
        shutil.rmtree(self.root / ".engine")
        output = self.root / "repacked.zip"
        with patch.object(distribution, "validate_bundle", return_value={}), \
             patch.object(distribution, "validate_binary_runtime"), \
             patch.object(distribution, "signing_details", return_value="Signature=adhoc\nflags=0x2(adhoc)"), \
             patch.object(distribution, "verify_trust", return_value={"mode": "development", "notarization": "not-verified"}), \
             patch.object(distribution.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)):
            distribution.repack_distribution(stage, output)
        self.assertEqual(expected.read_bytes(), output.read_bytes())
        with self.assertRaisesRegex(ValueError, "outside"):
            distribution.repack_distribution(stage, stage / "overlap.zip")

    def test_generated_repack_launcher_imports_without_writing_bytecode(self):
        stage, _ = self.stage()
        launcher_bytes = (stage / "Source/Repack.command").read_bytes()
        environment = dict(os.environ)
        environment.pop("PYTHONDONTWRITEBYTECODE", None)
        environment.pop("PYTHONPYCACHEPREFIX", None)
        for label, content, expected_disabled in (
                ("generated", launcher_bytes, True),
                ("plain-control", launcher_bytes.replace(b"exec python3 -B ", b"exec python3 "), False)):
            with self.subTest(label=label):
                source = self.root / ("launcher-" + label) / "Source"
                script = source / "script"
                script.mkdir(parents=True)
                (script / "synthetic_bytecache_probe.py").write_text('VALUE = "owned import marker"\n')
                (script / "package_native_distribution.py").write_text(
                    "import json, sys\nimport synthetic_bytecache_probe\n"
                    "print(json.dumps({'disabled': sys.dont_write_bytecode, "
                    "'value': synthetic_bytecache_probe.VALUE, 'args': sys.argv[1:]}))\n")
                launcher = source / "Repack.command"
                launcher.write_bytes(content)
                launcher.chmod(0o755)
                # Only this private synthetic module is imported. This invokes
                # the actual generated launcher, not native package validation.
                result = subprocess.run([str(launcher), "--output", "owned-test-output.zip"],
                                        env=environment, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                report = json.loads(result.stdout)
                self.assertEqual(report["disabled"], expected_disabled)
                self.assertEqual(report["value"], "owned import marker")
                self.assertEqual(report["args"], ["--from-distribution", str(source) + "/..",
                                                   "--output", "owned-test-output.zip"])
                caches = list(source.rglob("*.pyc"))
                if expected_disabled:
                    self.assertEqual(caches, [])
                    self.assertFalse((script / "__pycache__").exists())
                else:
                    self.assertTrue(any(path.name.startswith("synthetic_bytecache_probe.") for path in caches))

    def test_copied_dependency_and_retained_relink_drift_cannot_be_reinventoried(self):
        stage, manifest = self.stage()
        materials = [("Source/Dependencies/example.tar.gz", "pinned dependency source archive"),
                     ("Source/NativeEngine/patches/example.patch", "pinned dependency patch")]
        materials += [("Relink/" + name, "retained relink artifact")
                      for name in sorted(distribution.RELINK_NAMES - {"link-command.json"})]
        for name, diagnostic in materials:
            with self.subTest(name=name):
                path = stage / name
                original = path.read_bytes()
                try:
                    path.write_bytes(b"changed accompanying build material")
                    self.reinventory(stage, manifest)
                    with self.assertRaisesRegex(ValueError, diagnostic):
                        distribution.validate_distribution(stage)
                    # The actual repack entrypoint must reject before examining
                    # native signatures or creating an output archive.
                    output = self.root / (path.name + ".repacked.zip")
                    with patch.object(distribution, "validate_bundle") as native_validation:
                        with self.assertRaisesRegex(ValueError, diagnostic):
                            distribution.repack_distribution(stage, output)
                        native_validation.assert_not_called()
                    self.assertFalse(output.exists())
                finally:
                    path.write_bytes(original)
                    self.reinventory(stage, manifest)
                self.assertEqual(distribution.validate_distribution(stage), manifest)

    def test_copied_retained_relink_inventory_cannot_drop_a_required_binding(self):
        stage, manifest = self.stage()
        receipt_path = stage / "NativeForensics.app/Contents/Resources/engine-manifest.json"
        receipt = json.loads(receipt_path.read_text())
        for name in sorted(distribution.RELINK_NAMES):
            with self.subTest(name=name):
                altered = {**receipt, "relinkSha256": {key: value for key, value in receipt["relinkSha256"].items()
                                                      if key != name}}
                receipt_path.write_text(json.dumps(altered))
                self.reinventory(stage, manifest)
                with self.assertRaisesRegex(ValueError, "relink inventory is incomplete"):
                    distribution.validate_distribution(stage)
        receipt_path.write_text(json.dumps(receipt))
        self.reinventory(stage, manifest)
        self.assertEqual(distribution.validate_distribution(stage), manifest)

    def test_portable_relink_recipe_cannot_be_reinventoried(self):
        stage, manifest = self.stage()
        path = stage / "Relink/link-command.json"
        original_bytes = path.read_bytes()
        original = json.loads(original_bytes)
        variants = [original[:-1], [*original, "--extra-unrecorded-flag"],
                    ["/Users/synthetic/linker", *original[1:]],
                    [value for value in original if value != "Security"],
                    ["x86_64" if value == "arm64" else value for value in original],
                    ["-mmacosx-version-min=15.0" if value.startswith("-mmacosx-version-min=") else value
                     for value in original], {"argv": original}]
        for changed in variants:
            with self.subTest(recipe=changed):
                path.write_text(json.dumps(changed))
                self.reinventory(stage, manifest)
                with self.assertRaisesRegex(ValueError, "Portable relink metadata differs"):
                    distribution.validate_distribution(stage)
        path.write_bytes(original_bytes)
        self.reinventory(stage, manifest)
        self.assertEqual(distribution.validate_distribution(stage), manifest)

    def test_original_relink_command_digest_cannot_be_reinventoried(self):
        stage, manifest = self.stage()
        original = manifest["originalLinkCommandSha256"]
        for changed in ("a" * 64, None):
            with self.subTest(digest=changed):
                if changed is None:
                    manifest.pop("originalLinkCommandSha256")
                else:
                    manifest["originalLinkCommandSha256"] = changed
                self.reinventory(stage, manifest)
                with self.assertRaisesRegex(ValueError, "Original relink command digest differs"):
                    distribution.validate_distribution(stage)
        manifest["originalLinkCommandSha256"] = original
        self.reinventory(stage, manifest)
        self.assertEqual(distribution.validate_distribution(stage), manifest)

    def test_outer_version_and_build_cannot_be_reinventoried(self):
        stage, manifest = self.stage()
        for field, changed in (("appVersion", "9.9.9"), ("appBuild", "999")):
            original = manifest[field]
            with self.subTest(field=field):
                try:
                    manifest[field] = changed
                    self.reinventory(stage, manifest)
                    with self.assertRaisesRegex(ValueError, "version/build differs from the validated app"):
                        distribution.validate_distribution(stage)
                finally:
                    manifest[field] = original
                    self.reinventory(stage, manifest)
                self.assertEqual(distribution.validate_distribution(stage), manifest)

    def test_repack_cannot_preserve_reinventoried_trust_claims(self):
        stage, manifest = self.stage()
        original = dict(manifest["trust"])
        changed_claims = [{**original, field: value} for field, value in (
            ("mode", "release"), ("signature", "Developer-ID-and-hardened-runtime-verified"),
            ("notarization", "verified"), ("gatekeeper", "accepted"),
            ("cleanMachine", "tested"), ("physicalM5", "tested"))]
        changed_claims += [{key: value for key, value in original.items() if key != "notarization"},
                           {**original, "additionalClaim": "verified"}]
        for ordinal, claims in enumerate(changed_claims):
            with self.subTest(claims=claims):
                manifest["trust"] = claims
                self.reinventory(stage, manifest)
                output = self.root / f"trust-{ordinal}.zip"
                # Native trust assessment is independently computed here;
                # the outer self-reinventoried claims cannot override it.
                with patch.object(distribution, "validate_bundle", return_value={}), \
                     patch.object(distribution, "verify_install_support_receipt"), \
                     patch.object(distribution, "verify_trust", return_value=original):
                    with self.assertRaisesRegex(ValueError, "trust (mode|details)"):
                        distribution.repack_distribution(stage, output)
                self.assertFalse(output.exists())
        manifest["trust"] = original
        self.reinventory(stage, manifest)
        self.assertEqual(distribution.validate_distribution(stage), manifest)

    def test_xpc_nested_code_is_signed_before_parent_without_parent_entitlements(self):
        binaries = self.root / "compiled"
        binaries.mkdir()
        for product in source_provenance.PRODUCT_DIRECTORIES:
            (binaries / product).write_bytes(product.encode())
        self.create(".engine/bin/NFTSKEngine", b"synthetic helper", 0o755)
        build = source_provenance.seal_build(self.root, binaries, source_provenance.snapshot_products(self.root))
        receipt_path = self.create("build-inputs.json", json.dumps(build).encode())
        with patch.object(package_app, "ROOT", self.root), \
             patch.object(package_app, "apply_staged_privacy_transform", return_value="strip-S-on-staged-release-copy"), \
             patch.object(package_app, "validate_bundle", return_value={}), \
             patch.object(package_app.subprocess, "run") as calls:
            staged = package_app.stage_bundle(binaries / "NativeForensics", receipt_path)
        signing = [call.args[0] for call in calls.call_args_list]
        self.assertEqual(len(signing), 4)
        self.assertTrue(signing[1][-1].endswith(distribution.WORKER_EXECUTABLE_PATH))
        self.assertIn("--entitlements", signing[1])
        self.assertTrue(signing[2][-1].endswith(distribution.XPC_BUNDLE_PATH))
        self.assertIn("--entitlements", signing[2])
        self.assertEqual(signing[-1][-1], str(staged))
        self.assertNotIn("--entitlements", signing[-1])
        recorded = json.loads((staged / "Contents/Resources/document-xpc-manifest.json").read_text())
        self.assertEqual(recorded["compiledBinarySha256"], build["compiledBinarySha256"]["NFDocumentDecoderXPC"])
        self.assertEqual(recorded["worker"]["compiledBinarySha256"], build["compiledBinarySha256"]["NFDocumentDecoderWorker"])
        self.assertEqual(recorded["worker"]["entitlements"], self.worker["entitlements"])


@unittest.skipUnless(sys.platform == "darwin", "The installer publisher uses macOS exclusive rename.")
class NativeEngineSourceCaptureTests(unittest.TestCase):
    """Exercise corresponding-source checks without building or running an app."""
    HEADERS = {"NativeEngine/EFSKeyPipeline.hpp", "NativeEngine/EFSNativeContent.hpp"}
    CPP = "NativeEngine/NFTSKEngine.cpp"

    def setUp(self):
        self.fixture = DistributionTests("test_complete_source_static_relink_inventory_and_no_local_data")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root, self.app = self.fixture.root, self.fixture.app
        self.dependency_fingerprint = "synthetic-dependencies"

    def write_receipts(self):
        self.fixture.create(".engine/manifest.json", json.dumps(self.fixture.receipt).encode())
        bundled = {**self.fixture.receipt, "licenses": "Contents/Resources/EngineLicenses/",
                   "distributionArtifactsBundled": False}
        self.fixture.create_app("Contents/Resources/engine-manifest.json", json.dumps(bundled).encode())

    def change_version(self, version):
        self.fixture.spec["engineVersion"] = version
        self.fixture.receipt["engineVersion"] = version
        self.fixture.create("NativeEngine/dependencies.json", json.dumps(self.fixture.spec).encode())

    def install_captured_inputs(self):
        self.change_version("0.1.5")
        for name in sorted(self.HEADERS):
            self.fixture.create(name, ("// Synthetic compiler input: " + name).encode())
        captured = native_builder.capture_helper_inputs(self.root, self.dependency_fingerprint)
        portable = native_builder.portable_relink_command("arm64", "14.0").encode()
        self.fixture.create(".engine/relink/Relink.command", portable, 0o755)
        self.fixture.receipt["relinkSha256"]["Relink.command"] = self.fixture.digest(portable)
        self.fixture.receipt.update({
            "nativeHeaderSha256": captured["fingerprintPayload"]["headers"],
            "compiledInputSha256": captured["compiledInputSha256"],
            "buildInputCapture": native_builder.NATIVE_CAPTURE_SCOPE,
            "buildFingerprint": self.fixture.digest(native_builder.canonical(captured["fingerprintPayload"]))})
        self.write_receipts()
        return captured

    def fingerprint(self, receipt=None):
        return distribution.engine_input_fingerprint(self.root, receipt or self.fixture.receipt,
            self.dependency_fingerprint, self.fixture.receipt["licenseSha256"])

    def test_legacy_013_fingerprint_remains_byte_compatible_without_headers(self):
        self.change_version("0.1.3")
        original_payload = {"dependencyFingerprint": self.dependency_fingerprint,
            "source": distribution.sha(self.root / self.CPP),
            "script": distribution.sha(self.root / "script/build_native_engine.py"),
            "spec": distribution.sha(self.root / "NativeEngine/dependencies.json"),
            "notices": distribution.sha(self.root / "THIRD_PARTY_NOTICES.md"),
            "licenses": self.fixture.receipt["licenseSha256"]}
        original_bytes = json.dumps(original_payload, sort_keys=True, separators=(",", ":")).encode()
        expected = hashlib.sha256(original_bytes).hexdigest()
        self.fixture.receipt["buildFingerprint"] = expected
        self.write_receipts()
        actual, sources = self.fingerprint()
        self.assertEqual(actual, expected)
        self.assertFalse(self.HEADERS & sources.keys())
        self.assertFalse(any((self.root / name).exists() for name in self.HEADERS))
        materials = distribution.verify_materials(self.root, self.app)
        self.assertEqual(materials["engineReceipt"]["buildFingerprint"], expected)
        stage, manifest = self.fixture.stage()
        self.assertEqual(distribution.validate_distribution(stage), manifest)
        self.assertFalse(any("Source/" + name in manifest["files"] for name in self.HEADERS))

    def test_015_payload_matches_actual_builder_capture_and_copies_both_headers(self):
        captured = self.install_captured_inputs()
        actual, sources = self.fingerprint()
        self.assertEqual(actual, self.fixture.digest(native_builder.canonical(captured["fingerprintPayload"])))
        self.assertEqual(set(sources), self.HEADERS | {self.CPP, "script/build_native_engine.py", "NativeEngine/dependencies.json"})
        materials = distribution.verify_materials(self.root, self.app)
        for name in self.HEADERS:
            self.assertEqual(materials["engineSourceSha256"][name], captured["compiledInputSha256"][name])
        stage, manifest = self.fixture.stage()
        self.assertEqual(distribution.validate_distribution(stage), manifest)
        for name in self.HEADERS:
            copied = stage / "Source" / name
            self.assertEqual(copied.read_bytes(), (self.root / name).read_bytes())
            self.assertEqual(manifest["files"]["Source/" + name]["sha256"], captured["compiledInputSha256"][name])

    def test_changed_cpp_or_either_header_is_rejected_by_capture_check(self):
        self.install_captured_inputs()
        for name in sorted(self.HEADERS | {self.CPP}):
            with self.subTest(name=name):
                path = self.root / name
                original = path.read_bytes()
                path.write_bytes(original + b"\n// changed after compilation")
                try:
                    with self.assertRaisesRegex(ValueError, "captured compiler inputs"):
                        distribution.verify_materials(self.root, self.app)
                finally:
                    path.write_bytes(original)

    def test_packaged_and_retained_relink_match_actual_helper_frameworks(self):
        self.install_captured_inputs()
        stage, _ = self.fixture.stage()
        packaged = json.loads((stage / "Relink/link-command.json").read_text())
        retained = shlex.split(next(line for line in (stage / "Relink/Relink.command").read_text().splitlines()
                                   if line.startswith("/usr/bin/xcrun ")))
        actual = native_builder.helper_link_args("clang++", "arm64", "/synthetic-sdk", "14.0",
            Path("NFTSKEngine.o"), [Path("libtsk.a"), Path("libewf.a")], Path("NFTSKEngine"))
        expected = ["-lz", "-lbz2", "-liconv", "-framework", "CoreFoundation", "-framework", "Security"]
        for name, command in (("packaged JSON", packaged), ("retained command", retained), ("actual helper", actual)):
            with self.subTest(command=name):
                libraries_end = next(index for index, token in enumerate(command) if token.endswith("libewf.a")) + 1
                self.assertEqual(command[libraries_end:command.index("-o")], expected)

    def test_missing_or_symlink_cpp_or_header_is_rejected(self):
        self.install_captured_inputs()
        for name in sorted(self.HEADERS | {self.CPP}):
            path = self.root / name
            original = path.read_bytes()
            for kind in ("missing", "linked"):
                with self.subTest(name=name, kind=kind):
                    path.unlink()
                    if kind == "linked":
                        path.symlink_to(self.root / "THIRD_PARTY_NOTICES.md")
                    try:
                        with self.assertRaises(ValueError):
                            self.fingerprint()
                    finally:
                        if path.is_symlink():
                            path.unlink()
                        path.write_bytes(original)

    def test_missing_extra_or_nonmapping_header_inventory_is_rejected(self):
        self.install_captured_inputs()
        original = self.fixture.receipt["nativeHeaderSha256"]
        one = next(iter(self.HEADERS))
        variants = ({name: value for name, value in original.items() if name != one},
                    {**original, "NativeEngine/Uncaptured.hpp": self.fixture.digest(b"extra")},
                    None, [], "invalid", {})
        for headers in variants:
            with self.subTest(headers=headers), self.assertRaisesRegex(ValueError, "exactly the two public EFS headers"):
                self.fingerprint({**self.fixture.receipt, "nativeHeaderSha256": headers})

    def test_missing_extra_or_altered_compiled_input_hash_is_rejected(self):
        self.install_captured_inputs()
        original = self.fixture.receipt["compiledInputSha256"]
        for name in sorted(original):
            for variant in ({key: value for key, value in original.items() if key != name},
                            {**original, name: self.fixture.digest(b"altered capture")}):
                with self.subTest(name=name, inventory=variant), self.assertRaisesRegex(ValueError, "captured compiler inputs"):
                    self.fingerprint({**self.fixture.receipt, "compiledInputSha256": variant})
        for variant in ({**original, "NativeEngine/Uncaptured.hpp": self.fixture.digest(b"extra")}, None, []):
            with self.subTest(inventory=variant), self.assertRaisesRegex(ValueError, "captured compiler inputs"):
                self.fingerprint({**self.fixture.receipt, "compiledInputSha256": variant})
        missing = {key: value for key, value in self.fixture.receipt.items() if key != "compiledInputSha256"}
        with self.assertRaisesRegex(ValueError, "captured compiler inputs"):
            self.fingerprint(missing)

    def test_missing_or_altered_capture_scope_is_rejected(self):
        self.install_captured_inputs()
        for scope in (None, "", "CPP only", native_builder.NATIVE_CAPTURE_SCOPE + " altered"):
            with self.subTest(scope=scope), self.assertRaisesRegex(ValueError, "captured compiler inputs"):
                self.fingerprint({**self.fixture.receipt, "buildInputCapture": scope})
        missing = {key: value for key, value in self.fixture.receipt.items() if key != "buildInputCapture"}
        with self.assertRaisesRegex(ValueError, "captured compiler inputs"):
            self.fingerprint(missing)

    def test_current_and_future_versions_cannot_fall_back_to_cpp_only(self):
        for version in ("0.1.5", "0.1.5-development", "0.1.5+build", "0.2.0", "1.0.0"):
            with self.subTest(version=version), self.assertRaisesRegex(ValueError, "requires captured CPP/header inputs"):
                self.fingerprint({**self.fixture.receipt, "engineVersion": version})
        for key, value in (("compiledInputSha256", {}), ("buildInputCapture", native_builder.NATIVE_CAPTURE_SCOPE)):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "requires captured CPP/header inputs"):
                self.fingerprint({**self.fixture.receipt, "engineVersion": "0.1.3", key: value})

    def test_bundled_capture_disagreement_is_rejected_before_source_staging(self):
        self.install_captured_inputs()
        path = self.app / "Contents/Resources/engine-manifest.json"
        original = json.loads(path.read_text())
        for key in ("nativeHeaderSha256", "compiledInputSha256", "buildInputCapture"):
            for kind in ("missing", "altered"):
                changed = {**original}
                if kind == "missing":
                    changed.pop(key)
                else:
                    changed[key] = "altered"
                path.write_text(json.dumps(changed))
                try:
                    with self.subTest(key=key, kind=kind), self.assertRaisesRegex(ValueError, "Bundled engine provenance differs"):
                        distribution.verify_materials(self.root, self.app)
                finally:
                    path.write_text(json.dumps(original))

    def test_copied_source_drift_is_rejected_even_with_reinventoried_package(self):
        self.install_captured_inputs()
        stage, manifest = self.fixture.stage()
        name = next(iter(sorted(self.HEADERS)))
        (stage / "Source" / name).write_bytes(b"altered corresponding source")
        # Updating outer inventory cannot turn source that differs from the
        # captured compiler inputs into an acceptable corresponding-source ZIP.
        manifest["files"] = {key: facts for key, facts in distribution.inventory(stage).items()
                             if key not in {"SHA256SUMS", "distribution-manifest.json"}}
        (stage / "distribution-manifest.json").write_text(json.dumps(manifest))
        (stage / "SHA256SUMS").write_text("".join(f'{facts["sha256"]}  {key}\n'
            for key, facts in distribution.inventory(stage).items() if key != "SHA256SUMS"))
        with self.assertRaisesRegex(ValueError, "captured compiler inputs"):
            distribution.validate_distribution(stage)

    def test_header_edit_after_preflight_cannot_be_copied(self):
        self.install_captured_inputs()
        materials = distribution.verify_materials(self.root, self.app)
        materials["installSupportSourceSha256"] = distribution.sha(self.root / "script/native_install_publish.c")
        if hasattr(self.fixture, "support_receipt"):
            materials["installSupportBuildReceipt"] = self.fixture.support_receipt()
        stage = self.root / "stage"
        stage.mkdir()
        name = next(iter(sorted(self.HEADERS)))
        (self.root / name).write_bytes(b"changed after preflight")
        with self.assertRaisesRegex(ValueError, "differs from its pinned receipt"):
            distribution.stage_distribution(self.root, self.app, stage, self.fixture.support,
                {"mode": "development", "notarization": "not-verified"}, materials)
        self.assertFalse((stage / "Source" / name).exists())


@unittest.skipUnless(sys.platform == "darwin", "The installer publisher uses macOS exclusive rename.")
class InstallerPublisherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiler_temp = tempfile.TemporaryDirectory()
        cls.publisher = Path(cls.compiler_temp.name).resolve() / "publisher"
        subprocess.run(["/usr/bin/xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
            str(ROOT / "script/native_install_publish.c"), "-o", str(cls.publisher)], check=True, capture_output=True)
        work = cls.publisher.parent
        # Compile a fault shim only into these test executables. Production has
        # no failure environment variable, special arguments or bypass mode.
        renamed = work / "publisher.o"
        subprocess.run(["/usr/bin/xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-c",
            "-Drenameatx_np=nf_test_rename", str(ROOT / "script/native_install_publish.c"), "-o", str(renamed)],
            check=True, capture_output=True)
        for suffix, fail_rollback in (("rollback", False), ("retained", True)):
            shim = work / (suffix + ".c")
            shim.write_text('''#define _DARWIN_C_SOURCE 1
#include <stdio.h>
#include <errno.h>
int nf_test_rename(int a, const char *b, int c, const char *d, unsigned int e) {
  static unsigned int count;
  ++count;
  if (count == 3) { errno = ENOSPC; return -1; }
''' + ('  if (count == 4) { errno = EACCES; return -1; }\n' if fail_rollback else '') + '''
  return renameatx_np(a, b, c, d, e);
}
''')
            binary = work / suffix
            subprocess.run(["/usr/bin/xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
                str(renamed), str(shim), "-o", str(binary)], check=True, capture_output=True)
            setattr(cls, suffix + "_publisher", binary)

    @classmethod
    def tearDownClass(cls):
        cls.compiler_temp.cleanup()

    def test_captured_source_build_sign_receipt_matches_actual_macOS_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary).resolve() / "InstallSupport"
            receipt = distribution.build_install_support(ROOT, output, os.uname().machine, "14.0")
            distribution.verify_install_support_receipt(ROOT, output, receipt, os.uname().machine, "14.0")
            self.assertEqual(receipt["sourceSha256"], distribution.sha(ROOT / distribution.SUPPORT_SOURCE))
            self.assertEqual(receipt["signedBinarySha256"], distribution.sha(output))
            self.assertNotIn(str(ROOT), json.dumps(receipt))
            output.write_bytes(output.read_bytes() + b"modified after signing")
            with self.assertRaisesRegex(ValueError, "signed binary differs"):
                distribution.verify_install_support_receipt(ROOT, output, receipt, os.uname().machine, "14.0")

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.parent = self.root / "applications"
        self.parent.mkdir()
        self.stage_root = self.parent / "stage"
        self.stage_root.mkdir()
        self.stage = self.stage_root / "NativeForensics.app"
        self.stage.mkdir()
        (self.stage / "payload").write_bytes(b"new app")
        self.destination = self.parent / "NativeForensics.app"

    def run_publisher(self, replace=False):
        return subprocess.run([str(self.publisher), str(self.stage), str(self.destination)] + (["--replace"] if replace else []),
                              capture_output=True, text=True)

    def old_app(self):
        self.destination.mkdir()
        (self.destination / "payload").write_bytes(b"old app")

    def test_clean_install_moves_stage_and_preserves_neighbor(self):
        neighbor = self.parent / "other.txt"
        neighbor.write_bytes(b"neighbor")
        result = self.run_publisher()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.destination / "payload").read_bytes(), b"new app")
        self.assertFalse(self.stage.exists())
        self.assertEqual(neighbor.read_bytes(), b"neighbor")

    def test_existing_app_requires_explicit_replace(self):
        self.old_app()
        result = self.run_publisher()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.destination / "payload").read_bytes(), b"old app")
        self.assertEqual((self.stage / "payload").read_bytes(), b"new app")

    def test_replacement_retains_original_backup(self):
        self.old_app()
        result = self.run_publisher(True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.destination / "payload").read_bytes(), b"new app")
        backups = list(self.parent.glob(".nativeforensics-install-backup.*/NativeForensics.app/payload"))
        self.assertEqual([path.read_bytes() for path in backups], [b"old app"])

    def test_symlink_destination_and_parent_preserve_apps(self):
        other = self.parent / "other.app"
        other.mkdir()
        (other / "payload").write_bytes(b"other")
        self.destination.symlink_to(other)
        self.assertNotEqual(self.run_publisher(True).returncode, 0)
        self.assertEqual((other / "payload").read_bytes(), b"other")
        self.destination.unlink()
        link = self.root / "alias"
        link.symlink_to(self.parent)
        self.destination = link / "NativeForensics.app"
        self.assertNotEqual(self.run_publisher().returncode, 0)
        self.assertTrue(self.stage.exists())

    def test_overlapping_stage_rejected(self):
        self.destination = self.stage
        self.assertNotEqual(self.run_publisher(True).returncode, 0)
        self.assertEqual((self.stage / "payload").read_bytes(), b"new app")

    def test_lock_contention_is_failure_without_mutation(self):
        self.old_app()
        lock = self.parent / ".nativeforensics-install.lock"
        lock.mkdir()
        self.assertNotEqual(self.run_publisher(True).returncode, 0)
        self.assertEqual((self.destination / "payload").read_bytes(), b"old app")
        self.assertTrue(lock.is_dir())

    def test_unwritable_parent_rejects_preserving_app(self):
        if os.geteuid() == 0:
            self.skipTest("Owner permission check should run as a normal user.")
        self.old_app()
        self.parent.chmod(0o500)
        try:
            self.assertNotEqual(self.run_publisher(True).returncode, 0)
            self.assertEqual((self.destination / "payload").read_bytes(), b"old app")
        finally:
            self.parent.chmod(0o700)

    def test_failed_publication_rolls_back_existing_app(self):
        self.old_app()
        result = subprocess.run([str(self.rollback_publisher), str(self.stage), str(self.destination), "--replace"],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.destination / "payload").read_bytes(), b"old app")
        self.assertEqual((self.stage / "payload").read_bytes(), b"new app")
        self.assertIsNone(json.loads(result.stdout)["backup_path"])

    def test_failed_rollback_retains_recovery_copy(self):
        self.old_app()
        result = subprocess.run([str(self.retained_publisher), str(self.stage), str(self.destination), "--replace"],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        receipt = json.loads(result.stdout)
        self.assertFalse(self.destination.exists())
        self.assertEqual((Path(receipt["backup_path"]) / "payload").read_bytes(), b"old app")
        self.assertEqual((self.stage / "payload").read_bytes(), b"new app")


@unittest.skipUnless(sys.platform == "darwin", "Install.command uses macOS system tools.")
class InstallerCommandTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiler_temp = tempfile.TemporaryDirectory()
        work = Path(cls.compiler_temp.name).resolve()
        cls.publisher, cls.app_binary = work / "publisher", work / "minimal-app"
        main = work / "minimal.c"
        main.write_text("int main(void) { return 0; }\n")
        for source, output in ((ROOT / "script/native_install_publish.c", cls.publisher), (main, cls.app_binary)):
            subprocess.run(["/usr/bin/xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", str(source),
                            "-mmacosx-version-min=14.0", "-o", str(output)], check=True, capture_output=True)
            subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", str(output)], check=True, capture_output=True)
        # These signed fixtures exercise the real shell EXIT trap using actual
        # substitutions in its private test tree. No failure mode ships in C.
        fixture_source = work / "stage-retention-fixture.c"
        fixture_source.write_text(r'''#define _DARWIN_C_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static bool join_path(char *output, const char *parent, const char *leaf) {
    int count = snprintf(output, PATH_MAX, "%s/%s", parent, leaf);
    return count >= 0 && count < PATH_MAX;
}

static bool parent_path(char *output, const char *input) {
    if (strlen(input) >= PATH_MAX) return false;
    strcpy(output, input);
    char *slash = strrchr(output, '/');
    if (slash == NULL || slash == output) return false;
    *slash = '\0';
    return true;
}

static bool create_marker(const char *directory, const char *name, const char *text,
                          struct stat *identity) {
    char path[PATH_MAX];
    if (!join_path(path, directory, name)) return false;
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    size_t size = strlen(text);
    bool ok = write(fd, text, size) == (ssize_t)size && fstat(fd, identity) == 0;
    if (close(fd) != 0) ok = false;
    return ok;
}

static bool print_receipt(const struct stat *stage, const struct stat *canary) {
    printf("{\"fixtureMode\":%d,\"installed\":%s,\"stageDevice\":%llu,\"stageInode\":%llu",
           NF_TEST_MODE, NF_TEST_MODE == 3 ? "true" : "false",
           (unsigned long long)stage->st_dev, (unsigned long long)stage->st_ino);
    if (canary != NULL) {
        printf(",\"canaryDevice\":%llu,\"canaryInode\":%llu,\"canarySize\":%llu",
               (unsigned long long)canary->st_dev, (unsigned long long)canary->st_ino,
               (unsigned long long)canary->st_size);
    }
    printf("}\n");
    return fflush(stdout) == 0;
}

int main(int argc, char **argv) {
    if (argc != 3 && argc != 4) return 64;
    char stage[PATH_MAX], parent[PATH_MAX], root[PATH_MAX], displaced[PATH_MAX];
    struct stat original_stage, canary;
    if (!parent_path(stage, argv[1]) || !parent_path(parent, argv[2])
        || lstat(stage, &original_stage) != 0 || !S_ISDIR(original_stage.st_mode)) return 90;
    if (NF_TEST_MODE == 0) return print_receipt(&original_stage, NULL) ? 73 : 91;
    if (NF_TEST_MODE == 4) {
        if (!create_marker(stage, ".nf-test-ready", "owned fixture ready\n", &canary)
            || !print_receipt(&original_stage, NULL)) return 92;
        char control;
        ssize_t count;
        do { count = read(STDIN_FILENO, &control, 1); } while (count < 0 && errno == EINTR);
        return 74;
    }
    if (NF_TEST_MODE == 3
        && renameatx_np(AT_FDCWD, argv[1], AT_FDCWD, argv[2], RENAME_EXCL) != 0) return 93;
    if (NF_TEST_MODE == 1 || NF_TEST_MODE == 3) {
        if (!join_path(displaced, parent, ".nf-test-displaced-stage")
            || renameatx_np(AT_FDCWD, stage, AT_FDCWD, displaced, RENAME_EXCL) != 0
            || mkdir(stage, 0700) != 0) return 94;
    } else if (NF_TEST_MODE == 2) {
        if (!parent_path(root, parent) || !join_path(displaced, root, ".nf-test-displaced-parent")
            || renameatx_np(AT_FDCWD, parent, AT_FDCWD, displaced, RENAME_EXCL) != 0
            || mkdir(parent, 0700) != 0 || mkdir(stage, 0700) != 0) return 95;
    } else {
        return 64;
    }
    if (!create_marker(stage, "foreign-canary", "foreign stage canary\n", &canary)
        || !print_receipt(&original_stage, &canary)) return 96;
    return NF_TEST_MODE == 3 ? 0 : 73;
}
''')
        cls.stage_fixture_publishers = {}
        for mode in range(5):
            output = work / ("stage-retention-fixture-" + str(mode))
            subprocess.run(["/usr/bin/xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
                            "-DNF_TEST_MODE=" + str(mode), str(fixture_source),
                            "-mmacosx-version-min=14.0", "-o", str(output)], check=True, capture_output=True)
            subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", str(output)], check=True, capture_output=True)
            cls.stage_fixture_publishers[mode] = output

    @classmethod
    def tearDownClass(cls):
        cls.compiler_temp.cleanup()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.package = self.root / "package"
        self.app = self.package / "NativeForensics.app"
        (self.app / "Contents/MacOS").mkdir(parents=True)
        shutil.copy2(self.app_binary, self.app / "Contents/MacOS/NativeForensics")
        info = {"CFBundleExecutable": "NativeForensics", "CFBundleIdentifier": "io.github.pornmongkolnano.nativeforensics",
                "CFBundlePackageType": "APPL", "CFBundleVersion": "1", "CFBundleShortVersionString": "0.0.1",
                "LSMinimumSystemVersion": "14.0"}
        (self.app / "Contents/Info.plist").write_bytes(plistlib.dumps(info))
        subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", str(self.app)], check=True, capture_output=True)
        shutil.copy2(self.publisher, self.package / "InstallSupport")
        self.command = self.package / "Install.command"
        shutil.copy2(ROOT / "script/templates/native_install.command", self.command)
        self.command.chmod(0o755)
        (self.package / "README.md").write_text("Synthetic installer artifact, not a production app.\n")
        (self.package / "distribution-manifest.json").write_text('{"trust":{"mode":"development"}}\n')
        self.write_hashes()
        self.destination_parent = self.root / "applications"
        self.destination_parent.mkdir()
        self.destination = self.destination_parent / "NativeForensics.app"

    def write_hashes(self):
        facts = distribution.inventory(self.package)
        (self.package / "SHA256SUMS").write_text("".join(f'{value["sha256"]}  {name}\n' for name, value in facts.items() if name != "SHA256SUMS"))

    def run_installer(self, *extra):
        return subprocess.run(["/bin/zsh", str(self.command), "--destination", str(self.destination_parent), *extra],
                              capture_output=True, text=True)

    def use_stage_fixture_publisher(self, mode):
        shutil.copy2(self.stage_fixture_publishers[mode], self.package / "InstallSupport")
        self.write_hashes()

    def stage_candidate(self, result):
        prefix = "Stage path candidate for manual review (no automatic cleanup): "
        candidates = [line[len(prefix):] for line in result.stderr.splitlines() if line.startswith(prefix)]
        self.assertEqual(len(candidates), 1, result.stdout + result.stderr)
        candidate = Path(candidates[0])
        self.assertEqual(candidate.parent, self.destination_parent)
        self.assertTrue(candidate.name.startswith(".nativeforensics-install-stage."))
        return candidate

    def assert_fixture_stage_identity(self, directory, receipt):
        identity = directory.stat(follow_symlinks=False)
        self.assertTrue(stat.S_ISDIR(identity.st_mode))
        self.assertEqual((identity.st_dev, identity.st_ino), (receipt["stageDevice"], receipt["stageInode"]))

    def assert_foreign_stage_preserved(self, candidate, receipt):
        canary = candidate / "foreign-canary"
        identity = canary.stat(follow_symlinks=False)
        self.assertTrue(stat.S_ISREG(identity.st_mode))
        self.assertEqual((identity.st_dev, identity.st_ino, identity.st_size),
                         (receipt["canaryDevice"], receipt["canaryInode"], receipt["canarySize"]))
        self.assertEqual(canary.read_bytes(), b"foreign stage canary\n")
        self.assertEqual([path.name for path in candidate.iterdir()], ["foreign-canary"])

    def test_verify_and_clean_install_use_system_tools(self):
        result = self.run_installer("--verify-only")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.destination_parent.glob(".nativeforensics-install-stage.*")), [])
        self.assertNotIn("Stage path candidate", result.stderr)
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        subprocess.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(self.destination)], check=True, capture_output=True)
        self.assertEqual(distribution.inventory(self.app), distribution.inventory(self.destination))
        candidate = self.stage_candidate(result)
        self.assertEqual(list(self.destination_parent.glob(".nativeforensics-install-stage.*")), [candidate])
        self.assertTrue(candidate.is_dir())
        self.assertFalse(candidate.is_symlink())
        self.assertEqual(list(candidate.iterdir()), [])

    def test_publisher_failure_retains_stage_and_original_exit_status(self):
        shutil.copytree(self.app, self.destination)
        original = distribution.inventory(self.destination)
        self.use_stage_fixture_publisher(0)
        result = self.run_installer("--replace")
        self.assertEqual(result.returncode, 73, result.stdout + result.stderr)
        receipt = json.loads(result.stdout)
        self.assertFalse(receipt["installed"])
        candidate = self.stage_candidate(result)
        self.assert_fixture_stage_identity(candidate, receipt)
        self.assertEqual(distribution.inventory(candidate / "NativeForensics.app"), distribution.inventory(self.app))
        self.assertEqual(distribution.inventory(self.destination), original)
        self.assertNotIn("Installed:", result.stdout)

    def test_failed_stage_substitution_preserves_foreign_canary_and_displaced_stage(self):
        shutil.copytree(self.app, self.destination)
        original = distribution.inventory(self.destination)
        self.use_stage_fixture_publisher(1)
        result = self.run_installer("--replace")
        self.assertEqual(result.returncode, 73, result.stdout + result.stderr)
        receipt = json.loads(result.stdout)
        candidate = self.stage_candidate(result)
        self.assert_foreign_stage_preserved(candidate, receipt)
        displaced = self.destination_parent / ".nf-test-displaced-stage"
        self.assert_fixture_stage_identity(displaced, receipt)
        self.assertEqual(distribution.inventory(displaced / "NativeForensics.app"), distribution.inventory(self.app))
        self.assertEqual(distribution.inventory(self.destination), original)

    def test_failed_ancestor_substitution_preserves_both_owned_tree_and_foreign_canary(self):
        shutil.copytree(self.app, self.destination)
        original = distribution.inventory(self.destination)
        self.use_stage_fixture_publisher(2)
        result = self.run_installer("--replace")
        self.assertEqual(result.returncode, 73, result.stdout + result.stderr)
        receipt = json.loads(result.stdout)
        candidate = self.stage_candidate(result)
        self.assert_foreign_stage_preserved(candidate, receipt)
        displaced_parent = self.root / ".nf-test-displaced-parent"
        displaced_stage = displaced_parent / candidate.name
        self.assert_fixture_stage_identity(displaced_stage, receipt)
        self.assertEqual(distribution.inventory(displaced_stage / "NativeForensics.app"), distribution.inventory(self.app))
        self.assertEqual(distribution.inventory(displaced_parent / "NativeForensics.app"), original)
        self.assertFalse(self.destination.exists())

    def test_successful_publication_does_not_delete_substituted_stage(self):
        self.use_stage_fixture_publisher(3)
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        receipt = json.loads(result.stdout.splitlines()[0])
        self.assertTrue(receipt["installed"])
        candidate = self.stage_candidate(result)
        self.assert_foreign_stage_preserved(candidate, receipt)
        displaced = self.destination_parent / ".nf-test-displaced-stage"
        self.assert_fixture_stage_identity(displaced, receipt)
        self.assertEqual(list(displaced.iterdir()), [])
        self.assertEqual(distribution.inventory(self.destination), distribution.inventory(self.app))
        self.assertIn("Installed: " + str(self.destination), result.stdout)

    def test_owned_installer_term_preserves_stage_and_signal_exit_status(self):
        import signal
        import time
        shutil.copytree(self.app, self.destination)
        original = distribution.inventory(self.destination)
        self.use_stage_fixture_publisher(4)
        process = subprocess.Popen(["/bin/zsh", str(self.command), "--destination", str(self.destination_parent), "--replace"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        communication_started = False
        try:
            deadline = time.monotonic() + 10
            ready = []
            while time.monotonic() < deadline and process.poll() is None:
                ready = list(self.destination_parent.glob(".nativeforensics-install-stage.*/.nf-test-ready"))
                if ready:
                    break
                time.sleep(0.01)
            self.assertEqual(len(ready), 1, "Owned publisher fixture did not reach its prepublication barrier.")
            # Popen owns this exact shell child; never signal a discovered PID.
            process.send_signal(signal.SIGTERM)
            communication_started = True
            stdout, stderr = process.communicate(input="\n", timeout=10)
            result = subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
            self.assertEqual(result.returncode, 143, result.stdout + result.stderr)
            receipt = json.loads(result.stdout)
            candidate = self.stage_candidate(result)
            self.assert_fixture_stage_identity(candidate, receipt)
            self.assertEqual((candidate / ".nf-test-ready").read_bytes(), b"owned fixture ready\n")
            self.assertEqual(distribution.inventory(candidate / "NativeForensics.app"), distribution.inventory(self.app))
            self.assertEqual(distribution.inventory(self.destination), original)
            self.assertNotIn("Installed:", result.stdout)
        finally:
            if process.poll() is None:
                try:
                    if communication_started:
                        process.communicate(timeout=5)
                    else:
                        process.communicate(input="\n", timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate(timeout=5)

    def test_changed_or_extra_package_bytes_preserve_existing_app(self):
        shutil.copytree(self.app, self.destination)
        before = distribution.inventory(self.destination)
        (self.package / "README.md").write_text("corrupt package")
        result = self.run_installer("--replace")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(before, distribution.inventory(self.destination))
        self.write_hashes()
        (self.package / "unlisted.txt").write_text("unlisted")
        result = self.run_installer("--replace")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(before, distribution.inventory(self.destination))

    def test_replace_retains_backup_and_symlink_destination_rejected(self):
        shutil.copytree(self.app, self.destination)
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        result = self.run_installer("--replace")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        candidate = self.stage_candidate(result)
        self.assertEqual(list(candidate.iterdir()), [])
        self.assertEqual(list(self.destination_parent.glob(".nativeforensics-install-stage.*")), [candidate])
        backups = list(self.destination_parent.glob(".nativeforensics-install-backup.*/NativeForensics.app"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(distribution.inventory(backups[0]), distribution.inventory(self.app))
        alias = self.root / "alias"
        alias.symlink_to(self.destination_parent)
        self.destination_parent = alias
        result = self.run_installer("--replace")
        self.assertNotEqual(result.returncode, 0)

    def test_package_destination_overlap_rejected_without_staging(self):
        self.destination_parent = self.package
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(self.package.glob(".nativeforensics-install-stage.*")), [])

    def test_standard_release_debug_map_transform_preserves_raw_binary(self):
        main = self.root / "private-build.c"
        main.write_text("int main(void) { return 0; }\n")
        raw = self.root / "raw-debug-map"
        subprocess.run(["/usr/bin/xcrun", "clang", "-g", "-O2", str(main), "-o", str(raw)], check=True, capture_output=True)
        before = raw.read_bytes()
        with self.assertRaisesRegex(ValueError, "privacy blocker"):
            source_provenance.check_binary_privacy(raw)
        staged = self.root / "staged-debug-map"
        shutil.copy2(raw, staged)
        transform = source_provenance.apply_staged_privacy_transform(staged, "release")
        self.assertEqual(transform, "strip-S-on-staged-release-copy")
        source_provenance.check_binary_privacy(staged)
        self.assertEqual(raw.read_bytes(), before)
        self.assertEqual(subprocess.run([str(staged)], capture_output=True).returncode, 0)
        # Runtime path literals are not debug maps: strip must not masquerade
        # as arbitrary byte scrubbing and the privacy gate must still refuse them.
        main.write_text('const char *path = "/Users/synthetic-private/path"; int main(void) { return path[0] == 0; }\n')
        subprocess.run(["/usr/bin/xcrun", "clang", "-g", "-O2", str(main), "-o", str(staged)], check=True, capture_output=True)
        with self.assertRaisesRegex(ValueError, "privacy blocker"):
            source_provenance.apply_staged_privacy_transform(staged, "release")


if __name__ == "__main__":
    unittest.main()

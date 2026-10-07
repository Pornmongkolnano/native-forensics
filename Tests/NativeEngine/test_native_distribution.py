"""Synthetic source-compliance, archive and installer publication regressions."""
from pathlib import Path
import hashlib
import json
import os
import plistlib
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "script"))
import package_native_distribution as distribution
import source_provenance

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
        for name in ("package_app.py", "validate_app_bundle.py", "build_and_run.sh"):
            self.create("script/" + name, b"# synthetic recipe")
        self.create("script/source_provenance.py", b"# synthetic source graph recipe")
        self.create("script/native_install_publish.c", b"/* publisher */")
        self.create("script/templates/native_install.command", b"#!/bin/zsh\nexit 0\n", 0o755)
        self.create("Sources/ForensicsCore/Example.swift", b"// original core")
        self.create("Sources/NFDocumentDecoder/Example.swift", b"// original decoder")
        self.create("Sources/NativeForensics/Example.swift", b"// original UI")
        self.create("Sources/CSQLite3/module.modulemap", b"// synthetic system module")
        self.create("Sources/CSQLite3/shim.h", b"// synthetic system header")
        self.create("Tests/ForensicsCoreTests/ExampleTests.swift", b"// synthetic regression")
        for name in ("AppIcon.png", "AppIcon.icns", "README.md"):
            self.create("Assets/AppIcon/" + name, b"original icon materials")
        self.create("Package.swift", b"// synthetic package")
        self.create("docs/DISTRIBUTION.md", b"Distribution instructions")
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
            "CFBundleIdentifier": "io.github.pornmongkolnano.nativeforensics", "CFBundleShortVersionString": "0.6.0",
            "CFBundleVersion": "15", "LSMinimumSystemVersion": "14.0"}
        self.create_app("Contents/Info.plist", plistlib.dumps(info))
        self.create_app("Contents/Helpers/NFDocumentDecoder", b"synthetic decoder", 0o755)
        self.decoder = {"schemaVersion": 2, "protocolVersion": 1, "architecture": "arm64", "minimumMacOS": "14.0",
            "path": "Contents/Helpers/NFDocumentDecoder", "sha256": self.digest(b"synthetic decoder"),
            "compiledBinarySha256": self.digest(b"synthetic decoder"),
            "buildConfiguration": "release", "buildPathPolicy": source_provenance.BUILD_PATH_POLICY,
            "packagingTransform": "strip-S-on-staged-release-copy",
            **source_provenance.make_source_receipt(self.root, "NFDocumentDecoder")}
        self.create_app("Contents/Resources/document-decoder-manifest.json", json.dumps(self.decoder).encode())
        self.app_source = {"schemaVersion": 1, "path": "Contents/MacOS/NativeForensics", "appVersion": "0.6.0", "appBuild": "15",
            "compiledBinarySha256": self.digest(b"synthetic app"),
            "buildConfiguration": "release", "buildPathPolicy": source_provenance.BUILD_PATH_POLICY,
            "packagingTransform": "strip-S-on-staged-release-copy",
            **source_provenance.make_source_receipt(self.root, "NativeForensics")}
        self.create_app("Contents/Resources/app-source-manifest.json", json.dumps(self.app_source).encode())
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
        materials["installSupportSourceSha256"] = distribution.sha(self.root / "script/native_install_publish.c")
        manifest = distribution.stage_distribution(self.root, self.app, stage, self.support,
            {"mode": "development", "notarization": "not-verified"}, materials)
        return stage, manifest

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
        materials["installSupportSourceSha256"] = distribution.sha(self.root / "script/native_install_publish.c")
        (self.root / "NativeEngine/NFTSKEngine.cpp").write_bytes(b"edited after preflight")
        stage = self.root / "stage"
        stage.mkdir()
        with self.assertRaisesRegex(ValueError, "hash differs"):
            distribution.stage_distribution(self.root, self.app, stage, self.support, {"mode": "development"}, materials)

    def test_installer_source_edit_after_build_pin_cannot_be_copied(self):
        materials = distribution.verify_materials(self.root, self.app)
        materials["installSupportSourceSha256"] = distribution.sha(self.root / "script/native_install_publish.c")
        (self.root / "script/native_install_publish.c").write_bytes(b"edited after publisher build")
        stage = self.root / "stage"
        stage.mkdir()
        with self.assertRaisesRegex(ValueError, "hash differs"):
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
        for filename, receipt in (("app-source-manifest.json", self.app_source), ("document-decoder-manifest.json", self.decoder)):
            changed = {**receipt, "buildConfiguration": "debug", "packagingTransform": "unstripped-local-debug-copy"}
            (self.app / "Contents/Resources" / filename).write_text(json.dumps(changed))
        with self.assertRaisesRegex(ValueError, "optimized release configuration"):
            distribution.verify_materials(self.root, self.app)


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

    def test_verify_and_clean_install_use_system_tools(self):
        result = self.run_installer("--verify-only")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.destination.exists())
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        subprocess.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(self.destination)], check=True, capture_output=True)
        self.assertEqual(distribution.inventory(self.app), distribution.inventory(self.destination))
        self.assertEqual(list(self.destination_parent.glob(".nativeforensics-install-stage.*")), [])

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

"""Artifact regressions use temporary synthetic bundles, not application/evidence data."""
from pathlib import Path
import hashlib
import io
import json
import os
import plistlib
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "script"))
from package_app import publish_bundle
import package_app
from validate_app_bundle import validate_metadata
import build_native_engine


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.bundle = self.root / "NativeForensics.app"
        resources = self.bundle / "Contents/Resources"
        self.files = {
            "Contents/MacOS/NativeForensics": b"synthetic-app",
            "Contents/Helpers/NFTSKEngine": b"synthetic-helper",
            "Contents/Resources/AppIcon.icns": b"synthetic-icon",
            "Contents/Resources/EngineLicenses/component/LICENSE": b"synthetic-license",
            "Contents/Resources/EngineLicenses/THIRD_PARTY_NOTICES.md": b"synthetic-notices",
        }
        for name, data in self.files.items():
            path = self.bundle / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.receipt = {"schemaVersion": 1, "protocolVersion": 1, "architecture": "arm64",
            "engineVersion": "synthetic", "toolchain": {"minimumMacOS": "14.0"},
            "engineSha256": hashlib.sha256(b"synthetic-helper").hexdigest(),
            "licenses": "Contents/Resources/EngineLicenses/", "distributionArtifactsBundled": False,
            "licenseSha256": {"NativeEngine/licenses/component/LICENSE": hashlib.sha256(b"synthetic-license").hexdigest()},
            "noticesSha256": hashlib.sha256(b"synthetic-notices").hexdigest()}
        self.receipt_path = resources / "engine-manifest.json"
        self.write_receipt()
        info = {"CFBundleExecutable": "NativeForensics", "CFBundlePackageType": "APPL",
            "CFBundleIdentifier": "io.github.pornmongkolnano.nativeforensics", "LSMinimumSystemVersion": "14.0"}
        self.info_path = self.bundle / "Contents/Info.plist"
        with self.info_path.open("wb") as stream:
            plistlib.dump(info, stream)

    def write_receipt(self):
        self.receipt_path.write_text(json.dumps(self.receipt))

    def test_complete_metadata_accepts_and_returns_receipt_scope(self):
        result = validate_metadata(self.bundle, allow_legacy_development=True)
        self.assertEqual(result["minimumMacOS"], "14.0")
        self.assertEqual(result["helperSha256"], self.receipt["engineSha256"])

    def test_legacy_receipts_require_explicit_development_inspection(self):
        with self.assertRaisesRegex(ValueError, "Legacy development receipts"):
            validate_metadata(self.bundle)
        self.assertEqual(validate_metadata(self.bundle, allow_legacy_development=True)["sourceProvenance"],
                         "legacy-development-unbound")

    def test_changed_helper_is_rejected(self):
        (self.bundle / "Contents/Helpers/NFTSKEngine").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "helper differs"):
            validate_metadata(self.bundle, allow_legacy_development=True)

    def test_missing_or_changed_notices_are_rejected(self):
        path = self.bundle / "Contents/Resources/EngineLicenses/THIRD_PARTY_NOTICES.md"
        path.unlink()
        with self.assertRaises(ValueError):
            validate_metadata(self.bundle, allow_legacy_development=True)
        path.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "notices differ"):
            validate_metadata(self.bundle, allow_legacy_development=True)

    def test_license_escape_and_changed_license_are_rejected(self):
        self.receipt["licenseSha256"] = {"NativeEngine/licenses/../../outside": "a" * 64}
        self.write_receipt()
        with self.assertRaisesRegex(ValueError, "invalid path"):
            validate_metadata(self.bundle, allow_legacy_development=True)
        self.receipt["licenseSha256"] = {"NativeEngine/licenses/component/LICENSE": "a" * 64}
        self.write_receipt()
        with self.assertRaisesRegex(ValueError, "license does not match"):
            validate_metadata(self.bundle, allow_legacy_development=True)

    def test_symlinked_helper_is_rejected_without_following(self):
        helper = self.bundle / "Contents/Helpers/NFTSKEngine"
        helper.unlink()
        helper.symlink_to(self.info_path)
        with self.assertRaisesRegex(ValueError, "symlinks"):
            validate_metadata(self.bundle, allow_legacy_development=True)

    def test_minimum_version_mismatch_is_rejected(self):
        self.receipt["toolchain"]["minimumMacOS"] = "27.0"
        self.write_receipt()
        with self.assertRaisesRegex(ValueError, "minimum macOS"):
            validate_metadata(self.bundle, allow_legacy_development=True)

    def add_decoder(self):
        with self.info_path.open("rb") as stream:
            info = plistlib.load(stream)
        info["CFBundleShortVersionString"] = "0.5.0"
        with self.info_path.open("wb") as stream:
            plistlib.dump(info, stream)
        decoder = self.bundle / "Contents/Helpers/NFDocumentDecoder"
        decoder.write_bytes(b"synthetic-decoder")
        receipt = {"schemaVersion": 1, "protocolVersion": 1,
            "path": "Contents/Helpers/NFDocumentDecoder", "architecture": "arm64", "minimumMacOS": "14.0",
            "sha256": hashlib.sha256(decoder.read_bytes()).hexdigest(),
            "sourceSha256": {"Sources/NFDocumentDecoder/main.swift": "a" * 64}}
        path = self.bundle / "Contents/Resources/document-decoder-manifest.json"
        path.write_text(json.dumps(receipt))
        return decoder, path, receipt

    def test_current_version_requires_exact_decoder_receipt_and_payload(self):
        decoder, path, receipt = self.add_decoder()
        self.assertEqual(validate_metadata(self.bundle, allow_legacy_development=True)["documentDecoderSha256"], receipt["sha256"])
        decoder.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "decoder differs"):
            validate_metadata(self.bundle, allow_legacy_development=True)
        decoder.write_bytes(b"synthetic-decoder")
        path.unlink()
        with self.assertRaises(ValueError):
            validate_metadata(self.bundle, allow_legacy_development=True)

    def test_decoder_inventory_and_runtime_scope_mutations_are_rejected(self):
        _, path, receipt = self.add_decoder()
        for field, value in (("path", "../outside"), ("minimumMacOS", "27.0"),
                             ("architecture", "x86_64"), ("sourceSha256", {"../outside": "a" * 64})):
            changed = {**receipt, field: value}
            path.write_text(json.dumps(changed))
            with self.assertRaises(ValueError):
                validate_metadata(self.bundle, allow_legacy_development=True)

    def test_failed_publication_preserves_previous_bundle_and_stage(self):
        stage = self.root / "stage.app"
        stage.mkdir()
        (stage / "marker").write_text("new")
        def fail_stage(source, target):
            if source == stage:
                raise OSError("injected rename failure")
            source.rename(target)
        before = self.info_path.read_bytes()
        with self.assertRaisesRegex(OSError, "injected"):
            publish_bundle(stage, self.bundle, rename=fail_stage)
        self.assertEqual(self.info_path.read_bytes(), before)
        self.assertEqual((stage / "marker").read_text(), "new")
        backups = list(self.root.glob(".nativeforensics-previous-*"))
        self.assertEqual(len(backups), 1)
        self.assertTrue(backups[0].name.endswith(".noindex"))
        self.assertEqual(list(backups[0].iterdir()), [])

    def test_publication_replaces_bundle_only_after_valid_stage_exists(self):
        stage = self.root / "stage.app"
        stage.mkdir()
        (stage / "marker").write_text("new")
        previous = self.tree_bytes(self.bundle)
        publish_bundle(stage, self.bundle)
        self.assertEqual((self.bundle / "marker").read_text(), "new")
        self.assertFalse(stage.exists())
        backups = list(self.root.glob(".nativeforensics-previous-*"))
        self.assertEqual(len(backups), 1)
        self.assertTrue(backups[0].name.endswith(".noindex"))
        self.assertEqual(self.tree_bytes(backups[0] / self.bundle.name), previous)

    @staticmethod
    def tree_bytes(root):
        return {path.relative_to(root).as_posix(): path.read_bytes() for path in root.rglob("*") if path.is_file()}

    @staticmethod
    def file_identity(path):
        identity = path.stat(follow_symlinks=False)
        return identity.st_dev, identity.st_ino

    def test_staging_failure_preserves_substituted_stage_or_ancestor_and_primary_error(self):
        for variant in ("stage", "ancestor"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                binary = root / "compiled/NativeForensics"
                binary.parent.mkdir()
                binary.write_bytes(b"synthetic raw compiled bytes")
                receipt = root / "build-receipt.json"
                receipt.write_text("{}")
                failure = OSError("owned staging fault")
                observed = {}
                actual_copy = shutil.copy2
                def substitute(source, target):
                    actual_copy(source, target)
                    stage_root = Path(target).parents[3]
                    observed["stage"] = stage_root
                    observed["stageIdentity"] = self.file_identity(stage_root)
                    if variant == "stage":
                        displaced = root / "displaced-stage"
                        stage_root.rename(displaced)
                    else:
                        displaced_dist = root / "displaced-dist"
                        stage_root.parent.rename(displaced_dist)
                        stage_root.parent.mkdir()
                        displaced = displaced_dist / stage_root.name
                    observed["displaced"] = displaced
                    stage_root.mkdir()
                    canary = stage_root / "foreign-canary"
                    canary.write_bytes(b"foreign stage bytes")
                    observed["canary"] = canary
                    observed["canaryIdentity"] = self.file_identity(canary)
                    raise failure
                diagnostics = io.StringIO()
                # This reaches the real staging exception handler using an
                # owned copy fault; no signing/decoder/build command executes.
                with patch.object(package_app, "ROOT", root), \
                     patch.object(package_app, "verify_build_receipt"), \
                     patch.object(package_app.shutil, "copy2", side_effect=substitute), \
                     patch.object(package_app.sys, "stderr", diagnostics):
                    with self.assertRaises(OSError) as caught:
                        package_app.stage_bundle(binary, receipt)
                self.assertIs(caught.exception, failure)
                self.assertTrue(observed["stage"].name.endswith(".noindex"))
                self.assertEqual(self.file_identity(observed["displaced"]), observed["stageIdentity"])
                self.assertEqual(self.file_identity(observed["canary"]), observed["canaryIdentity"])
                self.assertEqual(observed["canary"].read_bytes(), b"foreign stage bytes")
                self.assertEqual((observed["displaced"] / "NativeForensics.app/Contents/MacOS/NativeForensics").read_bytes(), binary.read_bytes())
                self.assertIn("path candidate for manual review (no automatic cleanup): " + str(observed["stage"]), diagnostics.getvalue())

    def test_successful_publication_retains_previous_app_and_substituted_backup(self):
        stage = self.root / "stage.app"
        stage.mkdir()
        (stage / "marker").write_bytes(b"new app")
        previous = self.tree_bytes(self.bundle)
        observed = {}
        def substitute_backup(source, target):
            source.rename(target)
            if source == self.bundle:
                observed["backup"] = target.parent
            elif source == stage:
                backup = observed["backup"]
                displaced = self.root / "displaced-backup"
                backup.rename(displaced)
                backup.mkdir()
                canary = backup / "foreign-canary"
                canary.write_bytes(b"foreign backup bytes")
                observed.update(displaced=displaced, canary=canary, identity=self.file_identity(canary))
        diagnostics = io.StringIO()
        with patch.object(package_app.sys, "stderr", diagnostics):
            publish_bundle(stage, self.bundle, rename=substitute_backup)
        self.assertEqual((self.bundle / "marker").read_bytes(), b"new app")
        self.assertEqual(self.tree_bytes(observed["displaced"] / self.bundle.name), previous)
        self.assertEqual(self.file_identity(observed["canary"]), observed["identity"])
        self.assertEqual(observed["canary"].read_bytes(), b"foreign backup bytes")
        self.assertTrue(observed["backup"].name.endswith(".noindex"))
        self.assertIn(str(observed["backup"]), diagnostics.getvalue())

    def test_failed_publication_retains_substituted_empty_backup_and_stage(self):
        stage = self.root / "stage.app"
        stage.mkdir()
        (stage / "marker").write_bytes(b"new app")
        destination = self.root / "new-destination.app"
        observed = {}
        failure = OSError("owned publication failure")
        def substitute_backup_and_fail(source, target):
            self.assertEqual(source, stage)
            self.assertEqual(target, destination)
            backup = next(self.root.glob(".nativeforensics-previous-*"))
            displaced = self.root / "displaced-empty-backup"
            backup.rename(displaced)
            backup.mkdir()
            canary = backup / "foreign-canary"
            canary.write_bytes(b"foreign empty-backup bytes")
            observed.update(displaced=displaced, canary=canary, identity=self.file_identity(canary))
            raise failure
        with self.assertRaises(OSError) as caught:
            publish_bundle(stage, destination, rename=substitute_backup_and_fail)
        self.assertIs(caught.exception, failure)
        self.assertFalse(destination.exists())
        self.assertEqual((stage / "marker").read_bytes(), b"new app")
        self.assertEqual(list(observed["displaced"].iterdir()), [])
        self.assertEqual(self.file_identity(observed["canary"]), observed["identity"])
        self.assertEqual(observed["canary"].read_bytes(), b"foreign empty-backup bytes")

    def test_blocked_rollback_preserves_original_backup_and_foreign_destination(self):
        stage = self.root / "stage.app"
        stage.mkdir()
        (stage / "marker").write_bytes(b"new app")
        previous = self.tree_bytes(self.bundle)
        failure = OSError("owned stage rename refused")
        def occupy_destination(source, target):
            if source == stage:
                target.mkdir()
                (target / "foreign-canary").write_bytes(b"foreign destination")
                raise failure
            source.rename(target)
        with self.assertRaises(OSError) as caught:
            publish_bundle(stage, self.bundle, rename=occupy_destination)
        self.assertIs(caught.exception, failure)
        backup = next(self.root.glob(".nativeforensics-previous-*"))
        self.assertEqual(self.tree_bytes(backup / self.bundle.name), previous)
        self.assertEqual((self.bundle / "foreign-canary").read_bytes(), b"foreign destination")
        self.assertEqual((stage / "marker").read_bytes(), b"new app")

    def test_publish_cli_retains_empty_and_substituted_stage_parents(self):
        for variant in ("empty", "substituted-empty", "substituted-nonempty"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                dist = root / "dist"
                stage_root = dist / ".nativeforensics-stage-fixture.noindex"
                stage = stage_root / "NativeForensics.app"
                stage.mkdir(parents=True)
                (stage / "marker").write_bytes(b"new app")
                observed = {}
                def publish_and_substitute(source, target):
                    publish_bundle(source, target)
                    if variant != "empty":
                        displaced = root / "displaced-stage"
                        stage_root.rename(displaced)
                        stage_root.mkdir()
                        observed["displaced"] = displaced
                    observed["stageIdentity"] = self.file_identity(stage_root)
                    if variant == "substituted-nonempty":
                        (stage_root / "foreign-canary").write_bytes(b"foreign CLI stage")
                stdout, stderr = io.StringIO(), io.StringIO()
                with patch.object(package_app, "ROOT", root), \
                     patch.object(package_app.sys, "argv", ["package_app.py", "--publish", str(stage)]), \
                     patch.object(package_app, "validate_bundle"), \
                     patch.object(package_app, "publish_bundle", side_effect=publish_and_substitute), \
                     patch.object(package_app.sys, "stdout", stdout), \
                     patch.object(package_app.sys, "stderr", stderr):
                    self.assertEqual(package_app.main(), 0)
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual((dist / "NativeForensics.app/marker").read_bytes(), b"new app")
                self.assertEqual(self.file_identity(stage_root), observed["stageIdentity"])
                if variant == "substituted-nonempty":
                    self.assertEqual((stage_root / "foreign-canary").read_bytes(), b"foreign CLI stage")
                else:
                    self.assertEqual(list(stage_root.iterdir()), [])
                self.assertIn(str(stage_root), stderr.getvalue())

    def test_diagnostic_failure_does_not_replace_publication_error(self):
        class BrokenDiagnosticStream:
            def write(self, text):
                raise BrokenPipeError("owned diagnostic pipe closed")
        closed = io.StringIO()
        closed.close()
        for stream in (closed, BrokenDiagnosticStream()):
            with self.subTest(stream=type(stream).__name__):
                stage = self.root / ("stage-" + type(stream).__name__ + ".app")
                stage.mkdir()
                (stage / "marker").write_bytes(b"new app")
                destination = self.root / ("target-" + type(stream).__name__ + ".app")
                failure = OSError("original owned publication failure")
                def refuse(source, target):
                    raise failure
                with patch.object(package_app.sys, "stderr", stream):
                    with self.assertRaises(OSError) as caught:
                        publish_bundle(stage, destination, rename=refuse)
                self.assertIs(caught.exception, failure)
                self.assertEqual((stage / "marker").read_bytes(), b"new app")
                self.assertFalse(destination.exists())

    def test_publication_refuses_symlink_destination(self):
        stage = self.root / "stage.app"
        stage.mkdir()
        alias = self.root / "alias.app"
        alias.symlink_to(self.bundle)
        before = self.info_path.read_bytes()
        with self.assertRaisesRegex(ValueError, "symlinks"):
            publish_bundle(stage, alias)
        self.assertEqual(self.info_path.read_bytes(), before)

    def test_cache_receipt_requires_complete_relink_and_notice_sidecars(self):
        cache = self.root / "engine-cache"
        inventory = {}
        for name in ("NFTSKEngine.o", "libtsk.a", "libewf.a", "Relink.command", "link-command.json"):
            path = cache / "relink" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(name.encode())
            inventory[name] = hashlib.sha256(name.encode()).hexdigest()
        licenses = cache / "licenses/component/LICENSE"
        licenses.parent.mkdir(parents=True)
        licenses.write_bytes(b"synthetic-license")
        notice = cache / "licenses/THIRD_PARTY_NOTICES.md"
        notice.write_bytes(b"synthetic-notices")
        receipt = {**self.receipt, "relinkSha256": inventory}
        with patch.object(build_native_engine, "CACHE", cache):
            self.assertTrue(build_native_engine.valid_sidecars(receipt))
            (cache / "relink/NFTSKEngine.o").write_bytes(b"changed")
            self.assertFalse(build_native_engine.valid_sidecars(receipt))
            (cache / "relink/NFTSKEngine.o").write_bytes(b"NFTSKEngine.o")
            notice.unlink()
            self.assertFalse(build_native_engine.valid_sidecars(receipt))


class BuildCleanupTests(unittest.TestCase):
    def test_copied_pipeline_retains_snapshot_and_stage_candidates_and_exit_status(self):
        # This exercises the exact shell pipeline with fixture-only PATH tools.
        # It proves cleanup control flow, not a native build, drain, or launch.
        script = Path(__file__).resolve().parents[2] / "script/build_and_run.sh"
        driver_source = r'''
import json
from pathlib import Path
import sys
root, variant, tool = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
args = sys.argv[4:]
state_path = root / "observed.json"
state = json.loads(state_path.read_text()) if state_path.exists() else {}
def identity(path):
    value = path.stat(follow_symlinks=False)
    return [value.st_dev, value.st_ino]
def save():
    state_path.write_text(json.dumps(state))
def substitute(kind, candidate):
    if kind == "snapshot":
        state["originalIdentity"] = identity(candidate)
        if variant.endswith("ancestor"):
            displaced_parent = root / "displaced-build"
            candidate.parent.rename(displaced_parent)
            candidate.parent.mkdir()
            displaced = displaced_parent / candidate.name
        else:
            displaced = root / "displaced-snapshot"
            candidate.rename(displaced)
        candidate.write_bytes(b"foreign snapshot canary")
        canary = candidate
    else:
        state["originalIdentity"] = identity(candidate)
        if variant.endswith("ancestor"):
            displaced_parent = root / "displaced-dist"
            candidate.parent.rename(displaced_parent)
            candidate.parent.mkdir()
            displaced = displaced_parent / candidate.name
        else:
            displaced = root / "displaced-stage"
            candidate.rename(displaced)
        candidate.mkdir()
        canary = candidate / "foreign-canary"
        canary.write_bytes(b"foreign stage canary")
    state.update(displaced=str(displaced), canary=str(canary), canaryIdentity=identity(canary))
    save()
    raise SystemExit(73)
if tool == "swift":
    if "--show-bin-path" in args:
        print(root / ".build/release")
elif args[0] == "-":
    sys.stdin.read()  # Consume the drain heredoc without touching any process.
    if variant.startswith("stage-"):
        substitute("stage", Path(state["stage"]).parent)
elif args[0].endswith("build_native_engine.py"):
    pass
elif "--snapshot" in args:
    snapshot = Path(args[args.index("--snapshot") + 1])
    snapshot.write_bytes(b"owned synthetic input snapshot")
    state.update(snapshot=str(snapshot), snapshotIdentity=identity(snapshot))
    save()
elif "--seal-build" in args:
    snapshot = Path(state["snapshot"])
    if variant.startswith("snapshot-"):
        substitute("snapshot", snapshot)
    receipt = root / "fixture-build-receipt.json"
    receipt.write_text("{}")
    print(receipt)
elif "--stage" in args:
    stage = root / "dist/.nativeforensics-stage-fixture.noindex/NativeForensics.app"
    stage.mkdir(parents=True)
    (stage / "marker").write_bytes(b"new synthetic app")
    state["stage"] = str(stage)
    save()
    print(stage)
elif "--publish" in args:
    stage = Path(state["stage"])
    destination = root / "dist/NativeForensics.app"
    backup = root / "dist/.nativeforensics-previous-fixture.noindex"
    backup.mkdir()
    destination.rename(backup / destination.name)
    stage.rename(destination)
else:
    raise SystemExit("Unknown fixture-only invocation")
'''
        for variant in ("snapshot-leaf", "snapshot-ancestor", "stage-leaf", "stage-ancestor", "success"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                (root / "script").mkdir()
                copied_script = root / "script/build_and_run.sh"
                shutil.copy2(script, copied_script)
                previous = root / "dist/NativeForensics.app"
                previous.mkdir(parents=True)
                (previous / "marker").write_bytes(b"previous synthetic app")
                driver = root / "fixture-driver.py"
                driver.write_text(driver_source)
                tools = root / "fixture-tools"
                tools.mkdir()
                for name in ("python3", "swift"):
                    launcher = tools / name
                    command = " ".join(shlex.quote(str(item)) for item in (sys.executable, driver, root, variant, name))
                    launcher.write_text('#!/bin/sh\nexec ' + command + ' "$@"\n')
                    launcher.chmod(0o755)
                environment = {**os.environ, "PATH": str(tools) + os.pathsep + os.environ.get("PATH", "")}
                result = subprocess.run(["/bin/bash", str(copied_script), "--build-only"], cwd=root,
                                        env=environment, capture_output=True, text=True, timeout=15)
                state = json.loads((root / "observed.json").read_text())
                snapshot = Path(state["snapshot"])
                self.assertIn("Input snapshot path candidate for manual review (no automatic cleanup): " + str(snapshot), result.stderr)
                if variant == "success":
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(snapshot.read_bytes(), b"owned synthetic input snapshot")
                    self.assertEqual(BundleTests.file_identity(snapshot), tuple(state["snapshotIdentity"]))
                    self.assertEqual(list(Path(state["stage"]).parent.iterdir()), [])
                    self.assertEqual((previous / "marker").read_bytes(), b"new synthetic app")
                    self.assertEqual((root / "dist/.nativeforensics-previous-fixture.noindex/NativeForensics.app/marker").read_bytes(), b"previous synthetic app")
                else:
                    self.assertEqual(result.returncode, 73, result.stderr)
                    displaced, canary = Path(state["displaced"]), Path(state["canary"])
                    self.assertEqual(BundleTests.file_identity(displaced), tuple(state["originalIdentity"]))
                    self.assertEqual(BundleTests.file_identity(canary), tuple(state["canaryIdentity"]))
                    if variant.startswith("snapshot-"):
                        self.assertEqual(displaced.read_bytes(), b"owned synthetic input snapshot")
                        self.assertEqual(canary.read_bytes(), b"foreign snapshot canary")
                        self.assertEqual((previous / "marker").read_bytes(), b"previous synthetic app")
                    else:
                        self.assertEqual((displaced / "NativeForensics.app/marker").read_bytes(), b"new synthetic app")
                        self.assertEqual(canary.read_bytes(), b"foreign stage canary")
                        self.assertEqual(snapshot.read_bytes(), b"owned synthetic input snapshot")
                        old_app = root / "displaced-dist/NativeForensics.app" if variant.endswith("ancestor") else previous
                        self.assertEqual((old_app / "marker").read_bytes(), b"previous synthetic app")
                        self.assertIn("Build stage path candidate for manual review (no automatic cleanup): " + str(Path(state["stage"]).parent), result.stderr)


if __name__ == "__main__":
    unittest.main()

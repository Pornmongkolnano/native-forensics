"""Artifact regressions use temporary synthetic bundles, not application/evidence data."""
from pathlib import Path
import hashlib
import json
import plistlib
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "script"))
from package_app import publish_bundle
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
        result = validate_metadata(self.bundle)
        self.assertEqual(result["minimumMacOS"], "14.0")
        self.assertEqual(result["helperSha256"], self.receipt["engineSha256"])

    def test_changed_helper_is_rejected(self):
        (self.bundle / "Contents/Helpers/NFTSKEngine").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "helper differs"):
            validate_metadata(self.bundle)

    def test_missing_or_changed_notices_are_rejected(self):
        path = self.bundle / "Contents/Resources/EngineLicenses/THIRD_PARTY_NOTICES.md"
        path.unlink()
        with self.assertRaises(ValueError):
            validate_metadata(self.bundle)
        path.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "notices differ"):
            validate_metadata(self.bundle)

    def test_license_escape_and_changed_license_are_rejected(self):
        self.receipt["licenseSha256"] = {"NativeEngine/licenses/../../outside": "a" * 64}
        self.write_receipt()
        with self.assertRaisesRegex(ValueError, "invalid path"):
            validate_metadata(self.bundle)
        self.receipt["licenseSha256"] = {"NativeEngine/licenses/component/LICENSE": "a" * 64}
        self.write_receipt()
        with self.assertRaisesRegex(ValueError, "license does not match"):
            validate_metadata(self.bundle)

    def test_symlinked_helper_is_rejected_without_following(self):
        helper = self.bundle / "Contents/Helpers/NFTSKEngine"
        helper.unlink()
        helper.symlink_to(self.info_path)
        with self.assertRaisesRegex(ValueError, "symlinks"):
            validate_metadata(self.bundle)

    def test_minimum_version_mismatch_is_rejected(self):
        self.receipt["toolchain"]["minimumMacOS"] = "27.0"
        self.write_receipt()
        with self.assertRaisesRegex(ValueError, "minimum macOS"):
            validate_metadata(self.bundle)

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
        self.assertEqual(validate_metadata(self.bundle)["documentDecoderSha256"], receipt["sha256"])
        decoder.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "decoder differs"):
            validate_metadata(self.bundle)
        decoder.write_bytes(b"synthetic-decoder")
        path.unlink()
        with self.assertRaises(ValueError):
            validate_metadata(self.bundle)

    def test_decoder_inventory_and_runtime_scope_mutations_are_rejected(self):
        _, path, receipt = self.add_decoder()
        for field, value in (("path", "../outside"), ("minimumMacOS", "27.0"),
                             ("architecture", "x86_64"), ("sourceSha256", {"../outside": "a" * 64})):
            changed = {**receipt, field: value}
            path.write_text(json.dumps(changed))
            with self.assertRaises(ValueError):
                validate_metadata(self.bundle)

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
        self.assertFalse(list(self.root.glob(".nativeforensics-previous-*")))

    def test_publication_replaces_bundle_only_after_valid_stage_exists(self):
        stage = self.root / "stage.app"
        stage.mkdir()
        (stage / "marker").write_text("new")
        publish_bundle(stage, self.bundle)
        self.assertEqual((self.bundle / "marker").read_text(), "new")
        self.assertFalse(stage.exists())
        self.assertFalse(list(self.root.glob(".nativeforensics-previous-*")))

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


if __name__ == "__main__":
    unittest.main()

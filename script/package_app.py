#!/usr/bin/env python3
"""Stage a verified development bundle, then replace only this checkout's app.

Staging leaves the installed development app intact if copying, metadata,
signing, or verification fails. Publication rolls back a failed rename.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile

from validate_app_bundle import (validate_bundle, XPC_BUNDLE_PATH, XPC_EXECUTABLE_PATH, XPC_IDENTIFIER,
                                 WORKER_EXECUTABLE_PATH, WORKER_IDENTIFIER,
                                 validate_xpc_entitlements, validate_worker_entitlements)
from source_provenance import (verify_build_receipt, apply_staged_privacy_transform, XPC_INFO_INPUT,
                               XPC_ENTITLEMENTS_INPUT, WORKER_ENTITLEMENTS_INPUT)

ROOT = Path(__file__).resolve().parents[1]
NAME = "NativeForensics"
APP_VERSION = "0.7.0"
APP_BUILD = "16"


def report_retained_path_candidate(label: str, candidate: Path) -> None:
    """Report a lexical candidate without adopting its current filesystem entry."""
    if sys.stderr is None:
        return
    try:
        print(f"{label} path candidate for manual review (no automatic cleanup): {candidate}", file=sys.stderr)
    except (OSError, ValueError):
        # Diagnostic failure must not replace a build/publication result.
        pass


def stage_bundle(binary: Path, build_receipt_path: Path) -> Path:
    build_inputs = json.loads(build_receipt_path.read_text())
    verify_build_receipt(ROOT, binary.parent, build_inputs)
    dist = ROOT / "dist"
    dist.mkdir(exist_ok=True)
    stage_root = Path(tempfile.mkdtemp(prefix=".nativeforensics-stage-", suffix=".noindex", dir=dist))
    bundle = stage_root / f"{NAME}.app"
    try:
        for directory in ("MacOS", "Helpers", "Resources/EngineLicenses"):
            (bundle / "Contents" / directory).mkdir(parents=True, exist_ok=True)
        shutil.copy2(binary, bundle / f"Contents/MacOS/{NAME}")
        if hashlib.sha256((bundle / f"Contents/MacOS/{NAME}").read_bytes()).hexdigest() != build_inputs["compiledBinarySha256"][NAME]:
            raise ValueError("Copied app differs from its pre-compilation/source-bound build receipt.")
        app_transform = apply_staged_privacy_transform(bundle / f"Contents/MacOS/{NAME}", build_inputs["buildConfiguration"])
        shutil.copy2(ROOT / ".engine/bin/NFTSKEngine", bundle / "Contents/Helpers/NFTSKEngine")
        decoder = binary.parent / "NFDocumentDecoder"
        if decoder.is_symlink() or not decoder.is_file():
            raise ValueError("Build NFDocumentDecoder beside the app binary before packaging.")
        copied_decoder = bundle / "Contents/Helpers/NFDocumentDecoder"
        shutil.copy2(decoder, copied_decoder)
        if hashlib.sha256(copied_decoder.read_bytes()).hexdigest() != build_inputs["compiledBinarySha256"]["NFDocumentDecoder"]:
            raise ValueError("Copied decoder differs from its pre-compilation/source-bound build receipt.")
        decoder_transform = apply_staged_privacy_transform(copied_decoder, build_inputs["buildConfiguration"])
        subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", str(copied_decoder)], check=True)
        xpc_bundle = bundle / XPC_BUNDLE_PATH
        xpc_binary = bundle / XPC_EXECUTABLE_PATH
        xpc_binary.parent.mkdir(parents=True)
        shutil.copy2(binary.parent / "NFDocumentDecoderXPC", xpc_binary)
        if hashlib.sha256(xpc_binary.read_bytes()).hexdigest() != build_inputs["compiledBinarySha256"]["NFDocumentDecoderXPC"]:
            raise ValueError("Copied XPC decoder differs from its source-bound raw compiled receipt.")
        xpc_transform = apply_staged_privacy_transform(xpc_binary, build_inputs["buildConfiguration"])
        xpc_info_path = xpc_bundle / "Contents/Info.plist"
        shutil.copy2(ROOT / XPC_INFO_INPUT, xpc_info_path)
        xpc_info = plistlib.loads(xpc_info_path.read_bytes())
        entitlements_path = ROOT / XPC_ENTITLEMENTS_INPUT
        entitlements = plistlib.loads(entitlements_path.read_bytes())
        validate_xpc_entitlements(entitlements)
        worker_binary = bundle / WORKER_EXECUTABLE_PATH
        worker_binary.parent.mkdir(parents=True)
        shutil.copy2(binary.parent / "NFDocumentDecoderWorker", worker_binary)
        if hashlib.sha256(worker_binary.read_bytes()).hexdigest() != build_inputs["compiledBinarySha256"]["NFDocumentDecoderWorker"]:
            raise ValueError("Copied parser worker differs from its source-bound raw compiled receipt.")
        worker_transform = apply_staged_privacy_transform(worker_binary, build_inputs["buildConfiguration"])
        worker_entitlements_path = ROOT / WORKER_ENTITLEMENTS_INPUT
        worker_entitlements = plistlib.loads(worker_entitlements_path.read_bytes())
        validate_worker_entitlements(worker_entitlements)
        subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", "--identifier", WORKER_IDENTIFIER,
                        "--entitlements", str(worker_entitlements_path), str(worker_binary)], check=True)
        subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", "--identifier", XPC_IDENTIFIER,
                        "--entitlements", str(entitlements_path), str(xpc_bundle)], check=True)
        resources = bundle / "Contents/Resources"
        shutil.copy2(ROOT / "Assets/AppIcon/AppIcon.icns", resources / "AppIcon.icns")
        shutil.copytree(ROOT / "NativeEngine/licenses", resources / "EngineLicenses", dirs_exist_ok=True)
        shutil.copy2(ROOT / "THIRD_PARTY_NOTICES.md", resources / "EngineLicenses/THIRD_PARTY_NOTICES.md")
        receipt = json.loads((ROOT / ".engine/manifest.json").read_text())
        receipt["licenses"] = "Contents/Resources/EngineLicenses/"
        receipt["distributionArtifactsBundled"] = False
        receipt["relinkArtifacts"] = "Not bundled; development checkout .engine/relink/"
        receipt["sourceArtifacts"] = "Not bundled; development checkout .engine/downloads/ and tracked patches"
        (resources / "engine-manifest.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        decoder_receipt = {
            "schemaVersion": 2, "protocolVersion": 1,
            "path": "Contents/Helpers/NFDocumentDecoder",
            "sha256": hashlib.sha256(copied_decoder.read_bytes()).hexdigest(),
            "architecture": receipt["architecture"],
            "minimumMacOS": receipt["toolchain"]["minimumMacOS"],
            "scope": "Local bounded document and image inspection in an owned process",
            **build_inputs["products"]["NFDocumentDecoder"],
            "compiledBinarySha256": build_inputs["compiledBinarySha256"]["NFDocumentDecoder"],
            "buildInputScope": build_inputs["scope"],
            "buildConfiguration": build_inputs["buildConfiguration"], "buildPathPolicy": build_inputs["buildPathPolicy"],
            "packagingTransform": decoder_transform,
        }
        (resources / "document-decoder-manifest.json").write_text(json.dumps(decoder_receipt, indent=2, sort_keys=True) + "\n")
        xpc_receipt = {
            "schemaVersion": 2, "protocolVersion": 2,
            "path": XPC_BUNDLE_PATH, "executablePath": XPC_EXECUTABLE_PATH,
            "bundleIdentifier": XPC_IDENTIFIER, "sha256": hashlib.sha256(xpc_binary.read_bytes()).hexdigest(),
            "infoPlistSha256": hashlib.sha256(xpc_info_path.read_bytes()).hexdigest(),
            "entitlementsSourceSha256": build_inputs["products"]["NFDocumentDecoderXPC"]["sourceSha256"][XPC_ENTITLEMENTS_INPUT],
            "entitlements": entitlements,
            "architecture": receipt["architecture"], "minimumMacOS": receipt["toolchain"]["minimumMacOS"],
            "scope": "App Sandbox broker receiving bounded bytes and owning a fresh inheriting parser worker per request",
            **build_inputs["products"]["NFDocumentDecoderXPC"],
            "compiledBinarySha256": build_inputs["compiledBinarySha256"]["NFDocumentDecoderXPC"],
            "buildInputScope": build_inputs["scope"], "buildConfiguration": build_inputs["buildConfiguration"],
            "buildPathPolicy": build_inputs["buildPathPolicy"], "packagingTransform": xpc_transform,
            "worker": {
                "path": WORKER_EXECUTABLE_PATH, "identifier": WORKER_IDENTIFIER,
                "sha256": hashlib.sha256(worker_binary.read_bytes()).hexdigest(),
                "entitlementsSourceSha256": build_inputs["products"]["NFDocumentDecoderWorker"]["sourceSha256"][WORKER_ENTITLEMENTS_INPUT],
                "entitlements": worker_entitlements,
                "architecture": receipt["architecture"], "minimumMacOS": receipt["toolchain"]["minimumMacOS"],
                **build_inputs["products"]["NFDocumentDecoderWorker"],
                "compiledBinarySha256": build_inputs["compiledBinarySha256"]["NFDocumentDecoderWorker"],
                "buildInputScope": build_inputs["scope"], "buildConfiguration": build_inputs["buildConfiguration"],
                "buildPathPolicy": build_inputs["buildPathPolicy"], "packagingTransform": worker_transform,
            },
        }
        (resources / "document-xpc-manifest.json").write_text(json.dumps(xpc_receipt, indent=2, sort_keys=True) + "\n")
        if (xpc_info.get("LSMinimumSystemVersion") != receipt["toolchain"]["minimumMacOS"]
                or xpc_info.get("CFBundleShortVersionString") != APP_VERSION
                or xpc_info.get("CFBundleVersion") != APP_BUILD):
            raise ValueError("XPC metadata specification differs from app version or minimum macOS.")
        identifier = "io.github.pornmongkolnano.nativeforensics"
        case_type = identifier + ".case"
        info = {
            "CFBundleExecutable": NAME, "CFBundleIdentifier": identifier,
            "CFBundleName": NAME, "CFBundleDisplayName": "Native Forensics",
            "NSDownloadsFolderUsageDescription": "Read the evidence files and case folders you select, and save verified exports to the destinations you choose.",
            "NSDocumentsFolderUsageDescription": "Read the evidence files and case folders you select, and save verified exports to the destinations you choose.",
            "NSDesktopFolderUsageDescription": "Read the evidence files and case folders you select, and save verified exports to the destinations you choose.",
            "CFBundlePackageType": "APPL", "CFBundleShortVersionString": APP_VERSION,
            "CFBundleVersion": APP_BUILD, "CFBundleIconFile": "AppIcon",
            "LSMinimumSystemVersion": receipt["toolchain"]["minimumMacOS"],
            "NSPrincipalClass": "NSApplication", "NSHighResolutionCapable": True,
            "CFBundleDocumentTypes": [{"CFBundleTypeName": "Native Forensics Case",
                "CFBundleTypeRole": "Editor", "LSItemContentTypes": [case_type], "LSTypeIsPackage": True}],
            "UTExportedTypeDeclarations": [{"UTTypeIdentifier": case_type,
                "UTTypeDescription": "Native Forensics Case", "UTTypeConformsTo": ["com.apple.package"],
                "UTTypeTagSpecification": {"public.filename-extension": ["nativecase"]}}],
        }
        with (bundle / "Contents/Info.plist").open("wb") as stream:
            plistlib.dump(info, stream)
        app_sources = {"schemaVersion": 1, **build_inputs["products"]["NativeForensics"],
            "path": "Contents/MacOS/NativeForensics", "appVersion": info["CFBundleShortVersionString"],
            "appBuild": info["CFBundleVersion"], "compiledBinarySha256": build_inputs["compiledBinarySha256"]["NativeForensics"],
            "buildInputScope": build_inputs["scope"],
            "buildConfiguration": build_inputs["buildConfiguration"], "buildPathPolicy": build_inputs["buildPathPolicy"],
            "packagingTransform": app_transform,
            "binaryBinding": "pre-sign compiled bytes verified before staging; receipt sealed by enclosing bundle signature"}
        (resources / "app-source-manifest.json").write_text(json.dumps(app_sources, indent=2, sort_keys=True) + "\n")
        verify_build_receipt(ROOT, binary.parent, build_inputs)
        # The native build already signs the helper. Preserve its receipt bytes.
        subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", str(bundle)], check=True)
        validate_bundle(bundle, source_root=ROOT)
        return bundle
    except BaseException:
        report_retained_path_candidate("Build stage", stage_root)
        raise


def publish_bundle(stage: Path, destination: Path, rename=None) -> None:
    """Publish a previously validated bundle on the same filesystem."""
    rename = rename or (lambda source, target: source.rename(target))
    if stage.is_symlink() or not stage.is_dir() or destination.is_symlink():
        raise ValueError("App publication refuses symlinks or a missing stage.")
    if stage.stat().st_dev != destination.parent.stat().st_dev:
        raise ValueError("Staged app must be on the publication filesystem.")
    backup_root = Path(tempfile.mkdtemp(prefix=".nativeforensics-previous-", suffix=".noindex", dir=destination.parent))
    backup = backup_root / destination.name
    had_previous = destination.exists()
    published = False
    try:
        if had_previous:
            rename(destination, backup)
        try:
            rename(stage, destination)
            published = True
        except BaseException:
            if had_previous and backup.exists() and not destination.exists():
                backup.rename(destination)
            raise
    finally:
        # Retain even empty roots: a pathname cannot authorize cleanup after
        # substitution, and a backup may still contain the previous app.
        report_retained_path_candidate("Previous app directory", backup_root)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--stage", type=Path, metavar="APP_BINARY")
    choice.add_argument("--publish", type=Path, metavar="STAGED_APP")
    parser.add_argument("--build-receipt", type=Path, help="Required pre-compilation input/compiled-binary receipt when staging")
    args = parser.parse_args()
    if args.stage:
        if args.build_receipt is None:
            parser.error("--stage requires --build-receipt produced by source_provenance.py before/after compilation")
        print(stage_bundle(args.stage, args.build_receipt))
    else:
        stage = args.publish
        dist = ROOT / "dist"
        if stage.parent.parent != dist or not stage.parent.name.startswith(".nativeforensics-stage-") or stage.name != f"{NAME}.app":
            parser.error("The stage must be an app created inside this checkout's dist directory.")
        validate_bundle(stage, source_root=ROOT)
        publish_bundle(stage, dist / f"{NAME}.app")
        report_retained_path_candidate("Build stage", stage.parent)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

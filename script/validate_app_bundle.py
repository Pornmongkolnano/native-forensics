#!/usr/bin/env python3
"""Check a local app's provenance and runtime closure, without launching it.

This validates a development artifact; it does not certify notarization or
filesystem coverage. No network access, evidence input, or write is performed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import plistlib
import subprocess
import sys
from source_provenance import validate_source_receipt, check_binary_privacy, BUILD_PATH_POLICY


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def regular(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Required bundle file is absent or a symlink: {path.name}")


def validate_metadata(bundle: Path, *, source_root: Path | None = None,
                      allow_legacy_development: bool = False) -> dict:
    if bundle.is_symlink() or not bundle.is_dir():
        raise ValueError("The app bundle must be a real directory.")
    for path in bundle.rglob("*"):
        if path.is_symlink():
            raise ValueError("This app layout must not contain symlinks.")
    info_path = bundle / "Contents/Info.plist"
    receipt_path = bundle / "Contents/Resources/engine-manifest.json"
    regular(info_path)
    regular(receipt_path)
    with info_path.open("rb") as stream:
        info = plistlib.load(stream)
    receipt = json.loads(receipt_path.read_text())
    if not isinstance(info, dict) or not isinstance(receipt, dict):
        raise ValueError("Invalid app or engine metadata.")
    expected = {"CFBundleExecutable": "NativeForensics", "CFBundlePackageType": "APPL",
                "CFBundleIdentifier": "io.github.pornmongkolnano.nativeforensics"}
    if any(info.get(key) != value for key, value in expected.items()):
        raise ValueError("App identity or executable declaration is invalid.")
    minimum = receipt.get("toolchain", {}).get("minimumMacOS")
    if not minimum or info.get("LSMinimumSystemVersion") != minimum:
        raise ValueError("App and engine minimum macOS versions differ.")
    if receipt.get("schemaVersion") != 1 or receipt.get("protocolVersion") != 1:
        raise ValueError("Unsupported engine receipt or protocol version.")
    helper = bundle / "Contents/Helpers/NFTSKEngine"
    for path in (helper, bundle / "Contents/MacOS/NativeForensics",
                 bundle / "Contents/Resources/AppIcon.icns"):
        regular(path)
    if sha256(helper) != receipt.get("engineSha256"):
        raise ValueError("The bundled helper differs from its build receipt.")
    license_root = bundle / "Contents/Resources/EngineLicenses"
    if receipt.get("licenses") != "Contents/Resources/EngineLicenses/":
        raise ValueError("The receipt's license location is not bundle-relative.")
    inventory = receipt.get("licenseSha256")
    if not isinstance(inventory, dict) or not inventory:
        raise ValueError("The engine license inventory is missing.")
    for name, expected_hash in inventory.items():
        parts = PurePosixPath(name).parts
        if len(parts) < 3 or parts[:2] != ("NativeEngine", "licenses") or ".." in parts:
            raise ValueError("The license inventory contains an invalid path.")
        path = license_root.joinpath(*parts[2:])
        regular(path)
        if sha256(path) != expected_hash:
            raise ValueError(f"Bundled license does not match its receipt: {path.name}")
    notices = license_root / "THIRD_PARTY_NOTICES.md"
    regular(notices)
    if sha256(notices) != receipt.get("noticesSha256"):
        raise ValueError("The bundled third-party notices differ from the receipt.")
    if receipt.get("distributionArtifactsBundled") is not False:
        raise ValueError("Development bundle must disclose absent source/relink distribution artifacts.")
    decoder_receipt_path = bundle / "Contents/Resources/document-decoder-manifest.json"
    version = info.get("CFBundleShortVersionString", "0.0.0")
    try:
        parsed_version = tuple(int(part) for part in version.split("."))
        requires_decoder = parsed_version >= (0, 5, 0)
    except (ValueError, AttributeError):
        raise ValueError("Invalid application version.")
    decoder_hash = None
    complete_graph = parsed_version >= (0, 6, 0)
    if not complete_graph and not allow_legacy_development:
        raise ValueError("Legacy development receipts require explicit allow_legacy_development; current distributions require complete source graphs.")
    if requires_decoder or decoder_receipt_path.exists():
        regular(decoder_receipt_path)
        decoder_receipt = json.loads(decoder_receipt_path.read_text())
        decoder = bundle / "Contents/Helpers/NFDocumentDecoder"
        regular(decoder)
        expected_schema = 2 if complete_graph else 1
        if (decoder_receipt.get("schemaVersion") != expected_schema or decoder_receipt.get("protocolVersion") != 1
                or decoder_receipt.get("path") != "Contents/Helpers/NFDocumentDecoder"
                or decoder_receipt.get("architecture") != receipt.get("architecture")
                or decoder_receipt.get("minimumMacOS") != minimum):
            raise ValueError("Invalid document decoder receipt or runtime scope.")
        decoder_hash = sha256(decoder)
        if decoder_hash != decoder_receipt.get("sha256"):
            raise ValueError("The document decoder differs from its build receipt.")
        if complete_graph:
            validate_source_receipt(decoder_receipt, "NFDocumentDecoder", source_root)
            compiled = decoder_receipt.get("compiledBinarySha256")
            if not isinstance(compiled, str) or len(compiled) != 64 or any(value not in "0123456789abcdef" for value in compiled):
                raise ValueError("Missing decoder pre-sign compiled-binary binding.")
        else:
            source_hashes = decoder_receipt.get("sourceSha256")
            if not isinstance(source_hashes, dict) or not source_hashes:
                raise ValueError("The document decoder source inventory is missing.")
            for name, value in source_hashes.items():
                parts = PurePosixPath(name).parts
                if (".." in parts or not name.endswith(".swift") or not name.startswith(
                        ("Sources/NFDocumentDecoder/", "Sources/ForensicsCore/"))
                        or not isinstance(value, str) or len(value) != 64
                        or any(letter not in "0123456789abcdef" for letter in value)):
                    raise ValueError("Invalid document decoder source inventory.")
    app_graph_hash = decoder_graph_hash = None
    if complete_graph:
        app_source_path = bundle / "Contents/Resources/app-source-manifest.json"
        regular(app_source_path)
        app_sources = json.loads(app_source_path.read_text())
        if (app_sources.get("schemaVersion") != 1 or app_sources.get("path") != "Contents/MacOS/NativeForensics"
                or app_sources.get("appVersion") != version or app_sources.get("appBuild") != info.get("CFBundleVersion")):
            raise ValueError("Invalid application source binding or version scope.")
        inputs = validate_source_receipt(app_sources, "NativeForensics", source_root)
        if (app_sources.get("buildConfiguration") not in {"debug", "release"}
                or decoder_receipt.get("buildConfiguration") != app_sources.get("buildConfiguration")
                or app_sources.get("buildPathPolicy") != BUILD_PATH_POLICY
                or decoder_receipt.get("buildPathPolicy") != BUILD_PATH_POLICY):
            raise ValueError("Missing or inconsistent compiler/linker build-path policy receipt.")
        transform = "strip-S-on-staged-release-copy" if app_sources["buildConfiguration"] == "release" else "unstripped-local-debug-copy"
        if app_sources.get("packagingTransform") != transform or decoder_receipt.get("packagingTransform") != transform:
            raise ValueError("Missing or inconsistent staged debug-map transform receipt.")
        decoder_inputs = decoder_receipt["sourceSha256"]
        if any(inputs[name] != decoder_inputs[name] for name in set(inputs) & set(decoder_inputs)):
            raise ValueError("Application and decoder complete source graphs disagree on shared inputs.")
        app_graph_hash, decoder_graph_hash = app_sources["sourceGraphSha256"], decoder_receipt["sourceGraphSha256"]
        if inputs["Assets/AppIcon/AppIcon.icns"] != sha256(bundle / "Contents/Resources/AppIcon.icns"):
            raise ValueError("Bundled app icon differs from its complete input graph.")
        compiled = app_sources.get("compiledBinarySha256")
        if not isinstance(compiled, str) or len(compiled) != 64 or any(value not in "0123456789abcdef" for value in compiled):
            raise ValueError("Missing app pre-sign compiled-binary binding.")
    return {"appVersion": info.get("CFBundleShortVersionString"),
            "engineVersion": receipt.get("engineVersion"),
            "architecture": receipt.get("architecture"), "minimumMacOS": minimum,
            "helperSha256": receipt["engineSha256"], "documentDecoderSha256": decoder_hash,
            "appSourceGraphSha256": app_graph_hash, "decoderSourceGraphSha256": decoder_graph_hash,
            "buildConfiguration": app_sources["buildConfiguration"] if complete_graph else "unknown-legacy-development",
            "buildPathPolicy": app_sources["buildPathPolicy"] if complete_graph else "unknown-legacy-development",
            "packagingTransform": app_sources["packagingTransform"] if complete_graph else "unknown-legacy-development",
            "sourceProvenance": ("complete-graph-matches-source-root" if source_root is not None else "complete-recorded-graph")
                if complete_graph else "legacy-development-unbound"}


def command(argv: list[str]) -> str:
    result = subprocess.run(argv, capture_output=True, text=True, check=True)
    return result.stdout.strip()


def validate_bundle(bundle: Path, *, source_root: Path | None = None,
                    allow_legacy_development: bool = False) -> dict:
    result = validate_metadata(bundle, source_root=source_root, allow_legacy_development=allow_legacy_development)
    app = bundle / "Contents/MacOS/NativeForensics"
    helper = bundle / "Contents/Helpers/NFTSKEngine"
    binaries = [app, helper]
    if result.get("documentDecoderSha256"):
        binaries.append(bundle / "Contents/Helpers/NFDocumentDecoder")
    for binary in binaries:
        if result["sourceProvenance"] != "legacy-development-unbound" and result["buildConfiguration"] == "release":
            check_binary_privacy(binary)
        architectures = command(["/usr/bin/lipo", "-archs", str(binary)]).split()
        if result["architecture"] not in architectures:
            raise ValueError("App and helper architecture differ from the receipt.")
        lines = command(["/usr/bin/otool", "-L", str(binary)]).splitlines()[1:]
        dependencies = [line.strip().split(" (", 1)[0] for line in lines]
        if not dependencies or any(not value.startswith(("/usr/lib/", "/System/Library/"))
                                   for value in dependencies):
            raise ValueError("The app has a dynamic dependency outside macOS system libraries.")
    command(["/usr/bin/codesign", "--verify", "--strict", str(helper)])
    if result.get("documentDecoderSha256"):
        command(["/usr/bin/codesign", "--verify", "--strict", str(binaries[-1])])
    command(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(bundle)])
    result["validation"] = "passed-local-artifact-checks"
    result["compilerPathPrivacy"] = "passed-full-byte-scan" if result["sourceProvenance"] != "legacy-development-unbound" and result["buildConfiguration"] == "release" else "not-enforced-local-debug-or-legacy-development"
    result["distribution"] = "development; Developer ID/notarization and source/relink package not verified"
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--source-root", type=Path, help="Also compare complete input graphs with this current source tree")
    parser.add_argument("--allow-legacy-development", action="store_true", help="Inspect old incomplete development receipts; cannot be used by distribution packaging")
    args = parser.parse_args()
    print(json.dumps(validate_bundle(args.bundle, source_root=args.source_root,
                                    allow_legacy_development=args.allow_legacy_development), indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"App bundle validation failed: {error}", file=sys.stderr)
        raise SystemExit(1)

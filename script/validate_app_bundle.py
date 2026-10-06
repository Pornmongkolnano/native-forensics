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


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def regular(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Required bundle file is absent or a symlink: {path.name}")


def validate_metadata(bundle: Path) -> dict:
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
    return {"appVersion": info.get("CFBundleShortVersionString"),
            "engineVersion": receipt.get("engineVersion"),
            "architecture": receipt.get("architecture"), "minimumMacOS": minimum,
            "helperSha256": receipt["engineSha256"]}


def command(argv: list[str]) -> str:
    result = subprocess.run(argv, capture_output=True, text=True, check=True)
    return result.stdout.strip()


def validate_bundle(bundle: Path) -> dict:
    result = validate_metadata(bundle)
    app = bundle / "Contents/MacOS/NativeForensics"
    helper = bundle / "Contents/Helpers/NFTSKEngine"
    for binary in (app, helper):
        architectures = command(["/usr/bin/lipo", "-archs", str(binary)]).split()
        if result["architecture"] not in architectures:
            raise ValueError("App and helper architecture differ from the receipt.")
        lines = command(["/usr/bin/otool", "-L", str(binary)]).splitlines()[1:]
        dependencies = [line.strip().split(" (", 1)[0] for line in lines]
        if not dependencies or any(not value.startswith(("/usr/lib/", "/System/Library/"))
                                   for value in dependencies):
            raise ValueError("The app has a dynamic dependency outside macOS system libraries.")
    command(["/usr/bin/codesign", "--verify", "--strict", str(helper)])
    command(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(bundle)])
    result["validation"] = "passed-local-artifact-checks"
    result["distribution"] = "development; Developer ID/notarization and source/relink package not verified"
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    args = parser.parse_args()
    print(json.dumps(validate_bundle(args.bundle), indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"App bundle validation failed: {error}", file=sys.stderr)
        raise SystemExit(1)

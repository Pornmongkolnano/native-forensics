#!/usr/bin/env python3
"""Stage a verified development bundle, then replace only this checkout's app.

Staging leaves the installed development app intact if copying, metadata,
signing, or verification fails. Publication rolls back a failed rename.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile

from validate_app_bundle import validate_bundle

ROOT = Path(__file__).resolve().parents[1]
NAME = "NativeForensics"


def stage_bundle(binary: Path) -> Path:
    dist = ROOT / "dist"
    dist.mkdir(exist_ok=True)
    stage_root = Path(tempfile.mkdtemp(prefix=".nativeforensics-stage-", dir=dist))
    bundle = stage_root / f"{NAME}.app"
    try:
        for directory in ("MacOS", "Helpers", "Resources/EngineLicenses"):
            (bundle / "Contents" / directory).mkdir(parents=True, exist_ok=True)
        shutil.copy2(binary, bundle / f"Contents/MacOS/{NAME}")
        shutil.copy2(ROOT / ".engine/bin/NFTSKEngine", bundle / "Contents/Helpers/NFTSKEngine")
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
        identifier = "io.github.pornmongkolnano.nativeforensics"
        case_type = identifier + ".case"
        info = {
            "CFBundleExecutable": NAME, "CFBundleIdentifier": identifier,
            "CFBundleName": NAME, "CFBundleDisplayName": "Native Forensics",
            "CFBundlePackageType": "APPL", "CFBundleShortVersionString": "0.3.0",
            "CFBundleVersion": "8", "CFBundleIconFile": "AppIcon",
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
        # The native build already signs the helper. Preserve its receipt bytes.
        subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", str(bundle)], check=True)
        validate_bundle(bundle)
        return bundle
    except BaseException:
        shutil.rmtree(stage_root)
        raise


def publish_bundle(stage: Path, destination: Path, rename=None) -> None:
    """Publish a previously validated bundle on the same filesystem."""
    rename = rename or (lambda source, target: source.rename(target))
    if stage.is_symlink() or not stage.is_dir() or destination.is_symlink():
        raise ValueError("App publication refuses symlinks or a missing stage.")
    if stage.stat().st_dev != destination.parent.stat().st_dev:
        raise ValueError("Staged app must be on the publication filesystem.")
    backup_root = Path(tempfile.mkdtemp(prefix=".nativeforensics-previous-", dir=destination.parent))
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
        # Retain a backup if rollback itself failed; never delete that recovery copy.
        if published or not backup.exists():
            shutil.rmtree(backup_root)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--stage", type=Path, metavar="APP_BINARY")
    choice.add_argument("--publish", type=Path, metavar="STAGED_APP")
    args = parser.parse_args()
    if args.stage:
        print(stage_bundle(args.stage))
    else:
        stage = args.publish
        dist = ROOT / "dist"
        if stage.parent.parent != dist or not stage.parent.name.startswith(".nativeforensics-stage-") or stage.name != f"{NAME}.app":
            parser.error("The stage must be an app created inside this checkout's dist directory.")
        validate_bundle(stage)
        publish_bundle(stage, dist / f"{NAME}.app")
        stage.parent.rmdir()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

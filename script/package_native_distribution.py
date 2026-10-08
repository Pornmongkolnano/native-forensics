#!/usr/bin/env python3
"""Make a deterministic NativeForensics ZIP with pinned source/relink materials.

This packages an already built, verified app. It does not rebuild Swift, weaken
Gatekeeper, fetch binaries, notarize, or infer filesystem/clean-machine coverage.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile

from validate_app_bundle import validate_bundle, validate_metadata
from source_provenance import SOURCE_EXTENSIONS, check_binary_privacy
from build_native_engine import SYSTEM_LINK_ARGS

ROOT = Path(__file__).resolve().parents[1]
APP_NAME = "NativeForensics.app"
FIXED_TIME = (2020, 1, 1, 0, 0, 0)
RELINK_NAMES = {"NFTSKEngine.o", "libtsk.a", "libewf.a", "Relink.command", "link-command.json"}
SAFE_NAME = re.compile(r"[A-Za-z0-9._/-]+\Z")
NATIVE_HEADERS = {"NativeEngine/EFSNativeContent.hpp", "NativeEngine/EFSKeyPipeline.hpp"}
NATIVE_CAPTURE_SCOPE = "captured-complete-cpp-and-header-bytes; original inputs checked before and after compilation"


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def relative_name(name: str) -> PurePosixPath:
    value = PurePosixPath(name)
    if (not SAFE_NAME.fullmatch(name) or value.is_absolute() or ".." in value.parts
            or not value.parts or value.as_posix() != name):
        raise ValueError("Archive/material path is not a safe relative name.")
    return value


def no_links(path: Path, *, directory: bool = False) -> None:
    for ancestor in (path, *path.parents):
        if ancestor.is_symlink():
            raise ValueError("Distribution inputs/output must not traverse symlinks.")
    if directory and not path.is_dir():
        raise ValueError("A required distribution directory is missing.")
    if not directory and not path.is_file():
        raise ValueError("A required distribution file is missing.")


def inventory(directory: Path) -> dict[str, dict]:
    no_links(directory, directory=True)
    result = {}
    for path in sorted(directory.rglob("*")):
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise ValueError("Distribution must contain only real files/directories.")
        if path.is_file():
            name = path.relative_to(directory).as_posix()
            relative_name(name)
            result[name] = {"sha256": sha(path), "size": path.stat().st_size,
                            "mode": "0755" if path.stat().st_mode & 0o111 else "0644"}
    return result


def checked_copy(source: Path, destination: Path, expected: str | None = None) -> None:
    no_links(source)
    before = sha(source)
    if expected is not None and before != expected:
        raise ValueError("A source/relink/material hash differs from its pinned receipt.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(0o755 if source.stat().st_mode & 0o111 else 0o644)
    if sha(destination) != before or sha(source) != before:
        raise ValueError("Distribution input changed while copying.")


def engine_input_fingerprint(root: Path, receipt: dict, dependency_fingerprint: str,
                             licenses: dict[str, str]) -> tuple[str, dict[str, str]]:
    names = {"NativeEngine/NFTSKEngine.cpp", "script/build_native_engine.py", "NativeEngine/dependencies.json"}
    version = re.match(r"^(\d+)\.(\d+)\.(\d+)(?:[-+]|$)", str(receipt.get("engineVersion", "")))
    requires_headers = version is not None and tuple(map(int, version.groups())) >= (0, 1, 5)
    if "nativeHeaderSha256" in receipt:
        headers = receipt["nativeHeaderSha256"]
        if not isinstance(headers, dict) or set(headers) != NATIVE_HEADERS:
            raise ValueError("Native header inventory must contain exactly the two public EFS headers.")
        names |= NATIVE_HEADERS
    else:
        if requires_headers or "compiledInputSha256" in receipt or "buildInputCapture" in receipt:
            raise ValueError("Current native engine requires captured CPP/header inputs.")
        headers = None
    sources = {}
    for name in sorted(names):
        no_links(root / name)
        sources[name] = sha(root / name)
    payload = {"dependencyFingerprint": dependency_fingerprint, "source": sources["NativeEngine/NFTSKEngine.cpp"],
               "script": sources["script/build_native_engine.py"], "spec": sources["NativeEngine/dependencies.json"],
               "notices": sha(root / "THIRD_PARTY_NOTICES.md"), "licenses": licenses}
    if headers is not None:
        actual_headers = {name: sources[name] for name in sorted(NATIVE_HEADERS)}
        compiled = {name: sources[name] for name in sorted(NATIVE_HEADERS | {"NativeEngine/NFTSKEngine.cpp"})}
        if (headers != actual_headers or receipt.get("compiledInputSha256") != compiled
                or receipt.get("buildInputCapture") != NATIVE_CAPTURE_SCOPE):
            raise ValueError("Native CPP/header source differs from the captured compiler inputs.")
        payload["headers"] = actual_headers
    return hashlib.sha256(canonical(payload)).hexdigest(), sources


def verify_materials(root: Path, app: Path) -> dict:
    """Bind source archives, object files, patches and notices to the app helper."""
    metadata = validate_metadata(app, source_root=root)
    if metadata["buildConfiguration"] != "release":
        raise ValueError("Distribution requires the optimized release configuration with recorded build-path policy.")
    spec_path, receipt_path = root / "NativeEngine/dependencies.json", root / ".engine/manifest.json"
    no_links(spec_path)
    no_links(receipt_path)
    spec, receipt = json.loads(spec_path.read_text()), json.loads(receipt_path.read_text())
    if (receipt.get("schemaVersion") != 1 or spec.get("schemaVersion") != 1
            or receipt.get("dependencies") != spec.get("dependencies")
            or receipt.get("engineVersion") != metadata["engineVersion"]
            or receipt.get("engineSha256") != metadata["helperSha256"]
            or receipt.get("architecture") != metadata["architecture"]
            or receipt.get("toolchain", {}).get("minimumMacOS") != spec.get("minimumMacOS")):
        raise ValueError("Engine source specification/cache does not match the bundled engine.")
    bundled = json.loads((app / "Contents/Resources/engine-manifest.json").read_text())
    for key in ("buildFingerprint", "appliedPatches", "patchDigest", "relinkSha256",
                "licenseSha256", "noticesSha256", "dependencies", "nativeHeaderSha256",
                "compiledInputSha256", "buildInputCapture"):
        if bundled.get(key) != receipt.get(key):
            raise ValueError("Bundled engine provenance differs from the source/relink cache.")
    expected_patches = []
    for dependency in spec["dependencies"]:
        name = relative_name(dependency["archive"])
        if len(name.parts) != 1:
            raise ValueError("Pinned dependency archive must be a basename.")
        archive = root / ".engine/downloads" / name
        no_links(archive)
        if sha(archive) != dependency["sha256"]:
            raise ValueError("Pinned dependency source archive checksum mismatch.")
        for patch in dependency.get("patches", []):
            patch_path = root / relative_name(patch["path"])
            no_links(patch_path)
            if sha(patch_path) != patch["sha256"]:
                raise ValueError("Pinned dependency patch checksum mismatch.")
            expected_patches.append({"path": patch["path"], "sha256": patch["sha256"]})
    if (receipt.get("appliedPatches") != expected_patches
            or receipt.get("patchDigest") != hashlib.sha256(canonical(expected_patches)).hexdigest()):
        raise ValueError("Applied engine patch inventory is incomplete.")
    relink = receipt.get("relinkSha256", {})
    if set(relink) != RELINK_NAMES:
        raise ValueError("Static LGPL relink inventory is incomplete.")
    for name, digest in relink.items():
        path = root / ".engine/relink" / name
        no_links(path)
        if sha(path) != digest:
            raise ValueError("A retained relink artifact checksum mismatch.")
    for name, digest in receipt.get("licenseSha256", {}).items():
        path = root / relative_name(name)
        if not name.startswith("NativeEngine/licenses/"):
            raise ValueError("Invalid dependency license location.")
        no_links(path)
        if sha(path) != digest:
            raise ValueError("Dependency license checksum mismatch.")
    current_licenses = {path.relative_to(root).as_posix(): sha(path)
                        for path in (root / "NativeEngine/licenses").rglob("*") if path.is_file() and not path.is_symlink()}
    if current_licenses != receipt.get("licenseSha256"):
        raise ValueError("Dependency license source graph has missing or extra inputs.")
    notices = root / "THIRD_PARTY_NOTICES.md"
    no_links(notices)
    if sha(notices) != receipt.get("noticesSha256"):
        raise ValueError("Dependency notices checksum mismatch.")
    dependencies = root / ".engine/dependencies-build.json"
    no_links(dependencies)
    build = json.loads(dependencies.read_text())
    expected_fingerprint, engine_sources = engine_input_fingerprint(root, receipt, build["fingerprint"], receipt["licenseSha256"])
    if receipt.get("buildFingerprint") != expected_fingerprint:
        raise ValueError("Corresponding engine source/build recipe does not match the receipt.")
    return {"metadata": metadata, "spec": spec, "engineReceipt": receipt,
            "engineSourceSha256": engine_sources, "engineDependencyFingerprint": build["fingerprint"]}


def signing_details(path: Path) -> str:
    result = subprocess.run(["/usr/bin/codesign", "-dvvv", str(path)], capture_output=True, text=True, check=True)
    return result.stdout + result.stderr


def verify_trust(app: Path, support: Path, mode: str) -> dict:
    """Only measured Apple assessments can establish a release trust claim."""
    subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(support)], check=True, capture_output=True)
    components = [app, app / "Contents/Helpers/NFTSKEngine", app / "Contents/Helpers/NFDocumentDecoder", support]
    details = [signing_details(path) for path in components]
    ad_hoc = any("Signature=adhoc" in value for value in details)
    if mode == "development":
        return {"mode": "development", "signature": "ad-hoc" if ad_hoc else "signed-not-release-verified",
                "notarization": "not-verified", "gatekeeper": "not-verified",
                "cleanMachine": "not-tested", "physicalM5": "not-tested"}
    if any("Authority=Developer ID Application:" not in value or not re.search(r"flags=0x[0-9a-f]+\([^)]*\bruntime\b", value)
           or "TeamIdentifier=not set" in value for value in details):
        raise ValueError("Release unavailable: every executable must have Developer ID/hardened-runtime signing.")
    teams = [re.search(r"^TeamIdentifier=(.+)$", value, re.MULTILINE) for value in details]
    if any(value is None for value in teams) or len({value.group(1) for value in teams if value}) != 1:
        raise ValueError("Release unavailable: app and all helpers must have the same Developer ID team.")
    subprocess.run(["/usr/bin/xcrun", "stapler", "validate", str(app)], capture_output=True, check=True)
    for path, assessment in ((app, "execute"), (support, "execute")):
        result = subprocess.run(["/usr/sbin/spctl", "--assess", "--type", assessment, "--verbose=4", str(path)],
                                capture_output=True, text=True, check=True)
        if "Notarized Developer ID" not in result.stdout + result.stderr:
            raise ValueError("Release unavailable: Apple did not report Notarized Developer ID acceptance.")
    return {"mode": "release", "signature": "Developer-ID-and-hardened-runtime-verified",
            "notarization": "app-staple-and-component-acceptance-verified", "gatekeeper": "accepted",
            "cleanMachine": "not-tested", "physicalM5": "not-tested"}


def build_install_support(root: Path, destination: Path, architecture: str, minimum: str) -> str:
    source = root / "script/native_install_publish.c"
    no_links(source)
    source_bytes = source.read_bytes()
    source_hash = hashlib.sha256(source_bytes).hexdigest()
    subprocess.run(["/usr/bin/xcrun", "--sdk", "macosx", "clang", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                    "-arch", architecture, f"-mmacosx-version-min={minimum}", "-x", "c", "-",
                    "-o", str(destination)], input=source_bytes, cwd=root, check=True, capture_output=True)
    subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", str(destination)], check=True, capture_output=True)
    if sha(source) != source_hash:
        raise ValueError("Installer source changed while compiling its publisher.")
    return source_hash


def stage_distribution(root: Path, app: Path, stage: Path, support: Path, trust: dict, materials: dict) -> dict:
    """Copy only explicit inputs; never enumerate ignored evidence/local reports."""
    no_links(app, directory=True)
    validate_metadata(app, source_root=root)
    app_source_receipt = json.loads((app / "Contents/Resources/app-source-manifest.json").read_text())
    decoder = json.loads((app / "Contents/Resources/document-decoder-manifest.json").read_text())
    source_inputs = {**app_source_receipt["sourceSha256"], **decoder["sourceSha256"], **materials["engineSourceSha256"],
                     "script/native_install_publish.c": materials["installSupportSourceSha256"]}
    app_before = inventory(app)
    shutil.copytree(app, stage / APP_NAME, copy_function=shutil.copyfile)
    for name, facts in app_before.items():
        (stage / APP_NAME / name).chmod(int(facts["mode"], 8))
    if inventory(stage / APP_NAME) != app_before or inventory(app) != app_before:
        raise ValueError("App changed while staging its distribution.")
    checked_copy(support, stage / "InstallSupport")
    checked_copy(root / "script/templates/native_install.command", stage / "Install.command")
    (stage / "Install.command").chmod(0o755)
    spec, receipt = materials["spec"], materials["engineReceipt"]
    for dependency in spec["dependencies"]:
        checked_copy(root / ".engine/downloads" / dependency["archive"],
                     stage / "Source/Dependencies" / dependency["archive"], dependency["sha256"])
        for patch in dependency.get("patches", []):
            checked_copy(root / patch["path"], stage / "Source" / patch["path"], patch["sha256"])
    for name, digest in receipt["licenseSha256"].items():
        checked_copy(root / name, stage / "Licenses" / Path(*PurePosixPath(name).parts[2:]), digest)
        checked_copy(root / name, stage / "Source" / name, digest)
    checked_copy(root / "THIRD_PARTY_NOTICES.md", stage / "Licenses/THIRD_PARTY_NOTICES.md", receipt["noticesSha256"])
    checked_copy(root / "THIRD_PARTY_NOTICES.md", stage / "Source/THIRD_PARTY_NOTICES.md", receipt["noticesSha256"])
    for name in sorted(RELINK_NAMES - {"link-command.json"}):
        checked_copy(root / ".engine/relink" / name, stage / "Relink" / name, receipt["relinkSha256"][name])
    # The original build command contains host-specific absolute paths. Verify it
    # above, then ship a portable equivalent and retain its digest, never the paths.
    portable = ["xcrun", "--sdk", "macosx", "clang++", "-arch", receipt["architecture"],
                f'-mmacosx-version-min={spec["minimumMacOS"]}', "NFTSKEngine.o", "libtsk.a", "libewf.a",
                *SYSTEM_LINK_ARGS, "-o", "NFTSKEngine-relinked"]
    (stage / "Relink/link-command.json").write_text(json.dumps(portable, indent=2) + "\n")
    for name in ("NativeEngine/NFTSKEngine.cpp", "NativeEngine/dependencies.json", "script/build_native_engine.py",
                 "script/native_install_publish.c", "script/package_app.py", "script/validate_app_bundle.py",
                 "script/source_provenance.py", "script/build_and_run.sh", "Package.swift"):
        checked_copy(root / name, stage / "Source" / name, source_inputs.get(name))
    for name in sorted(NATIVE_HEADERS & materials["engineSourceSha256"].keys()):
        checked_copy(root / name, stage / "Source" / name, materials["engineSourceSha256"][name])
    for directory in (root / "Sources",):
        for source in sorted(directory.rglob("*")):
            if not source.is_file() or source.suffix not in SOURCE_EXTENSIONS:
                continue
            name = source.relative_to(root).as_posix()
            checked_copy(source, stage / "Source" / name, source_inputs.get(name))
    for source in sorted((root / "Tests").rglob("*.swift")):
        checked_copy(source, stage / "Source" / source.relative_to(root))
    for name in ("AppIcon.png", "AppIcon.icns", "README.md"):
        key = "Assets/AppIcon/" + name
        checked_copy(root / key, stage / "Source" / key, source_inputs[key])
    validate_metadata(app, source_root=root)
    validate_metadata(stage / APP_NAME, source_root=stage / "Source")
    rebuild = '''#!/bin/sh
set -eu
task_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# Seed ONLY verified matching source archives; build script rechecks each digest.
mkdir -p "$task_dir/.engine/downloads"
cp "$task_dir"/Dependencies/* "$task_dir/.engine/downloads/"
exec python3 "$task_dir/script/build_native_engine.py" --force "$@"
'''
    (stage / "Source/Rebuild-engine.command").write_text(rebuild)
    (stage / "Source/Rebuild-engine.command").chmod(0o755)
    checked_copy(root / "docs/DISTRIBUTION.md", stage / "README.md")
    app_info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
    result = {"schemaVersion": 1, **materials["metadata"], "appBuild": app_info["CFBundleVersion"], "trust": trust,
              "sourceAndRelinkMaterials": "included-and-hash-verified", "installScope": "user-owned directory; explicit replacement",
              "engineBuildFingerprint": receipt["buildFingerprint"],
              "engineDependencyFingerprint": materials["engineDependencyFingerprint"],
              "installSupportSourceSha256": materials["installSupportSourceSha256"],
              "originalLinkCommandSha256": receipt["relinkSha256"]["link-command.json"],
              "dependencies": spec["dependencies"], "files": inventory(stage)}
    (stage / "distribution-manifest.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    hashes = inventory(stage)
    (stage / "SHA256SUMS").write_text("".join(f'{facts["sha256"]}  {name}\n' for name, facts in hashes.items()))
    validate_distribution(stage)
    return result


def validate_distribution(stage: Path) -> dict:
    files = inventory(stage)
    manifest = json.loads((stage / "distribution-manifest.json").read_text())
    if manifest.get("schemaVersion") != 1 or manifest.get("sourceAndRelinkMaterials") != "included-and-hash-verified":
        raise ValueError("Unsupported or incomplete distribution manifest.")
    recorded = manifest.get("files")
    actual = {name: value for name, value in files.items() if name not in {"SHA256SUMS", "distribution-manifest.json"}}
    if recorded != actual:
        raise ValueError("Distribution inventory differs from its manifest.")
    expected_lines = "".join(f'{facts["sha256"]}  {name}\n' for name, facts in files.items() if name != "SHA256SUMS")
    if (stage / "SHA256SUMS").read_text() != expected_lines:
        raise ValueError("Distribution SHA256SUMS is incomplete or changed.")
    validate_metadata(stage / APP_NAME, source_root=stage / "Source")
    engine_receipt = json.loads((stage / APP_NAME / "Contents/Resources/engine-manifest.json").read_text())
    copied_license_hashes = {name: sha(stage / "Source" / name) for name in engine_receipt["licenseSha256"]}
    computed_engine, _ = engine_input_fingerprint(stage / "Source", engine_receipt,
                                                manifest["engineDependencyFingerprint"], copied_license_hashes)
    if computed_engine != engine_receipt["buildFingerprint"]:
        raise ValueError("Copied engine corresponding source differs from its build fingerprint.")
    if sha(stage / "Source/script/native_install_publish.c") != manifest["installSupportSourceSha256"]:
        raise ValueError("Copied installer source differs from its publisher build input.")
    return manifest


def deterministic_zip(stage: Path, output: Path) -> str:
    if output.exists() or output.is_symlink():
        raise ValueError("Output already exists; use a new ZIP path.")
    no_links(output.parent, directory=True)
    for input_path in (stage,):
        if output.absolute().is_relative_to(input_path.absolute()):
            raise ValueError("ZIP output overlaps its input directory.")
    expected = inventory(stage)
    temporary = output.parent / (".nativeforensics-zip-" + os.urandom(8).hex())
    try:
        with zipfile.ZipFile(temporary, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for path in sorted(stage.rglob("*")):
                name = path.relative_to(stage).as_posix()
                info = zipfile.ZipInfo(name + ("/" if path.is_dir() else ""), FIXED_TIME)
                info.create_system = 3
                mode = 0o755 if path.is_dir() or path.stat().st_mode & 0o111 else 0o644
                info.external_attr = ((stat.S_IFDIR if path.is_dir() else stat.S_IFREG) | mode) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                if path.is_dir():
                    archive.writestr(info, b"")
                else:
                    with path.open("rb") as source, archive.open(info, "w") as target:
                        shutil.copyfileobj(source, target, 1024 * 1024)
        # A concurrent input edit must not yield a successfully published ZIP
        # containing bytes different from the manifest checked before writing.
        with zipfile.ZipFile(temporary) as archive:
            actual_names = {item.filename for item in archive.infolist() if not item.is_dir()}
            if actual_names != set(expected):
                raise ValueError("ZIP inventory differs from the verified stage.")
            for name, facts in expected.items():
                digest = hashlib.sha256()
                with archive.open(name) as stream:
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(block)
                if digest.hexdigest() != facts["sha256"]:
                    raise ValueError("A staged file changed while writing the ZIP.")
        # Exclusive link publication prevents overwrite if another writer won.
        os.link(temporary, output)
        return sha(output)
    finally:
        temporary.unlink(missing_ok=True)


def package(app: Path, output: Path, mode: str = "development", install_support: Path | None = None,
            *, root: Path = ROOT) -> dict:
    app, output = app.absolute(), output.absolute()
    no_links(app, directory=True)
    no_links(output.parent, directory=True)
    if output.exists() or output.is_symlink() or output.is_relative_to(app):
        raise ValueError("Output must be new and outside the app.")
    if output.suffix != ".zip" or any(output.is_relative_to(root / name) for name in
                                      (".engine", "Sources", "NativeEngine", "patches", "script", "docs", "Tests")):
        raise ValueError("Distribution ZIP must be outside corresponding source/dependency/test trees.")
    materials = verify_materials(root, app)
    validate_bundle(app, source_root=root)
    with tempfile.TemporaryDirectory(prefix=".nativeforensics-distribution-", dir=output.parent) as temporary:
        work = Path(temporary)
        support = install_support
        if support is None:
            if mode == "release":
                raise ValueError("Release unavailable: provide Developer ID/notarized --install-support; no credentials are inferred.")
            support = work / "InstallSupport"
            materials["installSupportSourceSha256"] = build_install_support(root, support, materials["metadata"]["architecture"], materials["metadata"]["minimumMacOS"])
        else:
            materials["installSupportSourceSha256"] = sha(root / "script/native_install_publish.c")
        no_links(support)
        check_binary_privacy(support)
        trust = verify_trust(app, support, mode)
        stage = work / "package"
        stage.mkdir()
        manifest = stage_distribution(root, app, stage, support, trust, materials)
        # Reverify the staged signatures; file hashes alone do not validate code.
        validate_bundle(stage / APP_NAME, source_root=stage / "Source")
        verify_trust(stage / APP_NAME, stage / "InstallSupport", mode)
        zip_hash = deterministic_zip(stage, output)
    return {"schemaVersion": 1, "zipSha256": zip_hash, "bytes": output.stat().st_size,
            "appVersion": manifest["appVersion"], "architecture": manifest["architecture"],
            "trust": trust, "fileCount": len(manifest["files"])}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path, default=ROOT / "dist/NativeForensics.app")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mode", choices=("development", "release"), default="development")
    parser.add_argument("--install-support", type=Path, help="Prebuilt original publisher helper; release requires notarized Developer ID")
    args = parser.parse_args()
    print(json.dumps(package(args.app, args.output, args.mode, args.install_support), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        print(f"Native distribution failed: {error}", file=sys.stderr)
        raise SystemExit(1)

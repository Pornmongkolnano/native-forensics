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

from validate_app_bundle import (validate_bundle, validate_metadata, validate_binary_runtime,
                                 XPC_BUNDLE_PATH, WORKER_EXECUTABLE_PATH)
from source_provenance import SOURCE_EXTENSIONS, check_binary_privacy
from build_native_engine import SYSTEM_LINK_ARGS

ROOT = Path(__file__).resolve().parents[1]
APP_NAME = "NativeForensics.app"
FIXED_TIME = (2020, 1, 1, 0, 0, 0)
RELINK_NAMES = {"NFTSKEngine.o", "libtsk.a", "libewf.a", "Relink.command", "link-command.json"}
SAFE_NAME = re.compile(r"[A-Za-z0-9._/-]+\Z")
SUPPORT_SOURCE = "script/native_install_publish.c"
SUPPORT_BUILDER = "script/package_native_distribution.py"
SUPPORT_RECEIPT_NAME = "install-support-build-receipt.json"
NATIVE_HEADERS = {"NativeEngine/EFSNativeContent.hpp", "NativeEngine/EFSKeyPipeline.hpp"}
NATIVE_CAPTURE_SCOPE = "captured-complete-cpp-and-header-bytes; original inputs checked before and after compilation"


def report_retained_path_candidate(label: str, candidate: Path) -> None:
    """Report a lexical candidate without deleting its current filesystem entry."""
    if sys.stderr is None:
        return
    try:
        print(f"{label} path candidate for manual review (no automatic cleanup): {candidate}", file=sys.stderr)
    except (OSError, ValueError):
        # A closed diagnostic stream must not replace the packaging outcome.
        pass


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def portable_relink_recipe(architecture: str, minimum: str) -> list[str]:
    return ["xcrun", "--sdk", "macosx", "clang++", "-arch", architecture,
            f"-mmacosx-version-min={minimum}", "NFTSKEngine.o", "libtsk.a", "libewf.a",
            *SYSTEM_LINK_ARGS, "-o", "NFTSKEngine-relinked"]


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
            or receipt.get("engineVersion") != spec.get("engineVersion")
            or receipt.get("protocolVersion") != spec.get("protocolVersion", 1)
            or receipt.get("engineSha256") != metadata["helperSha256"]
            or receipt.get("architecture") != metadata["architecture"]
            or receipt.get("toolchain", {}).get("minimumMacOS") != spec.get("minimumMacOS")):
        raise ValueError("Engine source specification/cache does not match the bundled engine.")
    bundled = json.loads((app / "Contents/Resources/engine-manifest.json").read_text())
    for key in ("buildFingerprint", "appliedPatches", "patchDigest", "relinkSha256",
                "licenseSha256", "noticesSha256", "dependencies", "nativeHeaderSha256", "compiledInputSha256", "buildInputCapture"):
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
    if mode not in {"development", "release"}:
        raise ValueError("Unknown distribution trust mode.")
    subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(support)], check=True, capture_output=True)
    components = [app, app / "Contents/Helpers/NFTSKEngine", app / "Contents/Helpers/NFDocumentDecoder", support]
    if (app / XPC_BUNDLE_PATH).exists():
        components.append(app / XPC_BUNDLE_PATH)
        components.append(app / WORKER_EXECUTABLE_PATH)
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


def support_compile_recipe(architecture: str, minimum: str) -> list[str]:
    if architecture not in {"arm64", "x86_64"} or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){0,2}", minimum):
        raise ValueError("Invalid installer architecture or minimum macOS specification.")
    return ["xcrun", "--sdk", "macosx", "clang", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
            "-arch", architecture, f"-mmacosx-version-min={minimum}", "-x", "c", "-", "-o", "InstallSupport"]


def build_install_support(root: Path, destination: Path, architecture: str, minimum: str,
                          *, sign_identity: str = "-", hardened_runtime: bool = False) -> dict:
    source = root / SUPPORT_SOURCE
    no_links(source)
    no_links(root / SUPPORT_BUILDER)
    no_links(destination.parent, directory=True)
    if destination.exists() or destination.is_symlink():
        raise ValueError("Installer build output already exists; use a new path.")
    source_bytes = source.read_bytes()
    source_hash = hashlib.sha256(source_bytes).hexdigest()
    builder_hash = sha(root / SUPPORT_BUILDER)
    recipe = support_compile_recipe(architecture, minimum)
    subprocess.run(["/usr/bin/xcrun", *recipe[1:-1], str(destination)], input=source_bytes, cwd=root, check=True, capture_output=True)
    compiled_hash = sha(destination)
    sign = ["/usr/bin/codesign", "--force", "--sign", sign_identity]
    if hardened_runtime:
        sign += ["--options", "runtime", "--timestamp"]
    subprocess.run([*sign, str(destination)], check=True, capture_output=True)
    if sha(source) != source_hash or sha(root / SUPPORT_BUILDER) != builder_hash:
        raise ValueError("Installer source changed while compiling its publisher.")
    receipt = {"schemaVersion": 1, "product": "InstallSupport", "sourcePath": SUPPORT_SOURCE,
               "sourceSha256": source_hash, "builderSourceSha256": builder_hash,
               "architecture": architecture, "minimumMacOS": minimum, "buildConfiguration": "release",
               "compileRecipe": recipe, "compilerInput": "captured-complete-source-bytes-on-stdin",
               "compiledBinarySha256": compiled_hash, "signedBinarySha256": sha(destination),
               "signing": "ad-hoc" if sign_identity == "-" else "explicit-configured-identity",
               "hardenedRuntime": hardened_runtime,
               "scope": "captured source compiled before signing; raw and signed output hashes recorded"}
    verify_install_support_receipt(root, destination, receipt, architecture, minimum)
    return receipt


def verify_install_support_receipt(root: Path, support: Path, receipt: dict, architecture: str,
                                  minimum: str, *, verify_runtime: bool = True) -> None:
    expected_fields = {"schemaVersion", "product", "sourcePath", "sourceSha256", "builderSourceSha256", "architecture",
                       "minimumMacOS", "buildConfiguration", "compileRecipe", "compilerInput", "compiledBinarySha256",
                       "signedBinarySha256", "signing", "hardenedRuntime", "scope"}
    if (not isinstance(receipt, dict) or receipt.get("schemaVersion") != 1
            or set(receipt) != expected_fields
            or receipt.get("product") != "InstallSupport" or receipt.get("sourcePath") != SUPPORT_SOURCE
            or receipt.get("architecture") != architecture or receipt.get("minimumMacOS") != minimum
            or receipt.get("buildConfiguration") != "release"
            or receipt.get("compilerInput") != "captured-complete-source-bytes-on-stdin"
            or receipt.get("scope") != "captured source compiled before signing; raw and signed output hashes recorded"
            or receipt.get("compileRecipe") != support_compile_recipe(architecture, minimum)
            or receipt.get("signing") not in {"ad-hoc", "explicit-configured-identity"}
            or type(receipt.get("hardenedRuntime")) is not bool):
        raise ValueError("Missing or invalid captured installer compile/sign build receipt.")
    for field in ("sourceSha256", "builderSourceSha256", "compiledBinarySha256", "signedBinarySha256"):
        if not isinstance(receipt.get(field), str) or not re.fullmatch(r"[0-9a-f]{64}", receipt[field]):
            raise ValueError("Installer build receipt has an invalid source/binary hash binding.")
    for path in (root / SUPPORT_SOURCE, root / SUPPORT_BUILDER, support):
        no_links(path)
    if sha(root / SUPPORT_SOURCE) != receipt["sourceSha256"] or sha(root / SUPPORT_BUILDER) != receipt["builderSourceSha256"]:
        raise ValueError("Installer corresponding source/build recipe differs from its captured compilation receipt.")
    if sha(support) != receipt["signedBinarySha256"]:
        raise ValueError("Installer signed binary differs from its captured compilation/signing receipt.")
    if verify_runtime:
        check_binary_privacy(support)
        validate_binary_runtime(support, architecture, minimum)
        subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(support)], check=True, capture_output=True)
        details = signing_details(support)
        actual_ad_hoc = "Signature=adhoc" in details
        actual_runtime = bool(re.search(r"flags=0x[0-9a-f]+\([^)]*\bruntime\b", details))
        if actual_ad_hoc != (receipt["signing"] == "ad-hoc") or actual_runtime != receipt["hardenedRuntime"]:
            raise ValueError("Installer signature mode differs from its captured signing receipt.")


def stage_distribution(root: Path, app: Path, stage: Path, support: Path, trust: dict, materials: dict) -> dict:
    """Copy only explicit inputs; never enumerate ignored evidence/local reports."""
    no_links(app, directory=True)
    validate_metadata(app, source_root=root)
    app_source_receipt = json.loads((app / "Contents/Resources/app-source-manifest.json").read_text())
    decoder = json.loads((app / "Contents/Resources/document-decoder-manifest.json").read_text())
    xpc_path = app / "Contents/Resources/document-xpc-manifest.json"
    xpc = json.loads(xpc_path.read_text()) if xpc_path.exists() else {"sourceSha256": {}}
    support_receipt = materials["installSupportBuildReceipt"]
    verify_install_support_receipt(root, support, support_receipt, materials["metadata"]["architecture"],
                                  materials["metadata"]["minimumMacOS"], verify_runtime=False)
    source_inputs = {**app_source_receipt["sourceSha256"], **decoder["sourceSha256"], **xpc["sourceSha256"],
                     **xpc.get("worker", {}).get("sourceSha256", {}),
                     **materials["engineSourceSha256"], SUPPORT_SOURCE: support_receipt["sourceSha256"],
                     SUPPORT_BUILDER: support_receipt["builderSourceSha256"]}
    app_before = inventory(app)
    shutil.copytree(app, stage / APP_NAME, copy_function=shutil.copyfile)
    for name, facts in app_before.items():
        (stage / APP_NAME / name).chmod(int(facts["mode"], 8))
    if inventory(stage / APP_NAME) != app_before or inventory(app) != app_before:
        raise ValueError("App changed while staging its distribution.")
    checked_copy(support, stage / "InstallSupport", support_receipt["signedBinarySha256"])
    (stage / SUPPORT_RECEIPT_NAME).write_text(json.dumps(support_receipt, indent=2, sort_keys=True) + "\n")
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
    portable = portable_relink_recipe(receipt["architecture"], spec["minimumMacOS"])
    (stage / "Relink/link-command.json").write_text(json.dumps(portable, indent=2) + "\n")
    for name in ("NativeEngine/NFTSKEngine.cpp", "NativeEngine/dependencies.json", "script/build_native_engine.py",
                 "script/native_install_publish.c", "script/package_app.py", "script/validate_app_bundle.py",
                 "script/package_native_distribution.py", "script/source_provenance.py", "script/build_and_run.sh",
                 "script/templates/native_install.command", "docs/DISTRIBUTION.md", "docs/XPC-PACKAGING.md",
                 "docs/XPC-DECODE.md", "Package.swift"):
        checked_copy(root / name, stage / "Source" / name, source_inputs.get(name))
    for name, digest in source_inputs.items():
        if name.endswith(".plist") or name in NATIVE_HEADERS:
            checked_copy(root / name, stage / "Source" / name, digest)
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
    repack = '''#!/bin/sh
set -eu
task_source=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 -B "$task_source/script/package_native_distribution.py" --from-distribution "$task_source/.." "$@"
'''
    (stage / "Source/Repack.command").write_text(repack)
    (stage / "Source/Repack.command").chmod(0o755)
    checked_copy(root / "docs/DISTRIBUTION.md", stage / "README.md")
    for name in ("XPC-PACKAGING.md", "XPC-DECODE.md"):
        checked_copy(root / "docs" / name, stage / name)
    app_info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
    result = {"schemaVersion": 1, **materials["metadata"], "appBuild": app_info["CFBundleVersion"], "trust": trust,
              "sourceAndRelinkMaterials": "included-and-hash-verified", "installScope": "user-owned directory; explicit replacement",
              "engineBuildFingerprint": receipt["buildFingerprint"],
              "engineDependencyFingerprint": materials["engineDependencyFingerprint"],
              "installSupportSourceSha256": support_receipt["sourceSha256"],
              "installSupportBuildReceipt": SUPPORT_RECEIPT_NAME,
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
    metadata = validate_metadata(stage / APP_NAME, source_root=stage / "Source")
    app_info = plistlib.loads((stage / APP_NAME / "Contents/Info.plist").read_bytes())
    if (manifest.get("appVersion") != metadata["appVersion"]
            or manifest.get("appBuild") != app_info["CFBundleVersion"]):
        raise ValueError("Distribution version/build differs from the validated app.")
    engine_receipt = json.loads((stage / APP_NAME / "Contents/Resources/engine-manifest.json").read_text())
    copied_license_hashes = {name: sha(stage / "Source" / name) for name in engine_receipt["licenseSha256"]}
    computed_engine, _ = engine_input_fingerprint(stage / "Source", engine_receipt,
                                                 manifest["engineDependencyFingerprint"], copied_license_hashes)
    if computed_engine != engine_receipt["buildFingerprint"]:
        raise ValueError("Copied engine corresponding source differs from its build fingerprint.")
    # The outer manifest can be regenerated. Bind the accompanying archives
    # and retained static-link inputs to the app's sealed engine receipt too;
    # outer inventory agreement alone cannot establish their correspondence.
    for dependency in engine_receipt["dependencies"]:
        name = relative_name(dependency["archive"])
        if len(name.parts) != 1:
            raise ValueError("Pinned dependency archive must be a basename.")
        archive = stage / "Source/Dependencies" / name
        no_links(archive)
        if sha(archive) != dependency["sha256"]:
            raise ValueError("Copied pinned dependency source archive checksum mismatch.")
        for patch in dependency.get("patches", []):
            path = stage / "Source" / relative_name(patch["path"])
            no_links(path)
            if sha(path) != patch["sha256"]:
                raise ValueError("Copied pinned dependency patch checksum mismatch.")
    relink = engine_receipt.get("relinkSha256", {})
    if not isinstance(relink, dict) or set(relink) != RELINK_NAMES:
        raise ValueError("Static LGPL relink inventory is incomplete.")
    # link-command.json is deliberately transformed into a portable recipe;
    # the four other inputs must retain the exact sealed build-input bytes.
    for name in sorted(RELINK_NAMES - {"link-command.json"}):
        path = stage / "Relink" / name
        no_links(path)
        if sha(path) != relink[name]:
            raise ValueError("Copied retained relink artifact checksum mismatch.")
    portable_path = stage / "Relink/link-command.json"
    no_links(portable_path)
    if json.loads(portable_path.read_text()) != portable_relink_recipe(
            engine_receipt["architecture"], engine_receipt["toolchain"]["minimumMacOS"]):
        raise ValueError("Portable relink metadata differs from the generated system-link recipe.")
    if manifest.get("originalLinkCommandSha256") != relink["link-command.json"]:
        raise ValueError("Original relink command digest differs from the sealed engine receipt.")
    if manifest.get("installSupportBuildReceipt") != SUPPORT_RECEIPT_NAME:
        raise ValueError("Distribution lacks a captured installer compilation/signing receipt.")
    support_receipt = json.loads((stage / SUPPORT_RECEIPT_NAME).read_text())
    verify_install_support_receipt(stage / "Source", stage / "InstallSupport", support_receipt,
                                  manifest["architecture"], manifest["minimumMacOS"], verify_runtime=False)
    if support_receipt["sourceSha256"] != manifest.get("installSupportSourceSha256"):
        raise ValueError("Copied installer source differs from its publisher build input.")
    for path in ("Source/script/package_native_distribution.py", "Source/Repack.command",
                 "Source/script/templates/native_install.command", "Source/docs/DISTRIBUTION.md"):
        if path not in files:
            raise ValueError("Distribution lacks a required corresponding packaging/repack input.")
    return manifest


def deterministic_zip(stage: Path, output: Path, *, expected_inventory: dict | None = None) -> str:
    if output.exists() or output.is_symlink():
        raise ValueError("Output already exists; use a new ZIP path.")
    no_links(output.parent, directory=True)
    for input_path in (stage,):
        if output.absolute().is_relative_to(input_path.absolute()):
            raise ValueError("ZIP output overlaps its input directory.")
    expected = inventory(stage)
    if expected_inventory is not None and expected != expected_inventory:
        raise ValueError("Distribution changed after validation and before archiving.")
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
        # The temporary name is mutable. Retain it even after exclusive link
        # publication; an unchanged successful archive then has two hard links.
        report_retained_path_candidate("Temporary ZIP", temporary)


def package(app: Path, output: Path, mode: str = "development", install_support: Path | None = None,
            *, root: Path = ROOT, install_support_receipt: Path | None = None) -> dict:
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
    work = Path(tempfile.mkdtemp(prefix=".nativeforensics-distribution-", suffix=".noindex", dir=output.parent))
    try:
        support = install_support
        if support is None:
            if mode == "release":
                raise ValueError("Release unavailable: provide Developer ID/notarized --install-support; no credentials are inferred.")
            support = work / "InstallSupport"
            if install_support_receipt is not None:
                raise ValueError("--install-support-receipt requires --install-support.")
            materials["installSupportBuildReceipt"] = build_install_support(root, support, materials["metadata"]["architecture"], materials["metadata"]["minimumMacOS"])
        else:
            if install_support_receipt is None:
                raise ValueError("Prebuilt --install-support requires its captured --install-support-receipt; source correspondence cannot be inferred.")
            no_links(install_support_receipt)
            materials["installSupportBuildReceipt"] = json.loads(install_support_receipt.read_text())
        verify_install_support_receipt(root, support, materials["installSupportBuildReceipt"],
                                      materials["metadata"]["architecture"], materials["metadata"]["minimumMacOS"])
        no_links(support)
        check_binary_privacy(support)
        trust = verify_trust(app, support, mode)
        stage = work / "package"
        stage.mkdir()
        manifest = stage_distribution(root, app, stage, support, trust, materials)
        stage_inventory = inventory(stage)
        # Reverify the staged signatures; file hashes alone do not validate code.
        validate_bundle(stage / APP_NAME, source_root=stage / "Source")
        verify_trust(stage / APP_NAME, stage / "InstallSupport", mode)
        zip_hash = deterministic_zip(stage, output, expected_inventory=stage_inventory)
    finally:
        report_retained_path_candidate("Distribution work directory", work)
    return {"schemaVersion": 1, "zipSha256": zip_hash, "bytes": output.stat().st_size,
            "appVersion": manifest["appVersion"], "architecture": manifest["architecture"],
            "trust": trust, "fileCount": len(manifest["files"])}


def repack_distribution(directory: Path, output: Path, mode: str | None = None) -> dict:
    """Repack unchanged included inputs without relying on a checkout cache."""
    directory, output = directory.absolute(), output.absolute()
    no_links(directory, directory=True)
    no_links(output.parent, directory=True)
    if output.suffix != ".zip" or output.is_relative_to(directory):
        raise ValueError("Repack output must be a new ZIP outside the original package.")
    original_inventory = inventory(directory)
    manifest = validate_distribution(directory)
    source = directory / "Source"
    app, support = directory / APP_NAME, directory / "InstallSupport"
    validate_bundle(app, source_root=source)
    support_receipt = json.loads((directory / SUPPORT_RECEIPT_NAME).read_text())
    verify_install_support_receipt(source, support, support_receipt, manifest["architecture"], manifest["minimumMacOS"])
    trust = verify_trust(app, support, mode or manifest["trust"]["mode"])
    if trust["mode"] != manifest["trust"]["mode"]:
        raise ValueError("Repack must retain the existing package's measured trust mode.")
    if trust != manifest["trust"]:
        raise ValueError("Repack trust details differ from the measured trust receipt.")
    zip_hash = deterministic_zip(directory, output, expected_inventory=original_inventory)
    return {"schemaVersion": 1, "zipSha256": zip_hash, "bytes": output.stat().st_size,
            "appVersion": manifest["appVersion"], "architecture": manifest["architecture"],
            "trust": trust, "fileCount": len(manifest["files"]),
            "scope": "unchanged verified included source, signatures and distribution materials"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path, default=ROOT / "dist/NativeForensics.app")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--mode", choices=("development", "release"))
    parser.add_argument("--from-distribution", type=Path, help="Validate and repack the unchanged included Source/materials package")
    parser.add_argument("--install-support", type=Path, help="Prebuilt original publisher helper; release requires notarized Developer ID")
    parser.add_argument("--install-support-receipt", type=Path, help="Captured compile/sign receipt required for a prebuilt publisher")
    parser.add_argument("--build-install-support", type=Path, help="Compile captured installer source and record raw/signed binary hashes")
    parser.add_argument("--architecture", choices=("arm64", "x86_64"))
    parser.add_argument("--minimum-macos")
    parser.add_argument("--sign-identity", default="-", help="Explicit signing identity for a publisher build; default ad hoc")
    parser.add_argument("--hardened-runtime", action="store_true")
    args = parser.parse_args()
    if args.build_install_support:
        if (not args.architecture or not args.minimum_macos or not args.install_support_receipt
                or args.from_distribution or args.output or args.install_support):
            parser.error("--build-install-support requires --architecture, --minimum-macos and a new --install-support-receipt path; packaging arguments are separate")
        if args.install_support_receipt.exists() or args.install_support_receipt.is_symlink():
            parser.error("Installer receipt output already exists; use a new path")
        no_links(args.install_support_receipt.parent, directory=True)
        receipt = build_install_support(ROOT, args.build_install_support, args.architecture, args.minimum_macos,
                                        sign_identity=args.sign_identity, hardened_runtime=args.hardened_runtime)
        with args.install_support_receipt.open("x") as stream:
            stream.write(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        print(json.dumps(receipt, indent=2, sort_keys=True))
    else:
        if not args.output:
            parser.error("Packaging/repacking requires --output")
        if args.from_distribution:
            if args.install_support or args.install_support_receipt:
                parser.error("Repack uses its included captured publisher receipt")
            result = repack_distribution(args.from_distribution, args.output, args.mode)
        else:
            result = package(args.app, args.output, args.mode or "development", args.install_support,
                             install_support_receipt=args.install_support_receipt)
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        print(f"Native distribution failed: {error}", file=sys.stderr)
        raise SystemExit(1)

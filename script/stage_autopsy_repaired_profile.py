#!/usr/bin/env python3
"""Stage the reviewed JNI-only repair without changing installed Autopsy.

The preparation receipt remains immutable. This creates a third, task-owned
profile with identical Java classes, macOS adapters and private Solr settings.
Only ignored local/autopsy-comparison may receive outputs.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import shlex
import shutil
import zipfile

from benchmark_autopsy_pipeline import (JNI_RESOURCE, MODULES, digest,
    effective_runtime_files, jni_resource_receipt, owned_path, symlink_tree,
    verify_setup, write_json)


def stage(setup_path: Path, repair_path: Path, output: Path) -> dict:
    setup = copy.deepcopy(json.loads(owned_path(setup_path).read_text()))
    repair = json.loads(owned_path(repair_path).read_text())
    verify_setup(setup)
    if (repair.get("status") != "built-not-installed-not-functionally-validated"
            or repair.get("protectedInputsUnchanged") is not True
            or repair.get("exportedSymbolsIdentical") is not True
            or repair.get("strictCodeSignatureVerified") is not True
            or repair.get("onlyChangedZIPmember") != JNI_RESOURCE):
        raise ValueError("Repair receipt lacks successful build and protected ABI/signature checks")
    original = setup["variants"]["installed-adapted"]
    old_jar = Path(original["runtime"]) / "autopsy/modules/ext/sleuthkit-4.15.0.jar"
    candidate = Path(repair["candidateJar"]["path"]).absolute()
    jni = Path(repair["candidateJNI"]["path"]).absolute()
    for artifact, path in (("candidateJar", candidate), ("candidateJNI", jni)):
        owned_path(path)
        if any(part.is_symlink() for part in (path, *path.parents)) or digest(path) != repair[artifact]["sha256"]:
            raise ValueError("Candidate artifact differs from reviewed repair receipt")
    if digest(old_jar) != repair["originalJar"]["sha256"]:
        raise ValueError("Repair was built against a different original Java datamodel")
    with zipfile.ZipFile(old_jar) as before, zipfile.ZipFile(candidate) as after:
        names = before.namelist()
        if len(names) != len(set(names)) or names != after.namelist():
            raise ValueError("Repair changed JAR entries or introduced duplicates")
        changed = [name for name in names if before.read(name) != after.read(name)]
        if changed != [JNI_RESOURCE] or after.read(JNI_RESOURCE) != jni.read_bytes():
            raise ValueError("Only the ARM64 JNI resource may change")
    source_tsk = Path(original["nativeDirectory"]) / "libtsk.23.dylib"
    if digest(source_tsk) != repair["nativeTSK"]["sha256"]:
        raise ValueError("Repair did not preserve the reviewed exFAT-capable libtsk")
    output = owned_path(output)
    output.mkdir()  # Never reuse or overwrite an earlier profile.
    native = output / "native-repaired-mac"
    native.mkdir()
    shutil.copy2(source_tsk, native / source_tsk.name)
    shutil.copy2(jni, native / "libtsk_jni.dylib")
    runtime = output / "runtime-repaired-mac"
    symlink_tree(Path(original["runtime"]), runtime,
                 {"autopsy/modules/ext/sleuthkit-4.15.0.jar": candidate})
    java_home = Path(setup["javaHome"])
    jdk = output / "jdk-repaired-mac"
    jdk.mkdir()
    for path in java_home.iterdir():
        if path.name != "bin":
            (jdk / path.name).symlink_to(path.resolve(), target_is_directory=path.is_dir())
    (jdk / "bin").mkdir()
    for path in (java_home / "bin").iterdir():
        if path.name != "java":
            (jdk / "bin" / path.name).symlink_to(path.resolve())
    wrapper = jdk / "bin/java"
    wrapper.write_text("#!/bin/sh\nexport DYLD_LIBRARY_PATH=" + shlex.quote(str(native)) +
                       "\nexport DYLD_PRINT_LIBRARIES=1\nexec " +
                       shlex.quote(str(java_home / "bin/java")) + ' "$@"\n')
    wrapper.chmod(0o755)
    selected = {"runtime": str(runtime), "jdk": str(jdk),
        "nativeDirectory": str(native), "safetyAdapter": original["safetyAdapter"],
        "modules": [{"name": name, "sha256": digest(runtime / "autopsy/modules" / name)}
                    for name in MODULES],
        "nativeFiles": [{"path": str(path), "sha256": digest(path)} for path in sorted(native.iterdir())],
        "effectiveFiles": effective_runtime_files(runtime, jdk),
        "repairReceipt": {"path": str(repair_path.resolve()), "sha256": digest(repair_path)},
        "repairScope": "Copied POSIX timezone environment; named NTFS directory DATA stream import and regular-file classification"}
    resource = jni_resource_receipt(selected)
    selected.update(tskJarSHA256=resource["jarSHA256"], jniResourceEntry=resource["resourceEntry"],
                    jniResourceSHA256=resource["sha256"])
    setup["variants"]["repaired-mac"] = selected
    setup["protectedFiles"].extend([
        {"path": str(repair_path.resolve()), "sha256": digest(repair_path)},
        {"path": str(candidate), "sha256": digest(candidate)},
        {"path": str(jni), "sha256": digest(jni)}])
    verify_setup(setup)
    write_json(output / "setup.json", setup)
    return setup


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--setup", type=Path, required=True)
    parser.add_argument("--repair", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    stage(args.setup, args.repair, args.output)
    print(json.dumps({"setup": str(args.output / "setup.json"), "variant": "repaired-mac",
                      "installedRuntimeChanged": False}))


if __name__ == "__main__":
    main()

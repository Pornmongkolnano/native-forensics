#!/usr/bin/env python3
"""Build a task-owned ARM64 JNI repair; never install or update a baseline.

Only four upstream JNI files and their compiler-discovered TSK header closure
are copied to ignored local output. The existing exFAT-corrected libtsk is a
read-only link dependency. Candidate JAR classes and every non-ARM64-JNI member
must remain byte-identical. Each invocation creates a fresh retained build.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import subprocess
import uuid
import zipfile

REPO = Path(__file__).resolve().parents[1]
LOCAL = REPO / "local/autopsy-comparison"
PATCHES = REPO / "Benchmarks/AutopsyComparison/patches"
SOURCE_REVISION = "01de0345edaa1ebf21dba6939a7c6bc7129e6e7d"
ORIGINAL_JAR_SHA = "9e888f8dfb14eb9e5ebce8f8199f550d149615ac2a7002df3fabbf5b24f69b3b"
ORIGINAL_JNI_SHA = "84795278951e6aaf4075db1b6dfd182097ae042cec363685e3a264ff9d0135f4"
NATIVE_TSK_SHA = "8a48c53e8897e3594232e678b2608af1b3956f15011db2623611d1b7456df8fa"
ARM64_MEMBER = "NATIVELIBS/aarch64/mac/libtsk_jni.dylib"
SOURCE_SHA = {
    "dataModel_SleuthkitJNI.cpp": "907ca37d8c2e9bbedf4f09cf26eebfd4686257994e6538b4e732f7d688f143e6",
    "auto_db_java.cpp": "e7b3a8fbce105c6ecbee1b607c6db226f898bbcae02b11008689c32dbc3c999a",
    "dataModel_SleuthkitJNI.h": "fefeddd6dd40627f61a758ad818c92f11f31233a1cfeba09b01862376d0ded50",
    "auto_db_java.h": "637847ade1da85f36140c6000c9eb70a1368aa94fd38872f4acbece74ee1353c",
}


def digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            sha.update(block)
    return sha.hexdigest()


def item(path: Path) -> dict:
    return {"path": str(path), "sha256": digest(path), "size": path.stat().st_size}


def run(command: list[str], output: Path, commands: list[dict]) -> str:
    result = subprocess.run(command, cwd=output, capture_output=True, text=True,
                            timeout=120, stdin=subprocess.DEVNULL)
    record = {"command": command, "exitCode": result.returncode,
              "stdout": result.stdout, "stderr": result.stderr}
    commands.append(record)
    if result.returncode:
        raise RuntimeError("Command failed: " + shlex.join(command) + "\n" + result.stderr)
    return result.stdout


def dependencies(path: Path, output: Path, commands: list[dict]) -> list[str]:
    return [line.strip() for line in run(["/usr/bin/otool", "-L", str(path)],
                                       output, commands).splitlines()[1:]]


def exports(path: Path, output: Path, commands: list[dict]) -> list[str]:
    return sorted(run(["/usr/bin/nm", "-gjU", str(path)], output, commands).splitlines())


def make_dependencies(text: str) -> list[Path]:
    text = text.replace("\\\n", "")
    return [Path(token).resolve() for token in shlex.split(text.split(":", 1)[1])]


def build(args) -> dict:
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise ValueError("This audited build recipe requires macOS ARM64")
    base = args.output.resolve()
    if not base.is_relative_to(LOCAL.resolve()):
        raise ValueError("Output must remain under ignored local/autopsy-comparison")
    base.mkdir(parents=True, exist_ok=True)
    output = base / ("build-" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                     + "-" + uuid.uuid4().hex[:8])
    output.mkdir()
    commands = []
    receipt = {"schemaVersion": 1, "status": "building", "outputDirectory": str(output),
               "scope": "Isolated ARM64 JNI and JAR resource repair; no installation or benchmark",
               "commands": commands, "sourceRevision": SOURCE_REVISION,
               "limitations": ["Process-global timezone is retained; simultaneous imports with different zones remain outside this repair.",
                               "Named DATA on filesystem-root inodes, empty basenames, and dot aliases is excluded to preserve Java root bookkeeping.",
                               "Direct C++ database importer is unchanged; this repair targets Autopsy Java JNI."]}
    protected = {}
    try:
        source = args.source.resolve()
        jar = args.jar.resolve()
        native = args.native_tsk.resolve()
        original_jni = args.original_jni.resolve()
        java_home = args.java_home.resolve()
        for path, expected in ((jar, ORIGINAL_JAR_SHA), (native, NATIVE_TSK_SHA),
                               (original_jni, ORIGINAL_JNI_SHA)):
            if digest(path) != expected:
                raise ValueError("Audited input hash mismatch: " + str(path))
            protected[path] = digest(path)
        if run(["/usr/bin/git", "-C", str(source), "rev-parse", "HEAD"], output, commands).strip() != SOURCE_REVISION:
            raise ValueError("Upstream source revision differs from audited TSK 4.15.0")
        jni_root = source / "bindings/java/jni"
        sources = output / "sources"
        includes = output / "includes"
        objects = output / "objects"
        for directory in (sources, includes, objects):
            directory.mkdir()
        receipt["originalJar"] = item(jar)
        receipt["originalJNI"] = item(original_jni)
        receipt["nativeTSK"] = item(native)
        receipt["upstreamSources"] = []
        for name, expected in SOURCE_SHA.items():
            original = jni_root / name
            if digest(original) != expected:
                raise ValueError("Audited JNI source hash mismatch: " + name)
            protected[original] = expected
            shutil.copy2(original, sources / name)
            receipt["upstreamSources"].append(item(original))
        patch_paths = [PATCHES / "001-jni-posix-timezone-lifetime.patch",
                       PATCHES / "002-jni-directory-data-streams.patch"]
        receipt["patchHashes"] = [item(path) for path in patch_paths]
        for patch in patch_paths:
            run(["/usr/bin/patch", "--batch", "--forward", "-p1", "-d", str(sources),
                 "-i", str(patch)], output, commands)
        receipt["patchedSources"] = [item(sources / name) for name in SOURCE_SHA]
        compiler = run(["/usr/bin/xcrun", "--find", "clang++"], output, commands).strip()
        receipt["toolchain"] = {"compiler": item(Path(compiler)),
                                "version": run([compiler, "--version"], output, commands),
                                "sdkPath": run(["/usr/bin/xcrun", "--show-sdk-path"], output, commands).strip(),
                                "jdk": str(java_home),
                                "javaVersion": run([str(java_home / "bin/java"), "--version"], output, commands)}
        common = [compiler, "-std=c++14", "-g", "-O2", "-fPIC", "-arch", "arm64",
                  "-isysroot", receipt["toolchain"]["sdkPath"],
                  "-DHAVE_CONFIG_H", "-D_THREAD_SAFE", "-pthread",
                  "-Wno-unused-command-line-argument", "-Wno-overloaded-virtual",
                  "-I" + str(sources), "-I" + str(java_home / "include"),
                  "-I" + str(java_home / "include/darwin"),
                  "-I/opt/homebrew/include", "-I/opt/homebrew/opt/postgresql@15/include"]
        receipt["configuration"] = {"compilerFlags": common[1:],
                                    "nativeTSKRebuilt": False, "upstreamJNIOnly": True}
        # Discover only the TSK headers actually used by the two translation units.
        copied = set()
        for name in ("dataModel_SleuthkitJNI.cpp", "auto_db_java.cpp"):
            dependency_text = run(common + ["-I" + str(source), "-MM", "-MT", "object",
                                           str(sources / name)], output, commands)
            for dependency in make_dependencies(dependency_text):
                if dependency.is_relative_to(source):
                    relative = dependency.relative_to(source)
                    target = includes / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    if dependency not in copied:
                        shutil.copy2(dependency, target)
                        protected[dependency] = digest(dependency)
                        copied.add(dependency)
        receipt["copiedHeaderClosure"] = [item(path) for path in sorted(copied)]
        object_paths = []
        for name in ("dataModel_SleuthkitJNI.cpp", "auto_db_java.cpp"):
            target = objects / (Path(name).stem + ".o")
            depfile = objects / (Path(name).stem + ".d")
            run(common + ["-I" + str(includes), "-MMD", "-MF", str(depfile),
                          "-c", str(sources / name), "-o", str(target)], output, commands)
            if any(path.is_relative_to(source) for path in make_dependencies(depfile.read_text())):
                raise AssertionError("Actual compilation escaped copied upstream header closure")
            object_paths.append(target)
        candidate = output / "libtsk_jni.0.dylib"
        original_deps = dependencies(original_jni, output, commands)
        install_name = original_deps[0].split(" (compatibility version", 1)[0]
        run([compiler, "-arch", "arm64", "-isysroot", receipt["toolchain"]["sdkPath"],
             "-dynamiclib", "-install_name", install_name,
             "-compatibility_version", "1.0.0", "-current_version", "1.0.0",
             "-Wl,-headerpad_max_install_names", *map(str, object_paths), str(native),
             "-L/opt/homebrew/opt/libewf/lib", "-L/opt/homebrew/opt/afflib/lib",
             "-L/opt/homebrew/opt/sqlite/lib", "-lewf", "-lafflib", "-lsqlite3", "-lz",
             "-o", str(candidate)], output, commands)
        run(["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none", str(candidate)], output, commands)
        run(["/usr/bin/codesign", "--verify", "--strict", "--verbose=2", str(candidate)], output, commands)
        architecture = run(["/usr/bin/lipo", "-archs", str(candidate)], output, commands).strip()
        if architecture != "arm64":
            raise AssertionError("Candidate must contain only ARM64")
        candidate_deps = dependencies(candidate, output, commands)
        if sorted(candidate_deps) != sorted(original_deps):
            raise AssertionError("JNI dependency closure/install name changed")
        original_exports = exports(original_jni, output, commands)
        candidate_exports = exports(candidate, output, commands)
        if candidate_exports != original_exports:
            raise AssertionError("Exported JNI/C++ ABI symbol set changed")
        symbols = run(["/usr/bin/nm", "-g", str(candidate)], output, commands)
        if " U _setenv" not in symbols or " U _putenv" in symbols:
            raise AssertionError("Candidate POSIX timezone path does not exclusively import setenv")
        candidate_jar = output / "sleuthkit-4.15.0.jar"
        members = []
        with zipfile.ZipFile(jar) as old, zipfile.ZipFile(candidate_jar, "x") as new:
            names = old.namelist()
            if len(set(names)) != len(names) or names.count(ARM64_MEMBER) != 1:
                raise ValueError("Expected exactly one ARM64 JNI ZIP member and no duplicate names")
            if hashlib.sha256(old.read(ARM64_MEMBER)).hexdigest() != ORIGINAL_JNI_SHA:
                raise ValueError("Embedded original JNI differs from standalone audited baseline")
            new.comment = old.comment
            for info in old.infolist():
                data = candidate.read_bytes() if info.filename == ARM64_MEMBER else old.read(info.filename)
                new.writestr(info, data)
        with zipfile.ZipFile(jar) as old, zipfile.ZipFile(candidate_jar) as new:
            if old.namelist() != new.namelist() or old.comment != new.comment:
                raise AssertionError("ZIP order/names/comment changed")
            changed = []
            for name in old.namelist():
                before = hashlib.sha256(old.read(name)).hexdigest()
                after = hashlib.sha256(new.read(name)).hexdigest()
                members.append({"name": name, "originalSHA256": before, "candidateSHA256": after})
                if before != after:
                    changed.append(name)
            if changed != [ARM64_MEMBER]:
                raise AssertionError("Unexpected ZIP member contents changed")
        (output / "jar-member-hashes.json").write_text(json.dumps(members, indent=2) + "\n")
        receipt.update({"candidateJNI": item(candidate), "candidateJar": item(candidate_jar),
                        "onlyChangedZIPmember": ARM64_MEMBER,
                        "jarMemberHashes": item(output / "jar-member-hashes.json"),
                        "unchangedZIPmembers": len(members) - 1,
                        "architecture": architecture, "dependencies": candidate_deps,
                        "exportedSymbolCount": len(candidate_exports), "exportedSymbolsIdentical": True,
                        "strictCodeSignatureVerified": True, "posixSetenvImported": True,
                        "status": "built-not-installed-not-functionally-validated"})
    except Exception as error:
        receipt["status"] = "failed"
        receipt["error"] = type(error).__name__ + ": " + str(error)
    finally:
        receipt["protectedInputs"] = []
        for path, before in sorted(protected.items()):
            row = {"path": str(path), "beforeSHA256": before, "unchanged": False}
            try:
                after = digest(path)
                row.update({"afterSHA256": after, "unchanged": after == before})
            except Exception as error:
                row["readError"] = type(error).__name__ + ": " + str(error)
            receipt["protectedInputs"].append(row)
        receipt["protectedInputsUnchanged"] = all(row["unchanged"] for row in receipt["protectedInputs"])
        if not receipt["protectedInputsUnchanged"]:
            receipt["status"] = "failed"
            receipt["error"] = "Protected source or runtime input changed during build"
        receipt_path = output / "repair-receipt.json"
        receipt_path.write_text(json.dumps(receipt, indent=2) + "\n")
        receipt["receiptPath"] = str(receipt_path)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--jar", required=True, type=Path)
    parser.add_argument("--native-tsk", required=True, type=Path)
    parser.add_argument("--original-jni", required=True, type=Path)
    parser.add_argument("--java-home", required=True, type=Path)
    parser.add_argument("--output", type=Path, default=LOCAL / "repair-20261007")
    result = build(parser.parse_args())
    print(json.dumps({key: result[key] for key in ("status", "receiptPath", "candidateJNI", "candidateJar", "error")
                      if key in result}, indent=2))
    raise SystemExit(0 if result["status"].startswith("built-") else 1)


if __name__ == "__main__":
    main()

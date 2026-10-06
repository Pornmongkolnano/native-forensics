#!/usr/bin/env python3
"""Build the pinned, patched RAW/EWF helper using only Xcode and macOS libraries.

Downloads/builds stay in .engine (ignored by Git). No Homebrew runtime is used.
The manifest is an integrity/build receipt, not a filesystem-coverage assertion.
"""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import shlex
import tempfile
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / ".engine"
SPEC_PATH = ROOT / "NativeEngine/dependencies.json"
SCRIPT_VERSION = 2
LIBEWF_SUBDIRS = "include common libcerror libcthreads libcdata libcdatetime libclocale libcnotify libcsplit libuna libcfile libcpath libbfio libfcache libfdata libfdatetime libfguid libfvalue libhmac libcaes libewf libodraw libsmdev libsmraw ewftools"

def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

def atomic_json(path: Path, value: object) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)

def capture(argv: list[str], env: dict[str, str]) -> str:
    return subprocess.check_output(argv, env=env, text=True).strip()

def run(argv: list[str], cwd: Path, env: dict[str, str], log: Path) -> None:
    print(f"Native engine: {log.stem}", flush=True)
    with log.open("w") as output:
        output.write(json.dumps(argv) + "\n")
        output.flush()
        result = subprocess.run(argv, cwd=cwd, env=env, stdout=output, stderr=subprocess.STDOUT)
    if result.returncode:
        tail = "\n".join(log.read_text(errors="replace").splitlines()[-24:])
        raise RuntimeError(f"Command failed ({result.returncode}); {log}\n{tail}")

def download(dependency: dict, env: dict[str, str]) -> Path:
    destination = CACHE / "downloads" / dependency["archive"]
    if destination.exists():
        if sha(destination) != dependency["sha256"]:
            raise RuntimeError(f"Cached dependency checksum mismatch: {destination}; remove this cached file explicitly to retry")
        return destination
    temporary = destination.with_name(destination.name + ".part")
    try:
        subprocess.run(["/usr/bin/curl", "--fail", "--location", "--silent", "--show-error", "--retry", "2", "--proto", "=https", "--proto-redir", "=https", dependency["url"], "--output", str(temporary)], check=True, env=env)
        if sha(temporary) != dependency["sha256"]:
            raise RuntimeError(f"Downloaded dependency checksum mismatch: {dependency['name']}")
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)
    return destination

def safe_extract(archive: Path, source_root: str, destination: Path | None = None) -> Path:
    """Reject escapes/devices and archive entries traversing an earlier symlink."""
    destination = destination or CACHE / "deps"
    destination.mkdir(parents=True, exist_ok=True)
    root = destination / source_root
    if root.exists():
        shutil.rmtree(root)
    base = destination.resolve()
    with tarfile.open(archive) as bundle:
        members = bundle.getmembers()
        names: set[str] = set()
        for member in members:
            relative = PurePosixPath(member.name)
            if relative.is_absolute() or ".." in relative.parts or not relative.parts or relative.parts[0] != source_root:
                raise RuntimeError(f"Unsafe archive member: {member.name}")
            if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
                raise RuntimeError(f"Unsupported archive member: {member.name}")
            if member.name in names and not member.isdir():
                raise RuntimeError(f"Duplicate archive member: {member.name}")
            names.add(member.name)
            if member.issym() or member.islnk():
                link = PurePosixPath(member.linkname)
                target = (destination / relative.parent / member.linkname) if member.issym() else (destination / member.linkname)
                if link.is_absolute() or not target.resolve().is_relative_to(root.resolve()):
                    raise RuntimeError(f"Unsafe archive link: {member.name}")
        symlinks = {PurePosixPath(m.name) for m in members if m.issym()}
        for member in members:
            relative = PurePosixPath(member.name)
            if any(parent in symlinks for parent in relative.parents):
                raise RuntimeError(f"Archive entry traverses a symlink: {member.name}")
            if not (destination / member.name).resolve().is_relative_to(base):
                raise RuntimeError(f"Archive member escapes extraction: {member.name}")
        # Members have been validated above; no user-supplied archive is accepted.
        bundle.extractall(destination, members=members)
    return root

def valid_receipt(receipt: dict | None, fingerprint: str, artifacts: list[Path]) -> bool:
    if not receipt or receipt.get("fingerprint") != fingerprint:
        return False
    inventory = receipt.get("sha256", {})
    if any(str(path.relative_to(CACHE)) not in inventory for path in artifacts):
        return False
    current_files = {str(path.relative_to(CACHE)) for path in (CACHE / "prefix").rglob("*") if path.is_file()}
    current_files.add("deps/json/include/nlohmann/json.hpp")
    if current_files != set(inventory):
        return False
    return all((CACHE / name).is_file() and not (CACHE / name).is_symlink()
               and digest == sha(CACHE / name) for name, digest in inventory.items())

def read_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None

def build_dependencies(spec: dict, env: dict[str, str], jobs: int, identity: dict, force: bool) -> dict:
    prefix = CACHE / "prefix"
    required = [prefix / "lib/libtsk.a", prefix / "lib/libewf.a", prefix / "include/tsk/libtsk.h", prefix / "include/libewf.h", CACHE / "deps/json/include/nlohmann/json.hpp"]
    for dependency in spec["dependencies"]:
        for patch in dependency.get("patches", []):
            if sha(ROOT / patch["path"]) != patch["sha256"]:
                raise RuntimeError("Patch checksum differs from pinned dependency specification")
    dependency_identity = {"scriptVersion": SCRIPT_VERSION, "bootstrapSha256": sha(Path(__file__)), "dependencies": spec, "toolchain": identity, "jobs": jobs}
    fingerprint = hashlib.sha256(canonical(dependency_identity)).hexdigest()
    receipt_path = CACHE / "dependencies-build.json"
    receipt = read_json(receipt_path)
    # Source availability is part of the receipt even when native binaries are cached.
    archives = {item["name"]: download(item, env) for item in spec["dependencies"]}
    if not force and valid_receipt(receipt, fingerprint, required):
        print("Native engine: verified cached static dependencies", flush=True)
        return receipt
    # The temporary worktree is private, removed after install and independent
    # of checkout/SDK paths. All retained downloads/products remain in .engine.
    with tempfile.TemporaryDirectory(prefix="nf-native-", dir="/private/tmp") as directory:
        compile_static_dependencies(spec, env, jobs, identity, archives, Path(directory))
    json_include = CACHE / "deps/json/include/nlohmann"
    json_include.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(archives["nlohmann-json"], json_include / "json.hpp")
    inventory = [path for path in sorted(prefix.rglob("*")) if path.is_file()]
    inventory.append(json_include / "json.hpp")
    receipt = {"fingerprint": fingerprint, "identity": dependency_identity, "sha256": {str(path.relative_to(CACHE)): sha(path) for path in inventory}}
    atomic_json(receipt_path, receipt)
    return receipt

def compile_static_dependencies(spec: dict, env: dict[str, str], jobs: int, identity: dict, archives: dict[str, Path], work: Path) -> None:
    by_name = {item["name"]: item for item in spec["dependencies"]}
    ewf = safe_extract(archives["libewf"], by_name["libewf"]["sourceRoot"], work / "deps")
    tsk = safe_extract(archives["sleuthkit"], by_name["sleuthkit"]["sourceRoot"], work / "deps")
    prefix = work / "prefix"
    (prefix / "include").mkdir(parents=True)
    (prefix / "lib").mkdir()
    build_env = env.copy()
    # Autotools expands compiler flags without respecting embedded quotes.
    # Keep its complete source/prefix/SDK/tool paths free of spaces internally.
    sdk_alias = work / "sdk"
    sdk_alias.symlink_to(env["SDKROOT"], target_is_directory=True)
    for variable in ("CC", "CXX"):
        wrapper = work / variable.lower()
        wrapper.write_text("#!/bin/sh\nexec " + shlex.quote(env[variable]) + ' "$@"\n')
        wrapper.chmod(0o755)
        build_env[variable] = str(wrapper)
    flags = f'-O2 -arch {identity["architecture"]} -isysroot {sdk_alias} -mmacosx-version-min={spec["minimumMacOS"]}'
    build_env.update({"CFLAGS": flags, "CXXFLAGS": flags + " -std=c++17", "LDFLAGS": flags, "ZERO_AR_DATE": "1"})
    build_env["CPPFLAGS"] = f'-I{prefix / "include"}'
    build_env["LDFLAGS"] += f' -L{prefix / "lib"}'
    ewf_flags = [str(ewf / "configure"), f"--prefix={prefix}", "--disable-shared", "--enable-static", "--disable-dependency-tracking", "--disable-nls", "--disable-python", "--without-openssl", "--disable-openssl-evp-cipher", "--disable-openssl-evp-md", "--without-libfuse", "--without-libiconv-prefix", "--without-libintl-prefix"]
    # Pin libyal support libraries to the versions in this release tarball.
    ewf_flags += [f"--with-{name}=no" for name in LIBEWF_SUBDIRS.split() if name.startswith("lib") and name != "libewf"]
    run(ewf_flags, ewf, build_env, CACHE / "logs/libewf-configure.log")
    run(["/usr/bin/make", f"-j{jobs}", "all-recursive", f"SUBDIRS={LIBEWF_SUBDIRS}"], ewf, build_env, CACHE / "logs/libewf-build.log")
    run(["/usr/bin/make", "install-recursive", "SUBDIRS=include libewf ewftools"], ewf, build_env, CACHE / "logs/libewf-install.log")
    for index, patch in enumerate(by_name["sleuthkit"].get("patches", [])):
        patch_path = ROOT / patch["path"]
        if sha(patch_path) != patch["sha256"]:
            raise RuntimeError("TSK patch digest differs from dependencies.json")
        run(["/usr/bin/patch", "--batch", "--forward", "-p1", "-i", str(patch_path)], tsk, build_env, CACHE / f"logs/sleuthkit-patch-{index}.log")
    # Generated configure otherwise injects local package-manager paths on macOS.
    # Keep dependency discovery limited to the SDK and this owned static prefix.
    configure_path = tsk / "configure"
    configure_text = configure_path.read_text()
    for injected_flag in ('CPPFLAGS="$CPPFLAGS -I$HOMEBREW_PREFIX/include"',
                          'LDFLAGS="$LDFLAGS -L$HOMEBREW_PREFIX/lib"',
                          'CPPFLAGS="$CPPFLAGS -I/usr/local/include"',
                          'LDFLAGS="$LDFLAGS -L/usr/local/lib"'):
        if configure_text.count(injected_flag) != 1:
            raise RuntimeError("Pinned TSK configure search-path transformation no longer matches")
        configure_text = configure_text.replace(injected_flag, ': # NativeForensics: system-only dependency search')
    configure_path.write_text(configure_text)
    build_env["LIBS"] = "-lz -lbz2 -liconv"
    tsk_flags = [str(tsk / "configure"), f"--prefix={prefix}", "--disable-java", "--disable-cppunit", "--disable-dependency-tracking", "--disable-shared", "--enable-static", "--without-afflib", "--without-libbfio", "--without-libvhdi", "--without-libvmdk", "--without-libvslvm", f"--with-libewf={prefix}"]
    run(tsk_flags, tsk, build_env, CACHE / "logs/sleuthkit-configure.log")
    configuration = (tsk / "tsk/tsk_config.h").read_text()
    if "#define HAVE_LIBEWF 1" not in configuration:
        raise RuntimeError("TSK configure did not enable EWF; refuse a RAW-only helper")
    run(["/usr/bin/make", f"-j{jobs}", "-C", "tsk"], tsk, build_env, CACHE / "logs/sleuthkit-build.log")
    run(["/usr/bin/make", "-C", "tsk", "install"], tsk, build_env, CACHE / "logs/sleuthkit-install.log")
    run(["/usr/bin/make", "install-nobase_includeHEADERS"], tsk, build_env, CACHE / "logs/sleuthkit-headers.log")
    # Rewrite metadata-only installation prefixes before moving owned products.
    # The helper uses explicit archives, never a .la/pkg-config runtime lookup.
    for metadata in list((prefix / "lib").glob("*.la")) + list((prefix / "lib/pkgconfig").glob("*.pc")):
        metadata.write_text(metadata.read_text().replace(str(prefix), str(CACHE / "prefix")))
    for tool in (prefix / "bin").iterdir():
        if tool.is_file():
            dependency_closure(tool, env)
    stage = CACHE / "prefix.stage"
    previous = CACHE / "prefix.previous"
    for owned in (stage, previous):
        if owned.exists():
            shutil.rmtree(owned)
    shutil.copytree(prefix, stage)
    installed = CACHE / "prefix"
    if installed.exists():
        installed.rename(previous)
    try:
        stage.rename(installed)
    except OSError:
        if previous.exists() and not installed.exists():
            previous.rename(installed)
        raise
    if previous.exists():
        shutil.rmtree(previous)

def dependency_closure(binary: Path, env: dict[str, str]) -> list[str]:
    loads = capture(["/usr/bin/otool", "-L", str(binary)], env).splitlines()[1:]
    dependencies = [line.strip().split(" (", 1)[0] for line in loads]
    if not dependencies or any(not item.startswith(("/usr/lib/", "/System/Library/")) for item in dependencies):
        raise RuntimeError(f"Helper has a non-system dynamic dependency: {dependencies}")
    return dependencies

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="Rebuild static libraries and helper from pinned downloads")
    parser.add_argument("--jobs", type=int, default=4, choices=range(1, 5))
    parser.add_argument("--dependencies-only", action="store_true", help="Build native dependencies without compiling the helper")
    args = parser.parse_args()
    if sys.platform != "darwin" or platform.machine() not in ("arm64", "x86_64"):
        raise RuntimeError("This bootstrap requires a native macOS arm64 or x86_64 Xcode toolchain")
    for name in ("downloads", "deps", "logs", "bin", "relink"):
        (CACHE / name).mkdir(parents=True, exist_ok=True)
    spec = json.loads(SPEC_PATH.read_text())
    env = os.environ.copy()
    for key in list(env):
        if key.startswith(("DYLD_", "PKG_CONFIG_")) or key in ("CPATH", "CPLUS_INCLUDE_PATH", "C_INCLUDE_PATH", "LIBRARY_PATH", "CPPFLAGS", "LDFLAGS", "CFLAGS", "CXXFLAGS", "SDKROOT", "LIBS", "CC", "CXX"):
            env.pop(key, None)
    env.update({"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C", "PKG_CONFIG": "/usr/bin/false", "MACOSX_DEPLOYMENT_TARGET": spec["minimumMacOS"]})
    sdk = capture(["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path"], env)
    cc = capture(["/usr/bin/xcrun", "--find", "clang"], env)
    cxx = capture(["/usr/bin/xcrun", "--find", "clang++"], env)
    flags = f'-O2 -arch {platform.machine()} -isysroot {sdk} -mmacosx-version-min={spec["minimumMacOS"]}'
    env.update({"CC": cc, "CXX": cxx, "CFLAGS": flags, "CXXFLAGS": flags + " -std=c++17", "LDFLAGS": flags, "SDKROOT": sdk})
    identity = {"architecture": platform.machine(), "sdkVersion": capture(["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-version"], env), "compiler": capture([cc, "--version"], env).splitlines()[0], "minimumMacOS": spec["minimumMacOS"]}
    with (CACHE / "build.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        receipt = build_dependencies(spec, env, args.jobs, identity, args.force)
        if args.dependencies_only:
            return 0
        source = ROOT / "NativeEngine/NFTSKEngine.cpp"
        if not source.is_file():
            raise RuntimeError("NativeEngine/NFTSKEngine.cpp is not present; dependencies built successfully")
        patches = next(item for item in spec["dependencies"] if item["name"] == "sleuthkit")["patches"]
        applied_patches = [{"path": patch["path"], "sha256": patch["sha256"]} for patch in patches]
        patch_digest = hashlib.sha256(canonical(applied_patches)).hexdigest()
        license_inventory = {str(path.relative_to(ROOT)): sha(path) for path in sorted((ROOT / "NativeEngine/licenses").rglob("*")) if path.is_file()}
        fingerprint = hashlib.sha256(canonical({"dependencyFingerprint": receipt["fingerprint"], "source": sha(source), "script": sha(Path(__file__)), "spec": sha(SPEC_PATH), "notices": sha(ROOT / "THIRD_PARTY_NOTICES.md"), "licenses": license_inventory})).hexdigest()
        binary = CACHE / "bin/NFTSKEngine"
        manifest_path = CACHE / "manifest.json"
        manifest = read_json(manifest_path)
        if not args.force and manifest and manifest.get("buildFingerprint") == fingerprint and binary.exists() and manifest.get("engineSha256") == sha(binary):
            dependency_closure(binary, env)
            print(f"Native engine: verified cached helper {binary}")
            return 0
        obj = CACHE / "relink/NFTSKEngine.o"
        compile_args = [cxx, "-std=c++17", "-O2", "-arch", platform.machine(), "-isysroot", sdk, f'-mmacosx-version-min={spec["minimumMacOS"]}', "-I", str(CACHE / "prefix/include"), "-I", str(CACHE / "deps/json/include"), f'-DNF_PATCH_DIGEST="{patch_digest}"', f'-DNF_ENGINE_VERSION="{spec["engineVersion"]}"', "-c", str(source), "-o", str(obj)]
        run(compile_args, ROOT, env, CACHE / "logs/helper-compile.log")
        libraries = [CACHE / "prefix/lib/libtsk.a", CACHE / "prefix/lib/libewf.a"]
        link_args = [cxx, "-arch", platform.machine(), "-isysroot", sdk, f'-mmacosx-version-min={spec["minimumMacOS"]}', str(obj), *map(str, libraries), "-lz", "-lbz2", "-liconv", "-framework", "CoreFoundation", "-o", str(binary)]
        run(link_args, ROOT, env, CACHE / "logs/helper-link.log")
        subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", str(binary)], env=env, check=True, capture_output=True)
        closure = dependency_closure(binary, env)
        architecture = capture(["/usr/bin/lipo", "-archs", str(binary)], env)
        if architecture != platform.machine():
            raise RuntimeError("Helper architecture does not match the native build host")
        for library in libraries:
            shutil.copyfile(library, CACHE / "relink" / library.name)
        (CACHE / "relink/link-command.json").write_text(json.dumps(link_args, indent=2) + "\n")
        recipe = CACHE / "relink/Relink.command"
        recipe.write_text("#!/bin/sh\nset -eu\ntask_dir=$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd)\n" +
            f'/usr/bin/xcrun --sdk macosx clang++ -arch {architecture} -mmacosx-version-min={spec["minimumMacOS"]} ' +
            '\"$task_dir/NFTSKEngine.o\" \"$task_dir/libtsk.a\" \"$task_dir/libewf.a\" ' +
            '-lz -lbz2 -liconv -framework CoreFoundation -o \"$task_dir/NFTSKEngine-relinked\"\n' +
            '/usr/bin/codesign --force --sign - \"$task_dir/NFTSKEngine-relinked\"\n')
        recipe.chmod(0o755)
        notices = CACHE / "licenses"
        if notices.exists():
            shutil.rmtree(notices)
        shutil.copytree(ROOT / "NativeEngine/licenses", notices)
        shutil.copyfile(ROOT / "THIRD_PARTY_NOTICES.md", notices / "THIRD_PARTY_NOTICES.md")
        manifest = {"schemaVersion": 1, "protocolVersion": spec["protocolVersion"], "engineVersion": spec["engineVersion"], "patchDigest": patch_digest, "exfatPatchDigest": patches[0]["sha256"], "appliedPatches": applied_patches, "buildFingerprint": fingerprint, "engineSha256": sha(binary), "architecture": architecture, "toolchain": identity, "dependencies": spec["dependencies"], "dynamicDependencyClosure": closure, "compiledImageCapabilities": ["RAW", "EWF"], "capabilityNote": "Filesystem coverage is validated by integration tests; build features alone do not certify all filesystems", "linking": "static libtsk + libewf, header-only nlohmann/json; system-only dynamic libraries", "configureTransform": "Remove four generated TSK configure Homebrew/usr/local -I/-L injections; transformation is in build_native_engine.py", "relinkArtifacts": "relink/ (helper object, static archives, link-command.json and portable Relink.command); source archives in downloads/", "licenses": "licenses/", "licenseSha256": license_inventory, "noticesSha256": sha(ROOT / "THIRD_PARTY_NOTICES.md"), "buildOnlyTools": "libewf ewftools in prefix/bin are test utilities and are not bundled in the app"}
        atomic_json(manifest_path, manifest)
        print(f"Native engine: built {binary}")
    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError, subprocess.CalledProcessError, ValueError) as error:
        print(f"Native engine build failed: {error}", file=sys.stderr)
        raise SystemExit(1)

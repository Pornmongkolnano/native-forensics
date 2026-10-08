"""Path-relative complete input graphs for the app and document decoder.

Receipts bind source/build inputs as observed by packaging. They supplement code
signatures; they are not a claim of reproducible compiler output or remote trust.
"""
from __future__ import annotations

import hashlib
import argparse
import json
from pathlib import Path, PurePosixPath
import re
import subprocess

SCHEMA = 3
BUILD_PATH_POLICY = "configuration-specific-staged-debug-map-policy-v1"
PRIVATE_PATH_MARKERS = (b"/Users/", b"/private/var/folders/", b"/var/folders/")
PRODUCT_DIRECTORIES = {
    "NativeForensics": ("Sources/NativeForensics", "Sources/ForensicsCore", "Sources/NFDecoderIPC", "Sources/CSQLite3"),
    "NFDocumentDecoder": ("Sources/NFDocumentDecoder", "Sources/NFDocumentDecoding", "Sources/ForensicsCore", "Sources/NFDecoderIPC", "Sources/CSQLite3"),
    "NFDocumentDecoderXPC": ("Sources/NFDocumentDecoderXPC", "Sources/NFDocumentDecoding", "Sources/ForensicsCore", "Sources/NFDecoderIPC", "Sources/CSQLite3"),
    "NFDocumentDecoderWorker": ("Sources/NFDocumentDecoderWorker", "Sources/NFDocumentDecoding", "Sources/ForensicsCore", "Sources/NFDecoderIPC", "Sources/CSQLite3"),
}
V2_PRODUCT_DIRECTORIES = {name: value for name, value in PRODUCT_DIRECTORIES.items() if name != "NFDocumentDecoderWorker"}
# The schema-2 service parsed in-process. Schema 3 brokers only bounded IPC;
# the new worker independently binds the native parsing target's complete graph.
PRODUCT_DIRECTORIES["NFDocumentDecoderXPC"] = ("Sources/NFDocumentDecoderXPC", "Sources/ForensicsCore", "Sources/NFDecoderIPC", "Sources/CSQLite3")
LEGACY_PRODUCT_DIRECTORIES = {
    "NativeForensics": ("Sources/NativeForensics", "Sources/ForensicsCore", "Sources/CSQLite3"),
    "NFDocumentDecoder": ("Sources/NFDocumentDecoder", "Sources/ForensicsCore", "Sources/CSQLite3"),
}
RECIPES = {"Package.swift", "script/package_app.py", "script/validate_app_bundle.py",
           "script/source_provenance.py", "script/build_and_run.sh"}
SQLITE_INPUTS = {"Sources/CSQLite3/shim.h", "Sources/CSQLite3/module.modulemap"}
APP_ASSETS = {"Assets/AppIcon/AppIcon.icns", "Assets/AppIcon/AppIcon.png", "Assets/AppIcon/README.md"}
XPC_INFO_INPUT = "script/specs/document_xpc_info.plist"
XPC_ENTITLEMENTS_INPUT = "script/specs/document_xpc_entitlements.plist"
WORKER_ENTITLEMENTS_INPUT = "script/specs/document_worker_entitlements.plist"
V2_XPC_INPUTS = {XPC_INFO_INPUT, XPC_ENTITLEMENTS_INPUT}
XPC_INPUTS = V2_XPC_INPUTS | {WORKER_ENTITLEMENTS_INPUT}
IPC_INPUTS = {"Sources/NFDecoderIPC/NFDecoderIPC.m", "Sources/NFDecoderIPC/include/NFDecoderIPC.h"}
SOURCE_EXTENSIONS = {".swift", ".h", ".c", ".m", ".mm", ".cpp", ".modulemap"}
SAFE_PATH = re.compile(r"[A-Za-z0-9._/-]+\Z")
HASH = re.compile(r"[0-9a-f]{64}\Z")


def file_sha256(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def graph_digest(product: str, files: dict[str, str]) -> str:
    payload = json.dumps({"product": product, "sourceSha256": files}, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def safe_relative(name: str) -> bool:
    if not isinstance(name, str) or not SAFE_PATH.fullmatch(name):
        return False
    path = PurePosixPath(name)
    return not path.is_absolute() and ".." not in path.parts and path.as_posix() == name


def product_directories(product: str, schema: int = SCHEMA) -> tuple[str, ...]:
    products = (PRODUCT_DIRECTORIES if schema == SCHEMA else V2_PRODUCT_DIRECTORIES if schema == 2
                else LEGACY_PRODUCT_DIRECTORIES if schema == 1 else {})
    if product not in products:
        raise ValueError("Unknown source-provenance product.")
    return products[product]


def required_inputs(product: str, schema: int = SCHEMA) -> set[str]:
    product_directories(product, schema)
    return (RECIPES | SQLITE_INPUTS | (APP_ASSETS if product == "NativeForensics" else set())
            | (IPC_INPUTS if schema >= 2 else set())
            | ((XPC_INPUTS if schema == SCHEMA else V2_XPC_INPUTS) if schema >= 2
               and product in {"NativeForensics", "NFDocumentDecoderXPC"} else set())
            | ({WORKER_ENTITLEMENTS_INPUT} if product == "NFDocumentDecoderWorker" else set()))


def source_graph(root: Path, product: str, schema: int = SCHEMA) -> dict[str, str]:
    root = root.resolve(strict=True)
    paths = set(required_inputs(product, schema))
    for name in product_directories(product, schema):
        directory = root / name
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError("A required source graph directory is missing or linked.")
        for path in directory.rglob("*"):
            if path.is_symlink():
                raise ValueError("A source graph must not contain symbolic links.")
            if path.is_file() and path.suffix in SOURCE_EXTENSIONS:
                paths.add(path.relative_to(root).as_posix())
    files = {}
    for name in sorted(paths):
        path = root / name
        if (not safe_relative(name) or path.is_symlink() or not path.is_file()
                or any(parent.is_symlink() for parent in path.parents if parent != root and parent.is_relative_to(root))):
            raise ValueError("A required source graph input is missing or linked.")
        files[name] = file_sha256(path)
    # Reject additions/removals during enumeration; a caller also rechecks this
    # complete graph after staging. Missing required inputs never become optional.
    validate_source_receipt({"sourceGraphSchemaVersion": schema, "product": product,
        "sourceSha256": files, "sourceGraphSha256": graph_digest(product, files)}, product)
    return files


def make_source_receipt(root: Path, product: str) -> dict:
    files = source_graph(root, product)
    return {"sourceGraphSchemaVersion": SCHEMA, "product": product, "sourceSha256": files,
            "sourceGraphSha256": graph_digest(product, files)}


def validate_source_receipt(receipt: dict, product: str, root: Path | None = None) -> dict[str, str]:
    if (not isinstance(receipt, dict) or receipt.get("sourceGraphSchemaVersion") not in {1, 2, SCHEMA}
            or receipt.get("product") != product):
        raise ValueError("Invalid or unsupported complete source graph receipt.")
    schema = receipt["sourceGraphSchemaVersion"]
    files = receipt.get("sourceSha256")
    if not isinstance(files, dict) or not required_inputs(product, schema).issubset(files):
        raise ValueError("The complete source graph is missing required inputs.")
    prefixes = tuple(value + "/" for value in product_directories(product, schema))
    required = required_inputs(product, schema)
    for name, digest in files.items():
        if (not safe_relative(name) or not isinstance(digest, str) or not HASH.fullmatch(digest)
                or (name not in required and not (name.startswith(prefixes) and PurePosixPath(name).suffix in SOURCE_EXTENSIONS))):
            raise ValueError("The complete source graph has an invalid input or digest.")
    for directory in product_directories(product, schema):
        extensions = {".h", ".modulemap"} if directory.endswith("/CSQLite3") else {".m"} if directory.endswith("/NFDecoderIPC") else {".swift"}
        if not any(name.startswith(directory + "/") and PurePosixPath(name).suffix in extensions for name in files):
            raise ValueError("The complete source graph is missing a target's source inputs.")
    if receipt.get("sourceGraphSha256") != graph_digest(product, files):
        raise ValueError("The complete source graph digest differs from its inventory.")
    if root is not None and source_graph(root, product, schema) != files:
        raise ValueError("Corresponding complete source graph changed, is missing, or has extra inputs.")
    return files


def snapshot_products(root: Path, configuration: str = "release") -> dict:
    if configuration not in {"debug", "release"}:
        raise ValueError("Unknown build configuration.")
    return {"schemaVersion": 1, "buildConfiguration": configuration, "buildPathPolicy": BUILD_PATH_POLICY,
            "products": {product: make_source_receipt(root, product)
                                             for product in PRODUCT_DIRECTORIES}}


def verify_build_receipt(root: Path, binary_directory: Path, receipt: dict) -> None:
    if (not isinstance(receipt, dict) or receipt.get("schemaVersion") != 1
            or receipt.get("buildConfiguration") not in {"debug", "release"}
            or receipt.get("buildPathPolicy") != BUILD_PATH_POLICY
            or set(receipt.get("products", {})) != set(PRODUCT_DIRECTORIES)
            or set(receipt.get("compiledBinarySha256", {})) != set(PRODUCT_DIRECTORIES)):
        raise ValueError("Missing or incomplete pre-compilation build-input receipt.")
    for product in PRODUCT_DIRECTORIES:
        validate_source_receipt(receipt["products"][product], product, root)
        path = binary_directory / product
        if path.is_symlink() or not path.is_file() or file_sha256(path) != receipt["compiledBinarySha256"][product]:
            raise ValueError("Compiled binary differs from its source-bound build-input receipt.")


def seal_build(root: Path, binary_directory: Path, snapshot: dict) -> dict:
    if not isinstance(snapshot, dict) or snapshot.get("schemaVersion") != 1 or set(snapshot.get("products", {})) != set(PRODUCT_DIRECTORIES):
        raise ValueError("Invalid pre-compilation source snapshot.")
    hashes = {}
    for product in PRODUCT_DIRECTORIES:
        validate_source_receipt(snapshot["products"][product], product, root)
        path = binary_directory / product
        if path.is_symlink() or not path.is_file():
            raise ValueError("A compiled product is missing or linked.")
        hashes[product] = file_sha256(path)
    receipt = {**snapshot, "compiledBinarySha256": hashes,
               "scope": "source graph captured before compilation, checked after compilation and before staging"}
    verify_build_receipt(root, binary_directory, receipt)
    return receipt


def check_binary_privacy(path: Path) -> None:
    """Inspect all bytes, including linker debug-map strings skipped by strings."""
    carry = b""
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            combined = carry + block
            if any(marker in combined for marker in PRIVATE_PATH_MARKERS):
                raise ValueError("Distribution privacy blocker: compiler/user temporary path bytes remain in executable.")
            carry = combined[-max(map(len, PRIVATE_PATH_MARKERS)):]


def apply_staged_privacy_transform(path: Path, configuration: str) -> str:
    if configuration == "release":
        # Standard debug-map removal; raw .build products/dSYMs remain untouched.
        # Never rewrite arbitrary string bytes or alter an already sealed bundle.
        subprocess.run(["/usr/bin/strip", "-S", str(path)], check=True, capture_output=True)
        check_binary_privacy(path)
        return "strip-S-on-staged-release-copy"
    if configuration == "debug":
        return "unstripped-local-debug-copy"
    raise ValueError("Unknown staged packaging configuration.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument("--snapshot", type=Path)
    operation.add_argument("--seal-build", type=Path)
    parser.add_argument("--binary-directory", type=Path)
    parser.add_argument("--build-configuration", choices=("debug", "release"), default="release")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if args.snapshot:
        args.snapshot.write_text(json.dumps(snapshot_products(root, args.build_configuration), indent=2, sort_keys=True) + "\n")
    else:
        if args.binary_directory is None:
            parser.error("--seal-build requires --binary-directory")
        receipt = seal_build(root, args.binary_directory, json.loads(args.seal_build.read_text()))
        destination = args.binary_directory / "NativeForensics-build-inputs.json"
        destination.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

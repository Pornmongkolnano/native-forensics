#!/usr/bin/env python3
"""Synthetic FAT32 workload, independent byte oracle, and headless measurements.

All generated inputs and outputs are exclusive files below ignored local/.
No user image, GUI, provider, network, mount, cache purge or system setting is
used. A cold-advised run requests Darwin F_NOCACHE for its preflight hash only;
it cannot certify cold reads by the probe, which opens its own descriptors.
"""
from __future__ import annotations

import argparse
import ctypes
import datetime
import errno
import hashlib
import json
import math
import os
import platform
import signal
import stat
import statistics
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BLOCK_BYTES = 1024 * 1024
DEFAULT_IMAGE_BYTES = 512 * BLOCK_BYTES
MINIMUM_IMAGE_BYTES = 256 * BLOCK_BYTES
FILE_LIMIT = 32 * BLOCK_BYTES
IMAGE_NAME = "workload-fat32.raw"
METADATA_NAME = "metadata-only.raw"
QUERIES = ("needleOnlyInPayload", "largeNeedle", "เอกสาร", "้", "notPresentInAnyPayload")
REGIMES = ("warm-prehashed", "cold-requested-OS-cache-uncertain")
VIRTUAL_FILES = {"/$MBR", "/$FAT1", "/$FAT2"}
EXPECTED_COUNTS = {"indexed": 4, "skipped": 6, "pending": 0, "failed": 0}
ALPHA = "Alpha synthetic observation\nneedleOnlyInPayload\nภาษาไทย เอกสาร ก้\n".encode()
THAI = "ภาษาไทยต่อเนื่องเอกสารก้มีเครื่องหมายประกอบ\n".encode()
BETA = b"Beta synthetic observation, ordinary text.\n"
LARGE_PREFIX = b"NativeForensics synthetic large text\nlargeNeedle\n"
UNKNOWN = bytes((0, 255, 128, 1, 129, 0, 157, 254, 127))
METADATA_HEADER = b"NativeForensics synthetic metadata-only source v1\n"
HISTORY_SOURCE_BYTES = b"owned synthetic source\n"
HISTORY_CASE_NAME = "History Benchmark.nativecase"
HISTORY_JSON_LIMIT = BLOCK_BYTES
JSON_LIMIT = 16 * BLOCK_BYTES
HISTORY_INPUT_DIRECTORIES = ("Sources/CaseHistoryWorkloadProbe", "Sources/ForensicsCore",
                             "Sources/NFDecoderIPC", "Sources/CSQLite3")
HISTORY_INPUT_EXTENSIONS = {".swift", ".h", ".m", ".mm", ".c", ".cpp", ".modulemap"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def local_path(path: Path) -> Path:
    absolute = path.absolute()
    resolved = path.resolve()
    require(absolute == resolved and resolved.is_relative_to(ROOT / "local"),
            "Outputs and synthetic fixtures must be below ignored local/, without symlinks")
    return resolved


def exclusive_directory(path: Path) -> Path:
    path = local_path(path)
    base = ROOT / "local"
    if not base.exists():
        base.mkdir(mode=0o700)
    require(not base.is_symlink() and base.is_dir(), "local/ must be an ordinary directory")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(path.parent.resolve() == path.parent, "Symlink output parent is unsupported")
    path.mkdir(mode=0o700)  # Never reuse or overwrite another run.
    return path


def open_regular(path: Path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        require(stat.S_ISREG(os.fstat(descriptor).st_mode), "Expected an ordinary regular file")
        return os.fdopen(descriptor, "rb")
    except BaseException:
        os.close(descriptor)
        raise


def file_identity(value) -> tuple:
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns


def hash_file(path: Path, *, nocache: bool = False) -> tuple[str, dict]:
    """Hash selected-file bytes with bounded reads and an explicit cache receipt."""
    advisory = {"requested": nocache, "applied": False, "cacheEvictionVerified": False,
                "scope": "preflight hash descriptor only; probe opens independent descriptors"}
    with open_regular(path) as stream:
        before = os.fstat(stream.fileno())
        if nocache:
            if sys.platform == "darwin":
                import fcntl
                try:
                    fcntl.fcntl(stream.fileno(), 48, 1)  # Darwin F_NOCACHE, read-only FD.
                    advisory["applied"] = True
                except OSError as error:
                    advisory["error"] = f"F_NOCACHE unavailable: errno {error.errno}"
            else:
                advisory["error"] = "Darwin F_NOCACHE is unavailable on this platform"
        sha256 = hashlib.sha256()
        for chunk in iter(lambda: stream.read(BLOCK_BYTES), b""):
            sha256.update(chunk)
        require(file_identity(before) == file_identity(os.fstat(stream.fileno())) == file_identity(path.stat()),
                "Source changed while hashing")
    return sha256.hexdigest(), advisory


def write_json(path: Path, value: object) -> None:
    data = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()
    require(len(data) <= JSON_LIMIT, "JSON receipt exceeded bounded size")
    with path.open("xb") as stream:
        stream.write(data)
    path.chmod(0o600)


def read_json(path: Path, maximum_bytes: int = JSON_LIMIT) -> dict:
    require(isinstance(maximum_bytes, int) and 0 < maximum_bytes <= JSON_LIMIT, "Invalid JSON read bound")
    with open_regular(path) as stream:
        data = stream.read(maximum_bytes + 1)
    require(len(data) <= maximum_bytes, "JSON receipt exceeded bounded size")
    value = json.loads(data)
    require(isinstance(value, dict), "Expected a JSON object")
    return value


def literal_recipe(payload: bytes) -> dict:
    return {"kind": "literal", "hex": payload.hex(), "byteCount": len(payload)}


def payload_recipes() -> dict[str, dict]:
    return {"/ALPHA.TXT": literal_recipe(ALPHA), "/THAI.TXT": literal_recipe(THAI),
            "/LARGE.TXT": {"kind": "prefixAndFill", "prefixHex": LARGE_PREFIX.hex(), "fillByte": 88, "byteCount": FILE_LIMIT},
            "/OVER.TXT": {"kind": "prefixAndFill", "prefixHex": "", "fillByte": 89, "byteCount": FILE_LIMIT + 1},
            "/UNKNOWN.BIN": literal_recipe(UNKNOWN), "/EMPTY.TXT": literal_recipe(b""),
            "/BETA.TXT": literal_recipe(BETA)}


def recipe_blocks(recipe: dict, block_bytes: int = BLOCK_BYTES):
    require(0 < block_bytes <= BLOCK_BYTES, "Invalid block size")
    if recipe["kind"] == "literal":
        payload = bytes.fromhex(recipe["hex"])
        require(len(payload) == recipe["byteCount"], "Literal recipe size differs")
        for offset in range(0, len(payload), block_bytes):
            yield payload[offset:offset + block_bytes]
        return
    if recipe["kind"] == "fat32Table":
        require(block_bytes % 4 == 0 and recipe["byteCount"] % 4 == 0, "FAT blocks must contain complete 32-bit entries")
        ends = set(recipe["chainEndClusters"])
        for offset in range(0, recipe["byteCount"], block_bytes):
            chunk = bytearray(min(block_bytes, recipe["byteCount"] - offset))
            first, stop = offset // 4, (offset + len(chunk)) // 4
            for cluster in range(max(first, 0), min(stop, recipe["lastAllocatedCluster"] + 1)):
                if cluster == 0:
                    value = 0x0ffffff8
                elif cluster == 1 or cluster in ends:
                    value = 0x0fffffff
                else:
                    value = cluster + 1
                struct.pack_into("<I", chunk, (cluster - first) * 4, value)
            yield bytes(chunk)
        return
    require(recipe["kind"] == "prefixAndFill", "Unknown payload recipe")
    prefix = bytes.fromhex(recipe["prefixHex"])
    remaining = recipe["byteCount"]
    require(0 <= recipe["fillByte"] <= 255 and len(prefix) <= remaining, "Invalid repeat recipe")
    for offset in range(0, remaining, block_bytes):
        count = min(block_bytes, remaining - offset)
        retained = prefix[offset:offset + count]
        yield retained + bytes((recipe["fillByte"],)) * (count - len(retained))


def expected_text(path: str, recipe: dict) -> str | None:
    if path in {"/OVER.TXT", "/UNKNOWN.BIN", *VIRTUAL_FILES}:
        return None
    # Only one bounded text prefix is ever retained, even for a 32 MiB payload.
    return next(recipe_blocks(recipe), b"").decode("utf-8")


def search_oracle(files: dict, queries=QUERIES) -> dict:
    result = {}
    for query in queries:
        hits = []
        for path, file in sorted(files.items()):
            if file["indexStatus"] != "indexed":
                continue
            text, cursor = file["text"], 0
            while (offset := text.find(query, cursor)) >= 0:
                hits.append({"path": path, "utf16Offset": len(text[:offset].encode("utf-16le")) // 2,
                             "utf16Length": len(query.encode("utf-16le")) // 2})
                cursor = offset + len(query)
        result[query] = hits
    return result


def fat_geometry(image_bytes: int) -> dict:
    require(isinstance(image_bytes, int) and MINIMUM_IMAGE_BYTES <= image_bytes <= 4 * 1024 * BLOCK_BYTES
            and image_bytes % 512 == 0, "FAT32 image must be 256 MiB through 4 GiB and sector aligned")
    sectors, reserved, fat_sectors = image_bytes // 512, 32, 1
    # Fixed point can oscillate by one sector. Choose the smallest sufficient FAT.
    while True:
        clusters = sectors - reserved - 2 * fat_sectors
        needed = math.ceil((clusters + 2) * 4 / 512)
        if fat_sectors >= needed:
            break
        fat_sectors = needed
    require(clusters >= 65525, "Geometry is not FAT32")
    return {"sectorBytes": 512, "sectorsPerCluster": 1, "totalSectors": sectors,
            "reservedSectors": reserved, "fatCopies": 2, "fatSectors": fat_sectors,
            "clusterCount": clusters, "heapSector": reserved + 2 * fat_sectors, "rootCluster": 2}


def fat_entry(path: str, cluster: int, size: int) -> bytes:
    name, extension = path[1:].split(".")
    short = name.ljust(8).encode("ascii") + extension.ljust(3).encode("ascii")
    require(len(short) == 11, "Expected a short FAT 8.3 name")
    row = bytearray(32)
    row[:11], row[11] = short, 32
    date, clock = ((2024 - 1980) << 9) | (1 << 5) | 2, (3 << 11) | (4 << 5) | 3
    struct.pack_into("<HHH", row, 14, clock, date, date)
    struct.pack_into("<H", row, 20, cluster >> 16)
    struct.pack_into("<HHHI", row, 22, clock, date, cluster & 0xffff, size)
    return bytes(row)


def fat_boot(geometry: dict) -> bytes:
    boot = bytearray(512)
    boot[:11] = b"\xeb\x58\x90NFWLOAD1"
    struct.pack_into("<HBHBHHBHHHII", boot, 11, 512, 1, 32, 2, 0, 0, 248, 0, 63, 255, 0, geometry["totalSectors"])
    struct.pack_into("<IHHIHH", boot, 36, geometry["fatSectors"], 0, 0, 2, 1, 6)
    struct.pack_into("<BBBI", boot, 64, 128, 0, 41, 0x4e465731)
    boot[71:90], boot[510:512] = b"NFWORKLOAD FAT32   ", b"\x55\xaa"
    return bytes(boot)


def metadata_recipes(geometry: dict) -> dict:
    cursor, chain_ends = 3, [2]
    for recipe in payload_recipes().values():
        count = math.ceil(recipe["byteCount"] / 512)
        if count:
            chain_ends.append(cursor + count - 1)
            cursor += count
    table = {"kind": "fat32Table", "byteCount": geometry["fatSectors"] * 512,
             "lastAllocatedCluster": cursor - 1, "chainEndClusters": chain_ends}
    return {"/$MBR": literal_recipe(fat_boot(geometry)), "/$FAT1": table, "/$FAT2": dict(table)}


def generate(destination: Path, image_bytes: int = DEFAULT_IMAGE_BYTES) -> dict:
    geometry = fat_geometry(image_bytes)
    destination = exclusive_directory(destination)
    boot = fat_boot(geometry)
    fsinfo = bytearray(512)
    struct.pack_into("<I", fsinfo, 0, 0x41615252)
    struct.pack_into("<III", fsinfo, 484, 0x61417272, 0xffffffff, 0xffffffff)
    struct.pack_into("<I", fsinfo, 508, 0xaa550000)
    fat = bytearray(geometry["fatSectors"] * 512)
    struct.pack_into("<III", fat, 0, 0x0ffffff8, 0x0fffffff, 0x0fffffff)
    image = destination / IMAGE_NAME
    files, cursor, root_rows = {}, 3, bytearray()
    with image.open("xb") as stream:
        stream.truncate(image_bytes)  # Untouched ranges stay sparse, deterministic zero bytes.
        for offset, data in ((0, boot), (512, fsinfo), (6 * 512, boot), (7 * 512, fsinfo)):
            stream.seek(offset); stream.write(data)
        for path, recipe in payload_recipes().items():
            size = recipe["byteCount"]
            clusters = math.ceil(size / 512)
            first = cursor if clusters else 0
            offset = (geometry["heapSector"] + first - 2) * 512 if first else None
            root_offset = geometry["heapSector"] * 512 + len(root_rows)
            root_rows.extend(fat_entry(path, first, size))
            require(cursor + clusters <= geometry["clusterCount"] + 2, "Payload exceeds FAT32 data area")
            for cluster in range(first, first + clusters):
                struct.pack_into("<I", fat, cluster * 4, cluster + 1 if cluster + 1 < first + clusters else 0x0fffffff)
            sha256 = hashlib.sha256()
            if offset is not None:
                stream.seek(offset)
            for chunk in recipe_blocks(recipe):
                stream.write(chunk); sha256.update(chunk)
            skipped_reason = {"/OVER.TXT": "FILE_BYTE_LIMIT", "/UNKNOWN.BIN": "UNSUPPORTED_CONTENT", "/EMPTY.TXT": "NO_TEXT_LAYER_OR_BODY"}.get(path)
            text = expected_text(path, recipe)
            file = {"byteCount": size, "sha256": sha256.hexdigest(), "textIsComplete": not skipped_reason and path != "/LARGE.TXT",
                    "indexStatus": "skipped" if skipped_reason else "indexed",
                    "indexReason": skipped_reason or ("PARTIAL_DECODER_COVERAGE" if path == "/LARGE.TXT" else None),
                    "payloadRecipe": recipe, "onDisk": {"dataOffsetBytes": offset, "firstCluster": first,
                    "clusterCount": clusters, "rootEntryOffsetBytes": root_offset}}
            if text is not None:
                file["text"] = text
            files[path] = file
            cursor += clusters
        stream.seek(geometry["heapSector"] * 512); stream.write(root_rows)
        for copy in range(2):
            stream.seek((32 + copy * geometry["fatSectors"]) * 512); stream.write(fat)
    # Sleuth Kit exposes FAT's generated metadata as regular virtual files.
    # Keep them in the real production listing and independently specify their
    # bytes, rather than silently deleting rows to simplify index counts.
    for path, recipe in metadata_recipes(geometry).items():
        sha256 = hashlib.sha256()
        for chunk in recipe_blocks(recipe):
            sha256.update(chunk)
        copy = {"/$FAT1": 0, "/$FAT2": 1}.get(path)
        offset = 0 if copy is None else (32 + copy * geometry["fatSectors"]) * 512
        files[path] = {"byteCount": recipe["byteCount"], "sha256": sha256.hexdigest(), "textIsComplete": False,
            "indexStatus": "skipped", "indexReason": "UNSUPPORTED_CONTENT", "payloadRecipe": recipe,
            "onDisk": {"dataOffsetBytes": offset, "firstCluster": 0, "clusterCount": 0,
                       "rootEntryOffsetBytes": None, "generatedFilesystemMetadata": True}}
    image.chmod(0o600)
    metadata = destination / METADATA_NAME
    with metadata.open("xb") as stream:
        stream.truncate(BLOCK_BYTES); stream.seek(0); stream.write(METADATA_HEADER)
    metadata.chmod(0o600)
    oracle = {"schemaVersion": 1, "syntheticOnly": True, "imageName": IMAGE_NAME,
              "imageSHA256": hash_file(image)[0], "imageByteCount": image_bytes,
              "metadataName": METADATA_NAME, "metadataSHA256": hash_file(metadata)[0], "metadataByteCount": BLOCK_BYTES,
              "geometry": geometry, "files": files, "queries": search_oracle(files),
              "expectedCounts": EXPECTED_COUNTS, "missingListingCount": 1}
    write_json(destination / "oracle.json", oracle)
    return oracle


def validate_bytes(path: Path, expected: dict, *, offset: int = 0, whole_file: bool = True) -> dict:
    sha256 = hashlib.sha256()
    with open_regular(path) as stream:
        before = os.fstat(stream.fileno())
        if whole_file:
            require(before.st_size == expected["byteCount"], "Logical-file byte count differs: " + path.name)
        stream.seek(offset)
        count = 0
        for chunk in recipe_blocks(expected["payloadRecipe"]):
            actual = stream.read(len(chunk))
            require(actual == chunk, "Independent recipe bytes differ: " + path.name)
            count += len(actual); sha256.update(actual)
        require(count == expected["byteCount"] and sha256.hexdigest() == expected["sha256"], "Logical-file SHA256 differs")
        require(file_identity(before) == file_identity(os.fstat(stream.fileno())) == file_identity(path.stat()), "File changed during byte validation")
    return {"byteCount": count, "sha256": sha256.hexdigest(), "exactBytesMatched": True}


def load_fixture(fixture: Path) -> dict:
    fixture = local_path(fixture)
    oracle = read_json(fixture / "oracle.json")
    require(oracle["schemaVersion"] == 1 and oracle["syntheticOnly"] is True, "Requires a synthetic schema-1 oracle")
    require(oracle["imageName"] == IMAGE_NAME and oracle["metadataName"] == METADATA_NAME, "Unexpected fixture filename")
    recipes = dict(payload_recipes(), **metadata_recipes(fat_geometry(oracle["imageByteCount"])))
    require(set(oracle["files"]) == set(recipes), "Oracle file set differs")
    for path, recipe in recipes.items():
        file = oracle["files"][path]
        require(file["payloadRecipe"] == recipe and file["byteCount"] == recipe["byteCount"], "Oracle recipe differs from independent literal specification")
        require(file.get("text") == expected_text(path, recipe), "Oracle decoded prefix differs")
        reason = {"/OVER.TXT": "FILE_BYTE_LIMIT", "/UNKNOWN.BIN": "UNSUPPORTED_CONTENT", "/EMPTY.TXT": "NO_TEXT_LAYER_OR_BODY"}.get(path)
        if path in VIRTUAL_FILES:
            reason = "UNSUPPORTED_CONTENT"
        require(file["indexStatus"] == ("skipped" if reason else "indexed")
                and file["indexReason"] == (reason or ("PARTIAL_DECODER_COVERAGE" if path == "/LARGE.TXT" else None))
                and file["textIsComplete"] is (reason is None and path != "/LARGE.TXT"), "Oracle coverage differs from literal specification")
    require(oracle["expectedCounts"] == EXPECTED_COUNTS
            and oracle["missingListingCount"] == 1, "Oracle coverage counts differ")
    require(oracle["geometry"] == fat_geometry(oracle["imageByteCount"]), "Oracle FAT32 geometry differs")
    require(oracle["queries"] == search_oracle(oracle["files"]), "Oracle UTF-16 search ranges differ")
    for name, hash_key, count_key in ((IMAGE_NAME, "imageSHA256", "imageByteCount"), (METADATA_NAME, "metadataSHA256", "metadataByteCount")):
        source = fixture / name
        require(source.stat().st_size == oracle[count_key] and hash_file(source)[0] == oracle[hash_key], "Fixture source hash/size differs")
    for file in oracle["files"].values():
        validate_bytes(fixture / IMAGE_NAME, file, offset=file["onDisk"]["dataOffsetBytes"] or 0, whole_file=False)
    return oracle


def export_path(output: Path, relative: str) -> Path:
    require(isinstance(relative, str) and bool(relative), "Missing export path")
    value = Path(relative)
    require(not value.is_absolute() and ".." not in value.parts, "Export path escaped output")
    path = output / value
    require(path.resolve() == path and path.is_relative_to(output), "Symlink export path is unsupported")
    return path


def validate_stages(receipt: dict) -> None:
    stages = receipt.get("stageSeconds")
    require(isinstance(stages, dict) and bool(stages), "Missing stage measurements")
    require(all(isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value >= 0
                for value in stages.values()), "Invalid stage duration")


def verify(fixture: Path, output: Path) -> dict:
    fixture, output = local_path(fixture), local_path(output)
    oracle = load_fixture(fixture)
    receipt = read_json(output / "workload-receipt.json")
    require(receipt.get("schemaVersion") == 1 and receipt.get("syntheticOnly") is True and receipt.get("providerExecuted") is False,
            "Receipt must declare schema, synthetic input and no provider execution")
    require(receipt.get("measurementKind") == "ForensicsCore-headless-workflow" and receipt.get("mode") == "workflow",
            "Receipt must explicitly identify headless measurement")
    for key, expected in (("sourceBeforeSHA256", oracle["imageSHA256"]), ("sourceAfterSHA256", oracle["imageSHA256"]),
                          ("metadataBeforeSHA256", oracle["metadataSHA256"]), ("metadataAfterSHA256", oracle["metadataSHA256"])):
        require(receipt.get(key) == expected, "Source immutability receipt differs: " + key)
    verified = {}
    for key in ("verifiedFiles", "batchExportFiles"):
        require(set(receipt.get(key, {})) == set(oracle["files"]), "Exported file set differs: " + key)
        for path, expected in oracle["files"].items():
            actual = receipt[key][path]
            require(actual.get("byteCount") == expected["byteCount"] and actual.get("sha256") == expected["sha256"], "Export receipt differs: " + path)
            verified[key + ":" + path] = validate_bytes(export_path(output, actual["exportFile"]), expected)
    documents = receipt.get("documents", {})
    require(set(documents) == set(oracle["files"]), "Indexed document set differs")
    for path, expected in oracle["files"].items():
        actual = documents[path]
        require(actual.get("status") == expected["indexStatus"] and actual.get("reason") == expected["indexReason"]
                and actual.get("textIsComplete") is expected["textIsComplete"], "Document coverage differs: " + path)
        if expected["indexStatus"] == "indexed":
            pages = actual.get("textPages", [])
            require(actual.get("contentSHA256") == expected["sha256"] and len(pages) == 1
                    and pages[0].get("pageNumber") == 1 and pages[0].get("text") == expected["text"]
                    and pages[0].get("isTruncated") is (not expected["textIsComplete"]), "Decoded text/range coverage differs: " + path)
        else:
            require(not actual.get("textPages") and actual.get("contentSHA256") is None, "Skipped content retained a fabricated decoded body")
    decoded = receipt.get("decoded", {})
    require(set(decoded) == set(oracle["files"]) - {"/OVER.TXT"}, "Standalone decode file set differs")
    for path, actual in decoded.items():
        expected = oracle["files"][path]
        require(actual.get("sourceSHA256") == expected["sha256"] and actual.get("textIsComplete") is expected["textIsComplete"],
                "Standalone decoder hash/coverage differs")
        pages = actual.get("textPages", [])
        if expected["indexReason"] == "UNSUPPORTED_CONTENT":
            require(actual.get("status") == "unsupported" and not pages, "Unknown binary was decoded as text")
        else:
            require(actual.get("status") == "decoded" and len(pages) == 1 and pages[0].get("pageNumber") == 1
                    and pages[0].get("text") == expected["text"]
                    and pages[0].get("isTruncated") is (path == "/LARGE.TXT"), "Standalone decoder literal prefix differs")
    require(receipt.get("counts") == oracle["expectedCounts"] and receipt.get("missingListingCount") == 1, "Coverage counts differ")
    require(receipt.get("searchHits") == oracle["queries"], "Literal UTF-16 search ranges differ")
    require(receipt.get("indexReopened") is True and receipt.get("manifestUnchanged") is True, "Durable reopen or immutable manifest boundary differs")
    validate_stages(receipt)
    return {"oraclePassed": True, "independentBytesVerified": len(verified), "searchQueriesVerified": len(oracle["queries"])}


def process_snapshot() -> dict[int, tuple[int, int]]:
    """Public ps reports PPID and RSS KiB; helpers with changed argv are included."""
    result = subprocess.run(["/bin/ps", "-axo", "pid=,ppid=,rss="], capture_output=True, check=True, timeout=2)
    rows = {}
    for line in result.stdout.splitlines():
        values = line.split()
        require(len(values) == 3, "Malformed process memory snapshot")
        pid, parent, rss = map(int, values)
        rows[pid] = parent, rss * 1024
    return rows


def descendant_pids(rows: dict[int, tuple[int, int]], root_pid: int) -> set[int]:
    if root_pid not in rows:
        return set()
    owned, pending = {root_pid}, [root_pid]
    children = {}
    for pid, (parent, _) in rows.items():
        children.setdefault(parent, []).append(pid)
    while pending:
        for pid in children.get(pending.pop(), []):
            if pid not in owned:
                owned.add(pid); pending.append(pid)
    return owned


class DarwinTreeReader:
    """Public libproc PID/PPID/start identity and exact resident byte fields.

    SDK sys/proc_info.h: PROC_PIDTBSDINFO=3 is 136 bytes, pbi_ppid at
    offset 16 and start timeval at 120/128; PROC_PIDTASKINFO=4 is 96 bytes,
    resident size at offset 8. Short structures are never reported as zero RSS.
    Enumeration and per-process reads are sequential, not atomic snapshots.
    """
    def __init__(self, root_pid: int):
        self.root_pid = root_pid
        self.libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        self.libproc.proc_listallpids.argtypes = [ctypes.c_void_p, ctypes.c_int]
        self.libproc.proc_listallpids.restype = ctypes.c_int
        self.libproc.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
        self.libproc.proc_pidinfo.restype = ctypes.c_int
        self.root_identity = None

    def bsd(self, pid: int):
        buffer = ctypes.create_string_buffer(136)
        ctypes.set_errno(0)
        count = self.libproc.proc_pidinfo(pid, 3, 0, buffer, len(buffer))
        if count == 0:
            return None  # Other users' inaccessible or concurrently exited PIDs.
        require(count == len(buffer), "Unknown libproc BSD-info structure")
        actual, parent = struct.unpack_from("<II", buffer, 12)
        require(actual == pid, "libproc BSD-info PID mismatch")
        return parent, struct.unpack_from("<QQ", buffer, 120)

    def snapshot(self):
        estimate = self.libproc.proc_listallpids(None, 0)
        require(0 <= estimate < 131000, "Unavailable/unbounded libproc PID inventory")
        capacity = max(256, estimate + 256)
        buffer = (ctypes.c_int * capacity)()
        count = self.libproc.proc_listallpids(buffer, ctypes.sizeof(buffer))
        require(0 <= count < capacity, "Truncated libproc PID inventory")
        info = {}
        for pid in buffer[:count]:
            if pid > 0:
                value = self.bsd(pid)
                if value is not None:
                    info[pid] = value
        root = info.get(self.root_pid)
        if root is None:
            return {}
        if self.root_identity is None:
            self.root_identity = root[1]
        if root[1] != self.root_identity:
            return {}  # The already-reaped root PID must never admit a reused PID.
        pids = descendant_pids({pid: (row[0], 0) for pid, row in info.items()}, self.root_pid)
        rows = {}
        for pid in pids:
            task = ctypes.create_string_buffer(96)
            ctypes.set_errno(0)
            size = self.libproc.proc_pidinfo(pid, 4, 0, task, len(task))
            if size == 0 and ctypes.get_errno() == errno.ESRCH:
                continue
            require(size == len(task), "Unavailable/unknown owned-process libproc taskinfo")
            # Verify PPID/start identity again so an exited/reused PID cannot
            # contribute another process's RSS between discovery and taskinfo.
            if self.bsd(pid) == info[pid]:
                rows[pid] = info[pid][0], struct.unpack_from("<Q", task, 8)[0]
        if self.bsd(self.root_pid) != root:
            return {}
        return rows


class TreeRSSSampler:
    def __init__(self, root_pid: int, interval: float):
        require(math.isfinite(interval) and 0.01 <= interval <= 1, "RSS interval must be 0.01 through 1 second")
        self.root_pid, self.interval = root_pid, interval
        self.samples, self.failures, self.read_seconds = [], [], []
        self.reader = DarwinTreeReader(root_pid) if sys.platform == "darwin" else None
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self._sample, name="workload-tree-rss", daemon=True)

    def _sample(self):
        while not self.stopped.is_set():
            start = time.monotonic()
            try:
                rows = self.reader.snapshot() if self.reader else process_snapshot()
                pids = descendant_pids(rows, self.root_pid)
                if pids:
                    app_rss = rows[self.root_pid][1]
                    self.samples.append({"atMonotonicSeconds": time.monotonic(), "rssBytes": sum(rows[pid][1] for pid in pids),
                                         "appRSSBytes": app_rss, "helpersRSSBytes": sum(rows[pid][1] for pid in pids if pid != self.root_pid),
                                         "processCount": len(pids), "pids": sorted(pids)})
            except Exception as error:
                self.failures.append(str(error))
            self.read_seconds.append(time.monotonic() - start)
            self.stopped.wait(self.interval)

    def start(self):
        self.thread.start()

    def stop(self):
        self.stopped.set()
        if self.thread.ident is not None:
            self.thread.join(timeout=3)
            require(not self.thread.is_alive(), "RSS sampler did not stop")

    def receipt(self) -> dict:
        intervals = [right["atMonotonicSeconds"] - left["atMonotonicSeconds"] for left, right in zip(self.samples, self.samples[1:])]
        helpers = [pid for row in self.samples for pid in row["pids"] if pid != self.root_pid]
        return {"method": "macOS libproc PID/start-identity descendant closure and PROC_PIDTASKINFO resident bytes" if self.reader
                else "ps RSS KiB times 1024, current PPID descendant closure rooted at exact owned probe PID",
                "rootPID": self.root_pid, "appScope": "app RSS means the headless ForensicsCore probe process; native GUI is not measured",
                "requestedIntervalSeconds": self.interval, "actualIntervalMedianSeconds": statistics.median(intervals) if intervals else None,
                "actualIntervalMaximumSeconds": max(intervals) if intervals else None,
                "aggregatePeakRSSSampledBytes": max((row["rssBytes"] for row in self.samples), default=None),
                "appPeakRSSSampledBytes": max((row["appRSSBytes"] for row in self.samples), default=None),
                "helpersPeakRSSSampledBytes": max((row["helpersRSSBytes"] for row in self.samples), default=None),
                "firstHelperObservedPID": helpers[0] if helpers else None,
                "distinctHelperPIDsObserved": len(set(helpers)),
                "maximumObservedProcessCount": max((row["processCount"] for row in self.samples), default=0),
                "sampleCount": len(self.samples), "samples": self.samples, "failedSamples": self.failures,
                "rssSampleReadWallSeconds": sum(self.read_seconds),
                "limitations": "Discovery and RSS reads are sequential, not atomic. Short-lived helpers, inaccessible/reparented descendants and between-sample peaks can be missed; sampled maximum is an observation, not the true peak. Sampling adds measured scheduling overhead (including ps spawning on fallback platforms). Python driver and sampler are outside the owned probe tree."}


def launch_probe(command: list[str], output: Path, timeout: float, interval: float) -> dict:
    require(math.isfinite(timeout) and timeout > 0, "Invalid process timeout")
    require(math.isfinite(interval) and 0.01 <= interval <= 1, "Invalid RSS interval")
    finished, result = threading.Event(), {}
    lifecycle_errors, sampler = [], None
    waiter_started = False
    with (output / "probe.stdout").open("xb") as stdout, (output / "probe.stderr").open("xb") as stderr:
        start = time.monotonic()
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, start_new_session=True, cwd=ROOT,
                                   env=dict(os.environ, TZ="UTC", LC_ALL="C"))

        def record_exit(pid, status, usage):
            require(pid == process.pid, "Exact wait4 returned another process")
            result.update(pid=pid, returncode=os.waitstatus_to_exitcode(status), usage=usage, exited=time.monotonic())
            process.returncode = result["returncode"]  # Popen must not reap the same child again.

        def reap():
            try:
                pid, status, usage = os.wait4(process.pid, 0)
                record_exit(pid, status, usage)
            except BaseException as error:
                result["error"] = error
            finally:
                finished.set()

        try:
            waiter = threading.Thread(target=reap, name="workload-exact-wait4", daemon=True)
            try:
                waiter.start()
            finally:
                waiter_started = waiter.ident is not None
        except BaseException as error:
            lifecycle_errors.append({"phase": "waiter-start", "error": str(error)})

        def wait_for_exit(seconds):
            nonlocal waiter_started
            deadline = time.monotonic() + seconds
            if waiter_started:
                if not finished.wait(seconds):
                    return False
                if "error" not in result:
                    return True
                # The failed waiter has relinquished its only wait4 call. One
                # bounded caller may now recover the same child; retain the
                # failure even when the later terminal wait succeeds.
                lifecycle_errors.append({"phase": "waiter-reap", "error": str(result.pop("error"))})
                waiter_started = False
                finished.clear()
            # Thread setup failed: one caller owns bounded exact-PID WNOHANG
            # reaping. Never invoke Popen.poll()/wait() as a second reaper.
            while not finished.is_set():
                try:
                    pid, status, usage = os.wait4(process.pid, os.WNOHANG)
                    if pid:
                        record_exit(pid, status, usage)
                        finished.set()
                except BaseException as error:
                    result["error"] = error
                    finished.set()
                if finished.is_set():
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                finished.wait(min(.01, remaining))
            return True

        try:
            sampler = TreeRSSSampler(process.pid, interval)
            sampler.start()
        except BaseException as error:
            lifecycle_errors.append({"phase": "sampler-start", "error": str(error)})
        timed_out, observed_descendants, discovery_error = False, [], None
        try:
            if not wait_for_exit(timeout):
                timed_out = True
                # The exact child owns this fresh process group. Helpers may
                # create separate groups; do not signal bare descendant PIDs.
                try:
                    rows = process_snapshot()
                    observed_descendants = sorted(descendant_pids(rows, process.pid) - {process.pid})
                except Exception as error:
                    discovery_error = str(error)
                try: os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError: pass
                if not wait_for_exit(2):
                    try: os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                    if not wait_for_exit(3):
                        lifecycle_errors.append({"phase": "probe-drain", "error": "Owned probe could not be reaped after timeout"})
        except BaseException as error:
            lifecycle_errors.append({"phase": "probe-wait", "error": str(error)})
            if not finished.is_set():
                for signum, seconds in ((signal.SIGTERM, 2), (signal.SIGKILL, 3)):
                    try:
                        os.killpg(process.pid, signum)
                    except ProcessLookupError:
                        pass
                    except BaseException as signal_error:
                        lifecycle_errors.append({"phase": "probe-signal", "error": str(signal_error)})
                    if wait_for_exit(seconds):
                        break
        finally:
            if sampler is not None:
                try:
                    sampler.stopped.set()
                    sampler.stop()
                except BaseException as error:
                    lifecycle_errors.append({"phase": "sampler-stop", "error": str(error)})
    terminal_exit = all(key in result for key in ("pid", "returncode", "usage", "exited")) and "error" not in result
    usage = result.get("usage")
    sampling_receipt = {"available": False, "unavailability": "Sampler setup/stop did not complete"}
    if sampler is not None and not any(row["phase"].startswith("sampler-") for row in lifecycle_errors):
        try:
            sampling_receipt = sampler.receipt()
            sampling_receipt["available"] = True
        except BaseException as error:
            lifecycle_errors.append({"phase": "sampler-receipt", "error": str(error)})
    measurement = {"returncode": result.get("returncode"),
            "wallSeconds": result["exited"] - start if terminal_exit else None, "timedOut": timed_out,
            "terminalExitObserved": terminal_exit, "lifecycleErrors": lifecycle_errors,
            "exitObservation": ("blocking exact-PID os.wait4 with immediate monotonic timestamp" if waiter_started
                                else "fallback exact-PID WNOHANG wait4 after waiter became unavailable") + "; scheduling observation, not kernel exit timestamp",
            "wait4": {"pid": result["pid"], "userCPUSeconds": usage.ru_utime, "systemCPUSeconds": usage.ru_stime,
                      "kernelReportedMaximumRSSBytes": usage.ru_maxrss * (1 if sys.platform == "darwin" else 1024),
                      "scope": "kernel wait4 usage for the exact probe and its accounted children; kernel maximum RSS is not probe-only or simultaneous summed tree RSS"} if terminal_exit else None,
            "rssSampler": sampling_receipt}
    if "error" in result:
        measurement["wait4Error"] = str(result["error"])
    if timed_out:
        try:
            current = process_snapshot()
        except Exception as error:
            current = {}
            discovery_error = str(error)
        measurement["timeoutCleanup"] = {"signalledScope": "exact owned probe process group only",
            "descendantPIDsObservedBeforeTermination": observed_descendants,
            "previouslyObservedDescendantPIDsStillPresent": [pid for pid in observed_descendants if pid in current],
            "inventoryError": discovery_error,
            "limitations": "Helpers may own separate process groups and become reparented. Bare descendant PIDs are not signalled. Still-present PID inventory is observational and cannot certify that all helper processes drained."}
    write_json(output / "process-attempt.json", measurement)
    require(terminal_exit, "Owned probe terminal exit was not confirmed; raw process attempt retained")
    require(not lifecycle_errors, "Owned probe measurement lifecycle failed; terminal process attempt retained")
    require(not timed_out, "Owned probe exceeded process timeout; raw process attempt retained")
    return measurement


def distribution(values: list[float]) -> dict:
    ordered = sorted(values)
    require(bool(ordered), "Cannot summarize no measurements")
    return {"samples": len(ordered), "minimum": ordered[0], "median": statistics.median(ordered), "p50": statistics.median(ordered),
            "p95": ordered[max(0, math.ceil(len(ordered) * .95) - 1)], "maximum": ordered[-1]}


def validate_rss_measurement(measurement: dict, *, history_only: bool = False) -> None:
    """Accept observed samples, never a missing or silently reduced population."""
    require(measurement.get("terminalExitObserved") is True and not measurement.get("lifecycleErrors"),
            "RSS measurement has no clean terminal process receipt")
    usage = measurement.get("wait4", {})
    root_pid = usage.get("pid")
    require(type(root_pid) is int and root_pid > 0
            and type(usage.get("kernelReportedMaximumRSSBytes")) is int
            and usage["kernelReportedMaximumRSSBytes"] > 0, "Kernel RSS measurement is unavailable")
    receipt = measurement.get("rssSampler", {})
    samples = receipt.get("samples")
    require(receipt.get("available") is True and receipt.get("rootPID") == root_pid
            and isinstance(samples, list) and len(samples) > 0
            and type(receipt.get("sampleCount")) is int and receipt["sampleCount"] == len(samples)
            and receipt.get("failedSamples") == [], "RSS samples are missing or failed")
    previous_time, helpers, maximum_count = None, [], 0
    for row in samples:
        timestamp = row.get("atMonotonicSeconds")
        pids = row.get("pids")
        require(type(timestamp) in (int, float) and math.isfinite(timestamp) and timestamp >= 0
                and (previous_time is None or timestamp > previous_time), "RSS sample timestamp is invalid")
        require(isinstance(pids, list) and all(type(pid) is int and pid > 0 for pid in pids)
                and pids == sorted(set(pids)) and root_pid in pids
                and type(row.get("processCount")) is int and row["processCount"] == len(pids),
                "RSS sample owned process inventory is invalid")
        require(all(type(row.get(key)) is int and row[key] >= 0 for key in ("rssBytes", "appRSSBytes", "helpersRSSBytes"))
                and row["appRSSBytes"] > 0
                and row["rssBytes"] == row["appRSSBytes"] + row["helpersRSSBytes"], "RSS sample byte values are invalid")
        if history_only:
            require(pids == [root_pid] and row["helpersRSSBytes"] == 0,
                    "History-only probe unexpectedly spawned descendants")
        helpers.extend(pid for pid in pids if pid != root_pid)
        maximum_count = max(maximum_count, len(pids))
        previous_time = timestamp
    for metric, field in (("appPeakRSSSampledBytes", "appRSSBytes"),
                          ("helpersPeakRSSSampledBytes", "helpersRSSBytes"),
                          ("aggregatePeakRSSSampledBytes", "rssBytes")):
        require(type(receipt.get(metric)) is int and receipt[metric] == max(row[field] for row in samples),
                "RSS peak differs from retained samples: " + metric)
    require(receipt.get("maximumObservedProcessCount") == maximum_count
            and receipt.get("distinctHelperPIDsObserved") == len(set(helpers))
            and receipt.get("firstHelperObservedPID") == (helpers[0] if helpers else None),
            "RSS process summary differs from retained samples")


def provenance(probe: Path, engine: Path, decoder: Path) -> dict:
    recipes = {"script/native_workload_benchmark.py": ROOT / "script/native_workload_benchmark.py",
               "Sources/NativeWorkloadProbe/NativeWorkloadProbe.swift": ROOT / "Sources/NativeWorkloadProbe/NativeWorkloadProbe.swift"}
    hashes = {name: hash_file(path)[0] for name, path in recipes.items()}
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
    dirty = bool(subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip())
    ram_bytes = None
    if sys.platform == "darwin":
        memory = subprocess.run(["/usr/sbin/sysctl", "-n", "hw.memsize"], capture_output=True, text=True, check=True)
        ram_bytes = int(memory.stdout.strip())
    elif "SC_PHYS_PAGES" in os.sysconf_names:
        ram_bytes = os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")
    return {"sourceRevision": revision, "workingTreeDirty": dirty, "recipeSHA256": hashes,
            "binarySHA256": {"probe": hash_file(probe)[0], "engine": hash_file(engine)[0], "decoder": hash_file(decoder)[0]},
            "environment": {"architecture": platform.machine(), "os": platform.platform(),
                            "physicalRAMBytes": ram_bytes, "logicalCPUCount": os.cpu_count(), "pythonVersion": platform.python_version()}}


def validate_auxiliary_receipt(receipt: dict, mode: str, rows: int, oracle: dict | None = None) -> dict:
    require(receipt.get("schemaVersion") == 1 and receipt.get("syntheticOnly") is True
            and receipt.get("providerExecuted") is False and receipt.get("mode") == mode,
            "Auxiliary receipt mode/schema differs")
    validate_stages(receipt)
    if mode == "listing":
        require(receipt.get("rows") == rows and receipt.get("productionCap") == 50000
                and receipt.get("productionCount") == min(rows, 50000), "Listing production cap/count differs")
        expected_ids = hashlib.sha256()
        for offset in range(0, rows, 8):
            expected_ids.update(f"row-{offset}\n".encode())
        require(receipt.get("matchingRows") == len(range(0, rows, 8)) and receipt.get("matchingIDsSHA256") == expected_ids.hexdigest(),
                "Listing matching IDs differ from independent literal oracle")
        require(receipt.get("measurementKind") == ("production-bounded-search" if rows == 50000 else "derived-harness-only"),
                "Large derived harness was mislabeled as production")
        samples = receipt.get("searchSamplesSeconds", [])
        require(len(samples) == 5 and all(isinstance(value, (int, float)) and math.isfinite(value) and value >= 0 for value in samples),
                "Listing needs five post-warmup search samples")
        return {"listingIDsOraclePassed": True, "independentByteOracleApplicable": False}
    require(mode == "cancel" and receipt.get("cancelled") is True and receipt.get("newScratchRemaining") == 0,
            "Cancellation/drained scratch was not observed")
    require(oracle is not None, "Cancellation needs immutable source oracle")
    for key, expected in (("sourceBeforeSHA256", oracle["imageSHA256"]), ("sourceAfterSHA256", oracle["imageSHA256"]),
                          ("metadataBeforeSHA256", oracle["metadataSHA256"]), ("metadataAfterSHA256", oracle["metadataSHA256"])):
        require(receipt.get(key) == expected, "Cancellation changed source bytes")
    return {"cancellationReceiptPassed": True, "independentByteOracleApplicable": False}


def run(destination: Path, probe: Path, engine: Path, decoder: Path, *, fixture: Path | None = None,
        repetitions: int = 5, mode: str = "workflow", rows: int = 50000,
        timeout: float = 900, interval: float = .05) -> dict:
    require(repetitions >= 5 and mode in {"workflow", "listing", "cancel"}
            and (mode != "listing" or rows in {50000, 100000, 1000000}), "Invalid benchmark configuration")
    for executable in (probe, engine, decoder):
        require(executable.is_file() and not executable.is_symlink() and os.access(executable, os.X_OK), "Requires existing regular executable helpers")
    destination = exclusive_directory(destination)
    fixture = local_path(fixture) if fixture is not None else destination / "fixture"
    require(not destination.is_relative_to(fixture), "Run outputs must remain outside the original fixture")
    if not fixture.exists():
        generate(fixture)
    oracle = load_fixture(fixture)
    before_provenance = provenance(probe, engine, decoder)
    write_json(destination / "benchmark-provenance.json", before_provenance)
    baseline = {name: file_identity((fixture / name).stat()) for name in (IMAGE_NAME, METADATA_NAME)}
    runs = []
    # Regimes are paired/interleaved so a long background drift is not mistaken
    # for a regime effect. A read-only preflight hash is outside timed work.
    for repetition in range(repetitions):
        for regime in REGIMES:
            cold = regime == REGIMES[1]
            advisories = {}
            for name, expected in ((IMAGE_NAME, oracle["imageSHA256"]), (METADATA_NAME, oracle["metadataSHA256"])):
                observed, advisories[name] = hash_file(fixture / name, nocache=cold)
                require(observed == expected, "Fixture changed before measurement")
            output = destination / f"{mode}-{regime}-{repetition + 1:02d}"
            # The probe creates its exclusive output. Driver logs live outside it.
            logs = exclusive_directory(destination / (output.name + "-driver"))
            command = [str(probe.resolve()), "--fixture", str(fixture), "--engine", str(engine.resolve()), "--decoder", str(decoder.resolve()),
                       "--output", str(output), "--mode", mode, "--rows", str(rows)]
            attempt = {"schemaVersion": 1, "syntheticOnly": True, "mode": mode, "regime": regime,
                       "repetition": repetition + 1, "output": output.name, "validationState": "not-started",
                       "advisories": advisories, "provenance": before_provenance}
            write_json(logs / "attempt-configuration.json", attempt)
            try:
                measurement = launch_probe(command, logs, timeout, interval)
            except Exception as error:
                attempt.update(validationState="launch-failed", error=str(error))
                write_json(logs / "failed-attempt.json", attempt)
                raise
            attempt["measurement"] = measurement
            # Durable raw timing survives a failed exit or independent oracle.
            write_json(logs / "measurement-attempt.json", attempt)
            try:
                require(measurement["returncode"] == 0, "Probe failed; inspect ignored driver logs: " + str(logs))
                validate_rss_measurement(measurement)
                receipt = read_json(output / "workload-receipt.json")
                validation = verify(fixture, output) if mode == "workflow" else validate_auxiliary_receipt(receipt, mode, rows, oracle)
            except Exception as error:
                attempt.update(validationState="failed", error=str(error))
                write_json(logs / "failed-attempt.json", attempt)
                raise
            for name in baseline:
                require(file_identity((fixture / name).stat()) == baseline[name], "Original fixture identity changed")
                require(hash_file(fixture / name)[0] == oracle["imageSHA256" if name == IMAGE_NAME else "metadataSHA256"], "Original fixture bytes changed")
            run_receipt = {"repetition": repetition + 1, "regime": regime, "output": output.name,
                           "cache": {"label": regime, "cacheVerifiedCold": False, "advisories": advisories,
                                     "limitations": "Warm means preflight-hashed input. Cold-requested is advisory-only and may still use cached data; F_NOCACHE does not purge existing cache or control the probe's independent descriptors. Initial source inspection warms reads for later stages in both regimes. These samples are not a verified cold/warm storage comparison."},
                           "stageSeconds": receipt["stageSeconds"], "measurement": measurement, "validation": validation}
            write_json(logs / "driver-receipt.json", run_receipt)
            summary_run = dict(run_receipt)
            summary_run["measurement"] = dict(measurement)
            summary_run["measurement"]["rssSampler"] = {key: value for key, value in measurement["rssSampler"].items() if key != "samples"}
            summary_run["driverReceipt"] = logs.name + "/driver-receipt.json"
            runs.append(summary_run)
            print(f"{mode} {regime} {repetition + 1}/{repetitions}: verified, {measurement['wallSeconds']:.3f}s", flush=True)
    summary = {"schemaVersion": 1, "syntheticOnly": True, "guiMeasured": False, "providerExecuted": False,
               "kind": "ForensicsCore-headless-workload-benchmark", "mode": mode, "createdUTC": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "platform": platform.platform(), "provenance": before_provenance, "repetitionsPerRegime": repetitions,
               "percentileMethod": "p50 median; p95 nearest rank (with five runs p95 is the maximum)",
               "measurementScope": "Headless ForensicsCore workflow and its current descendant helper processes. GUI rendering and user interaction are not measured.",
               "runs": runs, "regimes": {}}
    for regime in REGIMES:
        selected = [row for row in runs if row["regime"] == regime]
        stages = set(selected[0]["stageSeconds"])
        require(all(set(row["stageSeconds"]) == stages for row in selected), "Stage set changed across repetitions")
        summary["regimes"][regime] = {"wallSeconds": distribution([row["measurement"]["wallSeconds"] for row in selected]),
                                      "stageSeconds": {stage: distribution([row["stageSeconds"][stage] for row in selected]) for stage in sorted(stages)},
                                      "kernelReportedMaximumRSSBytes": distribution([row["measurement"]["wait4"]["kernelReportedMaximumRSSBytes"] for row in selected])}
        summary["regimes"][regime]["rssSampledPeakBytes"] = {}
        for metric in ("appPeakRSSSampledBytes", "helpersPeakRSSSampledBytes", "aggregatePeakRSSSampledBytes"):
            values = [row["measurement"]["rssSampler"][metric] for row in selected]
            summary["regimes"][regime]["rssSampledPeakBytes"][metric] = distribution(values)
    after_provenance = provenance(probe, engine, decoder)
    require(after_provenance["recipeSHA256"] == before_provenance["recipeSHA256"]
            and after_provenance["binarySHA256"] == before_provenance["binarySHA256"]
            and after_provenance["sourceRevision"] == before_provenance["sourceRevision"], "Benchmark recipe, binary or revision changed during measurements")
    summary["provenanceReverifiedAfterRuns"] = True
    write_json(destination / "benchmark-summary.json", summary)
    return summary


def history_ids(records: int) -> list[str]:
    return [f"00000000-0000-0000-0000-{number:012d}" for number in range(1, records + 1)]


def history_request_hash(prompt_bytes: int) -> str:
    sha256 = hashlib.sha256()
    block = b"H" * min(65536, prompt_bytes)
    for offset in range(0, prompt_bytes, len(block)):
        sha256.update(block[:min(len(block), prompt_bytes - offset)])
    return sha256.hexdigest()


def history_file_state(path: Path) -> dict:
    require(path.resolve() == path, "Symlink history fixture paths are unsupported")
    before = path.stat()
    sha256 = hash_file(path)[0]
    after = path.stat()
    require(file_identity(before) == file_identity(after), "History fixture changed during verification")
    return {"byteCount": after.st_size, "sha256": sha256, "identity": list(file_identity(after))}


def validate_history_fixture(fixture: Path, records: int, prompt_bytes: int) -> dict:
    """Independent literal verification retaining at most one record body.

    Returned metadata contains hashes/stat identities/IDs only. JSON input is
    capped at 1 MiB and prompt validation never constructs a combined history
    array or a duplicate H-filled prompt string.
    """
    require(isinstance(records, int) and 1 <= records <= 1000 and isinstance(prompt_bytes, int)
            and 1 <= prompt_bytes <= 900000, "Invalid synthetic history dimensions")
    fixture = local_path(fixture)
    case = fixture / HISTORY_CASE_NAME
    analyses = case / "analyses"
    require(case.resolve() == case and analyses.resolve() == analyses and analyses.is_dir(), "Symlink/missing history directory")
    fixture_receipt = read_json(fixture / "history-fixture-receipt.json", HISTORY_JSON_LIMIT)
    require(fixture_receipt.get("syntheticOnly") is True and fixture_receipt.get("providerRequests") == 0
            and fixture_receipt.get("recordCount") == records and fixture_receipt.get("promptBytes") == prompt_bytes,
            "History fixture receipt differs from requested synthetic dimensions")
    source = fixture / "synthetic-source.dd"
    with open_regular(source) as stream:
        require(stream.read(len(HISTORY_SOURCE_BYTES) + 1) == HISTORY_SOURCE_BYTES, "History source literal bytes differ")
    sources = {"source": history_file_state(source), "manifest": history_file_state(case / "manifest.json"),
               "fixtureReceipt": history_file_state(fixture / "history-fixture-receipt.json")}
    # The manifest is also a bounded JSON document, never an arbitrary payload.
    read_json(case / "manifest.json", HISTORY_JSON_LIMIT)
    require(sources["source"]["sha256"] == fixture_receipt.get("sourceSHA256")
            and sources["manifest"]["sha256"] == fixture_receipt.get("manifestSHA256"), "History fixture source/manifest hashes differ")
    ids = history_ids(records)
    expected_names = {record_id + ".json" for record_id in ids}
    require({entry.name for entry in os.scandir(analyses)} == expected_names, "History record filename set differs")
    expected_request = history_request_hash(prompt_bytes)
    record_states, serialized_total, serialized_maximum = {}, 0, 0
    for index, record_id in enumerate(ids, 1):
        path = analyses / (record_id + ".json")
        require(path.resolve() == path, "Symlink history record is unsupported")
        with open_regular(path) as stream:
            before = os.fstat(stream.fileno())
            require(0 < before.st_size <= HISTORY_JSON_LIMIT, "History record exceeds the 1 MiB serialized cap")
            data = stream.read(HISTORY_JSON_LIMIT + 1)
            require(len(data) == before.st_size and len(data) <= HISTORY_JSON_LIMIT, "History serialized record size differs")
            sha256 = hashlib.sha256(data).hexdigest()
            record = json.loads(data)
            del data
            require(file_identity(before) == file_identity(os.fstat(stream.fileno())) == file_identity(path.stat()),
                    "History record changed during bounded verification")
        require(isinstance(record, dict) and record.get("schemaVersion") == 1
                and isinstance(record.get("id"), str) and record["id"].lower() == record_id
                and record.get("retention") == "full", "History record ID/schema/retention differs")
        prompt = record.get("prompt")
        require(isinstance(prompt, str) and len(prompt) == prompt_bytes and prompt.count("H") == prompt_bytes,
                "History stored prompt literal differs")
        require(record.get("requestSHA256") == expected_request, "History stored request hash differs")
        result = record.get("result", {})
        require(isinstance(result, dict) and result.get("requestSHA256") == expected_request
                and isinstance(result.get("response"), dict)
                and result["response"].get("summary") == f"Synthetic local history receipt {index}",
                "History result request hash or literal summary differs")
        record_states[record_id] = {"byteCount": before.st_size, "sha256": sha256, "identity": list(file_identity(before))}
        serialized_total += before.st_size
        serialized_maximum = max(serialized_maximum, before.st_size)
        # Drop every body before opening the next record; retain metadata only.
        del record, prompt, result
    require(serialized_total == fixture_receipt.get("serializedTotalBytes")
            and serialized_maximum == fixture_receipt.get("maximumSerializedRecordBytes"), "History serialized stat totals differ")
    newest = list(reversed(ids))
    pages = [newest[offset:offset + 50] for offset in range(0, len(newest), 50)]
    return {"syntheticOnly": True, "providerRequests": 0, "recordCount": records, "promptBytes": prompt_bytes,
            "requestSHA256": expected_request, "serializedTotalBytes": serialized_total,
            "maximumSerializedRecordBytes": serialized_maximum, "historyPages": pages,
            "sourceStates": sources, "recordStates": record_states}


def validate_history_scan(receipt: dict, baseline: dict, process_id: int) -> dict:
    require(receipt.get("schemaVersion") == 1 and receipt.get("syntheticOnly") is True and receipt.get("providerRequests") == 0,
            "History scan must explicitly declare synthetic data and zero provider requests")
    require(receipt.get("processID") == process_id, "History stdout receipt belongs to another process")
    for key in ("recordCount", "promptBytes", "requestSHA256", "serializedTotalBytes", "maximumSerializedRecordBytes", "historyPages"):
        require(receipt.get(key) == baseline[key], "Independent history oracle differs: " + key)
    require(receipt.get("maximumScanSerializedBytes") == baseline["maximumSerializedRecordBytes"]
            and 0 < receipt["maximumScanSerializedBytes"] <= HISTORY_JSON_LIMIT, "History scan serialized working-record cap differs")
    for key in ("exactOrderVerified", "everyStoredRequestVerified", "originalManifestUnchanged", "originalSourceUnchanged"):
        require(receipt.get(key) is True, "Missing history scan verification: " + key)
    require(receipt.get("originalManifestSHA256") == baseline["sourceStates"]["manifest"]["sha256"]
            and receipt.get("originalSourceSHA256") == baseline["sourceStates"]["source"]["sha256"], "History scan immutable hashes differ")
    require(receipt.get("generationSeconds") == 0, "Fixture generation entered a measured scan process")
    stages = {key: receipt.get(key) for key in ("historyScanSeconds", "verifySeconds")}
    validate_stages({"stageSeconds": stages})
    return {"independentHistoryOraclePassed": True, "recordsVerified": baseline["recordCount"],
            "maximumSerializedRecordBytes": baseline["maximumSerializedRecordBytes"], "stageSeconds": stages}


def history_input_graph() -> dict[str, str]:
    """Complete path-relative linked inputs observed by the benchmark caller.

    This inventory does not attest compilation. The caller must capture/compare
    it around the separately serialized release build as well as measurements.
    """
    def inventory():
        paths = {"Package.swift", "script/native_workload_benchmark.py"}
        for name in HISTORY_INPUT_DIRECTORIES:
            directory = ROOT / name
            require(directory.resolve() == directory and directory.is_dir(), "Missing or linked history input directory")
            for path in directory.rglob("*"):
                require(not path.is_symlink(), "Linked history source input is unsupported")
                if path.is_file() and path.suffix in HISTORY_INPUT_EXTENSIONS:
                    paths.add(path.relative_to(ROOT).as_posix())
        required = {"Sources/CaseHistoryWorkloadProbe/CaseHistoryWorkloadProbe.swift",
                    "Sources/NFDecoderIPC/NFDecoderIPC.m", "Sources/NFDecoderIPC/include/NFDecoderIPC.h",
                    "Sources/CSQLite3/shim.h", "Sources/CSQLite3/module.modulemap"}
        require(required.issubset(paths) and any(name.startswith("Sources/ForensicsCore/") for name in paths),
                "History graph is missing linked target inputs")
        return paths

    paths = inventory()
    hashes = {}
    for name in sorted(paths):
        path = ROOT / name
        require(path.resolve() == path and path.is_file(), "Missing or linked history source input")
        hashes[name] = hash_file(path)[0]
    require(inventory() == paths, "History linked input inventory changed during capture")
    return hashes


def history_provenance(probe: Path) -> dict:
    selected = {"script/native_workload_benchmark.py": ROOT / "script/native_workload_benchmark.py",
                "Sources/CaseHistoryWorkloadProbe/CaseHistoryWorkloadProbe.swift": ROOT / "Sources/CaseHistoryWorkloadProbe/CaseHistoryWorkloadProbe.swift"}
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
    dirty = bool(subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip())
    ram_bytes = None
    if sys.platform == "darwin":
        ram_bytes = int(subprocess.run(["/usr/sbin/sysctl", "-n", "hw.memsize"], capture_output=True, text=True, check=True).stdout.strip())
    elif "SC_PHYS_PAGES" in os.sysconf_names:
        ram_bytes = os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")
    inputs = history_input_graph()
    graph_hash = hashlib.sha256(json.dumps({"product": "CaseHistoryWorkloadProbe", "sourceSha256": inputs},
                                         sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"sourceRevision": revision, "workingTreeDirty": dirty,
            "recipeSHA256": {name: hash_file(path)[0] for name, path in selected.items()},
            "linkedInputSHA256": inputs, "linkedInputGraphSHA256": graph_hash,
            "linkedInputScope": "Complete local Package/probe/Core/IPC/SQLite/driver inputs observed before and after measurements; caller must separately bind compilation",
            "binarySHA256": {"historyProbe": hash_file(probe)[0]},
            "environment": {"architecture": platform.machine(), "os": platform.platform(), "physicalRAMBytes": ram_bytes,
                            "logicalCPUCount": os.cpu_count(), "pythonVersion": platform.python_version()}}


def run_history(destination: Path, probe: Path, *, fixture: Path | None = None, records: int = 120,
                prompt_bytes: int = 614400, repetitions: int = 5, timeout: float = 900, interval: float = .05) -> dict:
    require(repetitions >= 5 and 1 <= records <= 1000 and 1 <= prompt_bytes <= 900000, "Invalid history benchmark configuration")
    require(probe.is_file() and not probe.is_symlink() and os.access(probe, os.X_OK), "Requires an existing regular history probe executable")
    destination = exclusive_directory(destination)
    fixture = local_path(fixture) if fixture is not None else destination / "history-fixture"
    require(not destination.is_relative_to(fixture), "History run outputs must remain outside the original fixture")
    before_provenance = history_provenance(probe)
    write_json(destination / "benchmark-provenance.json", before_provenance)
    generation = None
    if not fixture.exists():
        fixture = exclusive_directory(fixture)
        generation_logs = exclusive_directory(destination / "history-generation-driver")
        command = [str(probe.resolve()), "--mode", "generate", "--root", str(fixture), "--records", str(records), "--prompt-bytes", str(prompt_bytes)]
        config = {"schemaVersion": 1, "syntheticOnly": True, "mode": "history-generate", "excludedFromScanMeasurements": True,
                  "fixture": str(fixture), "records": records, "promptBytes": prompt_bytes, "provenance": before_provenance}
        write_json(generation_logs / "attempt-configuration.json", config)
        try:
            generation = launch_probe(command, generation_logs, timeout, interval)
            write_json(generation_logs / "measurement-attempt.json", dict(config, measurement=generation, validationState="not-started"))
            require(generation["returncode"] == 0, "History fixture generation probe failed")
            require(read_json(generation_logs / "probe.stdout", HISTORY_JSON_LIMIT)
                    == read_json(fixture / "history-fixture-receipt.json", HISTORY_JSON_LIMIT), "History generation stdout/fixture receipts differ")
        except Exception as error:
            write_json(generation_logs / "failed-attempt.json", dict(config, error=str(error), validationState="failed"))
            raise
    preflight_logs = exclusive_directory(destination / "history-fixture-preflight-driver")
    preflight_config = {"schemaVersion": 1, "syntheticOnly": True, "mode": "history-preflight",
                        "fixture": str(fixture), "records": records, "promptBytes": prompt_bytes,
                        "validationState": "not-started", "provenance": before_provenance}
    write_json(preflight_logs / "attempt-configuration.json", preflight_config)
    try:
        baseline = validate_history_fixture(fixture, records, prompt_bytes)
    except Exception as error:
        write_json(preflight_logs / "failed-attempt.json", dict(preflight_config, validationState="failed", error=str(error)))
        raise
    write_json(destination / "independent-history-oracle.json", baseline)
    runs = []
    for repetition in range(1, repetitions + 1):
        # Independent bounded record validation warms the fixture. Every scan
        # receives a fresh process; no cold-cache request or claim is made.
        logs = exclusive_directory(destination / f"history-warm-preverified-{repetition:02d}-driver")
        command = [str(probe.resolve()), "--mode", "scan", "--root", str(fixture), "--records", str(records), "--prompt-bytes", str(prompt_bytes)]
        config = {"schemaVersion": 1, "syntheticOnly": True, "mode": "history", "regime": "warm-preverified",
                  "freshProcess": True, "repetition": repetition, "fixture": str(fixture), "validationState": "not-started",
                  "cacheVerifiedCold": False, "provenance": before_provenance}
        write_json(logs / "attempt-configuration.json", config)
        try:
            require(validate_history_fixture(fixture, records, prompt_bytes) == baseline, "History fixture changed before scan")
        except Exception as error:
            write_json(logs / "failed-attempt.json", dict(config, validationState="preflight-failed", error=str(error)))
            raise
        try:
            measurement = launch_probe(command, logs, timeout, interval)
        except Exception as error:
            write_json(logs / "failed-attempt.json", dict(config, validationState="launch-failed", error=str(error)))
            raise
        attempt = dict(config, measurement=measurement)
        write_json(logs / "measurement-attempt.json", attempt)
        try:
            require(measurement["returncode"] == 0, "History scan probe failed")
            validate_rss_measurement(measurement, history_only=True)
            receipt = read_json(logs / "probe.stdout", HISTORY_JSON_LIMIT)
            validation = validate_history_scan(receipt, baseline, measurement["wait4"]["pid"])
            require(validate_history_fixture(fixture, records, prompt_bytes) == baseline, "Original history fixture bytes or stat identities changed")
        except Exception as error:
            write_json(logs / "failed-attempt.json", dict(attempt, validationState="failed", error=str(error)))
            raise
        run_receipt = {"mode": "history", "repetition": repetition, "regime": "warm-preverified", "freshProcess": True,
                       "cache": {"label": "warm-preverified", "cacheVerifiedCold": False,
                                 "limitations": "Independent record verification warms OS cache outside timed work. Each scan is a fresh process; no cold-cache claim or storage-regime comparison."},
                       "stageSeconds": validation["stageSeconds"], "measurement": measurement, "validation": validation,
                       "scanReceipt": receipt, "fixtureUnchanged": True}
        write_json(logs / "driver-receipt.json", run_receipt)
        compact = dict(run_receipt, measurement=dict(measurement), driverReceipt=logs.name + "/driver-receipt.json")
        compact["measurement"]["rssSampler"] = {key: value for key, value in measurement["rssSampler"].items() if key != "samples"}
        runs.append(compact)
        print(f"history warm-preverified {repetition}/{repetitions}: verified, {measurement['wallSeconds']:.3f}s", flush=True)
    after_provenance = history_provenance(probe)
    require(all(after_provenance[key] == before_provenance[key] for key in ("recipeSHA256", "binarySHA256", "sourceRevision",
                                                                         "linkedInputSHA256", "linkedInputGraphSHA256")),
            "History benchmark recipe, binary or revision changed during measurements")
    summary = {"schemaVersion": 1, "syntheticOnly": True, "providerRequests": 0, "guiMeasured": False,
               "kind": "ForensicsCore-headless-history-benchmark", "mode": "history", "regime": "warm-preverified",
               "createdUTC": datetime.datetime.now(datetime.timezone.utc).isoformat(), "provenance": before_provenance,
               "provenanceReverifiedAfterRuns": True, "records": records, "promptBytes": prompt_bytes,
               "serializedTotalBytes": baseline["serializedTotalBytes"], "maximumSerializedRecordBytes": baseline["maximumSerializedRecordBytes"],
               "repetitions": repetitions, "generationExcludedFromMeasurements": True,
               "generationReceipt": "history-generation-driver/process-attempt.json" if generation is not None else None,
               "measurementScope": "Fresh headless CaseWorkStore history paging and per-record verification. No engine/decoder/provider/GUI. RSS covers the entire scan-plus-verification process; stage-separated RSS is unavailable.",
               "percentileMethod": "p50 median; p95 nearest rank (with five runs p95 is the maximum)",
               "runs": runs, "wallSeconds": distribution([row["measurement"]["wallSeconds"] for row in runs]),
               "kernelReportedMaximumRSSBytes": distribution([row["measurement"]["wait4"]["kernelReportedMaximumRSSBytes"] for row in runs]),
               "stageSeconds": {stage: distribution([row["stageSeconds"][stage] for row in runs]) for stage in ("historyScanSeconds", "verifySeconds")},
               "rssSampledPeakBytes": {}}
    for metric in ("appPeakRSSSampledBytes", "helpersPeakRSSSampledBytes", "aggregatePeakRSSSampledBytes"):
        values = [row["measurement"]["rssSampler"][metric] for row in runs]
        summary["rssSampledPeakBytes"][metric] = distribution(values)
    write_json(destination / "benchmark-summary.json", summary)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--generate", type=Path, metavar="LOCAL")
    actions.add_argument("--verify", type=Path, metavar="OUTPUT")
    actions.add_argument("--run", type=Path, metavar="LOCAL")
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--probe", type=Path)
    parser.add_argument("--engine", type=Path, default=ROOT / ".engine/bin/NFTSKEngine")
    parser.add_argument("--decoder", type=Path, default=ROOT / "dist/NativeForensics.app/Contents/Helpers/NFDocumentDecoder")
    parser.add_argument("--image-mib", type=int, default=512)
    parser.add_argument("--mode", choices=("workflow", "listing", "cancel", "history"), default="workflow")
    parser.add_argument("--records", type=int, default=120)
    parser.add_argument("--prompt-bytes", type=int, default=614400)
    parser.add_argument("--rows", type=int, default=50000)
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--timeout", type=float, default=900)
    parser.add_argument("--sample-interval", type=float, default=.05)
    args = parser.parse_args()
    if args.generate:
        generate(args.generate, args.image_mib * BLOCK_BYTES)
        print(args.generate / IMAGE_NAME)
    elif args.verify:
        require(args.fixture is not None, "--verify needs --fixture")
        print(json.dumps(verify(args.fixture, args.verify), sort_keys=True))
    else:
        require(args.probe is not None, "--run needs --probe")
        if args.mode == "history":
            run_history(args.run, args.probe, fixture=args.fixture, records=args.records, prompt_bytes=args.prompt_bytes,
                        repetitions=args.repetitions, timeout=args.timeout, interval=args.sample_interval)
        else:
            run(args.run, args.probe, args.engine, args.decoder, fixture=args.fixture, repetitions=args.repetitions,
                mode=args.mode, rows=args.rows, timeout=args.timeout, interval=args.sample_interval)
        print(args.run / "benchmark-summary.json")


if __name__ == "__main__":
    main()

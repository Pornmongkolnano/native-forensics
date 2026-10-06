# Native engine protocol v1

Implementation contract for Phase 1. One owned helper process serves one request. Input/output are UTF-8 NDJSON, maximum frame 1 MiB. No shell is involved. The first input line is the request; optional later `cancel` messages request cooperative cancellation. App termination remains an owned-PID fallback.

Request fields: `protocolVersion:1`, `jobID:String`, `operation: "enumerate"|"inspect"|"extract"`, `imagePaths:[absolute local paths in order]`, `imageType:"auto"|"raw"|"ewf"`, `sectorSize:0|512|4096`, `timezone:String`, `maxFiles:1...50000`, `hashLogicalImage:Bool`. Extract adds `file:{fsOffsetBytes:Int64,metaAddress:UInt64,attributeType:Int32?,attributeID:Int32?,size:Int64}`, `outputPath:String` (must not exist).

Every response has `protocolVersion:1`, the same `jobID`, monotonic `sequence` starting at 0, and `type`:

- `hello`: `engineVersion`, `patchDigest`, `capabilities:[String]`.
- `image`: `imageType`, `logicalSize:Int64`, `sectorSize:Int`, optional `logicalSha256:String` (scope: logical-image-bytes), and ordered `imagePaths` actually opened.
- `volume`: `volume:{id:String,offsetBytes:Int64,filesystem:String,blockSize:Int64,blockCount:Int64}`.
- `fileBatch`: `files:[FilesystemEntry]`, up to 128 rows and <=1 MiB.
- `progress`: `stage:String`, `completed:Int64`, optional `total:Int64`, `unit:String`.
- `warning` or `error`: `code:String`, `message:String`.
- `extracted`: `outputPath`, `byteCount:Int64`, `sha256` (scope: extracted-file-bytes).
- exactly one terminal `completed`, `partial`, `failed` or `cancelled`: `fileCount:Int64`, optional `message:String`.

FilesystemEntry fields: `id:String` stable within the source/volume, `path:String`, `name:String`, `fsOffsetBytes:Int64`, `metaAddress:UInt64`, optional `attributeType:Int32`, `attributeID:Int32`, `size:Int64`, `isDirectory:Bool`, `isDeleted:Bool`, optional Unix seconds `createdEpoch`, `modifiedEpoch`, `accessedEpoch`, `changedEpoch` and corresponding `createdNanoseconds`, `modifiedNanoseconds`, `accessedNanoseconds`, `changedNanoseconds:Int32` (default 0). Seconds/nanoseconds are retained without Date/Double normalization. Display timezone is separate from evidence timezone interpretation. IDs combine the filesystem/inode/attribute tuple with a SHA-256 of the UTF-8 path, retaining distinct hard-link paths without embedding an arbitrarily long name.

Engine `0.1.1` validates exFAT calendar/time fields before either offset conversion or IANA fallback. FAT/exFAT epoch-zero sentinels omit the corresponding epoch and nanoseconds; absent means unavailable, which may be missing or invalid recorded data. NTFS can legitimately represent Unix epoch zero, so it is retained. Unknown exFAT offsets still require an evidence-timezone assumption; DST overlaps/gaps do not establish a uniquely recorded UTC instant. NTFS directories retain their base directory row and expose named DATA streams as separate extractable rows with the exact attribute locator. Older caches preserve their engine version and require reanalysis to apply these changes.

`inspect` validates the supported image/filesystem and returns image metadata without file batches. The current helper also omits volume frames for this operation; clients may accept optional volume metadata. Extraction returns image metadata and one verified byte receipt, with no listing rows.

Complete success needs valid protocol, hello, exactly one terminal completed, and exit 0. Partial keeps usable records with explicit warnings. Exit 0 alone is never success. Unknown/truncated/unsupported filesystem is failed/partial, never a silently completed empty listing. Results are bounded at 50,000 records/64 MiB serialized input; limits are explicit partial/failure states. Failed/cancelled extraction removes only its newly created output, and never overwrites an existing path or an input image.

Case cache: separate versioned result JSON per evidence ID, written atomically under `filesystem/`; the Phase 0 manifest and selected-file hash scope stay readable. It records engine/patch versions, exact ordered source paths, each source-file SHA-256, identities, options, logical-image metadata, rows, warnings and terminal status. Cache loading is historical; every cached source-file digest must match before extraction. The client hashes all explicitly selected segments before analysis and verifies their identities after the job. EWF segment numbers, completeness/corruption flags and the TSK-opened path list must agree; RAW concatenation follows the user's explicit order and has no independent completeness oracle.

The Swift client launches a private staging output, independently verifies its size and SHA-256, then publishes with an exclusive atomic rename. Cancellation or failure cleans only owned staging files. Source identity is verified before/after each job. RAW/EWF and supported TSK filesystems are capability-tested; UDF/APFS/FileVault cannot be advertised from generic TSK auto-detection alone.

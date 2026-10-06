# Native filesystem helper

`NFTSKEngine.cpp` is this project's original C++17 process adapter. The dependency sources, patches and notices are tracked separately; the helper does not embed Autopsy Java or copy Strata application code.

The wire contract is [ENGINE-PROTOCOL.md](../docs/ENGINE-PROTOCOL.md). One process owns one request. Standard output contains only bounded NDJSON. The Swift client owns process launch, watchdogs, source-file hashes, result persistence, and final export publication.

## Implementation boundaries

- RAW and EWF logical-image readers feed Sleuth Kit's direct filesystem APIs. Ordered EWF paths are checked against intrinsic segment numbers, a read-only libewf completeness/corruption preflight, and the paths actually opened by TSK. Unlisted auto-discovered segments are rejected.
- Filesystems may be directly at byte offset zero or in MBR/GPT partitions. Allocated/deleted directory entries and NTFS file/directory data streams are retained, with distinct hard-link paths and stream locators. APFS, UDF and encrypted-image/filesystem support is deliberately unavailable in Phase 1.
- IANA evidence timezone interpretation is set only inside this owned helper process. TSK's integer seconds and nanoseconds are sent without floating-point conversion. Presentation timezone belongs to the app.
- exFAT validates Gregorian dates/time/increments before conversion. FAT/exFAT unavailable zero timestamps are omitted; NTFS epoch zero is retained. Unknown offsets require an IANA interpretation assumption, including DST behavior. Classic FAT invalid-calendar normalization is still an upstream limitation.
- Batches contain at most 128 entries, frames at most 1 MiB, and listings at most the configured 50,000-entry ceiling or 64 MiB response ceiling. Reaching a limit emits a warning and an explicit partial terminal result.
- `SIGTERM`, `SIGINT`, and a subsequent protocol cancel frame request cooperative cancellation. Nonblocking stdin polling occurs at file, hashing and extraction boundaries; the app still provides a timeout/owned-process termination fallback for a blocked native parser.
- Extraction reads the specified metadata address/data attribute, checks its current logical size against the reference, and streams only those bytes. SHA-256 describes the actual extracted bytes. Deleted-file recovery cannot prove that content was never overwritten after deletion.
- Output creation uses a held canonical parent-directory descriptor plus `O_EXCL`/`O_NOFOLLOW`. Existing files and input images cannot be overwritten. Failed/cancelled jobs remove only their newly created output inode. Successful export publication is a separate Swift operation.
- Image segment device/inode, size, modification time and change time are checked before/after work. The Swift client additionally checks selected-file byte hashes. Logical-image SHA-256 is optional and has a distinct scope from compressed EWF container hashes.

Build with `python3 script/build_native_engine.py`. Generated dependency sources, static libraries, helper binaries and build receipts remain under ignored `.engine/`. The manifest and all patches are checksum-pinned. Run `python3 Tests/NativeEngine/run_tests.py --help` for the independent synthetic fixture suite.

This helper provides filesystem enumeration and extraction. It does not provide carving, document-content indexing, artifact parsing, or Autopsy feature parity.

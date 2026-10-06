# Native workbench validation — 6 October 2026

Scope: Phase 0 foundation and the first Phase 1 filesystem adapter. Host: Apple Silicon M2 arm64, macOS 27.0.1, Xcode 27.0 / Swift 6.4. Deployment target is macOS 14; older macOS and physical M5 machines have not been tested. Phase 1 remains in progress under the [roadmap](ROADMAP.md).

## Swift core and real helper integration

All 40 Swift Testing test functions in three suites passed locally, covering selected-file hashing/case storage, engine protocol/cache/export handling, and real helper integration. The XCTest compatibility header reports zero XCTest tests; the subsequent Swift Testing suites contain the actual checks.

Regressions include malformed/version/job/sequence frames, repeated/missing terminal records, output bounds, saturated stderr, crash/nonzero exits, partial results, startup/inactivity deadlines, cancellation and owned-process termination. Export checks independently compare SHA-256 and size, reject stale source hashes, preserve existing destinations, and exercise destination/parent/staging replacement races. Cache tests reject unknown schemas, symlinks, foreign evidence IDs and mismatched source scopes.

Real Swift client tests enumerate 13 deterministic image configurations, save/reload filesystem results, and extract 57 known payloads including deleted, empty and nested files. Every payload is checked against independent bytes/SHA-256; all source hashes remain unchanged. Extraction skips redundant logical-image hashing while retaining cached source-file hash verification and independent output verification.

```sh
python3 script/build_native_engine.py
python3 Tests/NativeEngine/run_tests.py --helper .engine/bin/NFTSKEngine --output local/ci-native
NFTSK_ENGINE_HELPER="$PWD/.engine/bin/NFTSKEngine" \
NFTSK_SYNTHETIC_FIXTURES="$PWD/local/ci-native/fixtures" swift test
./script/build_and_run.sh --verify
```

## Native filesystem corpus

The final portable native suite passed 68/68 checks with 98 exact payload extractions and no skipped warnings. It additionally verifies FAT years 2038/2100, a 1,852-byte Unicode path with compact IDs, a FAT/UDF signature collision, and renamed singleton EWF containers. The portable Python suite generates FAT16/FAT32 with 512/4096-byte sectors, direct filesystems, MBR/GPT offsets, split RAW, Unicode source paths, allocated/deleted/empty/nested payloads, and exFAT valid per-entry UTC offsets with fractional timestamps. Split EWF uses the checksum-pinned build-time utility. Checks compare logical-image hashes, exact extracted bytes, timestamps and stable IDs. Negative checks cover invalid/truncated/unsupported images, framing/options, EWF order/completeness/duplicates/unlisted segments, damaged EWF headers, RAW rejection of EWF, cancellation, partial limits and no-overwrite extraction. Metadata pseudo-files are checked separately from payload names rather than silently discarded.

An additional local reference corpus passed 10/10 configurations: NTFS under UTC/Bangkok and exFAT UTC/positive/negative/unknown offsets under both zones. It checked 62 extracts, 200 integer epoch assertions and 200 nanosecond assertions; all five source hashes were unchanged. NTFS covered allocated/deleted, resident/nonresident, empty files and long Thai paths. This corpus is local evidence and is not a portable CI fixture. A historical negative-offset fixture name did not match its encoded offset; expectations follow the actual recorded −240-minute value.

## App and build checks

The bundle includes the helper, build receipt and license notices. Helper/app signatures are verified with ad-hoc signing. Native dynamic dependencies are macOS system libraries; Java, Solr and Homebrew libraries are not runtime dependencies. First native build downloads checksum-pinned source; generated sources/libraries/relink materials stay in ignored `.engine/`.

Actual GUI checks use a synthetic FAT image: create case → inspect source → analyze → browse allocated/deleted entries → extract a deleted 54-byte file → reopen cached listing. The final build also inspected `split.001`, explicitly added `split.002`, displayed their ordered paths/separate container hashes, and analyzed both into the same logical-image hash as the unsplit reference. Independent Python readback confirmed both caches, all ordered source hashes, the final four-patch digest, and the 54-byte output SHA-256. Opening a new file panel after extraction worked after correcting the parent-window selection. A fresh app launch exposed inconsistent custom-UTType filtering on macOS 27; the existing-case picker now selects folders/packages and delegates manifest validation to Core. Selecting the case folder and reopening its cached listing passed with this final picker.

Fresh native builds also passed in a checkout path containing spaces; cached builds, six unsafe-archive rejection cases, dependency/header integrity checks, and portable static-library relink recipes passed. Four source patches are checksum-pinned, and the final bundled helper bytes match the build receipt.

Cache load/save run outside the UI actor with case/evidence selection guards. Limits bound serialized data and record counts, not total process RAM. There is no matched speed or memory benchmark for the new app yet.

## Boundaries and delivery state

Current gates do not establish all NTFS streams/sparse/compressed/encrypted combinations, fragmented deleted-file completeness, carving, content search, artifact analysis, APFS/FileVault or UDF support. Cancel/crash correctness is covered by engine/client tests; full timed GUI cancellation/failure flows remain later acceptance work.

The development app is ad-hoc signed for local use. Developer ID signing, notarization, complete corresponding-source/relink distribution and clean-machine packaging remain release work. Cases, source images, reports, private paths and build products stay ignored and are not included in Git. Existing Autopsy runtime/cases were preserved; its read-only frozen-baseline health check was 30 PASS, 0 FAIL, 0 WARN before and after Phase 1 work. The baseline was not regenerated.

CI is configured to build native dependencies, run the portable native corpus, enable real Swift helper tests, and build the app on macOS 26. The prior Phase 0 remote CI success applies to the initial commit only. Phase 1 checks reported here are local until a new remote workflow has actually run.

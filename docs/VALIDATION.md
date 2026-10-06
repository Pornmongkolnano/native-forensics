# Native workbench validation — 6 October 2026

Scope: Phase 0 foundation and the first Phase 1 filesystem adapter. Host: Apple Silicon M2 arm64, macOS 27.0.1, Xcode 27.0 / Swift 6.4. Deployment target is macOS 14; older macOS and physical M5 machines have not been tested. Phase 1 remains in progress under the [roadmap](ROADMAP.md).

## Swift core and real helper integration

All 41 Swift Testing test functions in three suites passed locally, covering selected-file hashing/case storage, engine protocol/cache/export handling, and four real helper integration tests. The XCTest compatibility header reports zero XCTest tests; the subsequent Swift Testing suites contain the actual checks. All real helper tests ran with the configured environment; none were skipped in the final run.

Regressions include malformed/version/job/sequence frames, repeated/missing terminal records, output bounds, saturated stderr, crash/nonzero exits, partial results, startup/inactivity deadlines, cancellation and owned-process termination. Export checks independently compare SHA-256 and size, reject stale source hashes, preserve existing destinations, and exercise destination/parent/staging replacement races. Cache tests reject unknown schemas, symlinks, foreign evidence IDs and mismatched source scopes.

Real Swift client tests enumerate 20 deterministic image configurations, save/reload filesystem results, and extract 97 known payloads including deleted, empty, fragmented, sparse and named NTFS streams. Exact payload path sets, unique IDs and stream locators are checked. Every payload is checked against independent bytes/SHA-256; all source hashes remain unchanged. The separate timestamp matrix checks per-entry epoch/nanoseconds and omitted invalid fields under UTC, Bangkok and New York where declared. Extraction skips redundant logical-image hashing while retaining cached source-file hash verification and independent output verification.

```sh
python3 script/build_native_engine.py
python3 Tests/NativeEngine/run_tests.py --helper .engine/bin/NFTSKEngine --output local/ci-native
NFTSK_ENGINE_HELPER="$PWD/.engine/bin/NFTSKEngine" \
NFTSK_SYNTHETIC_FIXTURES="$PWD/local/ci-native/fixtures" swift test
./script/build_and_run.sh --verify
```

## Native filesystem corpus

The final portable native suite passed 87/87 checks with 188 exact payload extractions and no skipped warnings. It retains all 13 prior fixture hashes and adds seven image configurations. The Python standard-library corpus generates FAT16/FAT32 with 512/4096-byte sectors, direct filesystems, MBR/GPT offsets, split RAW, Unicode source paths, allocated/deleted/empty/nested payloads, FAT years 2038/2100, a 1,852-byte Unicode path with compact IDs, a FAT/UDF signature collision, allocated fragmented FAT and unavailable FAT dates. Split/singleton/renamed EWF uses the checksum-pinned build-time utility. Checks compare logical-image hashes, exact extracted bytes, timestamps and stable IDs. Negative checks cover invalid/truncated/unsupported images, framing/options, EWF order/completeness/duplicates/unlisted segments, damaged EWF headers, RAW rejection of EWF, cancellation, partial limits and no-overwrite extraction. Metadata pseudo-files are checked separately from payload names rather than silently discarded.

The portable NTFS generator directly constructs BPB, MFT/INDX update sequences, attributes, indexes, runlists and allocation bitmaps. Its 13 expected streams include allocated/deleted resident/nonresident data, fragmented positive/negative run deltas, a sparse zero hole, empty/nested/Unicode files, hardlinks and file/directory ADS. All streams extract byte-identically; hardlinks share an inode but retain distinct path IDs. Independent expected FILETIME values preserve 100 ns precision in all four timestamp fields. The deterministic 16 MiB image SHA-256 is `972e11ec14598d55a2f0da7def7db832f08530951e5d7301387173d854990c0d`. It is minimal and nonbootable, not a general Windows volume formatter.

Four exFAT matrices check per-field positive/negative/quarter-hour offsets, unknown-offset IANA winter/summer and DST-boundary interpretation, year 2107, leap-day validity, impossible dates/time fields, absent dates and increment 200. Valid-offset outputs remain identical under UTC/Bangkok/Los Angeles host timezones. The old helper failed 21 timestamp rows across three requested zones; `0.1.1` rejects invalid civil values before conversion and omits unavailable FAT/exFAT epochs plus nanoseconds. Unknown-offset overlaps/gaps remain ambiguous evidence and use the requested timezone fallback. Classic FAT invalid-calendar normalization is not fixed by the exFAT patch.

An additional local reference corpus passed 10/10 configurations: NTFS under UTC/Bangkok and exFAT UTC/positive/negative/unknown offsets under both zones. It checked 62 extracts, 200 integer epoch assertions and 200 nanosecond assertions; all five source hashes were unchanged. NTFS covered allocated/deleted, resident/nonresident, empty files and long Thai paths. This corpus is local evidence and is not a portable CI fixture. A historical negative-offset fixture name did not match its encoded offset; expectations follow the actual recorded −240-minute value.

## App and build checks

The bundle includes the helper, build receipt and license notices. Helper/app signatures are verified with ad-hoc signing. Native dynamic dependencies are macOS system libraries; Java, Solr and Homebrew libraries are not runtime dependencies. First native build downloads checksum-pinned source; generated sources/libraries/relink materials stay in ignored `.engine/`.

Prior GUI checks used a synthetic FAT image: create case → inspect source → analyze → browse allocated/deleted entries → extract a deleted 54-byte file → reopen cached listing, plus explicit split-RAW selection and analysis. Opening panels after extraction and selecting a case folder passed after picker/parent-window fixes. The new app version 0.2.1 opens those historical caches with a reanalysis notice. Reanalysis with engine 0.1.1 removes unavailable FAT pseudo-file times instead of displaying 1970. The portable NTFS fixture is inspected, analyzed and reopened through the GUI; its directory ADS appears as a separate 52-byte extractable row with exact inode/attribute and integer timestamp precision. The export's bytes/hash and cached source hash are independently read back. ADS export suggestions replace the stream colon with a plain separator for macOS save panels while retaining the original forensic path.

Fresh native builds also passed in a checkout path containing spaces; cached builds, six unsafe-archive rejection cases, dependency/header integrity checks, and portable static-library relink recipes passed. Four source patches are checksum-pinned, and the final bundled helper bytes match the build receipt.

Cache load/save run outside the UI actor with case/evidence selection guards. Limits bound serialized data and record counts, not total process RAM. There is no matched speed or memory benchmark for the new app yet.

## Boundaries and delivery state

Current gates do not establish NTFS ATTRIBUTE_LIST, multilevel indexes, compression/EFS or reallocated/overwritten deleted clusters. The known intact fragmented NTFS deleted fixture passes; a cleared fragmented FAT chain has no complete recovery guarantee. Carving, content search, artifact analysis, APFS/FileVault and UDF remain unsupported. Cancel/crash correctness is covered by engine/client tests; full timed GUI cancellation/failure flows and matched worker/RAM profiling remain later acceptance work.

The development app is ad-hoc signed for local use. Developer ID signing, notarization, complete corresponding-source/relink distribution and clean-machine packaging remain release work. Cases, source images, reports, private paths and build products stay ignored and are not included in Git. Existing Autopsy runtime/cases were preserved; its read-only frozen-baseline health check was 30 PASS, 0 FAIL, 0 WARN before and after Phase 1 work. The baseline was not regenerated.

CI builds native dependencies, runs the portable native corpus, enables real Swift helper tests, and builds the app on macOS 26. The prior Phase 1 baseline passed remotely at `50c9045` in [run 37447081860](https://github.com/Pornmongkolnano/native-forensics/actions/runs/37447081860). The expanded corpus above records local verification; check the [workflow runs](https://github.com/Pornmongkolnano/native-forensics/actions) for commit-specific remote results.

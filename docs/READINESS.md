# Local-use readiness — 7 October 2026

Current development build is **0.5.1 / build 14**. [Native export and scheduling validation](NATIVE-0.5.1.md) records the added UDF-to-Autopsy workflow, current debug/release tests and synthetic GUI export. The assignment and historical gates below retain their original version scopes.

NativeForensics **0.5.0 / build 13** is verified for the bounded assignment workflows in [the current validation report](ASSIGNMENT-VALIDATION-2026-10-07.md): 14 primary whole-image recovery payloads, 41 comparable filesystem exports and 20 UDF payloads, all checked against independent/reference bytes. Original evidence and Autopsy's frozen baseline were preserved. This is a local development milestone, not general Autopsy parity or a public release.

## Current verified scope

- Separate filesystem, RAW signature-recovery and UDF-history workspaces; explicit completed/partial/unsupported states and source-bound immutable generations.
- Whole-image PhotoRec scope, verified source-byte ranges, independent hashes, exclusive file/batch publication and owned process cancellation. PhotoRec remains a required external tool for carving.
- Bounded original UDF 2.01 physical/virtual/VAT inspection with current/history inventories, extents, raw timestamps and deleted-ancestor proof; nine snapshots and all 20 assignment target payloads verified.
- Isolated image/PDF/text/OpenXML decoding and literal document-body search. Extensions remain separate from detected content. Seven legacy Office bodies are unsupported; five modern assignment files retain partial-content flags. No OCR, media playback or Office layout/execution claim.
- Job-bound recovery assessments and complete-inventory recovery/UDF report exports. Filtered table rows do not narrow the exported UDF inventory. Saved report provenance and independently validated bundle provenance are separate receipts.
- Observable jobs release controls on completion; source/case transitions clear session export receipts; finite workspace dimensions keep long lists/properties scrollable. Source-only `O_SEARCH` descriptors permit bounded hex reads without directory enumeration, while write paths retain synchronized directory descriptors.

## Current verification

Debug/release each passed **367 Swift Testing declarations** (259 core + 108 app), with actual helper and optional local UDF-oracle tests enabled. Native checks passed **105/105**, Python checks **55/55**, source-bound assignment comparison **2,198 gates**, and separate GUI publication readbacks **783 batch/recovery gates, 385 UDF-report gates and 466 recovery-report gates**, all with zero mismatches/failures in their recorded scopes. The decoder corpus covers 91 reference exports. The [sanitized receipt](validation/2026-10-07-assignment.json) preserves these boundaries; the latest bundle passed independent signature/hash/architecture/dependency validation. The assignment report explicitly records actual PDF preview/search and 14-candidate recovery-report publication, while manual assessment save/reopened assessment readback remain unobserved because of intermittent UI automation pipe failures. The app remained alive and normal restart/reopen worked.

Observed host: Apple M2 / arm64, macOS 27.0.1, Swift 6.4 / Xcode 27. Runtime engine: unchanged 0.1.2-tsk4.15.0 with five pinned patches. Deployment metadata declares macOS 14. Test-suite durations and historical pipeline timings do not establish a new full-app performance advantage. Read-only Autopsy health reports 30 PASS, 0 FAIL, 0 WARN, 2 INFO and 3 SKIP.

## Current release gates

1. **Trust and distribution:** ad-hoc development signing; Developer ID/notarization, complete corresponding-source/relink distribution, clean-machine installation and external PhotoRec setup remain unverified. macOS security settings were not weakened.
2. **Evidence breadth:** general UDF profiles, APFS/FileVault, complex NTFS features, arbitrary damaged/reallocated filesystems and full artifact/browser/email/registry analysis need independent coverage. Legacy Office body decoding, OCR and media playback remain unsupported. Removable-media contents alone cannot answer PC user-action questions.
3. **Durability and review:** broader publication/cancellation/GUI fault races, crash/power-loss recovery, case-integrity/migration tooling and sidecar cryptographic authenticity remain work. Successful payload export does not prove a former original file is intact or deleted.
4. **Compatibility and performance:** physical M5, supported older macOS, large/cold/mixed datasets, complete-app latency/RAM/battery/thermal profiling and production worker policy remain unverified. No current speed claim follows from earlier workload benchmarks.

## Historical 0.2.5 readiness receipt

**Historical 0.2.5 receipt:** Results and remaining gates below describe that milestone, not current feature absence. Later [case work](CASE-WORK.md) and [assignment workflows](ASSIGNMENT-WORKFLOW.md) have separate validation receipts.

NativeForensics **0.2.5 / build 7**, engine **0.1.2-tsk4.15.0**. This pass improves bounded local filesystem workflows; Phase 1 remains in progress. It does not establish general Autopsy parity or a public distribution release.

## Correctness and data preservation

- Case create/open/add operations hold directory descriptors, validate lock/manifest/staging identities and recheck source identity before manifest publication. Edited manifests reject noncanonical paths and sources inside their own case bundle. Missing offline sources remain readable as historical records without opening evidence.
- A reproduced queued directory-to-symlink swap previously redirected a manifest write into a copied, unrelated synthetic case before reporting an error. The new transaction rejects the swap and preserves both manifests. Exclusive creation and stale-case checks remain in place.
- Live helper image frames must declare the complete ordered source scope. Hard-link aliases cannot count as distinct image segments. Cache validation enforces the requested logical hash, volume bounds and identity nanoseconds; historical optional `imagePaths` remains backward compatible.
- Deadline handling sends cooperative cancellation before process termination. Explicit user cancellation retains its cancellation outcome even if the helper emits malformed shutdown output. Verified extraction bytes are independently synchronized before exclusive publication.
- Classic FAT rejects impossible Gregorian dates, encoded seconds/minutes/hours and invalid creation increments before `mktime` can normalize them. The old helper reproduced 24 malformed-field cases across FAT16/FAT32. Valid leap days and 1980–2107 boundaries remain covered. Historical engine 0.1.1 FAT listings show a reanalysis notice; caches are not automatically rewritten.

## Desktop lifecycle and packaging

- External case URLs cannot switch workspaces while dialogs/jobs are active. A closing workspace cannot start work from a resumed file dialog.
- Closing/Quitting retains owning workspaces until job cancellation, helper cleanup and in-flight atomic publication drain. SIGTERM uses the same AppKit Quit path. A commit waiting for the case lock runs outside MainActor; if publication completes before cancellation, the UI reports that it was saved.
- Missing/non-executable helper detection precedes expensive hashing. Corrupt caches stay untouched and provide recovery guidance. Error text does not promise that no data was published after a durability failure.
- Build the new app in a private stage, sign it, verify helper/license/notice hashes and system library dependencies, then stop this checkout's app and publish. Failed packaging leaves the previous app intact; a failed replacement rename rolls back. Cached engine receipts also validate retained relink/license sidecars.
- The app includes `THIRD_PARTY_NOTICES.md` and bundle-relative license locations. Its receipt explicitly identifies source/relink materials as unbundled development artifacts. Settings displays implemented scope, unavailable features and local development signing.

## Verification receipts

Host: Apple M2 / arm64, macOS 27.0.1, Xcode 27. Deployment metadata declares macOS 14. Older macOS and a physical M5 were not tested.

| Check | Observed outcome |
|---|---|
| Swift debug and optimized release | 59 core + 20 workspace/presentation declarations per configuration; all passed with real-helper integration enabled |
| Portable native corpus | 105/105 checks, 26 image configurations, no failures or skipped warnings; exact bytes/hash/timestamp/source-integrity checks |
| Python harness and artifact regressions | 23/23 tests, including replacement rollback, helper/license/notice tampering and missing cache sidecars |
| FAT converter exhaustive supplement | 131,328 encoded date/time/increment checks against an independent Python UTC Gregorian oracle; zero failures; converter-level scope |
| Packaged app | Strict helper/deep bundle signatures, receipt hashes, architecture and system-only dependency closure passed; freshly built app launched |
| GUI positive workflow | Fresh synthetic case → inspect FAT16 → analyze 10 entries → extract deleted 54-byte payload → independent byte/SHA-256 check → Quit/reopen cached case |
| GUI Quit during inspection | Observed 586.2 MB of a synthetic sparse 8 GiB source being read; Quit exited the app, appended no evidence record and left prior manifest/cache hashes unchanged |
| GUI unsupported input | Fresh synthetic input reports `NO_SUPPORTED_FILESYSTEM`, controls recover, and the previous FAT result remains byte-identical |
| Existing Autopsy preservation | Read-only frozen-baseline health: 30 PASS, 0 FAIL, 0 WARN; app/Solr closed and not started; no baseline regeneration |

The first full optimized run exposed a test scheduling issue while a blocking lock transaction used Swift's cooperative executor. The regression now uses a dedicated thread with descriptor-based synchronization; the corrected complete runs passed. This was not a product-output change.

Local raw receipts stay in ignored `local/readiness/`. The [sanitized summary](validation/2026-10-07-readiness.json) contains no user evidence, cases, personal paths or raw logs. Tests compare synthetic evidence only. Unit lifecycle tests cover close/quit coordination and a real blocked manifest commit; GUI Quit observation above does not establish every native-job or publication race, force-kill recovery, or crash durability on all storage types.

## Release gates recorded at 0.2.5

1. **Distribution trust:** no Developer ID signing identity is available on this host. The artifact is ad-hoc signed. Hardened-runtime signing/notarization, complete corresponding-source/relink distribution and clean-machine installation remain unverified. Gatekeeper settings were not weakened.
2. **Forensic breadth:** complex NTFS ATTRIBUTE_LIST/multilevel indexes/compression/EFS, damaged/reallocated deleted data and timezone DST overlaps/gaps need more independent coverage. UDF, APFS/FileVault, carving, content search, previews and artifact analysis are unavailable. Filename categories are hints.
3. **Auditability/recovery:** extraction receipts remain session state; a durable extraction ledger, case integrity reports/migrations, crash/power-loss testing and broader GUI publication races remain work. Saved JSON caches are historical records, without cryptographic authentication.
4. **Compatibility/performance:** test physical M5 and supported older macOS, large/cold/mixed evidence, RAM/battery/thermal behavior and complete UI workflows. Previous benchmark results apply only to their recorded versions/workloads and are not remeasured by this pass.

## Run checks

```sh
python3 script/build_native_engine.py
python3 Tests/NativeEngine/run_tests.py --helper .engine/bin/NFTSKEngine --output local/readiness/native-tests
NFTSK_ENGINE_HELPER="$PWD/.engine/bin/NFTSKEngine" \
NFTSK_SYNTHETIC_FIXTURES="$PWD/local/readiness/native-tests/fixtures" swift test
NFTSK_ENGINE_HELPER="$PWD/.engine/bin/NFTSKEngine" \
NFTSK_SYNTHETIC_FIXTURES="$PWD/local/readiness/native-tests/fixtures" swift test -c release
PYTHONPATH=Tests/NativeEngine python3 -m unittest test_benchmark_native_engine test_compare_forensics_pipeline test_app_bundle
./script/build_and_run.sh --verify
python3 script/validate_app_bundle.py dist/NativeForensics.app
```

CI runs the native corpus, Python checks, configured debug/release Swift tests and bundle validation. Full timing benchmarks are not CI gates. Inspect commit-specific CI status separately from these local results.

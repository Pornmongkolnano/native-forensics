# Foundation validation — 6 October 2026

Scope: Phase 0 native app and pure Swift core. Host: Apple Silicon arm64, macOS 27.0.1, Xcode 27.0 / Swift 6.4. Package deployment target is macOS 14; older macOS and physical M5 machines have not been tested.

## Local checks completed

- `swift test`: 19 Swift Testing tests passed. The XCTest compatibility header reports zero XCTest tests; the subsequent Swift Testing suite ran all 19 assertions groups.
- Core regressions cover known SHA-256 bytes and empty/multi-chunk files, read-only source bytes, regular/local source checks, source mutation/path replacement, early and in-flight cancellation, selected-container hash scope, JSON roundtrip, unknown schema rejection, exclusive creation, concurrent/stale writers, duplicate evidence and untrusted inspection DTOs.
- `./script/build_and_run.sh --verify`: compiled the native executable, staged and ad-hoc signed the `.app`, verified its signature and observed the exact checkout app process. A separate GUI-target compile also passed.
- Actual GUI through CUA: Create Case → select a synthetic 16 MiB image → inspect → show SHA-256/details → reopen the same case. The visible SHA-256 and persisted manifest matched an independent Python digest. Source bytes remained unchanged.
- The smoke image only contains a filesystem signature hint; it is not a valid filesystem corpus and does not establish filesystem parsing/recovery.
- Runtime cases, smoke images, paths and raw logs stay in ignored `local/` and build directories. They are not committed.

## Boundaries

GUI progress/cancel controls exist; cancellation correctness was verified in core tests, not by a timed GUI cancellation test. No disk-image filesystem enumeration, EWF logical hashing, carved-file recovery, document index, artifact parser or native TSK helper is integrated yet. Those require the separate acceptance gates in the roadmap.

The development bundle is ad-hoc signed for local use. Developer ID signing, notarization and clean-machine packaging are later release work. The existing Autopsy installation/cases were preserved; its read-only health check remained at 30 PASS, 0 FAIL, 0 WARN.

GitHub CI is configured to run the same synthetic tests and build the app bundle on macOS 26. The remote workflow result is recorded separately after the initial push; local validation alone is not a claim that remote CI has passed.

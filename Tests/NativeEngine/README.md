# Native helper regression fixtures

These standard-library Python tests generate synthetic images into ignored `local/phase1-native-test/`. They do not read user evidence or change the installed Autopsy runtime. The test runner requires a separately built `.engine/bin/NFTSKEngine` and never compiles it itself.

```sh
python3 Tests/NativeEngine/run_tests.py --fixtures-only
python3 Tests/NativeEngine/run_tests.py
```

Fixture generation is deterministic. Reusing a fixture directory verifies its hashes rather than overwriting images. A failed/interrupted generator may leave an incomplete directory; use a fresh `--output` directory in that case.

The matrix includes FAT16/FAT32 with 512/4096-byte sectors, allocated/empty/deleted/nested files, exact extracted-byte SHA-256, local DOS timestamps under UTC and Asia/Bangkok (including years 2038 and 2100), a valid-offset exFAT entry with preserved nanoseconds, MBR/GPT volumes, split RAW, and a Unicode image path. A deep Unicode FAT path over 1 KiB verifies compact stable IDs, while `NSR02` bytes in FAT slack verify that a UDF signature collision does not override valid FAT detection. If bundled `ewfacquire` exists, the runner also creates a split EWF and compares its logical/decompressed hash against the original RAW bytes. It verifies a complete singleton renamed `.bin`, explicit source selection with an unrelated `.E02` sibling, and ordered opened-path receipts. Container hashes and logical image hashes are distinct.

Safety/protocol cases cover bounded listings, cancellation, stable IDs, output no-overwrite, output/source identity, leaf symlinks and a safely canonicalized parent, invalid locators, invalid/missing/truncated input, malformed/oversized frames, and unsupported APFS/UDF signatures. EWF cases cover explicit and automatic detection, ordered segments, missing/duplicate/reversed segments, raw fallback refusal and damaged headers. The APFS/UDF signatures are deliberately incomplete negative fixtures; rejecting them does not constitute a complete APFS/UDF compatibility test.

The ignored JSON report records actual pass/fail results and skipped capabilities. This verifies the helper, not the complete SwiftUI app, storage model, arbitrary damaged images, carving, encryption, or all Autopsy modules. FAT/exFAT fixtures are constructed directly rather than copied from upstream projects. No image or local report should be committed.

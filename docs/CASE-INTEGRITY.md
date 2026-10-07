# Read-only case integrity audit

The audit checks an existing v1 `.nativecase` without changing its manifest, saved results, sidecars, payloads or evidence. It produces a report describing exactly what was checked and what remains unavailable. It does not repair records, migrate schemas or replace recorded hashes.

The default mode opens only the case. It validates supported metadata and hashes stored recovery payloads. Evidence receipts retain the `historical` status even when their original source is present: the default audit never opens the source image. An examiner can explicitly request a fresh selected-file size and SHA-256 comparison. This hashes the selected container's bytes; it does not compute or verify a logical/decompressed image hash.

## What the statuses mean

| Status | Meaning |
| --- | --- |
| `pass` | The particular metadata, payload or explicitly requested source check passed. A metadata pass does not establish fresh source verification. |
| `historical` | An existing evidence receipt was retained without reopening its source. |
| `fail` | A supported check found changed bytes, malformed or mismatched metadata, unsafe storage, or a missing expected payload. |
| `offline` | An explicitly requested source check found that the recorded source or its parent was absent. This does not establish that the stored case is corrupt. |
| `unavailable` | A schema/store is unsupported, or a file, byte, depth or time budget prevents complete coverage. The unchecked item is not verified. |

`sourceRehashed` records the requested audit mode. To establish that an individual source was actually verified, use its `source.verified` check and the `verifiedSourceCount` summary. A fresh-mode report can contain offline, unavailable or failed source checks. `isPartial` discloses incomplete coverage, and `hasFailures` reports at least one failed check.

## In the app

1. Open a `.nativecase` and choose **Case Integrity** in the sidebar.
2. Leave **Freshly rehash recorded evidence files** off for a case-only historical audit, or explicitly enable it to read and compare recorded selected files.
3. Choose **Run Audit**. **Cancel** stops owned audit work without writing into the case.
4. Review each status, item and check. The table shows 100 rows per page; use **Previous** and **Next** for further checks. An unavailable check means that item is not verified.
5. Choose **Export Report → JSON… / Markdown…** and select a destination outside the case and evidence. Absolute host paths are omitted by default. Enable **Include private host paths in exported reports** only for a report that should contain them. **Show Report** reveals a completed export in Finder.

Export publication is exclusive: an existing destination is preserved rather than overwritten. Canceling the file chooser does not publish a report. Reports can be exported even when an audit finds failures or offline sources, so the diagnostic record is available without attempting to repair the case.

## Supported checks and bounds

The audit validates the manifest against the currently opened case and checks the known filesystem cache, case-work analysis/finding/extraction sidecars, multi-evidence comparison records, UDF generations and pointers, recovery generations and recovery assessment revisions. It checks the recorded case/evidence identifiers and selected-file hash scope, verifies UDF result checksums and immutable finding/recovery assessment revision chains, validates anchored comparison parent records and follow-up references, and compares stored recovery payload size and SHA-256 with their receipts. These checks do not send any AI requests.

The known derived content-index schema is checked for locator/text digests and source bindings. A valid index that no longer matches the complete current evidence set is explicitly unavailable as `derived.index.stale`; it must be rebuilt before its search coverage is treated as current. A valid index pass does not establish that current source artifacts have been freshly decoded. Unknown stores, unsupported schemas and unavailable current comparisons remain preserved and disclosed rather than silently counted as verified.

All case traversal uses held descriptors with no-follow opens. Symbolic links, hard-linked records and nonregular items are refused rather than followed. Cancellation unwinds the audit and throws `CancellationError`; the case and source remain untouched.

Default aggregate budgets are 10,000 case entries, 256 MiB metadata, 2 GiB stored recovery payloads, 32 GiB selected source files, and 120 seconds. The metadata-byte budget counts actual reads, including the initial manifest read and the final repeat used to detect a manifest change during the run. Existing store-specific record bounds also apply. Reaching a bound produces partial coverage, rather than claiming that remaining items passed. These limits make the audit practical for the declared local workflow; large cases may require narrower supported workflows or a later streaming audit design.

## Core API

```swift
let historical = try await CaseIntegrityAuditor.audit(forensicCase: openedCase)

let fresh = try await CaseIntegrityAuditor.audit(
    forensicCase: openedCase,
    options: CaseIntegrityAuditOptions(freshEvidenceRehash: true)
)

// Default exports omit absolute host case/source paths.
let json = try CaseIntegrityReportRenderer.json(fresh)
let markdown = try CaseIntegrityReportRenderer.markdown(fresh)

// Explicit opt-in for a private local examiner report.
let privateJSON = try CaseIntegrityReportRenderer.json(
    fresh, includePrivatePaths: true
)
```

The renderers return report bytes. They do not publish, upload or write back into the case. Save reports to a chosen destination outside the case and evidence. Default exports retain supported relative store paths, UUIDs and hashes needed to inspect the checks, while omitting absolute host paths. A report can still contain case/evidence identifiers and hashes, so the examiner should review it before sharing.

## Interpretation limits

The manifest, result files and sidecars are unsigned local records. Hash comparisons detect inconsistency with those records; they cannot authenticate an examiner or establish that a malicious party did not rewrite both data and its expected hash. The audit also does not prove that a recovered candidate is an intact former original file, has its original name, was deleted, or can be decoded. Those require their own source mapping, metadata, decoder and examiner checks.

The audit does not re-enumerate a filesystem or compare historical cached browser/download metadata with newly parsed current artifact contents. Those semantic comparisons remain unavailable in this audit. A metadata pass establishes schema and receipt consistency, while a fresh source pass establishes the selected container's size and SHA-256; each has its own scope.

The report describes a bounded run at its recorded time. An earlier successful audit does not establish that source or case bytes remain unchanged after the run, and an offline historical receipt is not a fresh source verification.

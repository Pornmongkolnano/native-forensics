# Timeline and reports

The initial timeline covers **one selected evidence filesystem snapshot** and optionally **one explicitly selected allocated Chromium `History` database**. It is a bounded parser workflow; it does not establish full browser-profile coverage or replace examiner judgment. It never asks AI to create deterministic events.

## Native workflow

1. Open a case, select evidence and load its recorded filesystem listing.
2. Open **Timeline** and choose **Build Filesystem**. Each non-missing created/modified/accessed/metadata-changed epoch becomes an observation. Directory timestamps are included. A deleted entry is labelled deleted; no deletion time is invented.
3. To add Chromium artifacts, select an allocated `History` in the timeline picker and choose **Verify & Import**. A complete filesystem listing is required. The engine freshly verifies every ordered evidence container and extracts the exact database plus every recorded matching `-wal`/`-shm` sibling into owned private scratch. A final source verification runs after parsing.
4. Search observations, filter normalized date instants, or control unresolved local times separately. The table shows 100 rows per page. **Open Source** resolves a recorded file only against its original case/evidence/snapshot binding; reopening a changed listing is a separate examination.
5. Add examiner notes and choose **Export Reports…**. A new directory contains `timeline.json`, `timeline.md` and `receipt.json`. The report exports the **complete timeline**, regardless of UI search/date filters. Evidence/case destinations, existing directories and symlink destinations are rejected. The immutable snapshot binding, ordered selected-file-byte hashes, parser and artifact receipts are separate from notes and any explicitly supplied AI interpretation. Native export currently includes no automatic AI interpretation.

## Timestamp policy

Filesystem engine protocol v1 exposes normalized epoch seconds and nanosecond fields. Its original civil timestamp spelling, per-field timezone offset and native resolution are unavailable. Reports preserve the engine values and selected evidence timezone while stating that limitation; a nonzero nanosecond value does not by itself establish original precision. Building filesystem metadata events does not rehash the source or refresh metadata. Historical and partial listings remain explicitly marked.

Standalone RFC3339 parsing requires an explicit numeric offset or `Z`, valid Gregorian calendar fields and at most nine fractional digits. `-00:00` means unknown offset and remains unresolved. Leap seconds are unsupported. Classic syslog parsing requires an explicitly selected year and IANA timezone. A DST gap has no normalized epoch. A DST overlap preserves both candidate epochs without choosing one. No host timezone or current year is inserted silently. This policy module is tested independently; a general syslog-file importer is outside the initial GUI coverage.

Chromium times are exact microseconds since 1601-01-01 UTC, preserved as their integer raw values and normalized deterministically to seconds/nanoseconds. Unknown/zero or out-of-range values must remain unresolved or be rejected as declared by the parser, never assigned the current time. Visit records are observations from `visits` joined to `urls`; downloads provide start/end records with recorded URL/path/state/byte counts. A browser record does not prove that a particular person performed an action or that a download completed successfully.

## SQLite / WAL safety

SQLite opens only a newly created private derived database, never the evidence image or extracted originals. Input files are independently size/SHA-256 verified through owned read-only descriptors before and after processing. Known sidecars must be explicitly supplied with exact evidence-path names. Unsupported/ambiguous/missing sidecar states fail closed rather than silently opening a potentially older main database. Zero-length/truncated WALs and stale/reset tails are rejected in this initial scope; they are not guessed as a coherent empty journal.

The WAL reader follows the persistent format in [SQLite database/WAL file format](https://sqlite.org/fileformat.html) and transient-cache assumptions in [SQLite WAL-index format](https://sqlite.org/walformat.html). It validates its header, version, page size, salts and chained frame checksums before applying frames only through the last complete transaction commit. A valid uncommitted tail is excluded. The reconstructed database receives read-only SQLite integrity/schema checks. SHM is receipt-bound when supplied; it is not authoritative transaction data and is not used to choose a committed WAL state. Reconstruction does not repair the original or checkpoint it in place.

Limits: database 64 MiB; each WAL/SHM 16 MiB; reconstructed database 64 MiB; initial browser event cap 20,000; filesystem event cap 200,000; parser elapsed budget 10 seconds; JSON and Markdown output each at most 64 MiB with conservative preflight estimates; examiner notes/AI text each 32 KiB. Over-limit input fails visibly; no silently truncated complete report is published. Scope includes known Chromium schemas exercised by independent fixtures, not every historical/future Chromium schema, WAL corruption recovery, SQLite free-page/deleted record carving, Firefox/Safari databases, network fetching, APFS/FileVault or a case-wide artifact index.

## Validation scope

Synthetic regressions cover exact filesystem epochs/nanoseconds, missing timestamps, source/hash binding, partial/historical warnings, date/search filtering, RFC3339 offsets/fractions, syslog explicit assumptions and DST gaps/overlaps; exclusive report publication and unchanged prior outputs; main-database schemas, receipt mismatch, coherent committed WAL, valid uncommitted WAL tails and malformed/inconsistent WALs; native stale completions, bounded filtering and owned shutdown drains. Actual passed counts and GUI outcomes belong in release validation after the root build/test run. Code presence is not evidence of a clean-machine distribution or full Autopsy parity.

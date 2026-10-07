# Synthetic milestone workflow

`MilestoneWorkflowProbe` exercises actual Core services, the pinned filesystem
helper and the isolated document decoder. It creates a new synthetic case and
new exports below ignored `local/`; it never opens coursework evidence or starts
Codex, a model provider, or a network request.

## Reproduce

Run from the repository root with the native engine already built:

```sh
python3 script/milestone_fixture_oracle.py --generate local/milestone-synthetic-fixture
swift build --product MilestoneWorkflowProbe
swift build --product NFDocumentDecoder
mkdir -p local/native-development
.build/debug/MilestoneWorkflowProbe \
  --image "$PWD/local/milestone-synthetic-fixture/milestone-fat16.raw" \
  --engine "$PWD/.engine/bin/NFTSKEngine" \
  --decoder "$PWD/.build/debug/NFDocumentDecoder" \
  --output "$PWD/local/native-development/milestone-workflow-1"
python3 script/milestone_fixture_oracle.py \
  --verify local/native-development/milestone-workflow-1 \
  --fixture local/milestone-synthetic-fixture
```

Fixture and output destinations must be new. Choose another numbered directory
for a rerun. Do not replace an existing case or regenerate a source fixture in
place. Swift builds are serialized with the repository's other validation.

## Independent expected observations

The Python standard-library producer manually writes an 8 MiB FAT16 filesystem,
with two known UTF-8 files and a Chromium SQLite database plus committed WAL.
SQLite's Python library creates these artifact bytes independently of the
production Swift/C parser. The browser database contains visit `101`; its WAL
adds visit `102`. Download `301` supplies independent start/end observations.

- `/ALPHA.TXT`: 167 exact UTF-8 bytes; SHA-256
  `47eb0ed6228769722ea56de7bbd1774b34097763c7789947f82f971a8d6452a3`.
- `/BETA.TXT`: 118 exact UTF-8 bytes; SHA-256
  `7c015d30fdd06a6df7b3676cd5200012fb084bc096b94f7c5bc0017de033a038`.
- Both FAT text files record UTC creation `1704164646`, modification
  `1704251048`, and access `1704326400`, using distinct manually encoded civil
  fields. These epochs do not come from the application parser.
- Chromium browser/download events record epoch seconds `1700000000` through
  `1700000003`, with microseconds `123456`, `123456`, `987654`, and `123456`.
- `needleOnlyInPayload` appears only in Alpha's body at UTF-16 offset 18,
  length 19. `shared marker` appears in both bodies. Thai `เอกสาร` and the
  single combining mark `้` prove literal substring coverage without tokenization.
- The synthetic secret is excluded from reviewed request bytes; valid Alpha
  and Beta citations resolve to `Alpha` and `Beta`, while a fabricated citation
  remains unresolved.

The independent Python verifier compares exported payload bytes with the
producer's originals, reconstructs expected search offsets using Python's
literal string search and UTF-16 encoding, checks exact browser event constants,
checks FAT timeline events and report-file hashes, and checks source immutability.

## Workflow and receipt boundaries

The probe inspects the source, creates a case, enumerates it, saves and reopens
the listing, extracts every declared logical payload, builds/saves/reopens a
case-wide derived content index, searches and resolves its immutable references,
prepares and redacts two verified files, reviews exact prompt bytes, persists a
**locally constructed fake answer**, validates citations, parses browser/WAL
events, exports combined filesystem/browser reports, and runs both historical
metadata and fresh source integrity audits.

The synthetic answer uses the production result/record shape solely to validate
persistence. Its question, summary and limitation explicitly identify it as fake;
`workflow-receipt.json` records `providerExecuted: false`. This is not evidence of
Codex submission, returned provider output, model accuracy, or provider isolation
during a real request.

The content index is partial because the browser database and FAT virtual files
are not UTF-8 document content. Successful searches cover the two indexed text
files; they do not claim that every byte of the image was searched. Reopening a
derived index or analysis record does not refresh source bytes. Fresh integrity
auditing separately verifies the selected image bytes against the recorded hash.

## Benchmark interpretation

The receipt records stage durations and 1,000 warm content-search samples for
both the derived search service and a direct literal scan of the two known texts.
It reports nearest-rank p50/p95 plus minimum/maximum and validates results against
the independent oracle. The direct scan is a correctness control and a narrowly
scoped timing baseline. These tiny-fixture timings do not compare Autopsy,
startup, ingestion, memory, filesystem enumeration, or complete app performance.

Generated cases, machine paths and local receipts remain ignored. A sanitized
validation summary may be added after an actual successful run; commands alone
do not establish completion.

## Observed development validation

The actual Core probe and independent Python oracle both passed on 8 October
2026, macOS 27.0.1/ARM64/Swift 6.4. See the sanitized
[validation receipt](validation/2026-10-08-milestone-workflow.json).

The native helper enumerated nine entries. The document pipeline indexed the
two text bodies, explicitly skipped five unsupported binary/virtual files, and
reported zero failures; coverage remains partial. Both the derived index and
fake two-file analysis record reopened exactly. Redaction, two valid citations
and one fabricated unresolved citation matched their independent expectations.

The browser parser produced four exact committed database/WAL observations.
Its natural traversal order groups visits before downloads; the probe compares
the same complete event set in chronological order, matching the UI's explicit
sort. It retains the raw and canonical projections in the ignored comparison
receipt. The combined report contained 19 events, with matching JSON/Markdown
hashes and no host source paths.

Historical and fresh integrity audits both completed without failures or partial
coverage. Fresh mode verified one selected-file source. Source bytes and the
case manifest were unchanged. The first probe attempt stopped at an incorrect
parser-order expectation; its output was preserved. A separate new output passed
after correcting only the comparison order, with no reduced event assertions.

The measured full synthetic workflow took 1.604 seconds. Warm derived search
p50/p95 were 8.208/8.792 microseconds; the direct two-text literal control measured
3.708/4.000 microseconds. These single-run development values are descriptive,
and the derived result includes reference/snippet construction. They are not a
speedup claim or an Autopsy comparison. No AI provider was executed.

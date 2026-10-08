# Large, mixed and cache-regime workloads

`NativeWorkloadProbe` and `script/native_workload_benchmark.py` measure a headless
ForensicsCore workflow with an independent Python byte/search oracle. They do not
measure SwiftUI frame rate, physical M5 performance, thermal state or battery use.
No provider process or network request is part of the workload.

## Immutable synthetic inputs and exact outputs

The generator creates an exclusive directory below ignored `local/`. Its default
RAW FAT32 source is a **512 MiB sparse file**, with known boot/FAT/directory bytes
and separately specified file payloads. Sparse allocation reduces fixture disk
use; hashing still processes every logical source byte, including zero holes.
The 1 MiB metadata-only source deliberately has no filesystem listing. Neither
fixture is a user case, and the harness never repairs or rewrites a source.

The mixed corpus contains small English text, Thai text without spaces and a
combining mark, a text payload of exactly **32 MiB**, one of **32 MiB + 1 byte**,
unsupported binary content and an empty file. The exact-cap text is extracted
and decoded, with the decoder's bounded 1 MiB text prefix explicitly incomplete.
The over-cap document is marked `FILE_BYTE_LIMIT` in the index; it remains an
exactly verified extraction/export workload. Unsupported and empty bodies remain
explicitly outside searched content. The metadata-only source contributes a
missing-listing coverage receipt rather than fabricated files.
The real TSK listing also includes `$MBR`, `$FAT1` and `$FAT2` metadata streams.
Their exact disk ranges and bytes are included in the independent oracle and
export checks; binary metadata remains unsupported for content search. The
`$OrphanFiles` virtual directory is counted as a skipped directory.

Each successful workflow must satisfy all of these gates before its timings are
included in a distribution:

1. Both source sizes and SHA-256 digests match the independent generator oracle
   before and after the workflow.
2. The real engine enumeration has the exact regular-file paths/sizes, and its
   listing survives save/reopen without changing rows or source hash scope.
3. Individual extraction and transactional batch export match the independently
   generated payload bytes, full SHA-256 and size for every file.
4. Isolated decoder output and index statuses, reasons, exact derived text,
   completeness flags and content digests match the oracle. The 32 MiB file is
   partial derived coverage, not a complete search of its body.
5. Every literal search hit has the exact file path, UTF-16 offset/length and
   source/content digest. Thai and one-character combining-mark queries are
   compared with Python's independent literal matching. A content-only term
   does not become a filename-search hit.
6. The derived index reopens with the same generation/documents/source bindings.
   The case manifest remains byte-identical while derived records are written.

Verification uses bounded streaming blocks. No whole-image `read_bytes()` is
needed to build an expected hash or compare an export.

## Reproduction

Build serialization is the caller's responsibility. Build the release executable
once before starting measurements; do not run SwiftPM or other performance jobs
concurrently with the timed workload.

```sh
swift build -c release --product NativeWorkloadProbe
python3 script/native_workload_benchmark.py --generate local/large-workload-fixture
python3 script/native_workload_benchmark.py --run local/large-workload-runs \
  --fixture local/large-workload-fixture \
  --probe .build/release/NativeWorkloadProbe \
  --engine .engine/bin/NFTSKEngine \
  --decoder dist/NativeForensics.app/Contents/Helpers/NFDocumentDecoder
```

The workload receipt separates source verification, engine enumeration,
case/listing persistence/reopen, verified extraction, isolated decoding,
production content-index construction, index persistence/reopen, search,
transactional export and final verification. Standalone extraction/decode work
is intentionally separate from the later production index rebuild, which repeats
those operations. `totalWorkflow` includes both enabled stages and their checks.

Five measured fresh processes per requested cache regime permit p50/p95 and
range reporting. Warmup is kept out of the samples. Failed/partial-execution
attempts remain in raw receipts and are never counted as successful throughput.
Partial content coverage is an expected successful result for this mixed corpus,
and all runs must produce the same partial coverage.

## Cache interpretation

Warm preparation reads the entire source and verifies its oracle hash before
launch. A fresh process is not a cold filesystem cache. On macOS, `F_NOCACHE`
applies only to the descriptor on which it is set; closing that descriptor does
not prove cache eviction or control later opens by the Swift process. The harness
records cold-requested runs as **OS-cache-uncertain** and never claims a verified
cold-cache measurement. It does not purge global caches, request privileges or
change system settings. Initial source verification itself reads and warms the
source before downstream extraction/index stages.

Consequently these regimes characterize fresh-process and warm-prepared
behavior under the observed host state. They cannot establish physical cold
storage latency or a cold/warm speedup.

## Memory and cancellation boundaries

The Python driver samples the exact owned probe and its helper descendants and
records requested/actual sample intervals. App/probe RSS, helper RSS and aggregate
owned RSS are distinct values. Samples are not atomic and may miss short-lived
peaks. The exact-PID Darwin `wait4` resource receipt includes the terminated probe
and its accounted children. Its kernel maximum RSS is neither probe-only memory
nor simultaneous summed tree RSS and is reported separately from sampled
app/helper values. The installed SDK's `wait.2` resource paragraph establishes
this scope.
Python harness memory is outside the app/probe measurement.

Cancellation mode starts real production index work, requests cancellation after
the first per-file operation has started, awaits task drainage, and compares
temporary `.native-document-*` names before/after. It must return cancellation,
leave no newly created document scratch behind and preserve both source hashes.
With the 25 ms request delay and this large source, cancellation commonly lands
in the first preview's source-verification pass. This does not assert that a
decoder/helper was active at the cancellation instant. It measures headless
task drainage and owned scratch cleanup rather than GUI event latency; active
helper/decoder cancellation requires its own lifecycle receipt.

## Listing-scale control

The production baseline uses exactly **50,000 synthetic rows** through
`FilesystemSearchIndex`. Separate derived harness modes use 100,000 and 1,000,000
rows, with the same row recipe, literal query, independent expected row order and
metadata comparison. The returned IDs have a stable SHA-256 digest. Larger rows
are never persisted as engine listings, admitted to content indexes, shown in the
GUI or used to raise an advertised capability.

Each larger mode also instantiates the real production search index and verifies
that its count stays 50,000 with 6,250 expected Thai matches. This preserves the
production cap while measuring the cost of a potential future array scan.

## Aggregate history workload

`CaseHistoryWorkloadProbe` creates a separate owned synthetic case with 120
full-retention records, each containing a known 600 KiB `H` request. Generation
runs once outside the measured processes. Five fresh scan processes then page
the same records as 50 + 50 + 20 deterministic UUIDs, newest first, and load each
record to verify its exact request/summary and digest. No provider is executed.

```sh
swift build -c release --product CaseHistoryWorkloadProbe
python3 script/native_workload_benchmark.py --run local/history-workload-runs \
  --mode history --probe .build/release/CaseHistoryWorkloadProbe \
  --records 120 --prompt-bytes 614400 --repetitions 5
```

The Python oracle reads at most one bounded 1 MiB JSON record at a time, compares
the literal request and expected record IDs/page order, and verifies every
record's size/hash/identity plus the unchanged source, manifest and fixture
receipt before/after each scan. Independent preflight reads warm the fixture, so
these are labelled `warm-preverified` fresh processes. Source/case reads remain
separate from the exclusive driver logs. RSS covers history paging and the later
per-record verification together; it does not isolate paging-only peak RSS.

## Repeated whole-image verification

At baseline revision `f84db869b3c4138bc3a98849069db97354a9f37c`, the production
index rehashes the ordered source set at the start/end of the build and before
extraction/after decoding for every preview attempt. If `S` is the source set
size and `N` is the number of completed preview calls, source hashing processes
approximately `(2N + 2) * S` logical container bytes. Unsupported/no-text previews
pay this cost; files rejected by a byte budget before preview do not. Initial
case inspection/enumeration, helper filesystem reads, output verification and
decoder fingerprints add work outside this formula.

The receipt's `legacyIndexSourceHashReadBytesStatic` is static source accounting,
**not a measured physical disk-read counter** and not a statement about any later
optimized implementation. For this mixed ten-stream corpus, nine preview attempts
over 512 MiB mean 10 GiB of source bytes processed by these baseline hash checks,
plus two metadata-source passes. The 512-file/256 MiB extracted-input limits do
not independently bound this container reread volume. Transactional export has
the same successful-file `(2N + 2) * S` baseline pattern.

An evidence-preserving optimization must retain independently verified extraction
bytes and decoder inputs, helper fingerprints, cancellation drainage and final
source verification. A scoped private verified source snapshot can let helpers
read an owned immutable copy throughout one operation, with full source hashes
and initial identities checked again before publication. A pinned descriptor
alone does not make a mutable original immutable. Persistent inode/mtime caches
or a public skip-verification option would not preserve the current guarantee.
Any implementation needs equal-output baseline/candidate measurements and
source-mutation/publication tests before reporting a speed gain.

## Results

### 8 October 2026: frozen development baseline

Actual runs used **Apple M2 / arm64, 16 GiB RAM, macOS 27.0.1 build 26A434, AC
power**, Apple Swift 6.4 release optimization. They used an archived
`f84db869b3c4138bc3a98849069db97354a9f37c` Core plus the new probe, with the 0.6.0
engine/decoder binaries frozen separately. These are baseline measurements of
the development Seatbelt helper path, not measurements of the new bundled XPC
backend or the native GUI. A full 512 MiB pilot passed before timed runs and is
excluded from the distributions.

There are five valid fresh processes per mixed cache regime. Two paired blocks
(four attempts) with observed compiler activity were retained as diagnostics and
replaced as entire pairs, regardless of their timing values. The final window's
0.5-second process observer captured compiler ancestry/arguments and saw no
compiler processes. The final mixed summary combines eight unaffected original
attempts with the last two replacements. Ordinary host activity remains; this
observer is not a guarantee that every unrelated process was idle.

| Mixed process scope | p50, s | p95, s | Sampled probe RSS p50/p95, MiB | Sampled helper RSS p50/p95, MiB | Sampled aggregate RSS p50/p95, MiB |
|---|---:|---:|---:|---:|---:|
| Warm, source prehashed | 18.117 | 18.986 | 22.42 / 23.55 | 73.14 / 73.14 | 89.80 / 91.08 |
| Cold requested, OS cache uncertain | 17.857 | 19.226 | 23.22 / 25.56 | 73.14 / 73.92 | 89.02 / 89.81 |

`p95` uses nearest rank; with five process samples it is the maximum. The cache
uncertainty prevents a cold/warm storage comparison or speedup inference.

| Enabled stage | Warm p50/p95, s | Cold-requested p50/p95, s |
|---|---:|---:|
| Initial full-source verification | 0.251 / 0.255 | 0.245 / 0.247 |
| Engine enumeration, including its prehash | 0.426 / 0.439 | 0.423 / 0.427 |
| Case/listing persistence and reopen | 0.0038 / 0.0043 | 0.0035 / 0.0037 |
| Individual extraction and independent verification | 3.189 / 3.506 | 3.156 / 3.174 |
| Isolated decoder work | 1.012 / 1.249 | 0.990 / 1.002 |
| Production content-index build | 6.566 / 6.887 | 6.582 / 7.340 |
| Index persistence and reopen | 0.0126 / 0.0127 | 0.0131 / 0.0133 |
| Five literal content queries and reference checks | 0.0125 / 0.0131 | 0.0125 / 0.0143 |
| Transactional batch export | 6.346 / 6.550 | 6.175 / 6.662 |
| Final full-source verification | 0.246 / 0.406 | 0.245 / 0.344 |

Every valid run verified 20 exact exported byte sequences (ten individual and
ten batch), nine standalone decoder receipts, ten index documents, five exact
UTF-16 search query outputs, one missing-listing source, source digests and
byte-identical manifests. The aggregate extracted payload is 75,498,263 bytes;
the index retains 1,048,845 derived-text bytes and serializes to 1,057,019 bytes.
All declared caps remain unchanged. The measured stage costs and static
10 GiB index source-hash accounting support investigating operation-scoped source
verification; no optimization or speed gain was implemented by this harness.

The listing table uses a separate final window, five fresh processes per size,
with one excluded warmup and five measured scans inside each process. Query
percentiles therefore use 25 correlated scans, while process/RSS percentiles use
five processes. Whole-process time includes generation, warmup, five scans and
independent row/order/metadata/digest checks.

| Rows and scope | Whole-process p50/p95, s | One query p50/p95, ms | Sampled probe RSS p50/p95, MiB |
|---|---:|---:|---:|
| 50,000, production search API | 0.790 / 0.946 | 107.61 / 115.17 | 24.94 / 25.98 |
| 100,000, derived harness only | 1.465 / 1.499 | 215.45 / 221.96 | 51.52 / 51.78 |
| 1,000,000, derived harness only | 13.931 / 14.073 | 2,205.10 / 2,342.55 | 351.19 / 351.95 |

Every larger probe also verified the production index still retains exactly
50,000 entries and returns the expected 6,250 Thai matches, with the last ID
`row-49992`. These results do not authorize a larger listing or GUI cap.

Ten cancellation trials passed with source hashes unchanged and no newly
created document scratch remaining. Drain latency p50/p95 was **0.836/1.004 ms**,
range 0.710–1.004 ms, in the documented first-preview source-verification scope.
It does not establish active-decoder cancellation or event-to-frame latency.

RSS requested sampling was 10 ms; actual timestamps, intervals, all descendant
observations and read overhead are in the raw receipts. Sequential sampling can
miss peaks. The Python observer/sampler are outside probe RSS. The historical
raw `wait4.scope` wording was clarified after measurement; the measured code was
preserved and the corrected interpretation includes accounted children.

Reproduction/evidence files remain below ignored `local/`:

- Fixture: `large-workload-fixture-20261008-v2/oracle.json`.
- Final mixed/row summaries: `large-workload-final-window-20261008/` with
  `workflow-summary-final.json`, `listing-{50000,100000,1000000}-summary.json`,
  `compile-observer.json`, per-attempt raw receipts and exact measured recipe
  copies. `measured-recipe-preservation.json` confirms the probe source matches
  the compiled frozen archive.
- Cancellation: `large-workload-baseline-cancel-50000-20261008/benchmark-summary.json`.
- Earlier diagnostic attempts: `large-workload-baseline-measured-20261008-v2/`,
  `large-workload-baseline-replacement-pair-20261008/` and the first listing
  directories. None were silently overwritten or used as clean final samples.

Pinned SHA-256 identities:

```text
source RAW: 617dc6d032b61b208db0eaed389470314db29f9ae390696a539c91a5c20225c2
metadata:   69d6f60028385975af42b90db215ee5a58a85b2ea6f4a80a00fa4a81fb716b15
probe:      eed8f829702118931c2d3e0786a9e3239cde75e2dc2342642324fa15d77cba65
engine:     e030b8caf557ff4e2a8295232b88b9e2eb50b343aa54dc0279d117073053844d
decoder:    4c8c41913c552ecda5bb0abdbe16f43cbed03916536d364000d119ece2d39feb
Swift recipe: 4a409bacdf53d8a914194c6bf2fd497898afdf88267f1f91bc56e2cdfc95371c
measured Python recipe: 0f9a3d44262d5f02cd8a15ea2304b1c40a0e4d5ad05a3d133d14a88ec19b25a3
```

No M5, battery, thermal, GUI or verified-cold claim follows from this headless
host experiment. Those gates remain open, as does measurement of the supported
bundled XPC backend and a later equal-output optimization candidate. This corpus
exercises the 32 MiB per-document boundary; it does not fill the 512-file,
256 MiB extracted-input or 16 MiB derived-text aggregate budgets. Worst-case
aggregate-cap memory and scheduling policy therefore remain separate gates.

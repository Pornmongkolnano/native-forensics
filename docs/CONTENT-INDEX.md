# Case-wide derived content index

Content Search rebuilds local decoded text across the case's recorded filesystem listings, including saved listings for sources which have not been selected in the current window. Typing a query searches document bodies, not names, paths or extensions. Rebuild is explicit: it recovers files using the existing verified-content/isolated-document pipeline, hashes every ordered source before and after the build, and atomically replaces one rebuildable `derived-content-index.json` inside the case. Manifest, listings, examiner notes and evidence remain separate.

The workspace shows indexed, skipped, failed and pending file counts, missing/uncovered source listings, partial coverage, historical reopen and stale binding states. Select a search hit to inspect a bounded excerpt of the saved decoder reference; Open File invokes the native recorded-file navigation callback. Opening a recorded file does not itself verify that its current bytes still match the hit. A new verified preview/extraction is a separate operation.

## Provenance and freshness

Each file has its exact evidence/file locator and a canonical locator digest. Each source has its selected container-file size/hash, ordered container hashes and a listing digest over the recorded engine/options/volume/entry snapshot. The live result and the same ISO-8601 cache reopened at whole-second precision produce the same digest. Host image paths, temporary output paths, decoder stderr and credentials are excluded from the index.

An indexed file stores the independently checked extracted-file SHA-256 and a canonical SHA-256 over its ordered derived pages, reference labels/kinds and truncation flags. A hit carries the index generation, listing/locator/source/content/derived hashes, exact decoder binary SHA-256, page/body reference and UTF-16 offset/length in that decoder output. PDF page positions are derived text positions; they are not ranges in the original PDF/image bytes. Resolving a hit requires the same immutable generation and all of those reference bindings.

Reopening the index reads bounded derived data only. It **never** opens evidence or labels saved text as freshly verified. The UI marks it Historical and compares its recorded source/listing bindings with currently available recordings; a changed binding marks it Stale. Identical recorded bindings still do not certify that offline or edited source bytes match. Rebuild verifies bytes, while timestamps and other listing metadata retain their historical provenance.

An extraction/decoder failure is a failed file, an unsupported format or document/image with no decoded text is skipped, and a file outside an aggregate input/text budget is pending. A changed source or mismatched verified-content receipt rejects the whole new generation. Canceled, timed out or failed builds before publication preserve the previous published generation. Compare-and-save rejects a competing newer generation. The writer holds no-follow case/lock/staging descriptors, validates their identities and publishes by atomic rename; replacement paths and symlinks do not redirect writes. A save committed immediately before cancellation retains its completed receipt for the same case scope. A failure after atomic commit reports publication uncertainty and requires Reload Index to inspect the generation actually on disk; it does not promise that the previous index survived.

## Advertised budgets and limits

| Resource | Limit |
|---|---:|
| Case evidence source records | 128 |
| Aggregate retained filesystem listings | 50,000 entries and 64 MiB serialized |
| Regular files attempted per rebuild | First 512, in case/listing order |
| Recovered bytes per file | 32 MiB |
| Aggregate recovered input attempted | 256 MiB |
| Derived text per document | Existing decoder limit: 1 MiB, at most 200 references |
| Aggregate persisted derived text | 16 MiB |
| Serialized index read/write | 32 MiB |
| Rebuild deadline | 600 seconds; cancels and drains owned work |
| Query | 4,096 UTF-8 bytes |
| Returned hits | 200; an additional match sets the explicit limit flag |
| Search snippet / reference sheet | About 160 UTF-16 units / at most 4,098 UTF-16 units, with scalar-safe boundaries |

These are application budgets, not an Instruments measurement or a hard process RSS limit. A saved listing is decoded one source at a time; a conservative size preflight precedes encoding, and listings beyond the retained aggregate budget become uncovered sources. The number of files beyond the first 512 remains visible as omitted/pending. Collection counts/text budgets are checked while decoding a stored generation, before accepting more records. Coverage counts must reconcile with the retained listings. Corrupt/unknown-schema, oversized or mismatched derived data is preserved and rejected rather than silently truncated or repaired.

Supported text comes from the existing document decoder's declared profiles: plain text and supported PDF text layers, modern Office bodies and bounded supported archive text. No OCR, scanned-PDF interpretation, legacy Office body guarantee, remote resources, AI query, carving/UDF-history indexing or live browser interpretation is implied. A complete index means complete decoded text within its recorded listing scope, not that unallocated, unlisted, encrypted or undecoded evidence cannot contain the term. Partial coverage and “no matches” must never be reported as an absence proof.

## Substring versus FTS5 experiment

The local synthetic experiment compared Python literal substring with SQLite 3.54.0 FTS5 trigram MATCH. It is a choice-of-search-semantics experiment, **not** a NativeForensics/Autopsy, Foundation, GUI or full recovery-pipeline benchmark. A 512-file corpus contained 16,827,552 UTF-8 text bytes, Thai with no spaces, decomposed accents and body-only terms. Each query had 21 warm samples.

| Query | Literal file hits | Trigram file hits | Literal p50/p95 ms | Trigram p50/p95 ms |
|---|---:|---:|---:|---:|
| `ภ` | 512 | 0 | 0.029 / 0.035 | 0.007 / 0.024 |
| `ภา` | 512 | 0 | 0.029 / 0.034 | 0.006 / 0.007 |
| `ภาษา` | 512 | 512 | 0.029 / 0.029 | 0.128 / 0.149 |
| `needle` | 32 | 32 | 11.456 / 11.770 | 0.046 / 0.068 |
| `missing-token` | 0 | 0 | 8.661 / 8.951 | 0.014 / 0.024 |

FTS5 built in 358.9 ms; its SQLite file was 36,425,728 bytes. The queried trigram index gave no hits for the one/two-character Thai terms, while literal substring found the independent expected 512 files. The bounded implementation therefore uses Foundation literal substring uniformly, preserves decoded text without normalization, and tests composed/decomposed accents separately. Case sensitivity is an explicit control. Token/regex/phrase syntax is not accepted: the entire query is a literal substring. Trigram acceleration can be reconsidered only with a verified literal fallback and unchanged references/coverage.

## Validation entry points

The feature-specific tests are `CaseContentIndexTests` in Core and `ContentIndexWorkspaceTests` in the native target. Their independent expected results cover multiple evidence IDs with identical inode IDs, body-only hits, Thai/short/combining queries, exact pages/offsets/hashes, budgets and partial states, real source mutation, cancellation/deadline drain, offline round-trip, stale competing saves, staged failure/root replacement, symlink/corrupt/oversized destinations, digest tampering, all-case saved-listing loading, stale generations, historical labels and superseded query/selection/close races.

Run through the repository's normal debug/release and real-helper validation gates. Synthetic injected tests verify contract/race behavior; an actual helper/decoder case workflow and GUI checks remain separate evidence stages. This document does not convert an unexecuted or failed gate into completion.

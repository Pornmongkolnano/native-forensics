# Signed content-index runtime receipt — 8 October 2026

Five fresh processes of the bundled **NativeForensics 0.7.1 / build 17** passed
the content-index semantic and physical worker-exit checks. The explicit
diagnostic runs the existing Core index API through the production
**App Sandbox XPC broker and worker**. This is a synthetic local acceptance
receipt; it does not establish general application or release readiness.

Each session runs rebuild, unchanged update, replacement-source update,
cancellation and recovery in that fixed order. Stage timers start **after the
initial source inspections and directory enumerations**. They include source
verification, extraction, decoding, and the diagnostic worker-observation ACK
overhead. The receipt therefore measures the content-index pipeline, without
measuring GUI interaction, workbench scheduling or full initial acquisition.
The fixture is preverified and caches are not flushed or verified cold. No
provider is executed.

## Workload and independent correctness checks

The owned fixture contains three **268,435,456-byte** FAT32 RAW containers:
stable A, original B and a separately generated replacement B. The read-only
audit streamed all **805,306,368 logical source bytes**, independently checked
30 complete payload byte sequences against the literal FAT32 recipes, and
recomputed source intervals, full file hashes and expected derived text. The
fixture's complete **14-entry namespace** matches the preflight and all five
before/after maps by named and held identity, mode, size, timestamps and file
SHA-256. It also remained unchanged across the later audit.

Each completed stage contains two sources and **20 documents**: eight indexed,
12 skipped, zero failed and zero pending. Each source listing includes its
directory entry, for 11 entries. The 32 MiB text payload produces a **1 MiB
derived prefix** and explicit partial coverage. This does not prove search over
its complete body. The existing limits remain 512 files, 32 MiB per file,
256 MiB aggregate extraction, 16 MiB aggregate derived text and 600 seconds.

Independent readback verified all **20 saved stage snapshots / 400 documents**
against the source recipes: paths, actual evidence IDs, full hashes, statuses,
reasons, text pages, completeness and provenance. The unchanged snapshot's
documents and sources equal the rebuild snapshot. Stable A's indexed documents
remain identical across unchanged, changed and recovery. The independently
checked decoder contract is `2.1.0`, backend `appSandboxXPC`, IPC version 2;
its bound worker/broker hashes, CodeDirectory identities and options digest
match every indexed document. The options retain a 12-second timeout, 1 MiB
text cap and no OCR, macro/formula execution or external resource fetch.

The audit independently recomputed **100 literal-query result sets**: five
queries across the 20 snapshots, including Thai and combining-mark matches.
Every UTF-16 match offset, length and source hash matches. The queries are
`largeNeedle`, `needleOnlyInPayload`, `notPresentInAnyPayload`, `เอกสาร` and `้`.
Replacement changes the original payload-marker query from two hits to the
one stable-A hit and changes the replacement Thai offsets as expected. There
is no separately executed replacement-only-marker query in this receipt.
Listing digest membership was checked, but the complete replacement listing
digest was not independently reconstructed because that listing is not saved.

| Completed stage | Reused documents | Rebuilt documents | Accepted decoder workers |
|---|---:|---:|---:|
| Rebuild | 0 | 18 | 18 |
| Unchanged update | 8 | 10 | 10 |
| Replacement-source update | 4 | 14 | 14 |
| Recovery | 4 | 14 | 14 |

Only indexed documents are reusable. Skipped metadata, unsupported and empty
items are attempted again; the two over-limit files are skipped before decoder
admission. The counters are actual Core results, rather than an assumption
that unchanged update avoids every read or worker.

## Publication, cancellation and physical exits

Replacement B is recorded through the normal `CaseStore` in a separate case,
with a **new actual evidence ID** and full source hash. Stable A keeps its
original ID and path binding. Changed and recovery are positive incremental
Core computations using those actual records. Publishing either result to the
original case manifest is deliberately refused with `sourceChanged`; the old
manifest still names original B. The durable index remains **byte-identical to
the unchanged-update generation**, and all four completed API snapshots have
distinct generation UUIDs within each session. A successful publication into
a newly recorded replacement case remains a separate acceptance requirement.

Cancellation is requested after the first authenticated accepted-worker event
has been pinned by the driver and acknowledged. The saved receipts confirm
task return, preservation of the prior durable generation and absence of index
scratch output. This proves ownership and drain at accepted, pre-decode
admission; document bytes need not have reached the parser when cancellation
is requested, so active parser interruption is not established.

The audit matched **625 NDJSON events** to the five saved attempts and checked
**285 distinct worker PID/birth identities**: 57 per session, including the
single cancellation worker. Every accepted worker has a matching exited event
and independently observed `NOTE_EXIT`, with its exact executable path, broker
parent birth and stage. Each host reached a retained natural exact-PID `wait4`
exit **0**, with no timeout, lifecycle failure or driver signal. Five separate
broker births were observed. Zero-byte current case locks were checked during
readback; fixture preservation does not imply that every mutable case output
or operational lock was unchanged throughout execution.

`NOTE_EXIT` timestamps are polling observation times, not kernel death times.
Buffered stdout alone does not establish that the physical exit preceded API
return or the next worker's creation. Keep those independent observations
separate from the code-backed lifecycle ordering. The request-to-return number
below is the Core task-return interval, rather than a timestamped kernel drain
duration.

## Observed distributions and memory qualification

Each distribution has **n = 5**. p50 is the median; p95 uses nearest rank and
therefore equals the maximum. Fixed order, shared warm fixture and per-worker
ACK overhead prevent a causal speedup claim from these paired stage times.

| Scope | p50 | p95 | Range |
|---|---:|---:|---:|
| Rebuild pipeline, seconds | 7.672537 | 7.699429 | 7.664446–7.699429 |
| Unchanged update pipeline, seconds | 4.337247 | 4.434071 | 4.327334–4.434071 |
| Replacement-source update pipeline, seconds | 6.009310 | 6.119060 | 5.938824–6.119060 |
| Recovery pipeline, seconds | 5.983098 | 6.101846 | 5.957605–6.101846 |
| Cancellation whole attempt, seconds | 0.522995 | 0.527118 | 0.521887–0.527118 |
| Cancellation request to Core return, milliseconds | 6.716042 | 6.826250 | 6.620375–6.826250 |
| Exact-host kernel `wait4` maximum RSS, MiB | 104.843750 | 105.781250 | 104.734375–105.781250 |

**Sampled RSS completeness did not pass.** Every session reports
`rssEvidenceComplete: false`, and the terminal summary contains no role or
sampled-family RSS percentile distributions. All 44 `pidpath` query failures
are retained: 13, 5, 9, 9 and 8 per session; 36 worker, four host and four broker
failures. They return zero with `ESRCH`. No owned-process query failure is
omitted. Since failures have no per-query timestamps, their consistency with
disappearing processes does not independently prove they occurred only after
exit.

The 4,680 sampling passes retain 4,676 valid host, 4,406 broker, 560 worker and
117 engine resident rows, zero failed resident reads and zero driver
observation errors. The saved peaks and sequential sampling-pass sums recompute
exactly. A pass labelled complete only means that all returned rows have valid
resident values; it does not prove that every owned process was collected. No
zero is substituted for an unavailable process read.

Kernel `wait4` usage covers the exact host and its accounted children. It is
reported separately and is **not an atomic app/broker/worker summed RSS peak**.
Launchd broker/worker memory is not thereby fully measured. Host memory also
contains the diagnostic's expected-text oracles, snapshots, setup and final
verification. Python sampling/auditing memory is outside the measured host.
This receipt accepts semantics and physical exit observations, while complete
app/helper aggregate memory acceptance remains open.

## Measured identities and retained failed attempt

All four measured executable byte hashes remain unchanged after execution.
The independent readback also checks their embedded CodeDirectory bytes and
the packaged application-source graph. That readback is separate from the
driver's retained SDK signature validation, rather than a new Security/Gatekeeper
enforcement run.

| Identity | SHA-256 |
|---|---|
| Main 0.7.1 / build 17 | `a3fea4ee264e85148a660f0fec42d3739672f6dc584cabaa0be97a68dfa63b74` |
| Production XPC broker | `3f6a47a43e5d40cd3fab992ef24d01674ddb16c02914c0e1dfa9069c096fade9` |
| Production decoder worker | `fa7d768634309e3f9ebca687a3308192ce11d25ddd67e30a91ff470c6abdec9c` |
| Filesystem engine 0.1.5 | `d200a9e1b764bf53781d1553a36a0c0168cabbe869db256c03408a49ddcb7a46` |
| Packaged E application-source graph | `7edede5c54bfc397f0ca3d123f2a48cd288944f9d2c02807c9db131f30aa1a4f` |
| Stable A / original B full RAW | `c912854501a8f588fde27f9226db392e3218de646596b58f76955a555da33596` |
| Replacement B full RAW | `a850954d7a30b1e04d8029c0215f3cbd46b704c00f5a61ab9f8eb06847171b8d` |
| Decoder options | `b3c2e4c7537017cab4b8431d33ee15c4745c03c54680b55736031c492f75b909` |
| Successful v2 terminal summary | `4ae6fdc2d96b91fbe3543481049ca6ff8b89e82f9197823cea9745c0ae50e896` |
| Independent read-only audit | `a65bc55dc0af5ac719a6a4ab44462f27a48feb0c692ceb73954a30b4ffa2dd8a` |

The first v1 driver attempt reached one natural diagnostic-host exit 0 and
completed its semantic stages, but its RSS audit detected an already running
GUI process from the same exact bundle path. The driver rejected the attempt
with **`Unrelated same-bundle host contaminated session RSS`** and terminal
exit **1**. Both host rows had entered that sampler. The failed raw receipt and
log remain retained, with no accepted n5 summary. After only the verified GUI
instance was stopped gracefully, the same code produced v2's five accepted
semantic/physical-exit sessions. No v1 timings enter the v2 distributions, and
this does not imply an implemented early same-bundle precondition.

This experiment makes no GUI, full acquisition, physical M5, verified cold-cache,
energy, Autopsy comparison, parser-interruption or universal performance-budget
claim. A future gate must independently cover positive replacement-case
publication and complete family RSS before asserting those outcomes.

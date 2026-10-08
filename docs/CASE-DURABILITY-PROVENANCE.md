# Explicit case migration, provenance and publication outcomes

Opening or creating a case still uses the historical manifest schema 1. Opening a
case never performs a migration. Existing immutable analysis, finding, extraction
and comparison sidecars retain their separate schema 1 and original bytes.

`CaseStore.migrateToSchema2(case)` is an explicit opt-in transaction. It acquires
the same case writer lock, checks the supplied manifest for staleness, writes the
exact previous manifest bytes to a private staging file, flushes and verifies
it, publishes `migrations/<migration UUID>.json` with an exclusive rename, flushes
its directories, then atomically replaces `manifest.json`. A failed partial write
does not expose truncated bytes under a recognized final backup filename. The backup's
byte count and SHA-256, migration procedure/version and time are recorded in the
schema 2 manifest. It does not open, copy, decode or modify evidence. The backup
is not a replacement hash baseline.

`CaseStore.rollbackSchema2Migration(case)` restores the exact original bytes,
including JSON formatting, only when the case's evidence list is unchanged and
no new job provenance would be discarded. Existing immutable work sidecars and
the historical backup remain available. Adding evidence or recording a job
preserves schema 2 and blocks a rollback that would lose that newer information.
An interrupted migration can leave an unused synchronized backup; it is retained
as historical data instead of being automatically deleted or treated as the
current migration. An inaccessible, altered, linked or missing declared backup
refuses schema 2 opening and rollback.

`CaseStore.recording(job:in:)` records a bounded immutable job UUID after an output
artifact has committed. Directory traversal walks every component without following user-created
symbolic links, and final validation checks the held directory identity again.
Apple's exact `/var` and `/tmp` system aliases remain supported.

The caller passes the real start/completion instants,
component version/build identity, optional observed executable SHA-256, terminal
status, warnings and actual options. `CaseJobProvenance.make` stores reconstructible
canonical JSON options alongside their digest. It preserves ordered selected-file
source hashes, selected-source ordinal and known byte counts. This supports a
selected EWF segment that is not the first ordered container segment. Unknown
executable identity or segment byte count remains `nil`; it is never guessed.
Job timestamps preserve the exact reference-date Double independently of the
older outer manifest's ISO8601 date encoding.

The convenience `CaseJobProvenance.enumeration` binds an existing validated
filesystem result. It replaces exact known source paths in all warning messages
with numbered selected-source labels, preserves every warning, and records full
engine options. A caller may additionally declare the output's case-relative
path and exact SHA-256. This receipt does not freshly rehash evidence or execute
those options. A job is a historical execution receipt, not permission to run it.
The integrity auditor verifies the schema 2 migration backup, provenance bounds
and scope. It verifies declared output hashes for artifacts it actually read in
its supported bounded store scope; unsupported or unvisited artifacts remain
explicitly unavailable.

Manifest size stays at 16 MiB. Job options are at most 65,536 bytes, ordered source
hashes at most 1,024, and a manifest at most 10,000 job UUIDs. Warning limits match
the engine's 1,024 warnings and 65,536 bytes per warning, with an 8 MiB aggregate
job warning bound. Exceeding any bound refuses a record; nothing is silently
truncated. These are persistence bounds, not changed evidence/index/decoder limits.

Immutable case-work publication now exposes deterministic test seams at staging
write, each actual 65,536-byte write chunk, file flush, exclusive rename and
parent-directory flush. Before the exclusive rename, errors remove only the
identity-matched owned staging file; old records, manifest and source stay intact.
After the rename, a flush or final validation failure returns
`CasePublicationError.publishedButDurabilityUnconfirmed(recordID:)`. The final
record remains available for reload, and retrying that UUID refuses replacement.
Case manifest transactions similarly distinguish published but unconfirmed
completion through `CaseManifestPublicationError`. No cancellation check after
publication incorrectly reports a committed record as an uncommitted cancellation.

Tests inject ENOSPC/EIO at the real boundaries and compare independently retained
old manifest, record and source bytes. They also exercise exact offline rollback,
stale manifests, duplicate UUIDs, fractional job dates, source-scope mismatches,
corrupt and symbolic-link migration backups, and rollback refusal after changes.
These deterministic syscall-boundary failures do not demonstrate an actual power
cut or storage-device behavior. Hardware power-loss validation, caller-facing
migration controls, complete integration of every job producer, and measured
aggregate history RSS remain separate roadmap gates until corresponding evidence
is captured.

## Immutable filesystem jobs and latest caches

`EngineResultStore.saveWithJobProvenance(result:evidenceID:in:jobID:startedAt:executableSHA256:)`
requires an explicitly migrated schema 2 case. The older schema 1
`EngineResultStore.save` API retains its behavior. The new transaction holds one
descriptor-anchored case lock while it publishes, in order:

1. `filesystem-jobs/<job UUID>.json`: one immutable `EnumerationResult`, capped
   at the existing 64 MiB limit. Its SHA-256 covers the exact serialized file
   bytes. Numeric reference-date values preserve the original fractional
   completion instant. No complete listing is copied into the manifest.
2. The manifest's immutable job receipt: exact helper version/build identity,
   optional observed executable digest, full canonical options, ordered
   selected-file hashes/sizes, selected source ordinal, start/completion time,
   status, every warning and the artifact's relative path/digest/exact byte count.
3. `filesystem/<evidence UUID>.json`: the independent mutable latest cache using
   the historical ISO8601 representation required by the older load API. This
   cache is not an immutable job artifact and may have second-resolution dates.

An exact job UUID retry compares original artifact bytes and the full receipt.
Matching reused files and their directories are flushed and revalidated before
durability is confirmed, including recovery from a prior rename without its
directory flush. An older job retry preserves the newer latest cache. A complete
orphan listing can be attached by an exact retry; a recorded but missing or unsafe
artifact refuses automatic reconstruction. A different result, option, time or
helper identity under the same UUID is refused without replacing the original.

`EngineJobSaveReceipt` returns the updated case, receipt, exact artifact path,
digest and byte count, plus explicit duplicate/cache-update flags. If publication
has occurred but the full transaction fails, `EngineJobSaveError.publishedButIncomplete`
reports the job/digest and each artifact, manifest and latest-cache phase as
`notCommitted`, `confirmed` or `uncertain`. Reopen and inspect before retrying.
This is historical persistence: it never opens evidence, treats saved hashes as
a fresh verification, invokes a provider or reruns the recorded helper/options.

The optional `CaseJobProvenance.artifactByteCount` is backward compatible with
earlier schema 2 receipts. New filesystem and APFS producers record the actual
serialized count; the auditor checks it against safely read bytes. An older
missing count remains explicitly unavailable, including on an exact UUID retry;
no expected size is inferred or written into the historical receipt.

The auditor recognizes immutable filesystem jobs separately from latest caches.
It validates exact filename identity, result schema/source scope and reconstructed
receipt fields before claiming the artifact is verified. Missing, observed unsafe
or malformed, unsupported-schema and digest-changed artifacts receive distinct
outcomes. Complete unrecorded orphan listings remain unavailable historical
artifacts. The deterministic tests cover all 19 engine boundaries, 8 real manifest
write/flush/rename boundaries, concurrent duplicate/conflicting jobs and directory
substitution while preserving old records and source bytes.

APFS generations in `apfs/<evidence UUID>/generations/<generation UUID>/` are
also recognized. The auditor independently binds `result.json` to `checksum.json`
by exact full-file SHA-256, serialized size, case/evidence/generation identity,
relative result path and allocated-view coverage. The mutable `latest.json`
must equal the generation checksum and resolve to that result. Schema 2 APFS
jobs additionally reconstruct component, full options, volume/encryption mode,
warnings, coverage status and source scope. Only compact validation summaries
are retained between generations; entire listing payloads are not accumulated.
These checks do not mount or unlock an APFS image, freshly hash its source, claim
snapshot content support or claim unallocated/deleted-file coverage.

Hashes alone do not authenticate an examiner or prevent coordinated rewriting of
a case and its unsigned receipts. See [INTEGRITY-AUTHENTICITY.md](INTEGRITY-AUTHENTICITY.md)
for opt-in signed report envelopes and the required independent public-key trust
anchor. Neither feature changes evidence or creates/persists a signing identity.

`CaseHistoryWorkloadProbe` supplies a separate synthetic history workload. Generate
a fixture with `--mode generate --root <owned fresh directory> --records 120
--prompt-bytes 614400`, then start a fresh process with the same arguments and
`--mode scan`. Paging returns 50 + 50 + 20 independently expected UUIDs, verifies
every stored full-retention request hash and known advisory, and checks unchanged
original source and manifest bytes. Scan emits its receipt on stdout and never
invokes a provider. Separate fresh scans reuse the read-only fixture so generation
allocations do not contaminate the measured paging/verification RSS. Actual RSS
numbers and baseline-derived budgets belong in the benchmark delivery receipt.

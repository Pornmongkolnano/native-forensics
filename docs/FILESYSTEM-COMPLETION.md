# Phase 1 filesystem correctness completion evidence

On 8 October 2026, engine `0.1.4-tsk4.15.0` passed **196/196 native integration
checks**, including the original RAW/EWF/protocol/safe-output suite and the
additional filesystem corpus below. This closes the tested corpus gaps for the
declared profiles. It does not establish every Windows-volume combination,
EFS/FileVault decryption, arbitrary lost-chain recovery, or full Autopsy parity.

The final helper SHA-256 is
`1956f78a1ca69ef996790845fbd420479ea96a0340877329bc2fbb3dcdb8ed8b`.
The final native manifest SHA-256 is
`434a897b8a96299fa6e676791380e0d91acd25f935b742aad4ced984aa3c1598`.
The pinned reader/patch lineage remains TSK 4.15.0; compressed content uses an
original bounded strict LZNT1 decoder in the adapter. Source images remain
read-only, and source hashes are checked again after the complete test run.

## Independent fixtures and observed outcomes

| Corpus | Independent oracle and actual helper result |
| --- | --- |
| Three-level NTFS directory index | A root, branch INDX block and two leaf blocks yield 17 independently named files; exactly 30 regular streams, directory paths, bytes, hashes and four 100 ns timestamps match |
| General ATTRIBUTE_LIST | Resident/nonresident lists, four records, seven extents, unnamed and Thai-named DATA streams yield exactly 14 regular streams; nonperiodic payloads distinguish reordered clusters |
| Damaged ATTRIBUTE_LIST | Missing middle/reference, overlapping VCN and zero-length list entries fail selected affected streams before output; an independently intact ADS remains readable where its mappings are intact |
| Compressed NTFS | 28 cases: 15 positive and 13 negative; whole/raw/sparse/mixed units, fragmented prefixes, named ADS, ATTRIBUTE_LIST, phrase-width boundaries, a one-byte final chunk and the 1 MiB extraction boundary |
| NTFS overwritten/deleted content | Partial/full overwrite and an allocated later owner preserve exact current-source bytes, while separating the original historical payload and its hash |
| EFS | Encrypted DATA and named DATA containing synthetic stored ciphertext fail before output with `UNSUPPORTED_ENCRYPTED_CONTENT`; no plaintext receipt is created |
| FAT16/FAT32 recovery | Retained fragmented mappings and a single known deleted cluster match exact current bytes; cleared, damaged or reallocated multi-cluster mappings fail before output; allocated short chains also fail |
| FAT/exFAT civil timestamps | Actual New York gap/overlap, authoritative exFAT offsets, date-only FAT access time and Pyongyang/Norfolk political 30-minute folds preserve raw fields and independent round-trip candidates |
| exFAT initialization | ValidDataLength 1/0/full is checked against nonzero residual disk bytes; logical tails are zero; ValidDataLength greater than DataLength fails before output |
| FAT boot/table selection | FAT32/exFAT backup boot paths supported by the reader preserve enumeration/extraction; a FAT32 active second FAT with stale first-FAT links reads the independently specified active mapping |

These fixtures are original Python-standard-library encoders. They neither
mount an image nor ask TSK to generate the expected bytes. NTFS logical payloads,
FILETIME integers, FAT link order, original civil fields and subsequent overwrite
bytes are declared separately. `ZoneInfo` round-trip candidates supply the
timezone oracle; the engine uses offsets from the installed TZif data plus
`localtime` round trips. Compression has an independent Python encoder/decoder
and hand-encoded MS-XCA token anchors, rather than a port of TSK's decoder.

The retained local final report is
`local/filesystem-completion-final-v2/run-20261008T021813Z-49ecb977/report.json`.
Generated images and detailed reports are ignored local artifacts. Retained
fixture hashes are verified on reuse; an incompatible corpus receipt requests a
fresh output directory instead of silently replacing images.

## Compressed-content contract

Supported compressed streams are nonresident NTFS DATA with standard 16-cluster
compression units, clusters no larger than 4 KiB, zero skip length, and valid
initialized/logical lengths. Every unit touching initialized content requires
complete mappings for the entire unit, including VCNs beyond the initialized
prefix. A unit can be entirely physical, entirely sparse, or a physical prefix
followed by a sparse suffix. Physical clusters after that suffix are invalid.

The preflight rejects missing/FILLER/cyclic/overlapping/zero-length/out-of-image
mappings and encrypted runs. Mixed units are strictly decoded before output
creation: header signature and declared length, chunk boundaries, phrase
distance/length, 4 KiB output bounds, a data item following each flag group and
the final stream marker are checked. MS-XCA permits unused high flag bits in a
final group; the adapter preserves that valid case. The decoder holds at most
one 64 KiB unit during streaming, plus the bounded extraction buffer.

Malformed payloads fail with `INVALID_COMPRESSED_CONTENT`; unknown mappings
fail with `INCOMPLETE_ATTRIBUTE_RUNLIST`. Sparse units remain logical zero
bytes. Bytes after initialized size are emitted as defined zeros, including an
unmapped uninitialized tail. Requiring initialized whole-unit mappings must not
turn such a valid tail into a blanket rejection.

References: [MS-XCA LZNT1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/cba0fa15-bd62-4eda-8838-8fc7ab406df1)
and [processing rules](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/b1ba6d34-499c-4017-ab0c-fe2daee93efc).

## Civil timestamp policy and protocol additions

For FAT/exFAT, each file row optionally contains `timestampProvenance` keyed by
`created`, `modified` and `accessed`. Each record carries `rawDate`, `rawTime`,
optional `rawIncrement`/`rawUTCOffset`, original `civil` formatted as
`YYYY-MM-DDTHH:MM:SS`, `status`, optional `timezone`/`utcOffsetMinutes`, sorted
`candidateEpochs`, and `precisionNanoseconds`. Fractional nanoseconds remain in
the corresponding ordinary timestamp field; precision denotes source resolution.
FAT date-only access precision is 86,400,000,000,000 ns, base DOS time is
2,000,000,000 ns, and increment-bearing fields are 10,000,000 ns.

| Status | Singular epoch policy |
| --- | --- |
| `recorded-offset` | The stored valid exFAT offset is authoritative; retain its exact instant even during a gap/overlap in the requested zone |
| `assumed-zone` | Exactly one instant round-trips to the recorded civil time in the selected IANA zone; retain the epoch and assumption |
| `ambiguous-local-time` | Omit singular epoch/nanoseconds; retain the civil time, zone and both candidates |
| `nonexistent-local-time` | Omit singular epoch/nanoseconds; retain the nonexistent civil time, zone and empty candidates |
| `invalid-calendar` / `missing` | Omit epoch/nanoseconds and retain raw fields/status |

No host timezone or `mktime` normalization chooses an invented timestamp.
Using all recorded TZif offsets also handles political folds where both sides
have the same DST flag. NTFS absolute FILETIME timestamps retain their existing
100 ns semantics. This is an additive protocol-v1 extension; older cache rows
without provenance remain historical records.

## Deleted recovery and initialized exFAT content

File rows distinguish `deleted-current-bytes`,
`deleted-reallocated-current-bytes`, and `deleted-fat-recovery-candidate`, with
`recoveryWarnings`. Observing an allocated mapped NTFS cluster is evidence of
possible reallocation. The bounded allocation observation is not proof of the
absence of overwrite or reallocation.

An `extracted` frame carries `contentStatus` (`logical-content` or
`recovery-candidate`) and optional `warnings`. Its SHA-256 and byte count verify
the exported current source bytes; even a matching original fixture hash does
not prove historical ownership on a real deleted file.

TSK's automatic deleted-FAT reader guesses forward free-cluster order. The
adapter follows the retained recorded classic-FAT chain itself and refuses
unknown multi-cluster order with `UNVERIFIABLE_DELETED_CHAIN`. It honors the
FAT32 active-table flag. Single-cluster deletion has one recorded physical
location and remains an explicitly uncertain recovery candidate. Deleted
exFAT content currently fails when independently retained stream mappings
cannot be established; this corpus does not enable a guessed chain.

The adapter reads exFAT ValidDataLength from the recorded stream entry instead
of TSK's inferred initialized length, which equals DataLength. It exports only
the initialized prefix physically and emits logical zeros for the remaining
tail. An invalid length or unavailable stream metadata fails before output.
See [exFAT ValidDataLength](https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification#765-validdatalength-field).

## Differential reference

The original retained TSK `fls`/`icat` sources were compiled as separate local
reference tools against retained patched static libraries. The reference
matched **58 positive structure stream extractions**, exact 30/14/14 stream
inventories, and all four whole-second NTFS timestamp fields. It observed 21
additional positive streams and 24 FAT recovery/damage cases. All reference
source images and executable hashes remained unchanged during observation.

The independent oracle takes precedence over shared-reader agreement. Five
known upstream divergences are preserved in the local report:

| Case | Upstream CLI observation | Adapter/independent oracle |
| --- | --- | --- |
| One-byte final LZNT1 chunk | 69,632 bytes, dropping the final byte | 69,633 exact bytes |
| Unmapped uninitialized compressed tail | 65,536 bytes despite a 131,089-byte logical size | Known initialized prefix plus defined zero tail |
| Completely uninitialized compressed stream | 4,096 bytes despite a 9,001-byte logical size | 9,001 defined logical zeros |
| exFAT ValidDataLength 1 | 42 physical bytes, including residual tail | One initialized byte plus 41 zeros |
| exFAT ValidDataLength 0 | 42 physical bytes | 42 logical zeros |

FAT forward-scan bytes are also checked against an independently predicted wrong
candidate where the original fragmented chain was cleared. The report records
those byte/hash differences and incomplete reads; it never calls an observed
candidate the original complete file. Reference output is in
`local/filesystem-completion-reference/report.json`.

## Reproduction and remaining prerequisites

```sh
python3 script/build_native_engine.py
python3 Tests/NativeEngine/run_tests.py --output local/filesystem-new-run
python3 Tests/NativeEngine/differential_reference.py \
  --fixtures local/filesystem-new-run/fixtures \
  --tools local/filesystem-reference --build-tools \
  --report local/filesystem-reference/report.json
```

The final runner covers 89 synthetic filesystem configurations and includes
the existing image/container, cancellation, partial-result and safe-publication
checks. The EFS negatives establish safe refusal, not decryption support. EFS
plaintext requires authenticated EFS metadata, a supplied matching private key,
a separate secret-safe decryption pipeline and an independent plaintext corpus.
BitLocker/APFS/FileVault likewise require their own declared combinations and
key pipeline; these tests make no encrypted-plaintext recovery claim.

The backup exFAT fixture damages both primary sector0 and the earlier sector6
candidate so the pinned reader reaches sector12. A primary-only failure with a
misleading sector6 signature is still an upstream boot-selection limitation.
Arbitrary damaged volumes, original ownership after overwrite, compression
profiles outside the declared geometry, transaction-log replay and WOF/dedup
remain outside this tested claim. Distribution, physical M5, clean-machine and
full GUI gates are tracked separately by the roadmap.

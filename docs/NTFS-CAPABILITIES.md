# NTFS extraction capabilities

NativeForensics uses the pinned Sleuth Kit 4.15.0 reader. Its engine version
`0.1.4-tsk4.15.0` validates content before creating an extraction output and adds bounded strict LZNT1 decoding. The [expanded independent corpus](FILESYSTEM-COMPLETION.md) records 196/196 native checks and the exact tested profiles.
Filesystem enumeration is an inventory of parsed metadata; successful
enumeration alone does not certify that every listed stream can be recovered.

## Validated synthetic coverage

The original Python fixture builder in `Tests/NativeEngine/ntfs_fixtures.py`
writes a small NTFS 3.1 image directly. Payload and FILETIME values are supplied
to the builder independently of the reader. It does not use TSK, a mounted
filesystem, an external formatter, or coursework evidence to generate oracles.

| Content shape | Verified behavior |
| --- | --- |
| Allocated and deleted resident DATA | Exact logical bytes and SHA-256 |
| Fragmented nonresident DATA, including a negative LCN delta | Exact logical bytes and SHA-256 |
| Named resident/nonresident DATA streams and directory DATA streams | Select and extract the individual stream |
| Hard links, nested directories, long Thai/Unicode names | Preserve inventory paths and stream identities |
| Explicit sparse runs | Preserve logical zero bytes without treating them as missing runs |
| General resident/nonresident ATTRIBUTE_LIST across records, named streams and multilevel indexes | Merge complete independently checked extents and preserve exact inventory/bytes |
| Standard 16-cluster compressed nonresident DATA with clusters up to 4 KiB | Strict whole-unit validation and exact logical bytes for the documented raw/sparse/mixed profiles |
| Initialized size ending inside a cluster | Preserve the initialized prefix; emit logical zeros for the tail |
| Completely uninitialized DATA | Emit logical zeros, without reading physical residual bytes |
| Uninitialized tail whose mappings are unavailable | Emit the independently known logical zeros after a fully mapped initialized prefix |

The capability fixtures target one known DATA attribute and check the published
byte count, literal payload bytes, SHA-256 and source hash. The original NTFS
corpus continues to cover all of its independently defined stream payloads.
These bounded fixtures do not establish compatibility with every Windows volume.

## Explicit extraction failures

| Condition | Error code | Reason |
| --- | --- | --- |
| Selected NTFS attribute or an initialized run is marked encrypted | `UNSUPPORTED_ENCRYPTED_CONTENT` | This engine has no EFS decryption capability; stored ciphertext is not verified logical plaintext |
| Compressed stream has unsupported geometry or invalid chunks | `INVALID_COMPRESSED_CONTENT` / `INCOMPLETE_ATTRIBUTE_RUNLIST` | Exact bounded compression profile and all initialized whole-unit mappings must validate |
| Initialized logical content contains a TSK FILLER run | `INCOMPLETE_ATTRIBUTE_RUNLIST` | TSK fills lost/unseen extents with zeros; those zeros are not recovered evidence |
| Missing leading, middle or trailing initialized VCN coverage | `INCOMPLETE_ATTRIBUTE_RUNLIST` | All initialized logical content must have a known mapping |
| Overlapping/zero-length/cyclic runs or invalid initialized-size geometry | `INCOMPLETE_ATTRIBUTE_RUNLIST` | Ambiguous content geometry cannot support a complete-byte receipt |

Each of these validations occurs before output creation and before extraction
progress. A failure produces an error and failed terminal response, without an
`extracted` receipt or published output. Sparse holes are mapped logical zeros;
FILLER runs are unknown mappings. The two have distinct meanings.

For the NTFS interval after initialized size, the engine explicitly emits zeros
instead of requesting residual disk bytes from TSK. Missing runs confined to
that interval do not invalidate the independently known logical zero content.
No source image is repaired or rewritten.

## Limits

Compressed extraction is restricted to the [documented independent whole-unit corpus](FILESYSTEM-COMPLETION.md). Unsupported geometry, missing initialized-unit mappings and malformed payloads fail before output. Initialized-prefix validation retains defined zero tails. The engine does not claim EFS/BitLocker decryption, forensic correctness for every
corrupt volume, transaction-log replay, deduplication/WOF decoding or full
Autopsy feature parity. Reader failures remain explicit extraction failures.

Deleted bytes may have been overwritten since deletion. Matching an extraction
receipt proves which bytes were exported from the selected source; it does not
prove that those bytes are the original historical file content.

## Reproduction

The normal native regression runner includes the additional capability cases:

```sh
python3 script/build_native_engine.py
python3 Tests/NativeEngine/run_tests.py --output local/native-regressions
```

Use a fresh output directory if an existing synthetic fixture hash differs.
Retained fixture bytes are checked on subsequent runs and are never silently
regenerated. The runner verifies all original source hashes after extraction.

## Reader rationale

The pinned source used for the guard decision is available locally after
bootstrap:

- `tsk/fs/tsk_fs.h`: `TSK_FS_ATTR_ENC`, `TSK_FS_ATTR_RUN_FLAG_FILLER`,
  `TSK_FS_ATTR_RUN_FLAG_SPARSE`, and nonresident initialized-size semantics.
- `tsk/fs/ntfs.c`: nonresident encrypted flags and ATTRIBUTE_LIST extent loading.
- `tsk/fs/fs_attr.c`: `tsk_fs_attr_read` returns zeros for FILLER runs and
  uninitialized/sparse content; its generic path does not decrypt NTFS EFS.

The guards use public TSK attribute/run structures. The adapter adds an original bounded strict LZNT1 content decoder; the NTFS metadata reader remains the pinned upstream lineage. Differential agreement is supplemented by independent expected bytes, including five explicitly recorded upstream byte/length divergences.

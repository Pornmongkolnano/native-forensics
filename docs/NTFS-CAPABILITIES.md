# NTFS extraction capabilities

NativeForensics uses the pinned Sleuth Kit 4.15.0 reader. Its engine version
`0.1.3-tsk4.15.0` adds content validation before creating an extraction output.
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
| Two-record ATTRIBUTE_LIST with contiguous logical VCN coverage | Merge extents and extract exact bytes |
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
| Selected NTFS attribute is marked compressed | `UNSUPPORTED_COMPRESSED_CONTENT` | Whole compression-unit semantics lack an independent correctness corpus |
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

Compressed NTFS extraction explicitly fails until an independent compression
corpus validates whole-unit and ATTRIBUTE_LIST behavior; TSK may consume mappings
beyond the requested initialized prefix while decompressing a unit. The negative
fixture tests the selected attribute's compression flag separately from valid
sparse content and does not claim an LZNT1 decoder oracle. Likewise, the
engine does not claim EFS/BitLocker decryption, forensic correctness for every
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

The new guards use the already-loaded public TSK attribute/run structures.
They do not patch the upstream reader or implement a replacement NTFS parser.

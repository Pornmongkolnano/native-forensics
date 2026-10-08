# Bounded EFS key and content pipeline

This is an original implementation using macOS Security/CommonCrypto and the
pinned TSK reader. It does not invoke Windows EFS APIs, copy ntfsdecrypt source,
change a TSK encryption flag, mount an image, or modify source filesystem bytes.
Positive cryptography, native filesystem integration, Windows interoperability,
GUI use and a verified release remain separate evidence stages.

## Current evidence

The standalone module passed **110/110 runtime checks** on the current macOS27 host
and **6/6 fixture/transport tests**. OpenSSL independently produces RSA/PFX
identities and AES256 ciphertext. Its CBC implementation first passes the fixed
NIST SP800-38A F.2.5 vector. The module consumes those bytes with Security RSA
decryption and CommonCrypto CBC, comparing complete output to literal plaintext.
No comparison uses output from the module as its expected plaintext.

Runtime positives cover historic RSA1024 and RSA2048/4096, DDF and DRF, a Unicode PFX passphrase,
nonmatching first recipients, EFS versions2/3 with RSA wrapping, exact EOF sizes
0/1/511/512/513/9001/9216, a packed owner SID, and known fragmented source extents. Both legacy and
data-protection keychain searches for the freshly generated certificate/key
identifiers returned zero before, after and in a new process after each import.
This does not inspect unrelated user identities. Key attributes, private key
bytes and passwords are never serialized into a report.

The captured native helper passed **31/31 actual-helper checks** against four
synthetic fragmented NTFS images and strict negative cases. These include exact
plaintext/ciphertext/metadata receipts, ordinary encrypted-extraction refusal,
wrong keys, incomplete inputs/mappings, descriptor/input caps, exclusive output,
signal cancellation, valid trailing cancellation and wrong-job/malformed/partial
trailing cancellation frames, and
reparse refusal. Separate certificate-only observer processes before and after
the helper matrix found zero matching certificate/key items in both legacy and
data-protection stores for all four generated identities. Enumeration advertises
the ordinary encrypted regular-file candidate and suppresses both NTFS reparse
attributes and the Standard Information reparse flag. Synthetic volumes were
**not created by Windows**.

The same helper also decrypted the complete **21,888,890-byte Windows-created
DigitalCorpora logfile** exactly equal to its complete RAW plaintext twin. This
is a genuine Windows interoperability positive for the bounded profile below.
The observed helper version was `0.1.5-tsk4.15.0`, SHA256
`d200a9e1b764bf53781d1553a36a0c0168cabbe869db256c03408a49ddcb7a46`.
Standalone, synthetic-helper and genuine-helper reports remain under ignored
`local/`; no generated keys, public-corpus images or decrypted content are
committed or bundled. GUI transport, the existing native regression suite and
release validation are separate coordinated gates. An independent executable
ntfsdecrypt differential has not been observed.

## Genuine Windows paired oracle

The official [DigitalCorpora nps-2009-ntfs1 scenario](https://digitalcorpora.org/corpora/disk-images/)
and its [creator paper, section4.2](https://dfrws.org/sites/default/files/session-files/2009_USA_paper-bringing_science_to_digital_forensics_with_standardized_forensic_corpora.pdf)
provide a Windows NTFS corpus containing encrypted files, plaintext twins and
exported test keys. The [narrative](https://digitalcorpora.s3.amazonaws.com/corpora/drives/nps-2009-ntfs1/narrative.txt)
and [published DFXML](https://digitalcorpora.s3.amazonaws.com/corpora/drives/nps-2009-ntfs1/ntfs1-gen2.xml)
are independent provenance inputs. No exact Windows version is asserted.

| Observed item | Bound identity |
| --- | --- |
| Original gen2 E01 container |36,083,007 bytes; SHA256 `2badead91bef56c80155d7731671ad1d93c08f32cd4ce17566fdf02d5769feea` |
| Complete logical media |516,554,752 bytes; SHA256 `5378309b19431aee2c15e71b4036b5a173f8c5454aa019110724e8be04dcb2d3` |
| Plaintext twin |RAW logfile, record47/DATA128/id5;21,888,890 bytes |
| Encrypted source |Encrypted logfile, record49/DATA128/id7; complete fragmented unnamed allocated stream |
| Observed profile |EFS version2; RSA1024; packed SID revision1/count5;32-byte AES256 FEK |
| Complete output |SHA256 `450acfbb1fe50167ec2a91ebd995def94d245a56b14dd89b27b8a29a5de352e3` |
| Published RAW digests |MD5 `be2828dda150f19edf9a0fc87e3ab640`; SHA1 `4a97f6bacc9d3abbfa7626ae140829aaaa7a6d03` |
| Ciphertext read |21,889,024 bytes; SHA256 `a56e59d4d378c40edb12666b0a935553595d35c0cd3467178a32b5c23dbe8aab` |

The test compares every emitted byte to the complete RAW twin, checks the two
independently published RAW hashes, checks the entire decryption receipt, hashes
the complete logical media, and independently hashes the original container
before and after. The original container's device, inode, length, mtime and ctime
also remain unchanged. Container, logical-media, ciphertext and plaintext hashes
identify different byte domains. The old DFXML volume length differs from the
actual complete-media length; it is not silently substituted for it.

The exported corpus key matches the encrypted logfile's certificate thumbprint.
The older encrypted JPEG/PDF entries refer to a different thumbprint and are not
claimed as successful decrypts with that key. A wrong key can produce implicit
RSA-rejection bytes in some OpenSSL versions; a successful subprocess exit alone
is not a valid FEK or plaintext oracle. Actual FEK length/entropy/algorithm,
recipient matching and full plaintext comparison are required here.

The historic1024-bit profile is for reading existing evidence, not creating new
encrypted data. Corpus acquisition is explicit and local; do not redistribute
its embedded third-party materials or test keys with this application. Consult
the [DigitalCorpora terms](https://digitalcorpora.org/about-digitalcorpora/terms-of-use/).

## Explicit supported profile

| Layer | Bounded profile |
| --- | --- |
| Filesystem | Allocated regular NTFS file, unnamed nonresident encrypted DATA attribute; no reparse attribute/flag |
| Content | Fully initialized, nonsparse, uncompressed; complete physical mappings |
| Metadata | Microsoft original84-byte fixed layout; EFS version2 or3; certificate credential type3 |
| Wrapping | Key-entry Flags0, RSA PKCS#1 v1.5; canonical modulus1024,2048 or4096 bits |
| OwnerHint | Omitted, or packed SID revision1 with count≤15 and exact8+4*count bytes; bounded nonoverlapping credential region |
| Recipient | Exact SHA1 of full DER certificate, EFS DDF or recovery DRF EKU |
| Key input | Explicit PKCS#1 RSA private DER plus matching certificate DER |
| FEK | Exact48 bytes: key length32, entropy256, AES algorithm0x6610,32 key bytes |
| Encryption units |512 bytes, per-unit CBC IV from logical stream byte offset |
| Output | Logical EOF bytes plus observed SHA256 and explicit unauthenticated-content warning |

Malformed/overlapping SID owner hints are rejected. Credential type1, smart-card
wrapping Flags1, DESX/3DES, metadata versions for EFS4/5/6, ECC, deleted files,
named streams, compressed/sparse content and uninitialized tails require separate
positive format oracles before support. An unsupported
profile is not described as a wrong password or as an empty plaintext file.

The key and certificate public RSA representations must match before FEK
unwrapping. CA trust and certificate expiration do not establish whether an
explicitly supplied historical private key can decrypt a matching FEK. The DER
path uses SecKeyCreateWithData and local certificate/public-key parsing without
requesting a trust evaluation or adding items to a keychain.

## PFX is diagnostic only

The PFX path is available only when a test explicitly defines
NF_EFS_ENABLE_PFX_DIAGNOSTIC. It uses macOS15+ SecPKCS12Import with the actual
CFBoolean memory-only option. It never uses the default persistent macOS import.
SecItemImport with a null keychain is not a reliable PFX identity fallback:
Apple's aggregate importer can return certificates without a usable private
identity. macOS14 PFX import is therefore unavailable in this diagnostic.

Memory-only import does not establish a strict network-free import: Apple's
importer evaluates certificate trust internally. No shipping caller may enable
PFX until its trust-fetch policy has been isolated and observed. The explicit
private DER profile avoids that importer entirely.

SecKeyCopyAttributes also synthesizes IsPermanent:true for local RSA objects;
this attribute is not a keychain lookup and cannot be used as a persistence
rejection test. The attributes dictionary can contain private key material, so
it is never logged. All owned CF objects are released at the job boundary.
Producer-owned mutable secret buffers receive a best-effort volatile zeroing
pass. Opaque Security objects and immutable framework copies are released; this
is not a claim that every physical RAM copy has been measured as erased.

## Secret transport and limits

The explicit operation is extract-efs. Its first NDJSON request contains the
ordinary image/file/output references and exactly this nonsecret descriptor:

    "credentialTransport": {
      "profile": "rsa-pkcs1-der-certificate",
      "privateKeyBytes": 1191,
      "certificateBytes": 809
    }

Immediately after the request newline, stdin carries exactly the private DER
bytes, followed by exactly the certificate DER bytes. Neither is JSON/base64,
an argument, an environment variable or a recorded key pathname. The descriptor
example's sizes are illustrative, not fixed sizes for a key.

The request frame remains capped at1MiB, private DER at64KiB, certificate DER at
128KiB, metadata at256KiB, recipients at64, metadata attributes at1024, and mapped
runs at65536. Maximum key/certificate binary input is192KiB in addition to the
bounded request frame. The standalone diagnostic PFX cap is512KiB and its UTF8
passphrase cap is4096 bytes; these are not enabled shipping input formats.

The input reader consumes the binary fields before resuming its NDJSON cancel
parser. It wipes an old pending allocation before moving its suffix, because a
plain string erase can leave duplicate secret bytes in allocation tails.
The4096-byte stack read buffer is guarded by the same volatile-wipe RAII primitive
whose normal-return and exception paths are directly checked in the standalone
probe; this is an owned-buffer oracle, not measurement of inaccessible copies.
SIGTERM/SIGINT wake a blocked credential read; incomplete fields fail with
TRUNCATED_CREDENTIAL. Trailing bytes must be a complete valid cancellation frame
for the same job; malformed or partial trailing input fails the existing
bounded cancellation protocol.

The adapter validates all mappings before exclusive output creation and reads
complete final ciphertext units, including the physical bytes past logical EOF.
It hashes those stored ciphertext units separately from the emitted plaintext.
Full source verification and the existing exclusive output publication must
also remain enforced by the client; key import does not replace them.

## Receipts and interpretation

An accepted extraction has contentStatus decrypted-content. Its decryption
receipt contains the profile, recipient role, metadata SHA256, certificate SHA1,
ciphertext SHA256/count, unit size512 and authenticatedPlaintext:false. It
contains no private-key digest, source key pathname, PFX, FEK or password.
The ordinary extraction SHA256/count identify the bytes actually emitted.

EFS AES-CBC has no content-authentication tag. The mutation oracle deliberately
flips ciphertext, observes changed plaintext and retains that limitation.
Successful RSA key matching and a new output hash do not prove the original
historical plaintext before possible source tampering.

## Reproducible checks

All generated identities and images must stay under ignored local. Existing
directories and output files are refused rather than overwritten. Root
coordinates production helper builds; the standalone command is:

    xcrun clang++ -std=c++17 -O1 -mmacosx-version-min=14.0 \
      -I .engine/deps/json/include -I .engine/prefix/include \
      Tests/EFSKeyPipeline/probe.cpp -framework Security \
      -framework CoreFoundation -o local/efs-research/efs-probe

    python3 Tests/EFSKeyPipeline/fixtures.py local/new-efs-corpus
    python3 -m unittest discover -s Tests/EFSKeyPipeline -p test_fixtures.py
    python3 Tests/EFSKeyPipeline/run_tests.py \
      --probe local/efs-research/efs-probe --corpus local/new-efs-corpus

After a captured production build with both header digests and the Security
framework in its source/link receipts:

    python3 Tests/EFSKeyPipeline/native_integration.py \
      --engine .engine/bin/NFTSKEngine --corpus local/new-efs-corpus \
      --output local/new-efs-native-results --report local/new-efs-native-report.json \
      --probe local/efs-research/efs-probe

With the separately acquired official corpus and locally converted public-test
DER key/certificate under ignored local (no acquisition or conversion occurs in
this runner):

    python3 Tests/EFSKeyPipeline/genuine_corpus.py \
      --engine .engine/bin/NFTSKEngine --corpus local/efs-digitalcorpora \
      --output local/new-efs-genuine-results --report local/new-efs-genuine-report.json

## Primary format and API references

- [Microsoft original EFS metadata layout](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/625335e5-a423-4d1c-be51-c696c32aa2eb)
- [Key-list entry and wrapping flags](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/f8c3837c-8617-4346-b188-989933705a40)
- [Public-key information](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/db88e723-1ff7-4351-a518-e1c60ee391a7)
- [Packed SID layout](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/5cb97814-a1c2-4215-b7dc-76d1f4bfad01)
- [Certificate thumbprint and nested offsets](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/066d0c3d-182c-4730-a005-dbf8990c9fbb)
- [FEK header](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/00933615-c9cf-4d51-9d9a-bb3fb33a3560)
- [CryptoAPI RSA ciphertext byte order](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptdecrypt)
- [Windows file-attribute reparse flag](https://learn.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants)
- [Primary ntfsdecrypt sector transform](https://github.com/tuxera/ntfs-3g/blob/2026.9.28/ntfsprogs/ntfsdecrypt.c#L1277-L1430): the IV algorithm is implementation evidence, not an official Microsoft sector-format specification.
- [Apple nonpersistent explicit RSA DER creation](https://github.com/apple-oss-distributions/Security/blob/main/keychain/headers/SecKey.h#L812-L830)
- [Apple memory-only PFX option](https://developer.apple.com/documentation/security/ksecimporttomemoryonly)
- [Apple local-key attributes](https://github.com/apple-oss-distributions/Security/blob/main/OSX/sec/Security/SecKey.m#L109-L173)
- [Apple importer trust evaluation](https://github.com/apple-oss-distributions/Security/blob/main/OSX/sec/Security/SecImportExport.c#L121-L137)

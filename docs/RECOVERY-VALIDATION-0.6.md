# Independent recovery validation for the next native release

This increment closes bounded recovery-content checks; it does not establish general fragmented recovery, deleted-file reconstruction, broad NTFS compatibility or full Autopsy parity. Carved candidates remain separate from deleted filesystem entries. Their original names, times and deletion state remain unknown.

## Independent corpus

The local oracle uses PhotoRec **7.2** with `partition_none,wholespace,search` against newly generated 8 MiB RAW images. JPEG/PNG bytes were generated independently with Pillow 12.2; ZIP with Python's `zipfile`; PDFs with literal objects, a complete xref/trailer, and an explicit `/Prev` incremental update. No user evidence is included. Selected RAW bytes were unchanged after every command-line probe.

| Input | Observed independent PhotoRec output | Oracle |
|---|---|---|
| JPEG 17 × 13 pixels | One 637-byte candidate | Every recovered byte and SHA-256 equal the independent JPEG |
| PNG 17 × 13 pixels | One 87-byte candidate | Every recovered byte and SHA-256 equal the independent PNG |
| ZIP containing `oracle.txt` | One 141-byte candidate | Every recovered byte equals the independent archive; separately decoded member text is `ZIP INDEPENDENT ORACLE` |
| Two independent PDFs, starts 1,024 bytes apart | Two distinct 597-byte candidates | Both exact SHA-256 values and source offsets; no combined span |
| PDF with two EOF revisions and a valid `/Prev` update | One exact 788-byte candidate | Recovered bytes retain the original and update; decoded current page says `INCREMENTAL UPDATED` |
| Truncated PNG/PDF, false JPEG signature and PNG interrupted by foreign data | No candidates for this corpus | An empty result is an observed tool outcome, not proof that no file or deleted content existed |

The app-service regressions additionally check reported versus clipped byte runs, exact stored bytes, exclusive export bytes/hashes, immutable result reopen, and unchanged original source. The JPEG/PNG/PDF/ZIP assertions operate on known original bytes; PhotoRec filenames are only format hints. Independent decoding is a separate check.

Real PhotoRec tests are optional when `/opt/homebrew/bin/photorec` exists; absence skips them rather than simulating a passing real-tool run. The portable malformed-candidate cases use a synthetic report-producing process and exercise the genuine native service, storage, document decoder and report builder. Their purpose is to test the boundary between verified source bytes and format validity, not to claim that PhotoRec emitted each malformed candidate.

## Correctness fix: truncated PNG was reported as decoded

The existing ImageIO path reported `decoded` for a PNG truncated to 44 of 87 bytes, without a complete IDAT or IEND. It also accepted a framed PNG with valid chunk CRCs after removal of the zlib trailer, and a compressed stream truncated to five bytes. This was a decoder observation defect, even though the tested PhotoRec run did not emit those negative inputs.

The decoder now validates the original PNG before producing a readable-content observation. It checks required critical chunk framing and order, header/palette constraints, every chunk CRC, final IEND, and the complete concatenated IDAT zlib stream. A 65,536-byte buffer checks expected scanline count and filter-byte bounds, including Adam7 passes; it does not retain a second full pixel image. The existing input, pixel, CPU and parent timeout limits remain applicable. ImageIO still performs actual pixel reconstruction and bounded thumbnail generation.

Independent valid fixtures cover RGB, alpha, monochrome, indexed palette, 16-bit grayscale, all seven Adam7 passes, 1 × 1 Adam7, and a row exceeding the streaming-buffer size, plus split/empty IDAT and unknown ancillary chunks. Complete zlib image streams followed by unused final-IDAT padding remain readable, with an explicit preserved-but-uninterpreted byte-count warning as allowed by [PNG section 11.2.3](https://www.w3.org/TR/png/#11IDAT). Negative fixtures cover CRC errors, truncated framing, missing IEND, impossible lengths, unknown critical chunks, nonconsecutive IDAT, invalid palette/header ordering, incomplete zlib data, excess/missing scanlines and invalid filter bytes. These checks follow the [W3C PNG datastream specification](https://www.w3.org/TR/png/#5DataRep). They do not certify every ancillary metadata or animation frame's semantics; the app continues to disclose first-frame image-preview scope.

`sourceBytesVerified` means that the recovered candidate's complete byte mapping was independently compared with the acquired source. It does not establish a usable image/document, an intact original pre-deletion file or a deletion event. Tests require a malformed but source-mapped candidate to retain `sourceBytesVerified` / deletion `unknown` while its decoder/report separately show failure.

Direct invocation of the rebuilt debug decoder passed all twelve valid and twenty malformed PNG profiles with unchanged input bytes. This deliberately separate diagnostic invocation does not exercise the production parent's required sandbox or establish that the client policy passed. The wide-row oracle is a 202-byte PNG with independently checked chunk CRCs and exactly 120,001 inflated bytes (one filter byte plus 40,000 RGB pixels), spanning the 65,536-byte buffer without weakening dimensions or decoded-status assertions.

## Remaining recovery and filesystem gates

- The synthetic fragmented-output service regression checks declared noncontiguous runs in output order. The real negative PNG checks damaged data; neither demonstrates successful arbitrary fragmented JPEG/PNG/PDF/ZIP reconstruction.
- Existing bounded PhotoRec scratch/cancellation/output-limit/source-change tests remain necessary. The new corpus does not replace them.
- The historical 13-stream NTFS baseline lacked ATTRIBUTE_LIST extension records, multilevel indexes, compressed data, EFS data and reallocated deleted clusters. Engine 0.1.3 adds bounded two-record ATTRIBUTE_LIST and initialized-size coverage, while encrypted/compressed attributes and missing initialized mappings now fail before publication; see [current NTFS capability checks](NTFS-CAPABILITIES.md). Those additional gates do not establish general multilevel indexes, EFS decryption, compression compatibility or intact pre-deletion recovery.
- A current acquired-source hash cannot prove that deleted clusters were never overwritten. Exported bytes and pre-deletion content must have separate claims and oracles.
- External PhotoRec distribution, clean-machine validation, Developer ID/notarization and physical M5 measurements are separate release gates.

## Regression entrypoints

`RecoveryCorpusTests` has five test declarations: four real-tool corpus checks and one portable parameterized malformed-candidate boundary check. `RecoveryPNGValidationTests` has two declarations covering twelve valid and twenty malformed PNG profiles. All seven declarations / forty parameter cases passed in the coordinated local debug Core run: **373 test declarations in 36 suites**, with the real installed PhotoRec corpus executed and the production parent's required decoder sandbox active. The retained log is `local/roadmap-development/core-debug-final.log`; release and exact-head CI are separate checks recorded by the release validation.

The command-line oracle outputs are intentionally ignored under `local/recovery-readiness-0.6/`; no host paths, runtime binaries or evidence cases are committed. The JPEG oracle includes a fixed 637-byte count and independently known SHA-256 guard so accidental literal changes cannot masquerade as a carver discrepancy.

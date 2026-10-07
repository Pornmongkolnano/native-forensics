# Assignment-driven validation, 2026-10-07

NativeForensics **0.5.0 / build 13** now completes the verified recovery, filesystem-export and optical-history tasks below. This sanitized engineering report uses generic datasets A/B/C. Source filenames, hashes, paths, payloads, cases, screenshots and assignment answers remain in ignored local validation material. No assignment was submitted and no coursework evidence was sent to Codex or another provider.

## Scope and comparison rules

The six-page assignment has five carving questions and six investigation questions. Practical checks use a damaged-filesystem image, a FAT32 removable-media image and a UDF optical-media image. HDD/SSD sanitization questions are explanatory; no device was wiped. Traversed-directory/opened-file questions require corroborating PC/user artifacts: removable-media directory contents alone do not establish those actions.

The reference is the repaired local **Autopsy 4.23.1** runtime, with completed isolated ingest and independently exported bytes. It is not a benchmark of stock Windows Autopsy or exhaustive forensic ground truth. Sources stay read-only; disposable cases, exported files and reports occupy separate owned locations. Existing Autopsy cases/configuration and its frozen health baseline were preserved.

Exact payload recovery means byte count, SHA-256 and recorded byte-for-byte comparisons agree. Filename extensions are insufficient. Primary candidates, filesystem records, historical namespace entries and embedded derivatives have distinct counts.

## Actual assignment results

| Generic dataset | NativeForensics | Autopsy or independent reference | Established result |
| --- | --- | --- | --- |
| A: damaged metadata, whole-image carving | 14 primary candidates saved, reopened and exported | 14 primary Autopsy carved candidates | **14/14 exact payloads** with source-byte range verification; original names and individual deletion states remain unknown |
| B: FAT32 removable media | 51 filesystem records; 41 comparable payloads exported through both core and GUI batch workflows | 62 Autopsy records; 41 comparable exported payloads | **41/41 exact payloads**, zero GUI batch failures; record-count differences reflect namespace/pseudo-entry representation |
| C: UDF optical-media history | Nine VAT snapshots; 20 exact logical exports: three current images and 17 historical Office payloads | Independent raw-UDF reader plus UDFclient agree on 20 target payloads; Autopsy carving matches 13/20 exactly | **20/20 exact payloads** and 80 raw timestamp fields verified; seven Autopsy target payloads are missing or partial |

The assignment labels Dataset A FAT32, but its damaged boot metadata does **not** establish actual filesystem geometry. Recovery is byte-based; this validation makes no repaired-filesystem or proven FAT32-geometry claim. The explicit PhotoRec command `partition_none,wholespace,search` scans the whole selected RAW image. A separate synthetic MBR control placed valid candidates inside and outside a partition: the old auto-selected scope missed the outside candidate, while the whole-image command recovered both. Legacy persisted jobs retain their original scope label.

Autopsy also produced 16 embedded derivatives for Dataset A and 394 for Dataset B. These are not additional original files. Two valid but unreported recovery thumbnail sideproducts are excluded with an explicit warning; undeclared non-thumbnail payloads are rejected. A recovered candidate opening successfully does not establish that it was deleted, nor identify its authoritative original filename or timestamps.

Dataset B contains 17 Office payloads, one configuration-text payload and 23 unidentified/overwritten original-file slots. Exact export verifies the acquired bytes, not intact recovery of each former original file. All 17 Office payloads also match the independent optical-media payloads. MIME agrees with Autopsy on 17/17 Office payloads and 40/41 total payloads; the remaining text classification is UTF-8 plain text versus an INI subtype. No specific wiping utility or overwrite time is inferred.

Dataset C is limited to the supported **RAW / 2,048-byte / UDF 2.01 / physical-and-virtual partition / VAT** profile. Ancestor directory FID `0x06` contains directory and deleted bits; those latest entries have null ICB references. The children's own FID flags remain non-deleted. The app/report describe the 17 files as historical files recovered through deleted ancestors, not as 17 individually FID-deleted files. Raw timestamps preserve explicit offsets and fractional fields. These results do not establish general UDF coverage or completeness for every optical image.

All three source hashes remained unchanged. Saved recovery, filesystem and optical results reopened with serialized-field equality. The initial combined probe rejected normalization of an unpersisted subsecond `savedAt` value after producing complete outputs; corrected canonical readback passed without rewriting inputs or results. That setup/probe failure is retained in private receipts.

## Document examination

The isolated decoder examined **91 independently verified reference exports**: 14 primary recovery candidates, 16 embedded derivatives, 41 removable-media payloads and 20 optical payloads. There were no decoder execution failures or source changes. Native analyses over actual exported payloads matched the same Native decoder's reference-byte controls; this is **not** Autopsy text-extractor parity.

Ten modern Office files expose referenced body/slide/worksheet text; seven legacy Office containers are recognized but their bodies remain unsupported. Five modern files carry explicit partial-content flags (four DOCX, one XLSX); all ten retain format/coverage warnings. Twenty-five literal text-search controls passed. Missing, empty, skipped and truncated units remain visible rather than silently becoming complete search coverage.

Images use bounded, re-encoded thumbnails; GIF preview covers its first frame. PDF text carries page references and does not prove that visually empty pages lack content. ZIP text keeps member references and labels inferred encoding. EXIF dates retain raw, unzoned values rather than adopting the host time zone. Office text excludes layout fidelity, embedded objects, macro/formula execution and OCR. Audio/video recognition does not provide playback.

## GUI observations and independently checked publications

Observed in the packaged native app: a disposable case opens; whole-image recovery finishes with 14 candidates and ready controls; image dimensions/raw EXIF appear; a misleading image extension is detected as DOCX and its body is searchable; filesystem batch export publishes 41/41 files with a manifest; source switching clears the previous export receipt; UDF history lists 20 files across nine snapshots, retains deleted-ancestor distinctions and previews a verified Office payload. The exported UDF report includes all 20 inventory files and nine snapshots even when the table filter shows one file. Actual recovery-report publication also passed with an explicit saved-report status and a 14-candidate inventory. Those recovery reports correctly contain zero loaded decoder analyses and zero manual notes after the restart; loaded-data report coverage has separate core/CLI verification.

Independent read-only checks are separate from visual observation: **783 GUI-output gates** verified the actual batch files, manifest, provenance, source integrity and current recovery generation; **385 UDF-report gates** verified job binding, inventory, extents and timestamp precision. Both had zero mismatches and retained six comparator negative controls. A further **466 recovery-report gates** verified both actual published reports against the final recovery generation, all 14 payload identities/ranges/bytes, zero loaded analyses/notes, unknown/not-reviewed assessments and host-path redaction. This separate readback had zero mismatches and reconfirmed all three source hashes. The UDF report records parser/result provenance but does not include app/decoder binary hashes; the bundle validation is a separate receipt.

The finite-window layout defect was reproduced: a 3,775-point split view occupied a 780-point window. The central viewport is now constrained to the actual window and each long pane scrolls. Hosted regressions cover 1,280 × 780 and 1,040 × 660 windows; the repaired app was also checked visually. Busy state now participates in Observation, so completed jobs release controls. Source/case changes clear session receipts without deleting their published files. Recovery controls now show the saved-report URL or export error, clear stale report URLs on result-generation changes, and clear prior errors when a new export starts.

A source-parent directory read could wait on macOS folder authorization after an ad-hoc rebuild. Source-only hex traversal now uses `O_SEARCH` with no-follow/close-on-exec checks, opening only the named file for reading. Writer directories retain ordinary descriptors and synchronization. Eight focused hex regressions passed; the actual GUI successfully read a 4 KiB window at offset zero after rebuilding. Folder-purpose descriptions are included in the app. No permission reset, folder grant or Full Disk Access change was performed.

### GUI boundary

Actual PDF preview showed 15 pages and 15 extracted text records; literal search returned 14 matches with page/UTF-16 references. The UI automation bridge intermittently closed its native pipe during accessibility inspection, while the app remained alive with an idle main loop and normal restart/reopen. Manual recovery assessment save and reopened assessment readback remain unobserved in this final session. Core assessment persistence tests passed, but do not substitute for those GUI observations. The bridge failure alone is not evidence of an app failure.

Final independent validation of the latest 0.5.0/build 13 bundle passed: app/helper strict signatures, receipt hashes, arm64 architecture and all three system-only dynamic-library closures. Signing remains local ad-hoc development signing.

## Test and preservation receipts

| Check | Current local result | Boundary |
| --- | --- | --- |
| Swift debug and release | **367 declarations per configuration**: 259 core in 24 suites plus 108 app in 15 suites; all passed | Real helper and local UDF oracle opt-ins enabled; parameterized cases add coverage without inflating declaration count |
| Portable native corpus | **105/105**, zero failures | Engine remains byte-identical at 0.1.2-tsk4.15.0 with five pinned patches |
| Python harness/bundle regressions | **55/55** | Includes decoder receipt/signing/dependency and package publication checks |
| Latest packaged app | Independent validation passed and app launched | Strict app/helper signatures, provenance hashes, arm64 and three system-only dependency closures; local ad-hoc signing |
| Assignment core comparison | **2,198 gates**, zero mismatches; six negative controls | Source-bound outputs, metadata/timestamps, document controls and canonical reopen; no timing benchmark |
| GUI batch/recovery readback | **783 gates**, zero mismatches; six negative controls | Actual batch files, manifest and current recovery generation; no UI interaction inferred |
| GUI UDF-report readback | **385 gates**, zero mismatches; six negative controls | Current-job inventory, extents and timestamps; no UI interaction inferred |
| GUI recovery-report readback | **466 gates**, zero mismatches | Two published reports, full 14-payload inventory/bytes, zero loaded analyses/notes, unknown/not-reviewed states and host-path redaction |
| Decoder reference corpus | **91 files**, zero execution failures/source changes | Recognition and bounded decoding remain separate from complete document readability |
| Autopsy health | **30 PASS, 0 FAIL, 0 WARN, 2 INFO, 3 SKIP** | Read-only frozen-baseline diagnostics, not exhaustive forensic functionality |

Core debug/release runs took 41.321/39.848 seconds and the current app debug/release runs 2.861/2.959 seconds. These are test-suite durations, not application performance measurements. The earlier pipeline benchmark remains a separate version/workload experiment. No fresh 0.5 speed or RAM advantage is claimed.

Local validation does not imply commit-specific CI success. The earlier CI run at the pre-assignment commit passed; new commits require their own GitHub Actions result. The [sanitized machine-readable receipt](validation/2026-10-07-assignment.json) keeps the number scopes separate.

## Remaining readiness boundaries

- Additional PC/user evidence is required to answer traversal/opened-file behavior questions; the local answer draft retains unknown states and has not been submitted.
- Legacy Office bodies, OCR, media playback, full artifact/browser/email/registry investigation and general damaged-filesystem reconstruction remain unsupported or incomplete.
- PhotoRec 7.2 is an independently pinned external dependency, not bundled; carving reports its absence explicitly. UDF support remains limited to the declared profile.
- Local development signing is ad-hoc. Developer ID/notarization, complete corresponding-source/relink distribution and clean-machine installation are not verified.
- The observed host is Apple M2 / arm64, macOS 27.0.1, Swift 6.4 / Xcode 27. The minimum OS declaration is macOS 14; older supported macOS and a physical M5 have not been tested.
- Broader cancellation/publication/crash/power-loss scenarios, mixed large evidence and full-app latency/RAM/thermal measurements need separate validation. Stored sidecars are not cryptographically authenticated.

See the [assignment workflow guide](ASSIGNMENT-WORKFLOW.md) for current controls and [readiness](READINESS.md) for release gates.

## Explanatory HDD/SSD sources

[NIST SP 800-88 Revision 2](https://csrc.nist.gov/pubs/sp/800/88/r2/final), finalized September 2025, distinguishes clear, purge and destroy and requires device-appropriate sanitization and verification. Ordinary deletion/quick-format is not equivalent to sanitization; host overwrites cannot address all flash spare/wear-levelled locations. [NIST publication, sections 3.1 and 4.5](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-88r2.pdf)

One sequential pass over decimal 1 TB at an assumed effective 150 MB/s takes `1,000,000,000,000 / 150,000,000 = 6,666.7 seconds`, approximately 1.85 hours. A full readback at that speed adds about 1.85 hours before setup/other overhead. This is arithmetic, not measured erase throughput or a sanitization guarantee; no wipe was performed.

SSD carving depends on whether the requested bytes remain readable in the acquired image. TRIM marks sectors unneeded for controller reclamation; garbage collection/device mappings can remove access to their old contents. Neither universal recoverability nor universal unrecoverability follows. [Microsoft TRIM description](https://learn.microsoft.com/en-us/windows/compatibility/new-api-allows-apps-to-send-trim-and-unmap-hints)

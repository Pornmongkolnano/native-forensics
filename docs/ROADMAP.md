# แผนพัฒนา NativeForensics

ฐานที่เก็บไว้คือ **0.6.0 / build15** และ rollback ZIP ส่วน **0.7.0 / build16 — frozen D development candidate** ผ่าน Debug/Release correctness, actual AES-wrapper API subset, four-product build/static, bounded GUI และ [executed local R2 source/rebuild/relink/system-installer](R2-DISTRIBUTION-CURRENT-2026-10-08.md) แล้ว ดู [current D evidence](NATIVE-0.7.md), [ฐาน0.6](NATIVE-0.6.md) และ [historical synthetic workflow](MILESTONE-WORKFLOW.md) เป้าหมายเต็มคงตาม [completion audit](GOAL-COMPLETION.md); ad hoc/local acceptance ไม่ปิด trust/clean-machine/M5/whole-goal gates

## สถานะการดำเนินแผนวันที่8 October2026

| ช่วง | Implementation และขอบเขตปัจจุบัน | Gate ที่ยังเปิด |
|---|---|---|
| 1 งานไม่หาย | Versioned sidecars/revisions, explicitv2migration/backup/rollback, immutablejobs; actual full/digestOnly parent-child save+quit/reopen byte preservation; [Release headless history n5](HISTORY-RELEASE-2026-10-08.md) ผ่าน | Case-only Saved History entrypoint UX, loadedanswer/freshciteafterrestart/changedsourceRefusal; complete publication races/power-loss/GUIaggregateRSS/trustedidentity |
| 2 เอกสาร/ค้นเนื้อหา | D XPC14scopes passed/brokerdeathunavailable77, actual binary provenance/caps/cancel/policy; literal/phrase/prefix+incremental verification; C captured-frame5/5แยกartifact | Brokerdeath/publictask-control, fivehostESRCHcause, broadercold/mixed/full-app budgets/currentGUI; OCR/legacybodiesคงlater scope |
| 3 Codex เปรียบเทียบ | Actual one-pageASCII PDFreview/redaction/freshprequitprefixopen; two liveparent-child responses8+4disclosedrefs; full/digestOnly binding | Loadedanswer/freshciteafterrestart/changedsourceRefusal และ case-only History UX; broaderproviderbehavior/completePDFgate |
| 4 Timeline/รายงาน | Filesystem/allocated Chromium-WAL/UTF8syslog, explicit time/source refs, JSON/Markdown/PDF | Current end-to-end/GUI reportreadback; additional parserfamilies/deleted-freeSQLite; renderer-onlyไม่แทนextraction/provider |
| 5 Recovery | JPEG/PNG/PDF/ZIP corpus, independent/updated PDFs, malformedcandidates/strictPNG completeness; UDIFraw-carverguard | Arbitrary fragmented/damaged media; no original-name/deletion inference |
| 6 Distribution | Local D ZIP25,504,203B/SHA59d1600f…7173be; extracted four-product/native196/relink196+EFS31/system-installer ordinary transactions passed; Python217 | Originallicense decision, Developer ID/notarization/Gatekeeper, clean older macOS/physicalM5; power-loss/concurrent publication/thermal-battery |

Engine **0.1.5/TSK4.15** ผ่าน existing196native และ31actual-helper EFS กับ separate Windows-created21,888,890-byte RAWtwin [bounded profile](EFS-KEY-PIPELINE.md) รวมcorpuscompression/ATTRIBUTE_LIST/deletedchain/civil-timeของ [0.1.4](FILESYSTEM-COMPLETION.md) Ordinary encrypted extractionยังrefused; plaintextผ่านexplicit matching-key operation ไม่ใช่generalEFS/BitLocker

D fullDebugCore727/80+Native268/31 และ Release727/80+268/31ผ่าน; newencrypted-snapshotopt-inถูกskipในmainCore จึงใช้ **separate actualAES API2 tests** ทั้งDebug/ReleaseสำหรับUDIFwrapperรอบunencryptedvolume Disk-user snapshots/bootFileVaultไม่qualified PlainUDIFhistorical GUI16,384Bexportผ่าน; current-file/encrypted GUIยังเปิด Prior675/75 snapshotobserver15issuesเก็บไว้และdiagnosticrerunไม่พิสูจน์cause/fixของcontention D XPC14/77ยังqualified ไม่โอนCframe/Abenchmarkเป็นDperformance [รายละเอียดทุกscope](NATIVE-0.7.md)

Native Mac foundation และ filesystem workflow มี implementation แล้ว ปัจจุบัน **Phase 1 coverage ยัง IN PROGRESS** เวอร์ชัน 0.5 เพิ่ม assignment recovery, bounded UDF VAT history, isolated document previews, selected-document text search และ transactional batch export ตาม [assignment validation](ASSIGNMENT-VALIDATION-2026-10-07.md) ผลนี้ไม่ปิด broad-format, artifact-analysis หรือ distribution gates

ลำดับนี้เป็น milestones ที่ใช้ตัดสินใจจากผลทดสอบ ไม่ใช่กำหนดเวลาหรือข้อรับรองว่าแอปแทน Autopsy ได้ครบ ทุก phase ต้องรักษา source integrity และไม่ใส่ evidence/cases ของผู้ใช้ใน Git

## ลำดับส่งมอบหลัง 0.3.0 — แผนวันที่ 7 October 2026

เป้าหมายคือให้ผู้ตรวจทำงานตั้งแต่เลือกไฟล์ → อ่านเนื้อหา → บันทึกข้อค้นพบ → ตรวจคำอธิบาย AI → ออกรายงาน โดยกลับมาเปิดเคสแล้วตรวจที่มาของแต่ละข้อสรุปได้ ใช้ TSK/helper เดิมต่อและเพิ่ม native workflow รอบ engine ที่มีอยู่ **ช่วง 1 มี implementation และ local validation ใน 0.4.0 / build 12 แล้ว** ส่วน 0.5 เพิ่มบาง workflow ของช่วงถัดไปตามขอบเขตที่ตรวจจริง หมายเลขช่วง 2–6 ยังเป็น milestones สำหรับพัฒนาต่อ ไม่ใช่ข้อรับรองว่าทุก gate เสร็จแล้วหรือกำหนดวัน release

ฐาน 0.4 มี case/listing/extraction, background path search, Codex สำหรับไฟล์เดียว, explicit Save Analysis, per-file history, revisioned notes/bookmarks/tags, extraction history และ fresh verified text/hex preview ดู [Case work/limits](CASE-WORK.md) และ [Codex scope](CODEX-ANALYSIS.md) เวอร์ชัน 0.5 เพิ่ม document decoder/search ในไฟล์ที่เลือก ยังไม่มี case-wide content index, artifact timeline, OCR หรือ legacy Office body decoding ผลทดสอบไม่แทนทุก filesystem หรือ benchmark บน M5

| ลำดับ / เป้าหมาย | สิ่งที่ผู้ใช้ทำได้เมื่อผ่าน gate | ขึ้นกับ |
|---|---|---|
| **1 / 0.4 มี local implementation แล้ว** | Save Analysis, เปิดประวัติต่อไฟล์, notes/bookmarks/tags, อ่าน text/hex ใน inspector ภายใต้ [limits](CASE-WORK.md) | Case publication ที่มีอยู่ และ fresh verified extraction; broader GUI/compatibility gates ยังเปิด |
| **2 / 0.5 เอกสารและค้นเนื้อหา** | Preview PDF/images ที่ประกาศรองรับ, สกัดข้อความพร้อมเลขหน้า, ค้นข้อความในไฟล์และกลับไปยังตำแหน่งที่พบ | Verified-content service, decoder isolation และ derived-store experiment |
| **3 / 0.6 Codex เปรียบเทียบหลักฐาน** | เลือกข้อความจากสองไฟล์ เปรียบเทียบ/ถามต่อ พร้อม references ที่แอปตรวจและเปิดดูได้ | Durable records และ content references ของช่วง 1–2 |
| **4 / 0.7 Timeline และรายงาน** | รวม filesystem/browser/download events, filter เวลา, export รายงานที่แยกข้อเท็จจริงกับ AI/บันทึกผู้ตรวจ | Independent artifact fixtures และ timestamp policy |
| **5 / 0.8 Recovery** | วิเคราะห์ unallocated/damaged data ผ่าน carving adapter และตรวจ candidates ก่อน export | Controlled scratch, candidate models และ independent recovery corpus |
| **6 / 1.0 รุ่นพร้อมแจกในขอบเขตที่ประกาศ** | ติดตั้งบนเครื่องใหม่ ใช้งานได้ตาม compatibility/capability matrix และมีตัวเลข performance ที่ตรวจซ้ำได้ | Correctness, packaging, license/source/relink และ clean-machine gates |

Phase 1 correctness กับ release preparation เป็นงานขนานตั้งแต่ช่วงแรก ไม่ต้องรอช่วง 6 จึงเริ่มจัด dependency materials, compatibility matrix หรือวัด app memory การผ่านช่วงฟีเจอร์ไม่ปิด gates ของ Phase 1 โดยอัตโนมัติ

### ช่วง 1: งานไม่หายและอ่านไฟล์ก่อนถาม AI — implemented locally

แบ่งเป็นสามชิ้นที่ใช้ได้แยกกัน: **Save Analysis → findings/notes → text/hex preview** เริ่ม Save Analysis ก่อนเพราะแก้ข้อจำกัดของฟีเจอร์ 0.3.0 ได้โดยไม่เพิ่มชนิดเนื้อหาที่ส่งออก

- เพิ่ม schema-v1 sidecars `analyses/<record-id>.json`, `findings/<revision-id>.json` และ `extractions/<record-id>.json` ภายใน `.nativecase` รักษา manifest v1 และ historical listing JSON เดิม ไม่ migrate/rewrite เคสโดยอัตโนมัติ
- Analysis record เป็น immutable receipt ผูก case/evidence IDs, exact file locator, filesystem snapshot digest/job reference กับ selected-entry/provenance summary, ordered container hashes พร้อม hash scopes, engine/options, extracted-content digest ถ้ามี, prompt-template/CLI versions, request digest, warnings และ structured answer ไม่คัดลอก listing เต็มลงทุกคำตอบ เวอร์ชัน model/provider บันทึกเฉพาะที่ตรวจได้จาก execution receipt; ค่าที่ไม่ทราบต้องระบุ unknown
- ตั้ง serialized/read cap เริ่มต้น 1 MiB ต่อ record และ history pages สูงสุด 50 records; oversized save ต้องรายงาน failure โดยไม่ตัด record เงียบ ๆ ไม่โหลด history ทั้งเคสลง MainActor การเปิดรายการต้องอ่าน/validate แบบ bounded และทดสอบ aggregate memory เมื่อมีประวัติจำนวนมาก
- ผู้ใช้เลือก Save หลังได้คำตอบที่ผ่าน response validation แล้ว หน้าบันทึกแจ้งว่าคำถาม/คำตอบ/metadata อาจมีข้อมูลส่วนตัว; exact outbound context และ text excerpt ต้องเป็น retention choice ที่มองเห็น ไม่มี raw provider log/credentials/host source paths ที่บันทึกตามมาโดยอัตโนมัติ `full` เก็บ exact UTF-8 request bytes ที่แอปส่งให้ CLI หลัง redaction รวมคำถาม/template text ที่ใช้จริง; ไม่สร้าง prompt ย้อนหลังจาก template version และไม่อ้างว่าเป็น HTTP payload ภายใน CLI `digestOnly` เก็บ digest แทน request bytes จึงสร้าง request เดิมกลับมาไม่ได้
- Findings/notes เป็นงานของผู้ตรวจ แยกจากคำตอบ AI และมีสถานะยังไม่ตรวจ/ตรวจเทียบแล้ว/ปฏิเสธพร้อมบันทึกเหตุผล ไม่มีการยก AI answer เป็น verified finding อัตโนมัติ การแก้ note ต้องมี revision reference; extraction history ผูก file/source/output scopes และยังแสดง historical/offline state
- แยก verified-content service จาก AssistantContextBuilder โดยคง owned descriptors, scratch lifetime และ independent output verification ให้ preview/decoders/AI ใช้ผลเดียวกัน เริ่ม regular file ขนาดไม่เกิน 1 MiB และ text prefix 32 KiB ตามฐานปัจจุบัน; hex แสดง byte offsets ของ extracted bytes, text แสดง encoding/truncation กับ line references ของ derived view
- Inspector เพิ่ม Properties / Content / Findings; แสดง loading/partial/error ในตำแหน่งเดิม พร้อม keyboard navigation, copy text และ labels ที่อ่านได้ด้วย accessibility ห้ามผล preview ของ selection เก่าทับ selection ใหม่

Gate: Save → Quit → Reopen ได้ record/notes เดิม; full-retention request hash คำนวณซ้ำตรง; case v1 เปิดได้; offline/changed source อ่าน record เป็น historical ไม่แสดงว่าเพิ่ง verify ใหม่ Test interrupted/disk-full/concurrent saves, corrupt/unknown schema, symlink replacement และ selection races ต้องไม่ทำ record/source เดิมเสียหาย Preview UTF-8/Thai/empty/binary/truncated มี expected bytes/hash และ cancel/close ล้างเฉพาะ owned scratch

### ช่วง 2: เอกสารและ content search

- สร้าง decoder contract คืน file digest, decoder/version/options, derived-text digest, page/line references, coverage และ failure/partial status เริ่ม text/CSV/JSON/logs กับ PDF ที่มี text layer; scanned PDF/OCR, Office macros และ image inference จัดเป็นขอบเขตถัดไป
- ทดลอง PDFKit สำหรับ native PDF text/rendering ตาม [Apple PDFDocument](https://developer.apple.com/documentation/pdfkit/pdfdocument) และ [PDFPage.string](https://developer.apple.com/documentation/pdfkit/pdfpage/string) ก่อนเลือก implementation ใช้ decoder process ที่ควบคุม inputs/resources และต้องตรวจ sandbox/network/file-access behavior จริง; process isolation อย่างเดียวไม่ใช่ security boundary GUI รับ safe derived output ไม่รัน actions/macros/เปิด external resources
- PDF reference ระบุหน้าและช่วงข้อความที่ decode ได้ ไม่อ้างว่าเป็น byte range ของ original PDF Cache key ครอบคลุม verified source set, file locator/extracted digest และ decoder version/options; inode/mtime อย่างเดียวไม่แทนการตรวจ source hash
- แยก rebuildable derived index จาก manifest/listing ที่มีอยู่ ทดลอง SQLite FTS5 เทียบ substring baseline ก่อนเลือก โดย [FTS5](https://www.sqlite.org/fts5.html) มี token/phrase/prefix และ trigram substring ที่มีข้อจำกัดสำหรับคำสั้น ต้องทดสอบไทยไม่มีช่องว่าง, combining marks, normalization และ queries 1–2 ตัวอักษร ไม่ถือ Unicode tokenizer เป็นคำรับรองภาษาไทย
- แสดงจำนวน indexed/skipped/failed/pending และ stale results ชัดเจน Search hit ผูก file ID + decoder reference + hashes; term ที่มีเฉพาะเนื้อหาต้องพบ ไม่ใช้ extension/path match อ้างว่าเป็น content search

Gate: known PDF/text/image fixtures ให้ข้อความ/หน้า/rendered outputs ตาม oracle; corrupt/encrypted/oversized documents, timeout/cancel และ decode failure ไม่ทำ GUI ล่มหรือส่งข้อมูลออก Index rebuild/incremental invalidation ตรง independent expected results ตั้ง byte/page/pixel/time/memory caps จาก experiment ก่อนเปิดใช้ และรักษา partial coverage ไม่ให้ผล “ไม่พบ” กลายเป็นข้อสรุปว่าไม่มีข้อมูล

### ช่วง 3: Codex ที่เปรียบเทียบและอ้างกลับได้

เริ่มสองไฟล์ใน evidence เดียวก่อน สำหรับ UTF-8 ใช้เพดานเดิม 32 KiB ต่อ excerpt รวมไม่เกิน 64 KiB และต้องจำกัดขนาด serialized request เพิ่มต่างหาก Budget สำหรับ PDF references กำหนดหลังช่วง 2 ผู้ใช้เลือก ranges/redaction และดู exact aggregate payload ก่อนทุก Send; local preview/search ไม่ส่ง cloud เก็บ selected ranges, transformation version/options, disclosed-text digest และ mapping กลับไป decoder references เพื่อไม่ให้ citations เลื่อนหลัง redaction โดยไม่เก็บข้อความที่ผู้ใช้ปิดบังเข้ามาตามหลัง

References ของคำตอบมี IDs/ranges ที่ตรวจว่าถูก disclosed จริงก่อนทำปุ่มเปิดหลักฐาน Reference ที่ resolve ได้ไม่รับรองว่าการตีความถูกต้อง Follow-up เป็น bounded reviewed request ใหม่ที่ผูก parent record; previous answer ถือเป็น untrusted interpretation ไม่เพิ่ม model tool access และไม่แก้ deterministic evidence/timeline facts

Gate: fabricated/out-of-range/stale references ถูกแสดง unresolved; เปลี่ยน selection/คำถาม/cancel ไม่บันทึกลงไฟล์ผิด; context budget/partial/missing-file coverage อยู่ทั้ง preview และ saved record; source/hash mismatch ไม่ส่งเนื้อหาออก CI ใช้ fake provider; live smoke ใช้ synthetic data และตรวจ permission contract ของ CLI เวอร์ชันที่รองรับ

### ช่วง 4–6: Timeline, recovery และ release

- **Timeline/reports:** เริ่ม filesystem events ที่มีแล้วและ browser/download parser แรกจาก known SQLite/WAL/SHM fixtures เก็บ raw time/precision/timezone assumption พร้อม deterministic normalization; DST gap/overlap ต้องมี policy ห้าม AI เติมเหตุการณ์ลง timeline Export JSON/Markdown ก่อน แล้วค่อย PDF report โดยแยก verified bytes, parser observations, hypotheses และ examiner notes
- **Recovery:** ใช้ PhotoRec adapter เป็น candidate ที่ต้องทดลอง พร้อม private output/scratch และ candidate offset/range/status/hash ระบุ unknown/unavailable เมื่อพิสูจน์ source extents ไม่ได้ แยก recovered logical bytes จาก original source extents และไม่อนุมาน contiguous range จาก output size เริ่ม JPEG/PNG/PDF/ZIP ที่มี oracle; fragmented/incomplete/false-positive และ two-independent-PDF/incremental-update gates ด้านล่างต้องผ่าน Carved candidate กับ deleted filesystem entry เป็นคนละชนิดข้อมูล
- **Release:** ปิด bugs ภายใน advertised capability และแจกพร้อม notices/corresponding source/relink materials, Developer ID/notarization เมื่อมี signing identity พร้อม ทดสอบ clean machine, macOS versions ที่ประกาศ และ physical MacBook Air M5 ไม่ลด Gatekeeper เพื่อชดเชย packaging ที่ยังไม่ผ่าน

APFS มี [separate system-view ADR](ADR-APFS-SYSTEM-VIEW.md) และ independent bounded profile corpus แล้ว แต่ snapshot/boot FileVault combinations ต้องมี positive acquisition/content evidence เพิ่ม OCR ทุกไฟล์และ engine rewrite ยังต้องมี ADR กับ independent corpus/measurement แยก ไม่ใช่ dependency ของ Save/preview/search แรก

### Backlog รอบแรกและการวัดผล

ช่วง 1 แยก implementation ตามขอบเขตด้านล่างแล้ว ดู [0.4 validation receipt](validation/2026-10-07-case-work.json) สำหรับผล local, retention/hash scopes และ GUI limitations; broad-format/compatibility/release gates ยังไม่ปิด:

1. Contracts/fixtures: AnalysisRecord, FindingRecord, retention modes, canonical request digest และ reference/status invariants
2. Core persistence: immutable sidecar publication/reopen, case ownership/locking, version handling และ fault-injection regressions
3. Native workflow: Save Analysis, per-file history, notes/bookmarks และ historical badges พร้อม GUI save/reopen checks
4. Verified-content service: shared ownership/cleanup contract และ extraction/hash regression parity กับ AssistantContextBuilder เดิม
5. Text/hex inspector: bounded content, copy/navigation/accessibility และ stale-selection/cancel/close regressions
6. Validation/docs: debug/release + real helper, bundle verification, end-to-end synthetic GUI receipt และ sanitized measurements

การวัดแยก source verification, extraction, decode/index, UI และ provider latency ใช้ cold/warm/mixed workloads และ fixed output oracles บันทึก p50/p95, peak app/helper RSS, cancellation cleanup และ UI interaction latency Provider time ไม่ใช้เป็นเครื่องชี้ว่า engine เร็วขึ้น; helper 1/2/4 results ไม่กำหนด production workers จนวัดทั้ง pipeline

เริ่ม baseline บน 50,000-entry workload ปัจจุบันก่อน ทดลอง 100,000/1,000,000 entries ได้ใน derived-store harness เท่านั้นจน query/paging/storage budgets ผ่าน ไม่เพิ่ม listing ceiling ที่ใช้งานจริงเพียงเพื่อทำ benchmark เป้าหมาย latency/RAM เชิงตัวเลขกำหนดจาก baseline และเครื่องเป้าหมาย พร้อม correctness gate และ regression budget ก่อนลงมือ optimize

## Phase 0 Native foundation ที่มีแล้ว

ขอบเขตเริ่มต้นใน repository: SwiftPM core และ SwiftUI desktop app สำหรับสร้างเคส, reopen manifest, เลือก source file, อ่าน bytes แบบ streaming, SHA-256, progress และ cancellation Hash ระบุว่าเป็น selected file bytes โดยไม่ตีความเป็น logical disk image

Acceptance gate:

1. สร้างเคสใน destination ที่ถูกต้อง และ reopen แล้ว metadata/evidence records ตรงเดิม
2. Synthetic known digest, empty file และ multi-chunk file ให้ผลตรงกับ independent hash tool
3. Cancel/read error/source changed ไม่สร้าง completed digest หรือ completed evidence state
4. Source hash before/after ไม่เปลี่ยน; writes อยู่ใน case/scratch ที่แยกออกมา
5. Unsafe/overlapping destinations, malformed manifest และ unsupported manifest version ได้ error ที่อธิบายได้โดยไม่เขียนทับข้อมูลเดิม
6. `swift test` และ `./script/build_and_run.sh --verify` ผ่าน พร้อมตรวจ GUI จาก `.app` bundle แยกจาก CLI test coverage

Phase 0 เดิมทำเฉพาะ selected-file inspection ส่วน listing/EWF logical reading เป็น implementation ใหม่ของ Phase 1 ดู test receipts และ GUI scope จริงใน [Validation](VALIDATION.md) การมีฟีเจอร์ใน code ไม่แทนการผ่านทุก gate

## Phase 1 Audited TSK adapter IN PROGRESS

ชุดแรกมี C++ helper เรียก TSK 4.15.0 โดยตรง พร้อม [exFAT offset patch](../patches/sleuthkit/exfat-utc-offset.patch), static libewf 20240506 และ patches สำหรับ [EWF read API](../NativeEngine/patches/ewf-20240506-read-api.patch), [explicit EWF segments](../NativeEngine/patches/ewf-explicit-segments.patch), [FAT dates ถึงปี 2107 บน 64-bit](../NativeEngine/patches/fat-64-bit-year-range.patch) Build/downloads ตรวจ checksum ตาม [dependency specification](../NativeEngine/dependencies.json) และเก็บ actual receipt ใน ignored `.engine/`

ส่วนที่มีใน code:

- RAW/EWF readers, byte-zero filesystem และ MBR/GPT partitions, allocated/deleted listing, NTFS attribute references และ extract-to-new-file SHA-256
- [Protocol v1](ENGINE-PROTOCOL.md), helper หนึ่ง process ต่อ job, progress, cancel/timeout/crash/protocol checks และ explicit partial states
- Swift client/cache/UI; 1 MiB frames, 128-row batches, 50,000 records และ 64 MiB serialized response/cache limits
- เลือก image type, sector size, listing limit 1–50,000 และ IANA evidence timezone พร้อม display timezone แยกต่างหาก
- Explicit ordered segments: no sibling discovery, intrinsic EWF order/completeness และ actual-opened-path validation
- Selected-file/container-segment hashes, hashes ของทุก ordered inputs, logical-image SHA-256 และ extracted-file SHA-256 เป็นคนละ scopes
- Atomic versioned JSON cache ที่เปิดเป็น historical result; extraction bytes ตรวจอิสระก่อน exclusive publication
- Portable NTFS corpus สร้างด้วย Python stdlib: resident/nonresident, allocated/deleted, fragmented runs, sparse hole, hardlinks, Unicode, file/directory ADS พร้อม exact bytes/locators และ 100 ns timestamps
- exFAT per-field offsets, unknown-offset IANA/DST interpretation, Gregorian date validation และ missing-time handling; valid-offset timestamps ตรวจภายใต้หลาย host timezones

ชุด readiness 0.2.5 ผ่าน native 105 checks รวม 26 image configurations และ Swift 59 core + 20 workspace/presentation tests; ดู [historical Readiness](READINESS.md) ส่วน 0.4.0 ผ่าน Swift 130 core + 72 app ทั้ง debug/release พร้อม real helper และ Python harness/artifact 23 tests C++ helper ไม่เปลี่ยน GUI เพิ่ม durable case work/local preview ต่อจาก limit validation, partial cache reopen/export, native cancellation และ failure ที่รักษาผลเดิมไว้ ดู coverage และข้อจำกัดใน [Validation](VALIDATION.md)

App 0.3.0 เพิ่ม [Analyze with Codex](CODEX-ANALYSIS.md): บริบทของไฟล์ที่เลือกและ optional UTF-8 excerpt ที่ตรวจ hash, explicit review ก่อนส่ง, คำตอบแบบ advisory แยก observations/hypotheses/limits และ cancellation ที่รอ cleanup ตัวอ่าน JSONL/permission profile ตรวจด้วย Codex CLI 0.160.1 การทดสอบ CI ใช้ fake provider; live GUI ใช้ synthetic FAT16 เท่านั้น นี่เป็นฟีเจอร์ช่วยตีความที่เปิดใช้แยก ไม่ใช่ document-content index หรือการปิด Phase 1 coverage gates

App 0.2.3 เพิ่ม single-pass background path search พร้อม superseded-query cancellation, store regressions และ 100-row presentation pages ลด fixed chrome และจัด inspector ให้ file details อยู่ก่อน image provenance มี matched search/scheduling experiment แยกจาก GUI frame measurements; optimized release เป็น default ของ app build งานนี้ไม่เปลี่ยน native helper worker policy

Acceptance gates ที่ยังต้องปิดก่อน Phase 1 complete:

- ATTRIBUTE_LIST/multilevel indexes, bounded compression, overwritten/deleted bytes และ bounded matching-key EFS มี independent positives/negatives แล้ว ต้องคง advertised profile/oracles ผ่าน current client/GUI/release gates; synthetic NTFS volumes ไม่รับรองทุก Windows acquisition
- Unknown-offset DST overlap/gap, political folds และ classic FAT invalid-calendar handling ผ่าน independent corpus แล้ว ต้องคง raw civil values/precision/candidates โดยไม่เลือก host-timezone instant ที่ไม่ได้บันทึก
- Fragmented deleted FAT retained/cleared/damaged/reallocated mappings มี independent differential checks แล้ว ต้องคง explicit uncertainty/refusal ของ unknown multi-cluster order; exported current bytes ไม่รับรอง historical content
- Negative input/protocol/cancel coverage พร้อม retained partial/error state และ safe export races; ผลที่ผ่านจริงระบุใน Validation ไม่อนุมานจาก code
- วัด worker policy ทั้งแอปต่อจาก helper 1/2/4 experiment ที่ผ่านแล้ว: Swift prehash/publication, mixed/cold/large inputs, battery/thermal และ GUI RAM; 50,000/64 MiB limits ไม่แทน memory scheduler
- Full GUI flow เพิ่ม create/inspect cancellation, fresh unsupported input, partition-open partial results และ cancel/save/publication races; success, listing-limit partial reopen/export, native hash cancellation และ retained-cache failure ผ่านพร้อม hash/receipt readback แล้ว
- Independent fixture outputs และ differential reference ตรงกันภายใน advertised capability ไม่ประกาศรองรับจาก compiled generic TSK formats เพียงอย่างเดียว

**UDF ไม่มีใน TSK adapter ที่เลือก** แต่ 0.5 มี Swift adapter แยกสำหรับ RAW 2,048-byte / UDF 2.01 physical/virtual VAT profile พร้อม synthetic malformed-input corpus และ independent assignment extents/hash oracle ยังไม่ครอบคลุม UDF ทุก profile 0.7 เพิ่ม separate experimental APFS allocated system view และ bounded EFS matching-key pipeline ตาม positive corpus; snapshots/boot FileVault/other encrypted profiles คง Phase 3 gates SQLite result store ยังเป็นทางเลือกหลัง bounded JSON/workload measurement ส่วน manifest-v2 migration ที่มีแล้วเป็น explicit transaction ไม่ใช่ automatic storage-backend migration

ก่อนแจก helper ต้องจัด dependency source/licenses/relink package ให้ครบ Local `.engine/relink/` และ source archives เป็น artifacts ที่เก็บไว้สำหรับงานนี้ ไม่ใช่ completed distribution package

## Phase 2 Recovery content search และ previews

เพิ่ม PhotoRec adapter สำหรับ filesystem ที่เสียหายและ unallocated-space workflows พร้อม scratch/output isolation เลือก document text extractor และ content index ด้วยการทดลอง workload แล้วเพิ่ม native file preview โดยอ่านเฉพาะ exported/scratch content ที่ควบคุมได้ [PhotoRec](https://www.cgsecurity.org/wiki/PhotoRec)

Acceptance gate:

- Carving ของ two independent PDFs ต้องได้สอง candidates ที่แยกกัน และยังรองรับ valid PDF incremental updates; ไม่ถือ span ใหญ่เป็น exact result โดยไม่มี validation
- JPEG/PNG/PDF/ZIP และชนิดที่ประกาศรองรับมี expected counts/content digests; ตรวจ incomplete/fragmented candidates และ false positives พร้อม provenance ของ offsets/ranges
- Search terms ที่มีเฉพาะในเนื้อหาเอกสารต้องพบ; metadata-only query, Thai/Unicode, phrase/prefix และ cancellation มีผลคาดหวัง
- Exported bytes มี hashes และ file validation status; never label carved candidates เป็น deleted files โดยอัตโนมัติ
- Previews ที่ corrupt/unsupported ไม่ทำ UI crash และไม่เปิด arbitrary network resources หรือ embedded executable content

## Phase 3 Artifacts timeline และ release quality

เพิ่ม parser modules ทีละชนิดโดยใช้ independent fixtures เริ่ม browser/download artifacts และ timeline ที่รักษา timezone assumptions เพิ่ม case integrity reports, reproducible exports และ schema migrations จากนั้นจึงประเมิน APFS, snapshots และ FileVault ด้วย images ที่ทราบผลจริง

Acceptance gate:

- Classic timezone-less syslog, RFC3339, DST overlap/gap และ filesystem timestamps ให้ timeline พร้อม source/assumption/precision ที่อ่านได้
- SQLite/WAL sidecars และ live-like artifact consistency ตรวจจาก scratch copies โดยไม่แก้ source
- APFS/FileVault ระบุ exact supported combinations และผ่าน encrypted/decrypted content tests; raw ciphertext scanning ไม่ถูกเสนอเป็น plaintext recovery
- Password/recovery key ไม่อยู่ใน argv, logs, environment, case manifest หรือ exported reports
- Case/export manifest มี component versions, selected parameters, source hashes, warnings และ partial-job status ที่ตรวจซ้ำได้
- GUI create → select → analyze → browse → preview → extract → reopen → export ผ่าน flow tests ทั้ง success/cancel/failure
- ARM64 dependency/signature/notarization และ clean-machine distribution ผ่าน; ทดสอบ MacBook Air M5 จริง พร้อม RAM/thermal/battery measurements ก่อนอ้างผลของ M5

## เงื่อนไขเพิ่มประสิทธิภาพ

มี matched native-helper concurrency experiment และ [repaired Autopsy import comparison](AUTOPSY-COMPARISON-2026-10-07.md) แล้ว; ยังไม่มี full GUI/module-parity หรือ production worker-policy claim ใช้ profiler และ [matched benchmark](BENCHMARKS.md) เพื่อเลือกว่า component ใดควรปรับ เป้าหมายของแต่ละ optimization ต้องระบุเวลา, throughput, peak memory หรือ UI latency ที่จะลด พร้อม unchanged correctness outputs

งานตัวอย่างที่ควรทดลองคือ fewer rereads, bounded streaming buffers, batched DB/index writes, export/hash pipeline และ preview caching Worker defaults ต้องมาจากผลบนหลาย workload/power policies ไม่ใช้ชื่อรุ่น CPU กำหนดจำนวน threads เพียงอย่างเดียว

## เงื่อนไขออกจากแต่ละ milestone

เก็บ test receipts และ benchmark summary ที่ sanitize แล้วใน repository พร้อม limitation ของ coverage บัคที่เปลี่ยน content bytes, dropped files, timestamps หรือ source integrity เป็น release blockers ภายใน capability ที่ประกาศรองรับ Features ที่ยังไม่ผ่าน gate แสดงเป็น unavailable/experimental และไม่ถูกนับเป็น parity

# NativeForensics 0.6.0 / build 15

รุ่นนี้ต่อ workflow เลือกหลักฐาน → ค้นเนื้อหา → เปรียบเทียบไฟล์ → timeline → รายงานและตรวจเคส โดยไม่เขียน source bytes ใช้ engine **0.1.3-tsk4.15.0** เป็น development milestone ภายใน bounded capabilities; ยังไม่ปิดทุก gate ของแผน 1.0

## Workflow

1. เปิดเคสและวิเคราะห์ filesystem ของ sources ที่ต้องการ
2. **Content Search → Rebuild Index** ตรวจ source/extracted/decoder hashes และสร้าง derived index จาก saved listings ทุก source ค้น literal text/ไทย/คำสั้น พร้อม references และ partial/historical coverage เปิด recorded file แล้ว preview/extract เพื่อ verify source ใหม่ [ขอบเขต](CONTENT-INDEX.md)
3. **Compare Evidence** เลือก **Use as A / Use as B → Prepare Comparison** สำหรับสอง regular UTF-8 files ใน evidence เดียว เลือก half-open byte ranges/redactions, rebuild disclosure และอ่าน exact request ก่อน Send ทุกครั้ง Save full/digest-only และ follow-up saved parent ได้ Citations resolve disclosed bytes ไม่รับรอง AI interpretation เปลี่ยน redaction แล้ว parent เดิมถูกล้าง [วิธีใช้](MULTI-EVIDENCE-CODEX.md)
4. **Timeline** สร้าง filesystem timeline หรือเลือก allocated Chromium `History` พร้อม explicit coherent WAL/SHM ผลรักษา raw epoch/nanoseconds/assumptions; parser rows ไม่พิสูจน์การกระทำของบุคคล Export whole JSON/Markdown/hash receipt แยกจาก presentation filters [ขอบเขต](TIMELINE.md)
5. **Case Integrity** audit historical metadata โดย default เลือก fresh rehash เพื่อเปิด source ใหม่ ผลแยก pass/fail/historical/offline/unavailable ไม่มี automatic repair/migration ส่งออก report ใหม่โดย host paths ปิดเป็นค่าเริ่มต้น [วิธีใช้](CASE-INTEGRITY.md)

## Correctness

- [NTFS guards](NTFS-CAPABILITIES.md) ปฏิเสธ encrypted/compressed/FILLER/gap/invalid initialized coverage ก่อนสร้าง output คง legitimate sparse/uninitialized zeros และ valid ATTRIBUTE_LIST ตาม independent oracle เดิม encrypted bytes/เติมศูนย์ใน extents ที่ขาดอาจได้ completed receipt
- [PNG validation](RECOVERY-VALIDATION-0.6.md) แก้ ImageIO false-success ด้วย CRC/chunk/order/IEND และ bounded streaming zlib/scanline/Adam7 checks Padding ที่ specification อนุญาตมี warning แยก
- [Required decoder sandbox](DOCUMENT-SANDBOX.md) ใช้ exact POSIX realpath, system runtime reads และ denied writes/network/other exec ไม่มี unrestricted fallback แก้ `/var`/`/tmp` alias grants และ normalize Document/Codex pipes เป็น FD ≥ 3
- References ตรวจ immutable source/listing/content bindings ปฏิเสธ malformed integer overflow, forged citation maps และ changed disclosure parents Cancel/close รอ owned task/process/scratch cleanup

## Observed validation

Local Apple M2/macOS 27.0.1/Swift 6.4: debug/release แต่ละ configuration ผ่าน **527 Swift Testing declarations** (374 Core/36 suites + 153 app/20 suites) พร้อม real helper/fixtures Strict cooperative-executor probe ผ่านอีกหนึ่ง invocation Native **114/114**, Python **90/90** รวม complete source-provenance, staged debug-map removal และ full-byte privacy checks

[Actual synthetic workflow และ independent Python oracle](MILESTONE-WORKFLOW.md) ผ่าน 9 entries, 2 indexed/5 skipped/0 failed, Thai/short/combining search offsets, exact redaction, durable **fake answer**, 4 committed browser/WAL events, 19 combined timeline events, report bytes/hashes, historical/fresh audits และ source/manifest ไม่เปลี่ยน **ไม่มี AI provider request** ใน workflow นี้ แยกจาก live smoke ด้านล่าง และไม่ใช้ผลเหล่านี้รับรอง model accuracy

Before/after failures ของ temporary-path sandbox, closed stdio, incomplete PNG และ corrupted JPEG/wide-PNG test literals ถูกเก็บไว้ หลังแก้ fixtures จาก independent bytes คง counts/hashes/negative assertions และ production deadlines เดิม

หน้าจอของ bundle ที่ seal แล้วผ่าน reopen → browser/WAL import → export ครบ 19 events; อ่าน JSON/Markdown ที่เขียนจริงและคำนวณ SHA-256 ซ้ำตรง receipt โดย host paths ไม่ปรากฏ หลังปรับ folder picker เป็น async owned sheet การเลือกปลายทางและ cancellation ผ่าน GUI จริง รายงานเดิมไม่หาย

**Live two-file Codex smoke** ผ่านด้วย Codex CLI 0.160.1 และข้อความสังเคราะห์เท่านั้น: request 6,788 UTF-8 bytes หลัง redaction, คำตอบแบบ structured Thai, 3 disclosed citations, fresh citation เปิด `shared marker` ตรง source; Save full request แล้ว hash ตรงและไม่มี redacted secret/host paths; post-save integrity 6 checks ผ่านกับ 1 fresh source Follow-up เป็น local reviewed-parent preview ไม่มี request รอบสอง รุ่น model ไม่ปรากฏใน execution receipt จึงไม่อนุมานชื่อ model หนึ่ง smoke ไม่แทน general model accuracy

Release staging ตรวจ raw compiled hashes ก่อนใช้ `strip -S` กับสำเนา release เพื่อเอา linker debug map ออก เก็บ `.build`/dSYM เดิมไว้ ตรวจ executable ทุก byte แล้วจึง sign; debug build ไม่ผ่าน distribution gate ชุด ZIP สร้างซ้ำได้ bytes เดิมและมี source/license/relink material ตาม [distribution receipt](DISTRIBUTION-VALIDATION-2026-10-08.md)

ตรวจ reference exports ของ assignment เดิมแบบ read-only อีกครั้ง: **91/91** hashes/size/file identity ไม่เปลี่ยน และ 8 ไฟล์ชื่อ `.png` คง MIME/status เดิม (4 DOCX decoded, 4 unknown unsupported) corpus นี้ไม่มี PNG bytes จริง จึงไม่ใช้เป็นหลักฐาน PNG compatibility; PNG completeness ตรวจด้วย independent synthetic corpus แยก

## Completion gates

Content index จำกัด 512 documents/32 MiB ต่อไฟล์/256 MiB input/16 MiB text/32 MiB sidecar/600 วินาที ไม่รวม recovery/UDF history/OCR และยัง verify image ต่อ document จึงอาจถึง deadline บน large images No-match ไม่แทนคำรับรอง coverage ที่ไม่ได้อ่าน Timeline ยังไม่ครอบคลุม SQLite deleted/free pages, unsupported WAL layouts หรือ artifact families อื่น NTFS compression/EFS/APFS/FileVault และ arbitrary damaged/fragmented data ไม่ถูกนับเป็น general support

[Development distribution](DISTRIBUTION.md) รวม installer/sources/licenses/patches/relink recipe/file hashes ไม่ลบ quarantine หรือเปลี่ยน Gatekeeper Signing inventory พบ **0 valid Developer ID identities**; release mode fail closed เมื่อไม่มี trusted signing/notarization

ยังไม่ complete 1.0: supported App Sandbox/XPC replacement สำหรับ deprecated Seatbelt backend, Developer ID/notarization, clean-machine/physical M5/older-macOS checks, large/cold/mixed RAM/thermal/battery profiling, broader format/artifact coverage, future schema migration และ cryptographic authenticity Bundle/GUI/installer/exact-head CI receipts ตรวจแยกจาก Core tests Raw outputs อยู่ใน ignored `local/`; Git มีเพียง sanitized synthetic summaries ไม่มี user evidence/cases/credentials

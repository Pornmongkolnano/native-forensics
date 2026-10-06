# แผนพัฒนา NativeForensics

เป้าหมายแรกคือ native Mac workflow ที่สร้างและเปิดเคสได้ ตรวจ evidence file แบบ read-only และบอกสถานะงานได้ชัด จากนั้นเพิ่ม filesystem และ recovery coverage โดยผ่าน correctness gates ก่อนรายงานผลเรื่อง performance

ลำดับนี้เป็น milestones ที่ใช้ตัดสินใจจากผลทดสอบ ไม่ใช่กำหนดเวลาหรือข้อรับรองว่าแอปแทน Autopsy ได้ครบ ทุก phase ต้องรักษา source integrity และไม่ใส่ evidence/cases ของผู้ใช้ใน Git

## Phase 0 Native foundation

ขอบเขตเริ่มต้นใน repository: SwiftPM core และ SwiftUI desktop app สำหรับสร้างเคส, reopen manifest, เลือก source file, อ่าน bytes แบบ streaming, SHA-256, progress และ cancellation Hash ระบุว่าเป็น selected file bytes โดยไม่ตีความเป็น logical disk image

Acceptance gate:

1. สร้างเคสใน destination ที่ถูกต้อง และ reopen แล้ว metadata/evidence records ตรงเดิม
2. Synthetic known digest, empty file และ multi-chunk file ให้ผลตรงกับ independent hash tool
3. Cancel/read error/source changed ไม่สร้าง completed digest หรือ completed evidence state
4. Source hash before/after ไม่เปลี่ยน; writes อยู่ใน case/scratch ที่แยกออกมา
5. Unsafe/overlapping destinations, malformed manifest และ unsupported manifest version ได้ error ที่อธิบายได้โดยไม่เขียนทับข้อมูลเดิม
6. `swift test` และ `./script/build_and_run.sh --verify` ผ่าน พร้อมตรวจ GUI จาก `.app` bundle แยกจาก CLI test coverage

Phase 0 ไม่มี filesystem listing, image decompression, deleted-file recovery, carving, artifact parsing หรือ content index

## Phase 1 Audited TSK adapter

เพิ่ม C/C++ helper build ที่ pinned TSK 4.15.0 และ [exFAT per-entry offset patch](../patches/sleuthkit/exfat-utc-offset.patch) พร้อม provenance ใช้ versioned NDJSON protocol, owned-process cancellation, partial/error states และ bounded job coordinator Enumerate volumes/files, read logical file content, hash และ extract ไปยัง validated output Patch artifact ที่เก็บไว้ยังไม่ได้ apply หรือโหลดใน Phase 0

Acceptance gate:

- FAT16/FAT32, NTFS, exFAT และ UDF synthetic corpus มี expected filenames, allocation flags, sizes, timestamps และ content hashes; เพิ่ม raw/MBR/GPT/E01 ที่ build รองรับจริง
- Valid exFAT offsets UTC/+07:00 และ negative offsets ให้ UTC instants เดิมเมื่อ host timezone เปลี่ยน Unknown offsets, DST/invalid date และ precision มี policy/tests ที่แยกชัด
- Thai/Unicode names, long paths, empty files, 512/4096 sector sizes, split image ordering และ known fragmented content ผ่าน extraction checks
- Truncated/unknown images, read errors, native crash และ helper exit 0 ที่มี parse errors ไม่ได้ complete state ที่ทำให้เข้าใจผิด
- Worker 1/2/4 measurements ใช้ workload และ output เดียวกัน Peak memory และ queued bytes อยู่ภายใน configured policy; ไม่เพิ่ม parallel use ของ parser handles โดยไม่มีความมั่นใจเรื่อง thread safety
- Logical-image hashes แยกจาก container-segment hashes และรองรับ segment completeness ที่ตรวจได้

ก่อนเปิดใช้ helper ต้อง inventory source revisions, patches, native dependency closure, enabled image formats และ licenses ของ exact build

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

ใช้ profiler และ [matched benchmark](BENCHMARKS.md) เพื่อเลือกว่า component ใดควรปรับ เป้าหมายของแต่ละ optimization ต้องระบุเวลา, throughput, peak memory หรือ UI latency ที่จะลด พร้อม unchanged correctness outputs

งานตัวอย่างที่ควรทดลองคือ fewer rereads, bounded streaming buffers, batched DB/index writes, export/hash pipeline และ preview caching Worker defaults ต้องมาจากผลบนหลาย workload/power policies ไม่ใช้ชื่อรุ่น CPU กำหนดจำนวน threads เพียงอย่างเดียว

## เงื่อนไขออกจากแต่ละ milestone

เก็บ test receipts และ benchmark summary ที่ sanitize แล้วใน repository พร้อม limitation ของ coverage บัคที่เปลี่ยน content bytes, dropped files, timestamps หรือ source integrity เป็น release blockers ภายใน capability ที่ประกาศรองรับ Features ที่ยังไม่ผ่าน gate แสดงเป็น unavailable/experimental และไม่ถูกนับเป็น parity

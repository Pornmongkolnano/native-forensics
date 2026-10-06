# แผนพัฒนา NativeForensics

Native Mac foundation และ filesystem workflow ชุดแรกมี implementation แล้ว ปัจจุบัน **Phase 1 ยัง IN PROGRESS** เพื่อเพิ่ม corpus/coverage และ GUI validation ก่อนขยาย recovery/content analysis หรือรายงานผลเรื่อง performance

ลำดับนี้เป็น milestones ที่ใช้ตัดสินใจจากผลทดสอบ ไม่ใช่กำหนดเวลาหรือข้อรับรองว่าแอปแทน Autopsy ได้ครบ ทุก phase ต้องรักษา source integrity และไม่ใส่ evidence/cases ของผู้ใช้ใน Git

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
- เลือก image type, sector size และ IANA evidence timezone พร้อม display timezone แยกต่างหาก
- Explicit ordered segments: no sibling discovery, intrinsic EWF order/completeness และ actual-opened-path validation
- Selected-file/container-segment hashes, hashes ของทุก ordered inputs, logical-image SHA-256 และ extracted-file SHA-256 เป็นคนละ scopes
- Atomic versioned JSON cache ที่เปิดเป็น historical result; extraction bytes ตรวจอิสระก่อน exclusive publication
- Portable NTFS corpus สร้างด้วย Python stdlib: resident/nonresident, allocated/deleted, fragmented runs, sparse hole, hardlinks, Unicode, file/directory ADS พร้อม exact bytes/locators และ 100 ns timestamps
- exFAT per-field offsets, unknown-offset IANA/DST interpretation, Gregorian date validation และ missing-time handling; valid-offset timestamps ตรวจภายใต้หลาย host timezones

ชุด correctness ล่าสุดผ่าน native 87 checks และ Swift 41 tests รวม 20 image configurations ดู coverage และข้อจำกัดใน [Validation](VALIDATION.md)

Acceptance gates ที่ยังต้องปิดก่อน Phase 1 complete:

- NTFS corpus เพิ่ม ATTRIBUTE_LIST, multilevel directory indexes, compression/EFS และ deleted clusters ที่ถูกเขียนทับ; corpus ปัจจุบันเป็น minimal nonbootable volume
- Unknown-offset DST overlap/gap policy และ classic FAT invalid-calendar handling; offset ที่ไม่ทราบค่าต้องคง timezone assumption
- Fragmented deleted FAT recovery เมื่อ chain ถูกล้าง และ differential references ของ damaged/reallocated files; known intact NTFS deleted runs และ allocated fragmented FAT ผ่าน exact-byte checks แล้ว
- Negative input/protocol/cancel coverage พร้อม retained partial/error state และ safe export races; ผลที่ผ่านจริงระบุใน Validation ไม่อนุมานจาก code
- Worker 1/2/4 experiment และ profiler ก่อนสร้าง measured worker policy; 50,000/64 MiB limits ไม่แทน peak-RAM measurement หรือ memory scheduler
- Full GUI create → inspect → analyze → browse → extract → reopen ทั้ง success, partial, cancel และ failure พร้อม hash/receipt readback
- Independent fixture outputs และ differential reference ตรงกันภายใน advertised capability ไม่ประกาศรองรับจาก compiled generic TSK formats เพียงอย่างเดียว

**UDF ไม่มีใน TSK adapter ที่เลือก** ต้องมี adapter และ independent corpus แยกเพื่อรองรับงาน UDF; เป็น extension ที่ยังไม่ได้ implement APFS/FileVault/encrypted filesystems ถูกปิดไว้สำหรับ Phase 3 ส่วน SQLite result store/migrations ยังเป็นทางเลือกหลัง bounded JSON และ workload จำเป็นต้องใช้

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

ยังไม่มี matched benchmark claim ของระบบใหม่ ใช้ profiler และ [matched benchmark](BENCHMARKS.md) เพื่อเลือกว่า component ใดควรปรับ เป้าหมายของแต่ละ optimization ต้องระบุเวลา, throughput, peak memory หรือ UI latency ที่จะลด พร้อม unchanged correctness outputs

งานตัวอย่างที่ควรทดลองคือ fewer rereads, bounded streaming buffers, batched DB/index writes, export/hash pipeline และ preview caching Worker defaults ต้องมาจากผลบนหลาย workload/power policies ไม่ใช้ชื่อรุ่น CPU กำหนดจำนวน threads เพียงอย่างเดียว

## เงื่อนไขออกจากแต่ละ milestone

เก็บ test receipts และ benchmark summary ที่ sanitize แล้วใน repository พร้อม limitation ของ coverage บัคที่เปลี่ยน content bytes, dropped files, timestamps หรือ source integrity เป็น release blockers ภายใน capability ที่ประกาศรองรับ Features ที่ยังไม่ผ่าน gate แสดงเป็น unavailable/experimental และไม่ถูกนับเป็น parity

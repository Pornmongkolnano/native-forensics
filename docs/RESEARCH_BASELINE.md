# หลักฐานที่ใช้เลือกฐาน native

บันทึกนี้สรุปผลประเมินวันที่ 6 ตุลาคม 2026 เพื่อกำหนด acceptance tests ของ NativeForensics เป็น snapshot ของรุ่นที่ตรวจ ไม่ขยายผลเป็นข้อรับรองทุก parser, filesystem, GUI หรือเครื่อง Apple Silicon รุ่นอื่น

## รุ่นและขอบเขต

Strata v0.2.0 ตรวจ exact commit `c2b587a5aee921f9d15268d79fd7abbf42a8a25f` Release payload ใช้ TSK 4.15.0 มี SwiftUI frontend ส่วน reference คือ Autopsy 4.23.1 ที่ปรับสำหรับ ARM64 พร้อม TSK 4.15.0 และ exFAT UTC-offset patch ของ build ที่ตรวจ

หลักฐานมาจากการประเมินภายในโดยใช้ synthetic inputs และ source probes รายงานเต็มและ raw receipts เก็บแยกจาก repository เพราะมี host-specific paths Source และ release ที่ตรวจ: [Strata v0.2.0](https://github.com/norbertbonnici/Strata/tree/v0.2.0), [release](https://github.com/norbertbonnici/Strata/releases/tag/v0.2.0), [Autopsy 4.23.1](https://github.com/sleuthkit/autopsy/tree/autopsy-4.23.1)

## ผลที่กำหนดการตัดสินใจ

| ผลประเมิน | ขอบเขตหลักฐาน | ผลต่อ NativeForensics |
|---|---|---|
| Strata เปิดได้และลายเซ็น/notarization ผ่าน | release ที่ดาวน์โหลด บน ARM64/macOS 27.0.1 | native app viability; ไม่ใช้แทน full-flow correctness |
| 55 Swift tests ผ่าน | isolated harness จาก 17 upstream files ใน 6 suites | ไม่เรียกว่า full Xcode/GUI suite และไม่ใช่ tests ของโครงการใหม่นี้ |
| Native matrix 20 runs; valid extraction hash ตรง 46 ครั้ง | 14 valid runs + 6 negative/control runs ของ FAT16 raw/MBR/GPT/E01, exFAT, NTFS | ใช้รูปแบบ matrix และ expected byte hashes ต่อไป |
| Source SHA-256 ไม่เปลี่ยน | ทุก input ใน matrix ที่ตรวจ | before/after integrity เป็น gate ของทุกงาน |
| exFAT times คลาด 7 ชั่วโมงในบาง host TZ | downloaded native binary; valid entry offsets +07:00/UTC; audited patch ผ่าน fresh UTC/Bangkok controls | per-entry offsets และ host-TZ invariance เป็น blocker tests |
| Two PDFs ได้หนึ่ง 1,681-byte carve | unmodified source probe; second header offset 1,353 ไม่มี result แยก | adjacent documents/incremental PDF corpus ก่อนใช้ carver |
| Search ไม่พบคำเฉพาะใน file content | source/test probe; filename query พบ แต่ content-only query 0 hits | content-index scope ต้องทดสอบแยกจาก metadata search |
| APFS-only carving menu และ 7 formats | source review ของ release: SQLite, binary plist, PNG, JPEG, PDF, ZIP, gzip | ต้องเพิ่ม damaged FAT/unallocated workflows ใน Phase 2 |
| Malformed/truncated ingest tool exit 0 พร้อม stderr errors | native controls; caller source ใช้ exit success แล้วโหลด DB | protocol terminal/partial status และ output validation จำเป็น |
| GUI case flow ยังตรวจไม่ครบ | folder picker ปุ่ม Open disabled ทั้ง New Case/Set Case Library; สาเหตุไม่ยืนยัน | ไม่เรียก GUI flow ว่าผ่าน; เริ่ม native case foundation ใหม่ |

Forced E01-as-raw controls ใช้เพื่อดู failure behavior App ของ Strata เลือก `ewf` ให้ E01 ตาม extension ได้อยู่แล้ว จึงไม่ยก control ที่บังคับผิดเป็น format-selection bug ของ app

## ข้อค้นพบเพิ่มจาก source

Strata `FsApfsIngestor` ส่ง FileVault password/recovery key ใน child argv ส่วนอีก extraction path ใช้ stdin แล้ว NativeForensics จึงกำหนด secrets ผ่าน private input channel และเพิ่ม no-secret-in-argv regression โดยไม่ใช้รหัสจริงใน research baseline

Classic Linux syslog parser สมมติ UTC สำหรับ timestamp ที่ไม่มี timezone Probe ของ 12:00 local กับ 12:00+07:00 ต่าง 25,200 วินาที Timeline ใหม่ต้องเก็บ evidence timezone และ assumption ที่แสดงได้

Sector-size behavior, real APFS/FileVault, UDF, fragmented deleted FAT และ GUI analyze/export ยังอยู่นอก validated coverage ของการประเมินนี้ ต้องสร้าง independent fixtures ก่อนประกาศรองรับ

## วิธีตีความ benchmark เดิม

NTFS synthetic image เดียวกันใช้ fresh processes/databases, warmup 1 คู่ และ measured runs 3 คู่สลับลำดับ ทั้งสองเส้นทางให้ metadata ของ expected files 7 ไฟล์ถูกต้อง Native CLI median process time 0.0300 s เทียบ Java/JNI probe 0.9030 s มีงาน startup/schema/verification ต่างกัน และไม่ครอบคลุม app pipelines จึงเป็น diagnostic ของ execution paths เท่านั้น

ไม่มี full-app matched workload หรือผล physical M5 ใน baseline นี้ ข้ออ้างความเร็วของระบบใหม่ต้องมาจาก [benchmark method](BENCHMARKS.md) หลังผ่าน output correctness gates

# Native Forensics

แอป forensic สำหรับ macOS ที่เริ่มจาก SwiftUI/AppKit และการรักษาความถูกต้องของหลักฐาน โครงการนี้เป็น **private repository** และอยู่ในช่วงสร้าง foundation

## ฐานที่เลือก

เลือก **Autopsy / Sleuth Kit lineage เป็นฐาน filesystem engine ในขั้นถัดไป** โดยเริ่มจาก TSK 4.15.0 และ exFAT UTC-offset patch ที่ตรวจแล้ว เขียนส่วนติดต่อผู้ใช้ใหม่ด้วย SwiftUI/AppKit ส่วน Strata ใช้เป็นแหล่งศึกษาสถาปัตยกรรมและทดสอบเทียบ ไม่มีการคัดลอกแอปหรือ runtime ของทั้งสองโครงการเข้า repo นี้

เหตุผลคือ engine ที่ปรับจาก Autopsy ผ่านการทดสอบเนื้อหาไฟล์และ timestamps แล้ว ส่วน Strata 0.2.0 ยังพบเวลา exFAT คลาด 7 ชั่วโมง, PDF สองไฟล์ถูกรวมในการ carving และขอบเขต search/recovery ที่ยังไม่ตรงกับงานที่ต้องการ รายละเอียดและทางเลือกอยู่ใน [ADR-0001](docs/adr/0001-native-foundation.md)

## เริ่มทำได้แล้ว: Phase 0

- สร้างและเปิดเคส `.nativecase` พร้อม manifest
- เลือกไฟล์ disk image แล้วอ่านแบบ read-only
- คำนวณ SHA-256 แบบ streaming แสดง progress และยกเลิกได้
- แสดงขนาดไฟล์, image-container และ filesystem signature hint
- บันทึก source reference และผล hash ลงเคส โดยไม่แก้ไข image
- ตรวจข้อมูลสังเคราะห์ด้วย Swift tests และสร้าง `.app` ที่รันได้

SHA-256 ในรุ่นนี้เป็น **hash ของ bytes ในไฟล์ที่เลือก** หากเลือก E01 หนึ่ง segment จะเป็น hash ของไฟล์ container segment นั้น การตรวจ logical image และครบทุก segment อยู่ใน milestone ของ engine

การอ่าน directory/filesystem, export/recovery, document-content indexing และ artifact analysis ยังอยู่ใน [แผนพัฒนา](docs/ROADMAP.md) Signature hint ไม่ได้ยืนยันว่า filesystem สมบูรณ์หรือ parse สำเร็จ

## Build และ run

ต้องใช้ macOS 14 ขึ้นไป และ Swift 6.1 ขึ้นไปผ่าน Xcode/Command Line Tools โครง foundation ไม่มี Homebrew, Java, Solr หรือ package dependencies ภายนอก

```sh
swift test
./script/build_and_run.sh --verify
```

แอปจะถูกสร้างที่ `dist/NativeForensics.app` ใช้ `./script/build_and_run.sh` สำหรับรันตามปกติ หรือ `--build-only`, `--debug`, `--logs`, `--telemetry` ตามงาน Codex Run action เรียก script เดียวกัน

## โครงสร้าง

```text
Sources/ForensicsCore/      Models, image inspection, case persistence
Sources/NativeForensics/    App, Views, Stores, AppKit panel services
Tests/ForensicsCoreTests/   Synthetic correctness and safety regressions
docs/                      Architecture, decisions, milestones, benchmark method
script/                    Reproducible local build/run
```

อ่าน [Architecture](docs/ARCHITECTURE.md), [Roadmap](docs/ROADMAP.md), [Engine process boundary](docs/adr/0002-engine-process-boundary.md), [Benchmark method](docs/BENCHMARKS.md) และ [Research baseline](docs/RESEARCH_BASELINE.md)

## หลักฐานและ dependency

Image, เคส, credentials, local logs และ build products ไม่อยู่ใน Git ใช้ข้อมูลสังเคราะห์สำหรับ tests เท่านั้น โครงการใหม่ยังไม่ได้กำหนด license สำหรับเผยแพร่ source; upstream dependencies คงสิทธิ์และ license ของตนเองตาม [Third-party notices](THIRD_PARTY_NOTICES.md)

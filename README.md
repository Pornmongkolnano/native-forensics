# Native Forensics

แอป forensic สำหรับ macOS ที่ใช้ SwiftUI/AppKit และรักษาความถูกต้องของหลักฐาน โครงการนี้เป็น **private repository** มี native foundation และ filesystem workflow ชุดแรกแล้ว โดย **Phase 1 ยังอยู่ระหว่างพัฒนาและตรวจ coverage**

## ฐานที่เลือก

เลือก **Autopsy / Sleuth Kit lineage เป็นฐาน filesystem engine** ปัจจุบันใช้ C++ helper ที่เรียก TSK 4.15.0 โดยตรง พร้อม exFAT UTC-offset patch และ static libewf 20240506 สำหรับ EWF เขียนส่วนติดต่อผู้ใช้ใหม่ด้วย SwiftUI/AppKit ส่วน Strata ใช้ศึกษาสถาปัตยกรรมและทดสอบเทียบ ไม่มี Autopsy Java/NetBeans หรือ Strata application runtime ในแอปนี้

เหตุผลคือ engine ที่ปรับจาก Autopsy ผ่านการทดสอบเนื้อหาไฟล์และ timestamps แล้ว ส่วน Strata 0.2.0 ยังพบเวลา exFAT คลาด 7 ชั่วโมง, PDF สองไฟล์ถูกรวมในการ carving และขอบเขต search/recovery ที่ยังไม่ตรงกับงานที่ต้องการ รายละเอียดและทางเลือกอยู่ใน [ADR-0001](docs/adr/0001-native-foundation.md)

## ความสามารถที่มีแล้ว

- สร้างและเปิดเคส `.nativecase` พร้อม manifest
- เลือกไฟล์ disk image แล้วอ่านแบบ read-only
- คำนวณ SHA-256 แบบ streaming แสดง progress และยกเลิกได้
- แสดงขนาดไฟล์, image-container และ filesystem signature hint
- บันทึก source reference และผล hash ลงเคส โดยไม่แก้ไข image
- วิเคราะห์ RAW/EWF ผ่าน helper process: filesystem ที่ byte offset zero หรือ MBR/GPT partitions, file listing, allocated/deleted metadata และ timestamps
- เลือก image format, 512/4096-byte sector size, IANA evidence timezone และ listing limit 1–50,000; เปลี่ยน display timezone โดยไม่เปลี่ยนค่าที่บันทึก
- เลือก additional image segments และตรวจ/เรียงลำดับเอง ไม่มีการค้น sibling files เพิ่มโดยอัตโนมัติ
- บันทึก listing ใน versioned JSON cache และ reopen เป็น historical result พร้อม warnings/partial status
- Extract file ไปยังไฟล์ใหม่ ตรวจขนาดและ SHA-256 ของ output ก่อน publish โดยไม่เขียนทับไฟล์เดิม
- จัดการ progress, cancellation, timeout, helper crash และ malformed protocol โดยไม่ใช้ exit 0 เพียงอย่างเดียวเป็น success
- ค้นหา file paths แบบยกเลิก query เก่าได้ โดยคง Unicode matching เดิมและทำงานนอก main thread; ตารางแบ่งหน้า 100 แถวพร้อมค้นหาจากผลทั้งหมด
- Analysis Options และ provenance พับได้; validation/partial warnings ยังมองเห็น และ inspector แสดงไฟล์ที่เลือกก่อนรายละเอียด image/hash scopes

Engine ส่งข้อมูลผ่าน [versioned NDJSON](docs/ENGINE-PROTOCOL.md) กำหนด frame ไม่เกิน 1 MiB, listing ไม่เกิน 50,000 records และ response/cache ไม่เกิน 64 MiB Limits แสดงเป็น partial/failure states; ขนาดเหล่านี้เป็น data limits ไม่ใช่ข้อรับรอง peak RAM ของ process

Hash scopes แยกกันชัดเจน:

| ค่า | Bytes ที่ครอบคลุม |
|---|---|
| Evidence SHA-256 | selected file bytes; หากเลือก E01 หนึ่ง segment คือ container segment นั้น |
| Source file hashes ของ analysis | hash แยกรายไฟล์สำหรับทุก segment ใน ordered input set |
| Logical image SHA-256 | logical image bytes หลัง RAW/EWF decoding รวมทุก segments ที่ระบุ |
| Extracted file SHA-256 | bytes ที่เขียนออกเป็นไฟล์ใหม่และตรวจซ้ำจาก output จริง |

Helper ตรวจ EWF segment order/completeness และปฏิเสธ segments ที่ถูกเปิดนอก ordered set ที่ผู้ใช้ระบุ Selected-file hash เพียงค่าเดียวไม่แทน logical-image hash หรือพิสูจน์ว่า split image ครบ

TSK adapter ชุดนี้ **ไม่มี UDF**; งาน UDF ต้องมี adapter แยก APFS/FileVault และ encrypted filesystem ถูกปิดไว้สำหรับ Phase 3 Carving, document-content indexing, previews และ artifact analysis ยังอยู่ใน [แผนพัฒนา](docs/ROADMAP.md) File/path filtering ใน UI ไม่ใช่ document-content search และ deleted metadata ไม่รับรองว่า content ยังสมบูรณ์

ดูผลและขอบเขตที่ตรวจจริงใน [Validation](docs/VALIDATION.md) ยังไม่รับรองทุก TSK filesystem, full GUI recovery flow หรือ performance ที่ดีกว่า Autopsy

## Build และ run

ต้องใช้ macOS 14 ขึ้นไป, Swift 6.1 ขึ้นไป, C/C++ toolchain ผ่าน Xcode/Command Line Tools และ Python 3 Build แรกต้องใช้ network เพื่อดาวน์โหลด pinned source archives/header แล้วตรวจ SHA-256 ก่อน build static helper จากนั้นใช้ verified build cache ใน `.engine/` แอปที่ build แล้วใช้ bundled helper และ macOS system libraries โดยไม่ต้องมี Homebrew, Java หรือ Solr

```sh
python3 script/build_native_engine.py
swift test
./script/build_and_run.sh --verify
```

`build_and_run.sh` เรียก native helper build ให้อัตโนมัติ แล้วสร้าง `dist/NativeForensics.app` แบบ optimized release สำหรับการใช้ปกติ/`--verify`/`--build-only` ใช้ `--debug` สำหรับ debug build และ LLDB หรือ `--logs`, `--telemetry` ตามงาน Codex Run action ใช้ script เดียวกัน

Independent native synthetic suite อยู่ที่ `python3 Tests/NativeEngine/run_tests.py` ส่วน real-helper Swift integration tests เป็น opt-in ตาม `NFTSK_ENGINE_HELPER` และ `NFTSK_SYNTHETIC_FIXTURES`; การผ่าน pure Swift/mock protocol tests ไม่แทน native format coverage

## โครงสร้าง

```text
NativeEngine/              C++ helper, pinned dependencies, patches and notices
Sources/ForensicsCore/      Case, byte inspection, engine client and result cache
Sources/NativeForensics/    App, Views, Stores, AppKit panel services
Tests/ForensicsCoreTests/   Synthetic correctness and safety regressions
Tests/NativeEngine/         Independent native synthetic fixtures and checks
docs/                      Architecture, decisions, milestones, benchmark method
script/                    Reproducible local build/run
```

อ่าน [Architecture](docs/ARCHITECTURE.md), [Roadmap](docs/ROADMAP.md), [Engine process boundary](docs/adr/0002-engine-process-boundary.md), [Native helper](NativeEngine/README.md), [Benchmark method](docs/BENCHMARKS.md) และ [Research baseline](docs/RESEARCH_BASELINE.md)

## หลักฐานและ dependency

Image, เคส, credentials, local logs และ build products ไม่อยู่ใน Git ใช้ข้อมูลสังเคราะห์สำหรับ tests เท่านั้น [Pinned dependency specification](NativeEngine/dependencies.json) ระบุ versions/source checksums; `.engine/manifest.json` เก็บ actual build receipt และ `.engine/relink/` เก็บ static relink artifacts รวม source archives/notices ใน cache

Development `.app` ใช้ ad-hoc signing และยังไม่เป็น distribution package ก่อนแจก binary ต้องจัด corresponding source/patches, licenses และ runnable relink recipe ของ static LGPL component พร้อม signing/notarization และ clean-machine checks โครงการใหม่ยังไม่ได้เลือก license สำหรับเผยแพร่ source ตาม [Third-party notices](THIRD_PARTY_NOTICES.md)

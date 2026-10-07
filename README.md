# Native Forensics

แอป forensic สำหรับ macOS ที่ใช้ SwiftUI/AppKit และรักษาความถูกต้องของหลักฐาน โครงการนี้เป็น **private repository** เวอร์ชัน 0.5 เพิ่ม recovery, optical history และ document examination สำหรับงาน assignment โดย **coverage ของ filesystem และ forensic artifacts ยังอยู่ระหว่างพัฒนา**

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
- **Analyze with Codex**: ถามเกี่ยวกับไฟล์ที่เลือก ทบทวน exact prompt ก่อนส่ง และดูคำตอบในแอปผ่าน Codex CLI เริ่มจาก metadata; เลือกรวม UTF-8 excerpt ได้พร้อมตรวจ source/extracted hashes ดู [วิธีใช้และขอบเขต](docs/CODEX-ANALYSIS.md)
- **Save Analysis**: เลือกบันทึกคำถาม/คำตอบ/ที่มาลงเคส พร้อม digest-only หรือ full exact-request retention แล้วเปิด per-file AI history ย้อนหลังได้
- **Examiner notes**: บันทึก note revisions, bookmark, tags และ review reason แยกจาก AI โดยตรวจ concurrent revisions และเตือน unsaved drafts ก่อนปิด
- **Local Text/Hex Preview**: extract/ตรวจ source และ output hashes ใหม่สำหรับไฟล์ไม่เกิน 1 MiB แสดง prefix ไม่เกิน 32 KiB /50 rows ต่อหน้า โดยไม่ส่ง provider
- **Export history**: เก็บ path-free historical extraction receipts ที่ผ่าน verification ดู [Case work และ preview](docs/CASE-WORK.md) สำหรับ retention, limits และความหมายของ historical verification
- **Recovered Files**: กู้ candidates จาก RAW image ด้วย PhotoRec ที่ติดตั้งแยก ตรวจ bytes เทียบ source extents, เก็บผลแต่ละงานแยกกัน พร้อม examiner assessments, raw evidence hex และ Markdown report; carving ไม่พิสูจน์ original filename หรือ deletion
- **Optical History**: อ่าน RAW / 2,048-byte / UDF 2.01 VAT profile ด้วย Swift reader แยกจาก TSK, แสดง current files และ linked historical namespaces พร้อม ancestor deletion proof, raw timestamps, extents และ verified export/report
- **Verified Document Preview**: helper แยก process ตรวจ image/PDF/text/ZIP/Office จากเนื้อหาจริง แม้นามสกุลไม่ตรง; thumbnails, referenced text และค้นหาภายในไฟล์ที่เลือก โดยบอก partial/unsupported ชัดเจน ไม่มี OCR หรือ Office page-layout renderer
- **Export Matching Files**: export ทุกไฟล์ที่ตรง filter ทั้งผลการค้นหาไปยัง directory ใหม่ พร้อม per-file hashes และ manifest; ไม่จำกัดเพียง 100 แถวที่แสดงในตาราง

Engine ส่งข้อมูลผ่าน [versioned NDJSON](docs/ENGINE-PROTOCOL.md) กำหนด frame ไม่เกิน 1 MiB, listing ไม่เกิน 50,000 records และ response/cache ไม่เกิน 64 MiB Limits แสดงเป็น partial/failure states; ขนาดเหล่านี้เป็น data limits ไม่ใช่ข้อรับรอง peak RAM ของ process

Hash scopes แยกกันชัดเจน:

| ค่า | Bytes ที่ครอบคลุม |
|---|---|
| Evidence SHA-256 | selected file bytes; หากเลือก E01 หนึ่ง segment คือ container segment นั้น |
| Source file hashes ของ analysis | hash แยกรายไฟล์สำหรับทุก segment ใน ordered input set |
| Logical image SHA-256 | logical image bytes หลัง RAW/EWF decoding รวมทุก segments ที่ระบุ |
| Extracted file SHA-256 | bytes ที่เขียนออกเป็นไฟล์ใหม่และตรวจซ้ำจาก output จริง |

Helper ตรวจ EWF segment order/completeness และปฏิเสธ segments ที่ถูกเปิดนอก ordered set ที่ผู้ใช้ระบุ Selected-file hash เพียงค่าเดียวไม่แทน logical-image hash หรือพิสูจน์ว่า split image ครบ

TSK adapter ชุดนี้ **ไม่มี UDF**; Optical History ใช้ bounded Swift adapter แยก รองรับเฉพาะ profile ที่ระบุ APFS/FileVault, OCR, legacy Office body decoding และ computer activity artifact analysis ยังไม่มี File/path filtering ใช้ชื่อไฟล์ ส่วน content search ครอบคลุมข้อความที่ decoder อ่านได้ในไฟล์ที่เลือก ไม่ใช่ case-wide index Deleted metadata และ hash ที่ตรงไม่รับรองว่า content สมบูรณ์

เวอร์ชัน 0.5.0 / build 13 ต่อยอด [case work/local preview 0.4](docs/CASE-WORK.md) และ [Codex file analysis](docs/CODEX-ANALYSIS.md) ดู [assignment comparison](docs/ASSIGNMENT-VALIDATION-2026-10-07.md) สำหรับการเทียบ exact exported bytes, content validation และข้อจำกัดของโจทย์ ส่วน [repaired Autopsy benchmark](docs/AUTOPSY-COMPARISON-2026-10-07.md) เป็นผล 0.4 เฉพาะ workload ที่ระบุ ไม่ใช่ timing ของฟีเจอร์ใหม่หรือ full application parity

เริ่มใช้งานตาม [คู่มือ assignment](docs/ASSIGNMENT-WORKFLOW.md) ซึ่งแยก recovery, deleted filesystem files และ optical history พร้อมขอบเขตความหมายของผลตรวจ

## Build และ run

ต้องใช้ macOS 14 ขึ้นไป, Swift 6.1 ขึ้นไป, C/C++ toolchain ผ่าน Xcode/Command Line Tools และ Python 3 Build แรกต้องใช้ network เพื่อดาวน์โหลด pinned source archives/header แล้วตรวจ SHA-256 ก่อน build static helper จากนั้นใช้ verified build cache ใน `.engine/` Filesystem, document preview และ Optical History ใช้ bundled helpers/system frameworks โดยไม่ต้องมี Java หรือ Solr **RAW carving ต้องติดตั้ง PhotoRec แยก**; แอปค้นที่ `/opt/homebrew/bin/photorec` หรือ `/usr/local/bin/photorec` และแสดง unavailable หากไม่พบ ดู integration provenance ใน [notices](THIRD_PARTY_NOTICES.md)

```sh
python3 script/build_native_engine.py
swift test
./script/build_and_run.sh --verify
```

`build_and_run.sh` เรียก native helper build ให้อัตโนมัติ แล้ว stage/sign/ตรวจ provenance และ system runtime dependencies ก่อนแทน `dist/NativeForensics.app` แบบ optimized release สำหรับการใช้ปกติ/`--verify`/`--build-only` ใช้ `--debug` สำหรับ debug build และ LLDB หรือ `--logs`, `--telemetry` ตามงาน ตรวจ artifact แยกได้ด้วย `python3 script/validate_app_bundle.py dist/NativeForensics.app` Codex Run action ใช้ script เดียวกัน

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

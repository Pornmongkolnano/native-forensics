# NativeForensics 0.4.0 เทียบกับ Autopsy ที่ซ่อมแล้ว — 7 October 2026

รอบนี้ซ่อม correctness blockers ของ Autopsy ก่อนจับเวลา แล้วใช้ fixed schedule ใหม่กับ NativeForensics 0.4.0 แบบ Release บน Apple M2 / RAM 16 GiB / macOS 27.0.1 ผลเป็น **fresh-process headless create/verify/import/persist workflow** รวมการเริ่ม JVM/NetBeans/private Solr ของ Autopsy ไม่ใช่ความเร็ว GUI หรือ steady-state engine ทั้งสองระบบใช้สาย The Sleuth Kit 4.15.0

## การซ่อมและหลักฐานก่อนวัด

1. JNI เดิมส่ง stack buffer เข้า POSIX `putenv` ซึ่งเก็บ pointer หลังฟังก์ชันคืนค่า ตัวซ่อมใช้ `setenv` ที่คัดลอก string ก่อนคืน JNI string ให้ JVM ตาม [Apple environment API](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/putenv.3.html) การทดสอบ native stack pointer พบตัวเดิม `0 → 1` และตัวซ่อม `0 → 0`; probe เปรียบเทียบเฉพาะ addresses กับขอบเขต stack และไม่อ่านหรือส่ง environment strings
2. FAT เดิม export bytes ได้ครบ แต่ UTC epochs เร็วกว่า oracle 25,200 วินาที ตัวซ่อมผ่าน 9 combinations ของ source timezone และ process timezone (`UTC`, `Asia/Bangkok`, `America/New_York`) ทั้ง creation/modification, date-only access และ absent changed time โดย decode DOS fields จาก image แยกจาก TSK ของทั้งสองแอป ไม่ปรับ timestamp ที่ verifier เพื่อชดเชยข้อผิดพลาด
3. JNI importer เดิมเลือก default INDEX_ROOT ของ directory จึงข้าม named NTFS DATA ตัวซ่อมเพิ่ม stream row ชนิด regular file โดยรักษา default directory, hierarchy และ nested child ตัวเดิมได้ 12/13 payloads; ตัวซ่อมได้ 13/13 พร้อม exact bytes, stream identity, allocation และ timestamps

ซ่อมเฉพาะ ARM64 JNI resource ใน Java datamodel JAR: **363 members อื่นเหมือนเดิมทุก byte**, exported symbols ทั้ง 125 และ dynamic dependency closure เท่าเดิม, ARM64 และ strict ad-hoc signature ผ่าน `libtsk.23.dylib` ที่แก้ exFAT ไว้เดิมยังมี hash เดิม Candidate JAR SHA-256 `3ff4c5e32412cd29fecdb9bc58565630388ec9a0143d312eb709765c204f436f`; JNI SHA-256 `c5b857b705e6eb313ae8f9cfe5b4687ac8561a193b338eeb98c7e6c01c2402bf`

Autopsy โหลด JNI จาก `NATIVELIBS/aarch64/mac/libtsk_jni.dylib` ใน JAR ไม่ใช่เพียงไฟล์ standalone จึงตรวจ hash ของ resource **และไฟล์ที่ dyld โหลดจริง** ทุก full import/readback ก่อนยอมรับผล การควบคุม old/new ทำ 20 direct imports และ final artifact confirmation อีก 4 imports; full CLI readiness และ oracle readback ผ่านก่อนเริ่ม fixed schedule

ข้อสรุปเชิงสาเหตุแยกกัน: old/new reproduction ยืนยัน lifetime defect และแก้ FAT epochs ด้วย binary candidate ที่เปลี่ยน JNI; crash เก่าเกิดใน environment lookup และสอดคล้องกับ defect นี้ แต่ไม่ได้ replay crash เก่าแบบ deterministic จึงไม่รับรองว่าทุก crash ของ Autopsy มีสาเหตุเดียวกัน

Patch ไม่ครอบคลุม named streams บน filesystem-root inode, direct C++ database importer หรือ concurrent imports ที่เลือก timezone ต่างกันใน process เดียว ยังไม่มี full Autopsy feature-parity claim [Patch scope และ provenance](../Benchmarks/AutopsyComparison/patches/README.md)

## ผลรอบใหม่

| Synthetic workload | Native median (range), s | Repaired Autopsy median (range), s | Autopsy/Native ต่อคู่ (median) | Correct payloads ต่อ run |
|---|---:|---:|---:|---:|
| FAT16, image 2.44 MiB | 0.147490 (0.138530–0.152110) | 23.458734 (20.747421–26.239696) | 159.05× | 5/5 ทั้งสองแอป |
| FAT32, image 273.44 MiB / payload ใหญ่ 128 MiB | 0.812665 (0.804039–0.825035) | 23.159012 (21.365697–27.809818) | 28.55× | 6/6 ทั้งสองแอป |
| NTFS, image 16 MiB / resident, nonresident, directory ADS | 0.181305 (0.180846–0.255931) | 28.319510 (24.631339–32.712735) | 147.65× | 13/13 ทั้งสองแอป |

**ครบ 15/15 measured pairs และ warmups 3/3 คู่ ไม่มี failed attempts หรือ replacement** Autopsy จบ 18/18 full imports ใน schedule นี้ Native จบ 18/18 เช่นกัน ทุกครั้ง bytes/hash, allocation/stream identity และ independent timestamp gates ผ่าน Source/runtime/recipe hashes ระหว่างทดลองไม่เปลี่ยน และ private service cleanup ผ่าน

Ratios เป็น median ของ ratios แต่ละคู่ จึงไม่จำเป็นต้องเท่ากับการหาร median ของเวลาแต่ละแอป ความต่างมากใน images เล็กสัมพันธ์กับ fresh JVM/NetBeans/Solr bootstrap ซึ่ง Native core executable ไม่ต้องเริ่ม ผลนี้แสดงเวลา workflow นี้ ไม่ใช่ engine-only throughput, UI responsiveness หรือ full feature parity

เครื่องใช้ AC power; OS ไม่รายงาน thermal/performance warning ระหว่าง snapshot ก่อน/หลังทดลอง มี background load จากระบบจริงและค่ามี variation จึงเก็บ range ทุก attempt ไม่มี cold-cache หรือ dedicated-idle-machine claim

[Sanitized raw receipts และ old/new controls](benchmarks/2026-10-07-m2-repaired-autopsy-pipeline.json) เก็บ 5 pairs ต่อ workload, warmups, actual loaded JNI, timer method, errors/coverage และ recipe digestsครบ RSS/CPU fields เป็น sampled observations; ไม่มีการคำนวณ memory/CPU reduction ratio

## วิธีวัดและข้อจำกัด

- แต่ละ filesystem ใช้ warmup 1 คู่ที่แยกออก และ measured pairs 5 คู่; สลับลำดับด้วย seed `20261007` ประกาศ schedule ก่อน launch และไม่มี automatic replacement
- เปิด process/case ใหม่ทุก attempt; Autopsy ใช้ user/module cache ใหม่และ private Solr ที่มี ports/STOP.KEY แยก ปิดเฉพาะ process identities ที่งานนี้สร้าง ไม่เปิดเคสเรียนเดิม
- Timer เริ่มก่อน `Popen` และใช้ blocking exit observer ที่เริ่มทันทีหลัง launch หยุดเมื่อ waiter สังเกต process exit; แยก bounded watchdog ออกจาก timeout polling และไม่นับ subsequent Solr cleanup/readback/export เป็น app time ยังมี scheduler/exit-observation overhead จึงไม่ใช่ kernel exit timestamp
- ก่อนคำนวณ ratio ต้องผ่าน exact exports, known payload paths/sizes/allocation/stream classification, independent timestamp oracle, loaded JNI/libtsk hashes, source preservation และ cleanup gates ทุก measured pair ที่กำหนดไว้ Failed launch/readback/cleanup จะถูกเก็บใน attempt journal; final integrity failure ยกเลิก ratio ทุก workload
- FAT เวลา decode จาก DOS bytes ตาม UTC ที่ตั้งไว้ ส่วน NTFS ใช้ per-file synthetic oracle Native ตรวจ fractional nanoseconds ด้วย; Java datamodel ของ Autopsy รายงาน whole seconds จึงไม่มี fractional metadata parity claim
- Native วัด application core create/inspect/analyze/save รวม container SHA-256 4 passes, logical SHA-256, helper startup/traversal และ JSON persistence แต่ไม่รวม SwiftUI search-index/row refresh, notes/findings หรือ Codex workflow Autopsy วัด full NetBeans CLI import/persist SQLite และเริ่ม Solr แม้ไม่รัน ingest modules งาน persistence/bootstrap จึงมีต้นทุนต่างกัน
- Prehash ก่อน attempt อ่าน image ทั้งไฟล์ จึงเป็น **warm OS/file-cache** ไม่ใช่ cold disk หรือ fresh hardware cache ส่วน NetBeans module cache ยัง fresh ต่อ attempt
- FAT32 image 273.4375 MiB มีไฟล์ใหญ่ 128 MiB เพียงหนึ่งไฟล์พร้อม small controls; ใช้ประเมิน hashing/large-byte workload ไม่ใช่ scaling ของไฟล์นับหมื่น
- RSS/CPU เป็น sampled owned-process observations มีโอกาสพลาด short-lived children/peaks/exit tails แม้ไม่มี sampler error เก็บ coverage gaps และไม่รายงาน RAM/CPU reduction ratio
- Reference เป็น Autopsy 4.23.1 ที่ปรับสำหรับ macOS ARM64 และซ่อม JNI แล้ว ไม่ใช่ pristine vendor Windows build; version number ไม่เปลี่ยนเพราะ Java classes/GUI ไม่เปลี่ยน

เก็บ [รอบเก่า 6 October](AUTOPSY-COMPARISON.md) ไว้เป็น historical diagnostic evidence ตัวเลขเก่าผ่านเฉพาะ payload gates แต่ FAT timestamps ผิด, NTFS stream ไม่ครบ และ timer ใช้ timeout polling จึงไม่ใช้เกณฑ์เก่านั้นอ้างความเร็วหลังซ่อม หรือสรุปเปอร์เซ็นต์การปรับปรุงจากวันก่อนโดยตรง

## Reproducibility

Source recipe อยู่ที่ commit `0b92111b5e2089659cb1033da237e71f81e53287` พร้อม build receipt ของ Native 0.4.0, compiler, binary/helper hashes, per-product source hashes, frozen runtime/config/launchers และ control report hashes ทุก artifact ที่มี personal paths/runtime binaries/cases เก็บใน ignored `local/autopsy-comparison`; Git เก็บเฉพาะ synthetic sanitized receipts และ source/patches

```sh
swift build -c release --product ForensicsPipelineBenchmark
python3 script/build_autopsy_jni_repair.py \
  --source <audited-tsk-source> --jar <audited-original-tsk-jar> \
  --native-tsk <reviewed-exfat-libtsk> --original-jni <audited-original-jni> \
  --java-home <java17-home>
python3 script/stage_autopsy_repaired_profile.py \
  --setup <new-prepared-setup.json> --repair <repair-receipt.json> \
  --output local/autopsy-comparison/<new-repaired-profile>
python3 script/validate_autopsy_jni_repair.py --help
python3 script/compare_forensics_pipeline.py \
  --setup <frozen-setup-with-nativeBuild-and-controls.json> \
  --variant repaired-mac --verifier-classes <owned-compiled-verifier-directory> \
  --pairs 5 --seed 20261007
```

คำสั่งเป็น recipe ที่ต้องใช้ audited input hashes และ owned paths ตาม argument contracts ไม่ควรแก้ frozen hashes ให้ยอมรับ runtime ที่เปลี่ยนโดยยังไม่ตรวจใหม่ ถ้า installed baseline เปลี่ยนหลังทดลอง ต้องใช้ retained original backups หรือสร้าง setup ใหม่เพื่อทำซ้ำ; historical receipts ไม่ควรถูกแก้ตาม installation ปัจจุบัน

## Installation หลังการทดลอง

ติดตั้งเฉพาะ JAR/JNI คู่ที่วัดจริง โดยสำรอง binaries และ baseline เดิมก่อน เปลี่ยนด้วย atomic replacement แล้วสร้าง isolated smoke runtime จาก **ไฟล์ที่ติดตั้งจริง** ไม่ใช้ candidate paths เป็น source ของ smoke JAR/JNI Full CLI imports FAT16 และ NTFS หลังติดตั้งผ่าน bytes/UTC epochs ครบ 5/5 และ 13/13 พร้อม loaded JNI hash เดียวกับ benchmark

Health check สุดท้าย **30 PASS / 0 FAIL / 0 WARN** (INFO 2, SKIP 3 เพราะ app/Solr ไม่ได้เปิดค้าง) หลัง review delta เฉพาะ `tsk_jar` และ `tsk_jni` ใน baseline เดิม ไม่ regenerate inventory หรือรับ hash ใหม่ของ component อื่น components อื่นและ `libtsk` ที่แก้ exFAT ยังมี hash เดิม เก็บ original frozen baseline และ rollback binaries/receipt ไว้ใน ignored local installation directory ไม่เปิดเคสเรียนหรือเปลี่ยน user settings

Installation เป็นขั้นตอนหลัง benchmark; historical frozen setup ตรวจ installed hashes ก่อนซ่อม จึงตั้งใจไม่แก้ setup/report เก่าให้ตาม installation ใหม่ Post-install smoke มี setup/receipts ใหม่ที่ตรวจ current installed hashes แยกกัน

Python harness regressions **53 tests ผ่าน** ครอบคลุม timer, failure journaling, timestamp gates, loaded JNI, symlink/staging mutations และ app-bundle checks Native product source ไม่เปลี่ยนในการซ่อมนี้; Native release benchmark ถูก build ด้วย Swift 6.4 และผูก digest กับ source revision ใน receipt


# การเลือกฐานสำหรับ NativeForensics

สถานะ: Accepted สำหรับทิศทางการพัฒนา วันที่ 6 ตุลาคม 2026

NativeForensics จะสร้างส่วนติดต่อ macOS ใหม่ด้วย SwiftUI และ AppKit และใช้ The Sleuth Kit 4.15.0 จากสายที่ตรวจสอบร่วมกับ Autopsy เป็นฐาน filesystem engine ในระยะถัดไป รวมการแก้ exFAT UTC offset ที่ผ่าน regression ในการประเมินเดิม ส่วน Strata เป็นแหล่งศึกษาโครงสร้างและประสบการณ์ใช้งาน การตัดสินใจนี้ไม่ใช่การ fork แอป Java/NetBeans ทั้งชุด และยังไม่ได้นำ engine ใดมารวมใน Phase 0

## เหตุผลและหลักฐาน

การประเมิน Strata v0.2.0 ตรวจ exact tag ที่ commit `c2b587a5aee921f9d15268d79fd7abbf42a8a25f` ใช้ synthetic inputs และแยกการตรวจ source, native tools และ GUI ผลสำคัญบันทึกใน [research baseline](../RESEARCH_BASELINE.md)

| เกณฑ์ | Fork Autopsy ทั้งแอป | Fork Strata v0.2.0 | UI ใหม่กับ audited TSK lineage ที่เลือก |
|---|---|---|---|
| ส่วนติดต่อ macOS | ต้องย้าย Swing/NetBeans และ state จำนวนมาก | SwiftUI มีอยู่แล้ว | SwiftUI และ AppKit ตั้งแต่ต้น |
| Filesystem parsing | ใช้ TSK ผ่าน Java/JNI | ใช้ TSK 4.15.0 ผ่าน native tools | ใช้ TSK C/C++ ผ่าน helper ที่กำหนดสัญญาเอง |
| เวลา exFAT | รุ่นที่ปรับผ่าน UTC/Bangkok controls | ยืนยันการคลาดเคลื่อน 7 ชั่วโมงในบาง timezone | นำ patch มาตรวจซ้ำใน build ใหม่ก่อนเปิดใช้ |
| Recovery ที่ต้องการ | PhotoRec workflow มีฐานเดิม | เมนู carving เลือกเฉพาะ APFS และ 7 formats; PDF probe ได้ 2 เอกสารเป็น 1 result | เพิ่ม PhotoRec adapter หลัง filesystem foundation ผ่าน |
| ค้นเนื้อหาเอกสาร | Keyword Search และ text extraction มีฐานเดิม | UI search ของ release ตรวจ metadata และ artifacts ที่โหลดอยู่ | ทำ content index เป็น milestone ที่มี acceptance tests |
| ความพร้อมใช้งาน | ชุดเดิมยังใช้ทำงานต่อได้ | พบ partial/error และ GUI flow ที่ต้องตรวจต่อ | เริ่มเล็กกว่า แต่แยก milestone และผลลัพธ์ที่รับรองได้ชัด |
| ขอบเขต dependency | Java, NetBeans และ module runtime กว้าง | มีหลาย toolkit และ parser ที่ต้องตรวจ | เลือกเฉพาะ dependency ที่จำเป็น พร้อม provenance รายตัว |

TSK มี image, volume และ filesystem APIs อยู่แล้ว การเขียน parser ทุก filesystem ใหม่ตั้งแต่ต้นจึงเพิ่มภาระด้านความถูกต้องก่อนมีหลักฐานเรื่อง performance ส่วน native UI สามารถพัฒนาแยกจาก parser ได้ [TSK library API](https://www.sleuthkit.org/sleuthkit/docs/api-docs/4.15.0-develop/index.html)

Autopsy source ที่ตรวจมี Swing/NetBeans dependencies ในการจัดการเคสและ ingest การ fork ทั้งแอปแล้วเปลี่ยน UI จึงไม่ใช่การสับเปลี่ยนหน้าจออย่างเดียว Strata แสดงแนวทาง native ที่น่าสนใจ แต่ผลทดสอบความถูกต้องของ release ยังไม่ผ่านเกณฑ์ที่โครงการนี้ต้องการ [Autopsy source](https://github.com/sleuthkit/autopsy/tree/autopsy-4.23.1), [Strata release](https://github.com/norbertbonnici/Strata/releases/tag/v0.2.0)

## ขอบเขตที่เลือก

- เขียน desktop UI, case model, job orchestration และ protocol เป็นโค้ดของโครงการนี้
- Phase 0 ใช้ Foundation และ CryptoKit เพื่ออ่านและ hash selected file bytes เท่านั้น
- Phase 1 เพิ่ม native helper ที่ build จาก pinned TSK 4.15.0 พร้อม patch และ regression corpus ไม่มี Java/NetBeans runtime
- เก็บ [exFAT patch artifact](../../patches/sleuthkit/exfat-utc-offset.patch) ไว้เพื่อทำ reproducible build ใน Phase 1; SHA-256 คือ `fe17dab7a4f83f774eb9b4992801033131e66bf9579e91bc0e5aa5a5309613cf` Phase 0 ไม่โหลด TSK หรือ patch นี้
- ใช้ Autopsy ที่ปรับแล้วเป็น differential reference ร่วมกับ expected fixture outputs และ metadata บนดิสก์ การตรงกับโปรแกรมหนึ่งเพียงอย่างเดียวไม่พิสูจน์ความถูกต้อง
- ศึกษา Strata โดยไม่คัดลอก source หรือ binary เข้าฐานนี้ หากจะใช้ส่วนใดภายหลังต้องบันทึก exact revision และตรวจ license ของส่วนนั้นก่อน

การเลือก audited lineage ไม่ได้ทำให้ helper ที่จะเขียนได้รับผลรับรองจาก build เดิมโดยอัตโนมัติ Compiler, build flags, format libraries, bindings และ runtime paths ต้องตรวจใหม่ทั้งหมด การแก้ exFAT เดิมครอบคลุม valid per-entry offsets; malformed dates, unknown offsets และ DST ambiguities ยังต้องเพิ่ม corpus

## ทางเลือกที่เลื่อนออกไป

Parser engine ใหม่ทั้งหมดจะพิจารณาเป็นราย component หลัง profiler ชี้ต้นทุนและมี corpus ที่ยืนยัน output parity แล้ว ไม่ใช้ภาษาโปรแกรมหรือเวลาที่เร็วขึ้นบน fixture ขนาดเล็กเป็นเหตุผลเพียงอย่างเดียวในการแทน parser

In-process C/C++ binding อาจลดค่า process startup แต่เริ่มด้วย helper boundary เพื่อแยก crash, cancellation และ dependency lifecycle ตาม [ADR 002](0002-engine-process-boundary.md) จะทบทวนเมื่อ matched benchmark ระบุว่า protocol overhead เป็นต้นทุนสำคัญ

## ผลต่อการพัฒนา

ฐานนี้ให้ความสำคัญกับ evidence integrity, partial-result reporting และ timestamp provenance ก่อนเพิ่ม artifact coverage ชุดที่มีอยู่เดิมยังเป็น reference ระหว่างพัฒนา NativeForensics ไม่มี full Autopsy parity และยังไม่มีข้อสรุปว่าเร็วกว่าบน workload เดียวกัน

การออก release ต้องมี dependency inventory และ notices แยกกัน ไม่กำหนด blanket open-source license ให้โค้ดใหม่ในงานเริ่มต้นนี้ [Third party inventory](../../THIRD_PARTY_NOTICES.md)

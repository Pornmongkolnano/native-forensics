# Case work และ local preview — 0.4.0

เพิ่มงานของผู้ตรวจรอบ filesystem engine เดิม: saved AI analysis, notes/bookmarks/tags, extraction history และ text/hex preview ข้อมูลใหม่อยู่ใน `.nativecase` แยกจาก evidence; manifest schema v1 และ historical listing เดิมเปิดได้ ไม่มีการ migrate เคสหรือ rewrite cache อัตโนมัติ

## วิธีใช้

1. เปิดเคสและเลือกไฟล์ใน File Views
2. เลือก **Content → Load Preview** เพื่อ extract/ตรวจ hash แล้วอ่านในเครื่อง Text/Hex แสดงสูงสุด 32 KiB แบ่งหน้า 50 rows สำหรับ regular files ไม่เกิน 1 MiB Source hashes ตรวจใหม่ทุกครั้งที่ Load; metadata/timestamps และ logical-image hash ยังอ้าง recorded filesystem snapshot
3. เลือก **Findings → Notes** เขียน note, bookmark, tags และ review reason แล้วกด **Save Note Revision** สถานะ Compared/Rejected เป็นการประเมินของผู้ตรวจ ไม่ใช่การตรวจ bytes หรือคำรับรองจาก AI
4. ใน **Analyze with Codex** ทบทวน prompt และส่งตาม workflow เดิม เมื่อได้คำตอบกด **Save Analysis…** แล้วเลือก retention ก่อน Save Locally การบันทึกไม่ส่ง request เพิ่ม
5. เปิด **Findings → AI History** เพื่อดูคำถาม/คำตอบ/ที่มา; **Exports** แสดง receipt ของ extraction ที่ผ่าน verification ใน workflow ของแอป Saved notes และ AI records เปิดย้อนหลังได้แม้ source offline โดยมี historical labels

เปิด Content, Findings หรือ saved history ไม่ส่งข้อมูลไป provider การ Send to Codex ยังเป็น action แยกตาม [Codex analysis](CODEX-ANALYSIS.md) Text/hex preview ยังไม่ decode PDF/images/Office และ File Views ยังเป็น path search ไม่ใช่ document-content search

## Retention และความหมายของ records

- **Digest only (default):** เก็บคำถาม, AI answer, selected-file metadata/provenance และ request SHA-256 โดยไม่เก็บ exact prompt/text excerpt คำถามหรือคำตอบยังอาจ quote ข้อมูลหลักฐาน; digest สร้าง request เดิมกลับมาไม่ได้
- **Full:** เก็บ exact UTF-8 bytes ของ prompt ที่แอปส่งให้ CLI รวม question/template/context/excerpt ที่ผู้ใช้ทบทวน เป็น app-to-CLI receipt ไม่ใช่ HTTP payload ภายใน CLI; recompute SHA-256 ของ retained request ได้
- Records ผูก case/evidence IDs, exact stream/file locator, selected-entry digest, redacted filesystem-snapshot digest, ordered container hashes/byte scope, engine/options และ warnings ไม่คัดลอก listing เต็มลงแต่ละ answer และไม่เก็บ host source/export paths หรือ raw provider diagnostics ตามมา
- CLI/model version ที่ไม่ได้รับจาก validated execution receipt แสดง Unknown ไม่อนุมานจากการพบ executable หรือข้อความในคำตอบ
- AI observations/hypotheses กับ examiner notes แยกชนิดข้อมูล ไม่มี auto-verification Reference/digest ที่ตรวจผ่านไม่รับรองว่าข้อสรุป AI ถูกต้อง
- Extraction history ระบุ output bytes/hash ที่ตรวจเมื่อ export; การเปิด receipt ไม่ rehash source/output และไม่มี host output path ที่ใช้เปิดไฟล์ arbitrary ตามหลัง
- Source verification ของ preview/excerpt ตรวจ ordered source hashes กับ extracted bytes ในรอบนั้น ไม่ทำให้ metadata/timestamps/logical hash ของ snapshot กลายเป็นผลตรวจใหม่ และไม่รับรอง deleted contents ว่าสมบูรณ์

## Persistence และ limits

Sidecars schema v1 อยู่ใน `analyses/`, `findings/`, `extractions/` ภายในเคส Filename เป็น record UUID และ publication เป็น exclusive immutable new file ภายใต้ case lock Finding ใช้ revision IDs/parent chain กับ optimistic latest-revision check; concurrent edit ไม่ overwrite silent

Reads/writes ยึด held directory/file descriptors ตรวจ no-follow/regular-file/reference identities และ case/evidence scope ก่อน publication ใช้ synchronized staging + exclusive rename; cancellation ที่ยังไม่ commit ยุติได้ งานที่ commit ไปแล้วรายงานว่าบันทึกและต้อง drain cleanup ไม่อ้างว่าการ Cancel ลบ record ที่ publish แล้ว

Serialized record/read ไม่เกิน 1 MiB; history แสดงไม่เกิน 50 summaries/page และ diagnostics ไม่เกิน 50 details พร้อม total count ต่อ scan เก็บ working set ทีละ record ไม่โหลด full answers ของทั้ง page ลง UI การ fingerprint snapshot/history scan ยัง O(n) และทำ background; ไม่มี full-case index ในรุ่นนี้

Note ไม่เกิน 64 KiB, review reason 8 KiB, tags ไม่เกิน 32 distinct values /128 UTF-8 bytes ต่อ tag Oversized edit คงข้อความเดิมไว้และแสดง validation โดยไม่ตัดเงียบ ๆ Drafts เก็บใน window เมื่อสลับไฟล์: สูงสุด 32 inactive drafts /1 MiB รวม text กับ active editor อีกหนึ่งรายการ หากเก็บ draft ปัจจุบันเกิน budget จะบล็อกการเปลี่ยน file/case/reanalysis จนแก้หรือ discard

Drafts ไม่ autosave ปิด window/Quit จะเตือนเมื่อมี unsaved changes โดย default เป็น Cancel ผู้ใช้ต้อง Save หรือเลือก Discard อย่างชัดเจน การ close/quit ปิด saved-record sheets และรอ task owners ของ hashing/preview/reads/publication/helper cleanup

Corrupt/unknown-version sidecars ถูกเก็บเดิมและแสดง coverage diagnostics Corrupt finding history บล็อก revision save เพราะยืนยัน latest parent chain ไม่ได้; ไม่ลบ/repair records อัตโนมัติ Source/hash mismatch ของ fresh preview ไม่แก้ saved records

## ขอบเขตการตรวจสอบ

Synthetic regression suites ครอบคลุม exact-request retention/offline reopen, selection/cancellation/close races, revision conflicts, size/pagination/diagnostics bounds, no-follow paths และ publication faults รวมถึงการสลับไปมา A→B→A ระหว่าง save และ scope ที่ container byte count ถูกแก้

Shared verified-content ownership ตรวจ published inode จาก output descriptor ของ EngineClient ก่อนรับผิดชอบ scratch cleanup; replacement regular file/symlink/directory และ unknown leaves ต้องไม่ถูกลบ Text/hex มี Thai/Unicode/empty/binary/truncated fixtures และ real helper checks

ผล full debug/release, bundle และ GUI ของรุ่นนี้บันทึกแยกใน [Validation](VALIDATION.md) ส่วน Phase 1 filesystem coverage gates และ physical M5/clean-machine distribution ยังอยู่ใน [Roadmap](ROADMAP.md)

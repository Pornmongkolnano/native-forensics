# NativeForensics 0.5.1 / build 14

รุ่นนี้เพิ่มการส่งออก UDF จาก native workspace ไปวิเคราะห์ใน Autopsy และแก้การรอผล subprocess ที่อาจยึด Swift cooperative executor เมื่อมีหลายงานพร้อมกัน ใช้ parser, format limits และ engine เดิม ไม่เปลี่ยนเคสเก่าหรือหลักฐานต้นฉบับ

## ส่งออก UDF ไป Autopsy

1. เปิดเคสและเลือก RAW UDF image แล้วเลือก **Optical History** → **Inspect UDF History** ถ้ายังไม่มีผลที่บันทึกไว้
2. เลือก **Export for Autopsy…** แล้วเลือก parent folder นอกเคส แอปสร้างโฟลเดอร์ใหม่ชื่อไม่ซ้ำ
3. รอ receipt ที่ระบุจำนวนไฟล์และตำแหน่ง output สามารถ Cancel งานที่กำลังทำได้
4. ใน Autopsy ใช้ **Add Data Source → Logical Files** แล้วเลือก `LogicalFiles` ภายใน output เปิด File Type Identification และ Extension Mismatch Detector

ส่งออกทั้ง current และ historical inventory แม้ตารางกำลังค้นหา/กรองหรือเลือกเพียงหนึ่งไฟล์ เปรียบเทียบ source SHA-256/size กับ receipt ในเคสก่อนสร้าง stage ตรวจ source อีกครั้งและตรวจทุก payload/report ก่อน atomic publication ไม่มีการเขียนทับโฟลเดอร์เดิม เมื่อเปลี่ยน source/ปิดเคส งานเก่าจะไม่แสดงผลทับ selection ใหม่และ lifecycle รอเจ้าของงานล้าง process/scratch ของตน

การนำเข้า Logical Files ไม่ถ่ายทอด timestamps หรือ deletion flags จาก UDF เข้า Autopsy ให้ปิดตัวเลือกนำเข้า host timestamps และใช้ `Reports/udf-history.json` / `.md` อ้างข้อมูลต้นฉบับและ ancestor proof โฟลเดอร์ output ต้องอยู่ตำแหน่งเดิมหลัง import เพราะ Autopsy อ้างไฟล์เหล่านี้ `Reports` มี source metadata จึงควรทบทวนก่อนแชร์

หากงานล้มเหลว stage ส่วนตัวอาจยังอยู่สำหรับตรวจปัญหา ถ้า failure เกิดหลัง directory rename ให้ตรวจ `Reports/manifest.json` ก่อนนำเข้า; UI ไม่รับรองว่าไม่มี output เพียงเพราะพบ error ขอบเขตยังเป็น RAW/2,048-byte/UDF 2.01 physical+virtual+linked-VAT profile ภายใต้ limits เดิมและ deadline 600 วินาที ใช้ปุ่มนี้เฉพาะผลตรวจที่ใช้ default full-inventory options

## การรอ process และ cancellation

Engine, document decoder และ Codex client ใช้ concurrent native queue สำหรับ blocking poll ไม่ยึด cooperative executor Cancellation ตั้ง token ของงานนั้นและรอ operation unwind/reap จบก่อนส่งผลกลับ ยังคง output/frame caps, source checks, protocol และ process ownership เดิม Recovery ยังใช้ Task cancellation ตลอด pipeline จึงไม่ได้ย้ายโดยตัดกลไกนี้ออก

Fixtures ของการทดสอบ recovery/Codex เปลี่ยนจาก `sleep 30` เป็น ready handshake และ process ที่รอจนถูกสั่งหยุด ตัว controller ยกเลิกงานที่เป็นเจ้าของจาก native queue โดยตรง Assertions ยังตรวจ owned leader/descendant หาย, unrelated process ยังอยู่, source ไม่เปลี่ยนและไม่ publish generation เมื่อ cancel โดยไม่ขยาย production deadlines

Engine เปลี่ยน launcher เป็น explicit POSIX spawn ที่ปิด descriptors ของงานอื่นระหว่าง spawn และให้แต่ละงานมี process group ของตน เก็บ leader ด้วย `waitid(WNOWAIT)` จนหยุด descendants/reap จบ ก่อนคืนผล เมื่อเสีย ownership (`ECHILD`) จะไม่ส่ง signal อีก มี test จงใจเปิด unrelated writer โดยไม่ตั้ง CLOEXEC แล้วตรวจ EOF ขณะที่ helper ยังอยู่ รวมทั้ง cancellation ที่ยืนยัน owned descendants หยุดและ process อื่นยังอยู่ Fixture ของ unrelated process ใช้การแยก descriptors แบบเดียวกัน

## Validation

บน Apple M2/macOS 27.0.1: debug และ optimized release แต่ละ configuration ผ่าน **389 Swift Testing declarations** (270 Core/26 suites + 119 workspace/15 suites) พร้อม real filesystem helper/fixtures Core ใช้ maximum parallelization width 4 และยังทดสอบหลายงานพร้อมกัน ชุด Python harness/bundle ผ่าน **55/55** Strict single-thread cooperative executor probe ผ่านหนึ่ง test ซึ่งพิสูจน์ว่า async caller กลับมาปล่อย blocking worker ได้ ไม่ใช่การวัด throughput

CI แรกของ 0.5.1 บน macOS 26/Swift 6.3.3 พบ output-pipe lifetime และ fixture deadline failures จึงเพิ่ม explicit descriptor isolation ข้างต้น และแยก parser preparation ออกจาก deadline 0.1 วินาทีของ test ที่ตั้งใจวัด lock acquisition หลังแก้ การรันเต็มที่ไม่จำกัด concurrency บนเครื่อง local ยังพบ 3 helper startup/response timeouts เมื่อหลาย fixtures แย่งทรัพยากร ทั้ง debug/release ผ่านเมื่อจำกัดพร้อมกัน 4 test cases จึงใช้เงื่อนไขเดียวกันใน Core CI โดยคงครบทุก test, parallel coverage และ production deadlines เดิม การแก้นี้ไม่ได้อ้างว่าได้พิสูจน์สาเหตุ inheritance ของ Foundation บน macOS 26 จากเครื่อง local macOS 27

GUI ใช้ synthetic UDF fixture เดิมเท่านั้น เปิด saved optical receipt → กรองตารางเหลือ 1/2 → ยกเลิก chooser → retry → เห็น completed receipt สำหรับ **2/2** files การอ่าน output กลับด้วย Python เทียบ bytes กับ literal oracle แยกจาก exporter ตรงทั้งสองไฟล์ พร้อม payload/report hashes และ source SHA-256 เดิม New export ใช้ adapter case/job IDs แยกจากเคสที่เปิดอยู่ ไม่ได้ทดสอบ in-progress cancel ด้วย GUI ใน fixture ขนาดเล็กนี้; lifecycle/cancel/stale-selection cases ตรวจผ่าน store/core tests

การตรวจ GUI ต่อวันที่ 8 ตุลาคมพบว่าแผงผลส่งออกเดิมกินพื้นที่ตาราง จึงรวมจำนวนไฟล์และปุ่มไว้แถวเดียว พับคำแนะนำโดยค่าเริ่มต้นและจำกัดพื้นที่เลื่อนของรายละเอียด การทดสอบ AppKit วัด viewport ของ `NSTableView` จริงที่ 1040×660 และ 1280×780 ทั้งก่อนและหลัง completed receipt รวม 4 กรณี ยืนยันว่าแสดงอย่างน้อย 3 แถวครบโดยไม่ขยาย split view เกินหน้าต่าง ทดสอบ workspace 119 declarations ซ้ำทั้ง debug/release ผ่าน และเปิด bundle ใหม่ส่งออก fixture ซ้ำเพื่อตรวจ bytes/hashes และการเปิด/พับคำแนะนำผ่าน GUI

`build_and_run.sh --verify` สร้างและเปิด app bundle 0.5.1 สำเร็จ Independent bundle validation ผ่าน strict signatures, receipt hashes, ARM64 และ system-only library closures Engine ยังเป็น 0.1.2-tsk4.15.0 เดิม Autopsy frozen-baseline health ได้ **30 PASS / 0 FAIL / 0 WARN** โดยไม่เปิด services หรือปรับ baseline ดู [sanitized receipt](validation/2026-10-07-native-0.5.1.json) สำหรับขอบเขต checks

CI ใช้ synthetic/native corpus, debug/release, strict executor probe และ packaged bundle checks ให้ดูสถานะของ commit ที่จะใช้งานแยกจากผล local ข้างต้น ผล timing ของ fixture ไม่ใช่ full-app speedup ยังไม่ได้ทดสอบเครื่อง M5 จริงหรือ notarization และชุด Autopsy ZIP ที่แชร์ก่อนหน้านี้เป็น artifact แยกจาก native app รุ่นนี้

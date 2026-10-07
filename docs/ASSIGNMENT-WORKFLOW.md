# ทำ assignment ด้วย Native Forensics 0.5

สร้างเคสใหม่ด้วย **New Case** เก็บคนละที่กับ evidence แล้วใช้ **Add Data Source** เพิ่ม RAW image ระบบอ่านอย่างเดียวและบันทึก SHA-256 ของไฟล์ที่เลือก อย่าแก้หรือ mount ต้นฉบับเพื่อให้โปรแกรมเปิดได้ ผลการตรวจจริงและขอบเขตการเทียบอยู่ใน [validation report](ASSIGNMENT-VALIDATION-2026-10-07.md)

## Part I: filesystem เสีย แต่ยังมี bytes ให้กู้

1. เลือก source แล้วกด **Recover Files** หรือไป **Recovered Files → Run New Recovery** ต้องมี PhotoRec ที่ติดตั้งแยก ระบบสแกนทั้ง RAW image และเก็บผลแต่ละงานแยกกัน
2. เปิด **RAW Source Hex → Read 4 KiB** เพื่อดู bytes เริ่มต้นหรือระบุ byte offset ระบบตรวจ hash ของ source ทั้งไฟล์ก่อนและหลังอ่านช่วงที่เลือก
3. เลือก candidate → **Preview → Verify and Preview** ดู MIME จริง, thumbnail, PDF pages หรือข้อความที่มี reference ชัดเจน ค้นหาข้อความได้ในไฟล์ที่เลือก หากข้อความไม่ครบจะมี partial warning
4. ใน **Properties → Examiner Assessment** บันทึกผลตรวจและกด **Save Assessment** การเปิด thumbnail ได้ไม่พิสูจน์ว่าไฟล์ทุกส่วนสมบูรณ์ หาก decoder ไม่รองรับ ให้ export bytes ไปตรวจด้วยแอปที่เหมาะสม
5. ใช้ **Export to New File…** และ **Export Report** เลือกไฟล์ใหม่ภายนอกเคส รายงานมี hash, source ranges, decoder results ที่โหลดไว้และ assessments ที่บันทึกแล้ว เมื่อส่งออกรายงานสำเร็จ หน้าหลักจะแสดง **Report saved** พร้อมชื่อไฟล์

ชื่อ candidate เป็นชื่อที่ PhotoRec สร้างขึ้น Original filename, filesystem timestamps และ deletion status ยัง unknown เมื่อไม่มี metadata รองรับ จำนวน candidates และ embedded derivatives ต้องนับแยกกัน

## Part II: FAT32 USB

1. เลือก source USB แล้วใช้ **Analyze Filesystem** ผลเก่าเมื่อ reopen เป็น historical listing; reanalysis หรือ extraction จะตรวจ source ปัจจุบันอีกครั้ง
2. ไป **Deleted Files** เพื่อดู deleted/orphan metadata; ค้นชื่อหรือ path จากทั้ง listing ไม่ใช่เฉพาะหน้าตาราง
3. เลือกไฟล์ → inspector **Preview → Verify and Preview** โดยเฉพาะไฟล์ที่ชื่อรูปภาพแต่เนื้อหาเป็น Office ดูชื่อเดิมแยกจาก MIME จริง
4. **Export Matching Files** จะส่งออกทุกไฟล์ปกติที่ตรง filter ไปยัง folder ใหม่ รวมแถวที่อยู่หน้าอื่น มี manifest และ SHA-256 รายไฟล์ จำกัด 1,000 files / 512 MiB ต่อไฟล์ / 2 GiB รวม ระบบไม่เขียนทับ folder เดิม

การ export bytes ได้ไม่รับรองว่าเนื้อหาเดิมยังอยู่ deleted slot ที่ถูกเขียนทับต้องแยกจากเอกสารที่ตรวจโครงสร้างได้ Modern Office แสดงข้อความตาม body/slide/worksheet โดยไม่มี page layout, formula evaluation หรือ OCR; legacy Office ระบุชนิด container ได้ แต่ยังไม่อ่าน body

## Part II: UDF CD

1. เลือก optical RAW source แล้วใช้ **Inspect UDF History** หรือไป **Optical History** รองรับ bounded UDF 2.01 physical/virtual VAT profile กับ block size 2,048 bytes
2. แยก **current** files ออกจาก **historical** files เปิด ancestor deletion proof, linked VAT snapshots, original paths/aliases, source extents และ raw timestamps
3. เลือกไฟล์แล้ว preview/export; ใช้ **Export Report** เพื่อเก็บ current/history inventories และ provenance

เมื่อ directory แม่ถูกลบ แต่ FID ของลูกยังไม่ตั้ง deleted bit ระบบใช้สถานะ historical through deleted ancestor การตั้งชื่อเหมือนภาพไม่เปลี่ยน Office bytes ส่วน timestamp ที่ไม่มี timezone จะคง raw/unzoned ไม่มีการเดาเวลาจากเครื่องผู้ตรวจ

## ข้อจำกัดของคำตอบ

RM2/RM3 inventories ไม่พิสูจน์ว่าใครเปิดไฟล์หรือเข้า directory ใด ต้องมี PC/user activity artifacts เพื่อยืนยันคำถามเหล่านั้น แอปยังไม่มี browser/registry/email artifact analysis หรือ case-wide content index ผลจาก Codex เป็นคำอธิบายที่ต้องตรวจยืนยัน; workflow นี้ไม่ส่ง evidence ให้ provider อัตโนมัติ

ปิดและเปิด `.nativecase` กลับมาได้ ผล listing/recovery/optical history และ notes ที่บันทึกแล้วจะยังอยู่ การยกเลิกต้องรอ cleanup ของงานที่แอปเป็นเจ้าของ; ไม่ใช้ force quit เพื่อหยุด export ที่กำลัง publish

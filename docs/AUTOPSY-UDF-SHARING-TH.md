# Autopsy สำหรับ Mac: นำเข้า CD/UDF

ชุดนี้ใช้ Autopsy 4.23.1 ที่แก้บั๊ก JNI แล้ว พร้อมตัวช่วย `AutopsyUDFExport` ซึ่งอ่าน UDF/VAT และส่งออกไฟล์พร้อมข้อมูลตรวจสอบ ไม่ได้เพิ่ม UDF parser เข้า Sleuth Kit โดยตรง

## ติดตั้ง

1. ใช้ Apple silicon และ macOS 27 ขึ้นไป แตก ZIP ทั้งชุด
2. เปิด `Install.command` รอจนแสดง `Installed successfully`
3. เปิด `~/Applications/Autopsy ARM64 UDF.app` ปิด Autopsy ตัวอื่นก่อน เพราะพอร์ต Solr ใช้ร่วมกัน
4. หาก macOS บล็อก ให้ใช้ Privacy & Security → Open Anyway เฉพาะชุดจากผู้ส่งที่เชื่อถือ ไม่ต้องปิด Gatekeeper ทั้งระบบ ชุดนี้ใช้ลายเซ็น ad-hoc และยังไม่ได้ notarize

ตัวติดตั้งตรวจ checksum ลายเซ็นและ functional checks แบบ offline ก่อนติดตั้ง ไม่เขียนทับแอปเดิมที่ชื่อปลายทางเดียวกันแต่เป็นคนละ build และไม่แก้ case เดิม

## อ่าน CD/UDF

1. เปิด `Import UDF.command` จากชุดที่แตก ZIP หรือ shortcut `Autopsy ARM64 UDF - Import UDF.command` ใน `~/Applications` หลังติดตั้ง
2. เลือก image ต้นฉบับ แล้วเลือกโฟลเดอร์ปลายทางสำหรับสร้างผลชุดใหม่ ห้ามเก็บผลทับ image
3. รอให้ส่งออกสำเร็จ ตัวช่วยอ่าน source แบบ read-only และตรวจ SHA-256 รวมทั้งไฟล์ที่ส่งออก
4. ใน Autopsy สร้าง case ใหม่หรือเปิด case งาน → Add Data Source → Logical Files → Local files and folders → Add → เลือกโฟลเดอร์ `LogicalFiles` ในผลชุดใหม่ ไม่ติ๊กช่องนำเข้าวันเวลาจากระบบไฟล์ของ Mac
5. เลือก File Type Identification, Extension Mismatch Detector, Embedded File Extractor และ Keyword Search ตามงาน แล้วเริ่ม ingest รอให้ครบก่อนใช้ผล
6. ตรวจ `Reports` ประกอบกับผล Autopsy เสมอ โฟลเดอร์ผลทั้งหมดต้องอยู่ที่เดิมขณะใช้ case เพราะ Logical Files อ้างอิงไฟล์ในเครื่อง

ไม่ต้องใส่ BitLocker password เพื่อแก้ UDF ที่ไม่รองรับ หากต้องการเก็บ raw image ใน case ด้วย ให้เพิ่มเป็นอีก data source ตามชนิดที่เหมาะสม และระบุว่าไฟล์จากตัวช่วยเป็น derived logical files

หากต้องการใช้ Terminal แทนหน้าต่างเลือกไฟล์ ให้เปลี่ยน path ตัวอย่างเป็นของตนเองและใช้ชื่อโฟลเดอร์ปลายทางใหม่:

```sh
"$HOME/Applications/Autopsy ARM64 UDF.app/Contents/Helpers/AutopsyUDFExport" \
  --source "/path/to/image.dd" --output "/path/to/NEW-UDF-output"
```

## ความหมายของผล

- ชื่อโฟลเดอร์ state/entry แยกไฟล์ปัจจุบันและไฟล์จากประวัติ เพื่อไม่ให้ไฟล์ชื่อซ้ำเขียนทับกัน ชื่อเดิมและการแปลงชื่ออยู่ใน manifest
- ลิงก์ของโฟลเดอร์แม่ที่ลบกับสถานะของไฟล์ลูกเป็นคนละเรื่อง อย่าเรียกทุก historical file ว่าไฟล์ลูกถูกลบ
- Logical Files ไม่ส่งต่อเวลาและสถานะการลบของ UDF เข้า Autopsy โดยตรง เมื่อไม่เลือกนำเข้าเวลา ช่องเวลาอาจว่าง หากเปิดนำเข้าเวลาจะเป็นข้อมูลไฟล์ส่งออกบน macOS ให้ใช้ raw timestamps และสถานะ UDF ใน Reports สำหรับการอ้างอิงหลักฐานต้นฉบับ
- Source SHA-256, ตำแหน่ง extent, ขนาด และ hash ของ payload ใช้ตรวจย้อนกลับไปยัง image เดิม ผลส่งออกไม่ใช่ disk image ที่ซ่อมแล้ว
- ตัวช่วยรองรับ RAW UDF 2.01 ขนาด sector 2048 พร้อม physical/virtual partition และ VAT ตามขอบเขต parser ที่ตรวจแล้ว หากไม่รองรับหรือ metadata ผิดรูปแบบจะหยุดและแจ้งข้อผิดพลาด ไม่เขียนแก้ image

## ขอบเขต

สร้างและทดสอบบน Apple M2 / macOS 27.0.1 ยังไม่ได้ทดสอบบนเครื่อง M5 จริง ให้ผู้รับรัน `Check.command` และทดสอบ image ของตนก่อนทำงาน ชุดแชร์ไม่มี assignment image, case หรือผลกู้ข้อมูลส่วนตัว มีเฉพาะข้อมูลสังเคราะห์สำหรับ self-test

การนำเข้า Logical Files ช่วยให้ Autopsy วิเคราะห์ payload ที่ส่งออกได้ แต่ไม่ทำให้ผล metadata เทียบเท่าการอ่าน UDF โดยตรง และไม่รับรองทุกโมดูลหรือ UDF ทุกแบบ

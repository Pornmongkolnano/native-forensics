# การแยก native engine เป็น helper process

สถานะ: Accepted สำหรับ Phase 1 วันที่ 6 ตุลาคม 2026

NativeForensics จะใช้ native helper process เป็นขอบเขตระหว่าง desktop app และ TSK C/C++ engine ใน Phase 1 แอปจะไม่โหลด parser ที่กำลังตรวจสอบเข้า process ของ UI โดยตรง Protocol และ helper ที่อธิบายด้านล่างเป็นสัญญาที่วางไว้ ยังไม่ได้ implement ใน Phase 0

## เหตุผล

Native parser สามารถ crash หรือให้ผลบางส่วนกับ damaged inputs ได้ การแยก process ทำให้แอปรักษาสถานะเคสและแสดง failure ได้โดยไม่ผูก lifecycle ของ UI กับ parser นอกจากนี้ยังทำให้จับเวลาและ peak RSS ของ engine แยกจาก UI ได้ ค่าของ isolation นี้ต้องวัดร่วมกับต้นทุน startup และ serialization

| ทางเลือก | ประโยชน์ | ต้นทุนและข้อจำกัด |
|---|---|---|
| In-process C/C++ interop | เรียก APIs ตรงและลดการส่งข้อมูลข้าม process | parser crash กระทบ UI; cancellation และ lifetime ต้องควบคุมใกล้ชิด |
| Native helper ที่เลือก | แยก failure, version และ lifecycle; วัดทรัพยากรได้ชัด | startup, protocol, data copies และ pipe backpressure |
| เรียก CLI tools พร้อมแปลข้อความทั่วไป | ทำ prototype ได้เร็ว | output เปลี่ยนตาม version; exit 0 อาจไม่แปลว่า ingest สมบูรณ์ |

Swift รองรับ C++ interop จึงเป็นทางเลือกในอนาคต แต่โครงการนี้เลือก isolation ก่อนพยายามลด overhead [Swift C++ interoperability](https://www.swift.org/documentation/cxx-interop/)

## Protocol ที่วางไว้

ใช้ UTF-8 NDJSON บน stdin/stdout แบบหนึ่ง JSON object ต่อหนึ่งบรรทัด Stderr เป็น diagnostic stream ที่มีขนาดจำกัดและแยกจาก protocol Launcher ใช้ executable URL และ argument array โดยตรง ไม่มี shell interpolation

ทุก message มี `protocolVersion`, `jobID`, `sequence` และ `type` handshake แจ้ง `engineVersion`, pinned source revision, patch-set digest, build identifier และ capabilities App ปฏิเสธ major protocol version ที่ไม่รู้จัก และเก็บ capability/version ใน provenance ของ job

Request v1 จะครอบคลุม `inspect`, `enumerate`, `extract` และ `cancel` พร้อม parameters ที่ตรวจ type/range บันทึก format hint, image segment ordering, sector size และ evidence timezone อย่างชัดเจน ไม่ใช้ file extension เป็นข้อพิสูจน์ image format

Response แยก `progress`, bounded `fileBatch`, `warning`, `error` และ terminal `completed`, `partial`, `failed`, `cancelled` Progress ระบุ stage และหน่วยของ completed/total; งานที่คำนวณ total ไม่ได้ใช้ indeterminate state

ตัวอย่าง envelope ของ protocol ที่วางไว้:

```json
{"protocolVersion":1,"jobID":"synthetic-job","sequence":1,"type":"progress","stage":"enumerate","completed":120,"total":null,"unit":"files"}
```

กำหนด maximum frame size เริ่มต้น 1 MiB พร้อม limits ของ batch, queued bytes และ stdout/stderr buffers ผล file contents เขียนเป็น streaming export ไปยังปลายทางที่รับรองแล้ว ไม่ส่งเป็น base64 ก้อนใหญ่ใน protocol หาก frame เกิน limit, JSON ผิด หรือ sequence/terminal state ขัดกันให้ fail job พร้อม retained diagnostic

## Completion และ partial results

ไม่ใช้ exit status เพียงอย่างเดียวเป็นหลักฐาน success Job สำเร็จได้เมื่อมี terminal `completed`, exit 0 และ checks ของ output schema/expected stages ผ่าน หาก helper ล้ม, ไม่มี terminal message หรือมี read error ให้คงผลที่ทำได้พร้อมสถานะ `partial` หรือ `failed` และไม่เปลี่ยนเป็น complete เมื่อ reopen case

สำหรับ filesystem ที่ตรวจพบแต่ parse ไม่ครบ ให้บันทึก error ของ volume/file และจำนวน skipped records การแสดง unallocated-only image ต้องแยกจาก filesystem enumeration ที่สมบูรณ์ Unknown format และ truncated input เป็น regression cases โดยตรง

## Cancellation และ timeout

หนึ่ง job ใช้ process หรือ process group ที่ app สร้างและติดตามเอง Cancellation ส่ง cooperative request ก่อน จากนั้นหลัง grace period จึงส่ง SIGTERM และ SIGKILL ให้เฉพาะ process ที่เป็นเจ้าของ โดยตรวจ identity/lifecycle ก่อนส่ง signal ไม่ใช้ process-name matching หรือ global kill

Timeout แยก startup handshake, protocol heartbeat และ stage budget งานที่กำลังอ่าน image ใหญ่สามารถใช้ indeterminate progress และ heartbeat ต่อได้โดยไม่ถูกนับว่า hang เพราะไม่มี file result มานาน Cancelled job จะไม่บันทึก digest/output เป็น completed และจะเก็บ partial stage state ที่อธิบายได้

## Concurrency และ secrets

Job coordinator จำกัด workers, queued bytes และ I/O concurrency ตาม policy ที่วัดได้ ห้ามสมมติว่าทุก TSK handle ใช้พร้อมกันได้; เริ่มจาก isolated parser handles/processes และเพิ่ม parallelism หลังตรวจ API/source และ stress tests

Passwords และ recovery keys ในระยะ FileVault จะส่งด้วย framed stdin หรือ private IPC ที่ตรวจแล้ว ไม่ใส่ argv, environment, logs หรือ case manifest Secrets มี lifecycle แยกจาก metadata และไม่ถูกทำ serializable แบบทั่วไป

## Acceptance gate

ก่อนเปิด Phase 1 ต้องผ่าน protocol compatibility, malformed/oversized frame, stderr saturation, unexpected exit, duplicate terminal, cancel race, timeout และ owned-process cleanup tests รวมทั้ง source SHA-256 before/after ทุก fixture และ output correctness ตาม [benchmark method](../BENCHMARKS.md)

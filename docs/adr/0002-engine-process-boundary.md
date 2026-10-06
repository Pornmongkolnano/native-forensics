# การแยก native engine เป็น helper process

สถานะ: Accepted สำหรับ Phase 1 วันที่ 6 ตุลาคม 2026

NativeForensics ใช้ native helper process เป็นขอบเขตระหว่าง desktop app และ TSK C/C++ engine ใน Phase 1 แอปไม่โหลด parser เข้า process ของ UI โดยตรง มี helper, Swift client/cache และ listing/extraction UI ชุดแรกแล้ว แต่ Phase 1 ยัง IN PROGRESS ตาม [roadmap](../ROADMAP.md) ส่วน Phase 0 ยังคงเป็น case/selected-file inspection

เอกสารนี้บันทึกเหตุผลและขอบเขตของการตัดสินใจ สัญญา implementation ที่ใช้จริงคือ [Engine protocol v1](../ENGINE-PROTOCOL.md) และผลทดสอบ/ข้อจำกัดอยู่ใน [Validation](../VALIDATION.md)

## เหตุผล

Native parser สามารถ crash หรือให้ผลบางส่วนกับ damaged inputs ได้ การแยก process ทำให้แอปรักษาสถานะเคสและแสดง failure ได้โดยไม่ผูก lifecycle ของ UI กับ parser นอกจากนี้ยังทำให้จับเวลาและ peak RSS ของ engine แยกจาก UI ได้ ค่าของ isolation นี้ต้องวัดร่วมกับต้นทุน startup และ serialization

| ทางเลือก | ประโยชน์ | ต้นทุนและข้อจำกัด |
|---|---|---|
| In-process C/C++ interop | เรียก APIs ตรงและลดการส่งข้อมูลข้าม process | parser crash กระทบ UI; cancellation และ lifetime ต้องควบคุมใกล้ชิด |
| Native helper ที่เลือก | แยก failure, version และ lifecycle; วัดทรัพยากรได้ชัด | startup, protocol, data copies และ pipe backpressure |
| เรียก CLI tools พร้อมแปลข้อความทั่วไป | ทำ prototype ได้เร็ว | output เปลี่ยนตาม version; exit 0 อาจไม่แปลว่า ingest สมบูรณ์ |

Swift รองรับ C++ interop จึงเป็นทางเลือกในอนาคต แต่โครงการนี้เลือก isolation ก่อนพยายามลด overhead [Swift C++ interoperability](https://www.swift.org/documentation/cxx-interop/)

## Protocol ที่ implement

ใช้ UTF-8 NDJSON บน stdin/stdout แบบหนึ่ง JSON object ต่อหนึ่งบรรทัด Stderr เป็น diagnostic stream ที่มีขนาดจำกัดและแยกจาก protocol Launcher ใช้ executable URL และ argument array โดยตรง ไม่มี shell interpolation

Request มี `protocolVersion: 1`, `jobID`, `operation` และ explicit ordered `imagePaths` ทุก response มี version, job ID, monotonic `sequence` และ `type` โดยเริ่มจาก `hello` ที่แจ้ง `engineVersion`, `patchDigest` และ capabilities Client ปฏิเสธ version ที่ไม่รู้จักและ handshake/sequence ที่ผิด Actual source/build/toolchain provenance เก็บแยกใน `.engine/manifest.json` และ bundled receipt

Request v1 ครอบคลุม `inspect`, `enumerate` และ `extract`; frame ภายหลังใช้ `operation: cancel` เพื่อหยุด owned job Parameters ตรวจ type/range ได้แก่ image type `auto/raw/ewf`, sector size `0/512/4096`, IANA timezone, `maxFiles` และ `hashLogicalImage` Extraction ระบุ filesystem offset/metadata address/attribute/expected size และ output path ไม่ใช้ file extension เป็นข้อพิสูจน์ image format

Response แยก `image`, `volume`, `progress`, bounded `fileBatch`, `warning`, `error`, `extracted` และ terminal `completed`, `partial`, `failed`, `cancelled` Progress ระบุ stage และหน่วยของ completed/total; งานที่คำนวณ total ไม่ได้ใช้ indeterminate state

ตัวอย่าง progress envelope:

```json
{"protocolVersion":1,"jobID":"synthetic-job","sequence":1,"type":"progress","stage":"enumerate","completed":120,"total":null,"unit":"files"}
```

Frame size จำกัด 1 MiB, file batches ไม่เกิน 128 rows, listings ไม่เกิน configured ceiling สูงสุด 50,000 records และ response/cache ไม่เกิน 64 MiB Stderr ที่เก็บเป็น diagnostic จำกัด 64 KiB โดย poll loop ยัง drain bytes ที่เหลือเพื่อไม่ให้ pipe deadlock Limits ไม่แทน measured peak RSS หรือ parallel worker memory policy

File content ใช้ streaming export ไปยัง owned staging ไม่ส่ง base64 ก้อนใหญ่ใน protocol Swift ตรวจ output bytes/hash อิสระก่อน exclusive publication หาก frame เกิน limit, JSON ผิด หรือ sequence/terminal state ขัดกันให้ fail job

## Completion และ partial results

ไม่ใช้ exit status เพียงอย่างเดียวเป็นหลักฐาน success Job สำเร็จได้เมื่อมี hello, terminal `completed` เพียงครั้งเดียว, exit 0 และ schema/scope checks ผ่าน Terminal `partial` คง usable listing พร้อม warnings Native crash, malformed/incomplete protocol, failed terminal หรือ cancellation ไม่ถูกบันทึกเป็น complete result และไม่เขียนทับ prior historical cache

สำหรับ filesystem ที่ตรวจพบแต่ parse ไม่ครบ ให้บันทึก error ของ volume/file และจำนวน skipped records การแสดง unallocated-only image ต้องแยกจาก filesystem enumeration ที่สมบูรณ์ Unknown format และ truncated input เป็น regression cases โดยตรง

Cache เป็น bounded versioned JSON แยกจาก Phase 0 manifest มี engine version, patch digest, ordered sources/hashes, options, volumes/files, warnings และ terminal completed/partial status Cached result เป็น historical observation; source จะตรวจใหม่ก่อน extraction

## Cancellation และ timeout

หนึ่ง job ใช้หนึ่ง helper process ที่ app สร้างและติดตามเอง Cancellation ส่ง cooperative protocol request ก่อน จากนั้นหลัง grace period จึงส่ง SIGTERM และ SIGKILL เฉพาะ owned helper PID ที่ยังทำงานอยู่ ไม่ใช้ process-name matching หรือ global kill Helper ปัจจุบันไม่สร้าง child processes

Client แยก startup deadline และ inactivity deadline ของ stdout activity Helper รายงาน progress ระหว่าง hashing/enumeration/extraction ที่ทำได้ Cooperative cancel ถูก poll ตาม boundaries; native call ที่ block ใช้ owned-process termination fallback Cancelled job ไม่บันทึก completed result หรือ publish incomplete extraction

## Concurrency และ secrets

Desktop เริ่มด้วยหนึ่ง active job และ helper หนึ่ง process ต่อ request ยังไม่มี worker scheduler 1/2/4 หรือ performance result เพิ่ม parallelism หลังตรวจ API/source, stress tests, measured memory และ equivalent-workload benchmark ห้ามสมมติว่าทุก TSK handle ใช้พร้อมกันได้

Phase 1 ปิด APFS/FileVault/encrypted filesystem จึงไม่มี credential request fields เมื่อเพิ่ม FileVault ใน Phase 3 ให้ส่ง secrets ด้วย framed stdin หรือ private IPC ที่ตรวจแล้ว ไม่ใส่ argv, environment, logs หรือ case manifest

## Acceptance gate

ก่อนประกาศ Phase 1 complete ต้องผ่าน protocol compatibility, malformed/oversized frame, stderr saturation, unexpected exit, duplicate terminal, cancel race, timeout และ owned-process cleanup tests รวมทั้ง source integrity และ output correctness ของ independent fixtures ดู receipt coverage จริงใน Validation ยังต้องเพิ่ม portable NTFS, timestamp corner cases, fragmented/deleted content, worker experiments และ full GUI gates ตาม roadmap

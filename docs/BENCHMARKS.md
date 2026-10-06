# วิธีทดสอบและ benchmark NativeForensics

ผลที่เร็วขึ้นมีความหมายเมื่อ input, enabled work และ expected output เหมือนกัน โครงการนี้แยก correctness, performance และ GUI validation และให้ evidence integrity เป็น gate ก่อนเทียบเวลา

## ชุดงานที่ต้องใช้

| Workload | สิ่งที่เทียบ | Expected output |
|---|---|---|
| Selected file SHA-256 | streaming hash ของ bytes เดียวกัน | digest/size/hash scope |
| Filesystem enumeration | format libraries, sector size, timezone, allocation scope และ database work เดียวกัน | file/volume records, sizes, flags, normalized timestamps |
| File extraction and hashing | files/ranges เดียวกันรวม empty/deleted/fragmented cases | byte-identical exports และ digests |
| Carving | ranges, formats, validation policy เดียวกัน | candidates/counts/content hashes/false-positive status |
| Content search | extractor, corpus, index/query options เดียวกัน | documents and hits ไม่ใช้ filename search แทน content search |
| Artifact and timeline | parser modules/timezone assumptions เดียวกัน | normalized artifacts พร้อม source/precision |
| Full desktop flow | create/analyze/browse/export เดียวกัน | completed workflow และ report content |

แต่ละ run ใช้ immutable synthetic inputs, fresh case/database/index/scratch และ checksum before/after Synthetic fixture manifest ระบุ generation recipe, hashes, expected facts และ unsupported facts Expected data มาจาก generator และ independent on-disk inspection ร่วมกับ differential reference

## ข้อมูลที่ต้องเก็บ

บันทึก app/engine version, source revision, patch-set/build digest, compiler flags, enabled image libraries, modules, worker/memory settings และ format/timezone parameters รวม architecture, OS build, RAM, power mode, AC/battery, thermal state และ filesystem ของ source/output

วัด wall time ของ process/startup และ stages แยกกัน: read/decompress → enumerate → extract/hash → text extraction → DB/index → query/export วัด aggregate CPU, peak RSS ของทุก owned processes, disk bytes read/write, first useful result latency, cancellation latency และ UI responsiveness เพิ่ม dataset throughput เมื่อหน่วยงานเทียบกันได้

## วิธีรัน

1. ตรวจ source inputs และ setup ก่อนเริ่ม; ปิดเฉพาะ isolated jobs ที่โครงการสร้างเอง
2. แยก warmup runs และ cold/warm cache regimes ห้ามนำ warmup เข้า median
3. สลับลำดับ A/B ด้วย seed ที่บันทึกไว้; ใช้ measured runs อย่างน้อย 5 คู่สำหรับข้ออ้าง performance เมื่อผลแปรปรวนให้เพิ่ม runs ตามช่วงความไม่แน่นอน
4. รัน reference/candidate ด้วย modules, workers และ generated work เดียวกัน; แยก UI/headless measurements
5. ตรวจ metadata/content/search digests และ source integrity ทุก run ก่อนนำเวลาเข้า comparison
6. รายงาน median, range และ distribution/paired differences พร้อม sample size; ค่าใกล้เคียงกันหรือ ranges ทับกันต้องแสดง uncertainty

Machine setup ต้องคงเดิมระหว่างคู่ หาก thermal/power state หรือ background load เปลี่ยนจนเทียบไม่ได้ ให้เก็บ run พร้อมเหตุผลและรันคู่ใหม่ ไม่เลือกตัด outlier เฉพาะฝั่งที่ทำให้ผลดูดี

## Known diagnostic ที่ไม่ใช้เป็นข้ออ้างความเร็ว

การประเมินก่อนเริ่มโครงการมี NTFS fixture ขนาดเล็กที่ Strata bundled `tsk_loaddb` ใช้เวลาทั้ง process median 0.0300 s และ peak RSS 6.27 MiB ส่วน audited Java/JNI probe ใช้เวลาทั้ง process 0.9030 s และ peak RSS 173.94 MiB แต่ work มี JVM startup, schema creation และ verification ที่ต่างกัน Native helper ไม่ได้ทำ artifact parsing, content indexing, Solr หรือ UI จึงไม่ใช่ full Strata-versus-Autopsy benchmark

ค่า ingest ภายใน Java/JNI process ชุดนั้นคือ 0.05268 s และทั้งคู่ใช้ TSK 4.15.0 ตัวเลขเหล่านี้ชี้ให้แยก startup/runtime costs ใน profiling ไม่ได้ยืนยันว่า NativeForensics engine ใหม่จะเร็วขึ้นเท่าใด [Research baseline](RESEARCH_BASELINE.md)

## Correctness gates ที่ต้องอยู่กับ performance

- Timestamp corpus เปลี่ยน host timezone โดยคง evidence offsets แล้วเทียบ UTC instants, raw values และ precision
- Recovery corpus รวมสอง independent PDFs, incremental PDF, adjacent signatures, malformed trailers, false positives และ fragmented/deleted content
- Failure corpus รวม unknown/truncated inputs, read errors, no terminal protocol result, exit 0 with parse error, timeout และ cancel races
- Export ต้องเขียนใน safe destination, เก็บ source identifiers และ content hashes; source hash before/after ตรง
- รายงาน partial/failed results อยู่ใน benchmark receipts แต่ไม่ปนเป็น successful throughput ที่ทำ output น้อยลง

## รูปแบบผลที่เก็บใน Git

เก็บ sanitized JSON summary, environment class, version/build identifiers, fixture recipe/digests และ commands ที่ใช้ repository-relative paths ไม่เก็บ cases, user evidence, private local paths, secrets, compiled runtimes หรือ raw diagnostics ที่มีชื่อไฟล์จริง

ข้ออ้าง M5 ต้องมีผลจากเครื่อง M5 จริง การผ่าน tests บน Apple Silicon รุ่นอื่นไม่เท่ากับ performance, thermal หรือ complete GUI validation บน M5

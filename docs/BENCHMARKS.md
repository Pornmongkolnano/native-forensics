# วิธีทดสอบและ benchmark NativeForensics

ผลที่เร็วขึ้นมีความหมายเมื่อ input, enabled work และ expected output เหมือนกัน โครงการนี้แยก correctness, performance และ GUI validation และให้ evidence integrity เป็น gate ก่อนเทียบเวลา

## ชุดงานที่ต้องใช้

ผลเทียบ NativeForensics 0.2.3 กับ Autopsy 4.23.1 Mac-adapted ใน fresh-session import อยู่ใน [รายงานเปรียบเทียบ](AUTOPSY-COMPARISON.md) และ [ข้อมูลทุก attempt](benchmarks/2026-10-06-m2-autopsy-pipeline.json) แยก successful-import timings, JVM crash, timestamp mismatch และ NTFS capability gap; ไม่ใช้เป็นข้ออ้าง GUI/steady-state engine performance หรือ pristine stock parity

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

## Native helper concurrency experiment — 6 October 2026

ชุดแรกวัด **จำนวน helper processes ที่ทำงานพร้อมกันสูงสุด 1/2/4** ผ่าน bounded Python queue ไม่ใช่จำนวน threads ของ Autopsy หรือ worker scheduler ในแอป ใช้ helper `0.1.1-tsk4.15.0` เดียวกันและ jobs/bytes/outputs เดียวกันทุกจำนวน processes เครื่องคือ M2 arm64, RAM 16 GiB, macOS 27.0.1, APFS บน SSD, AC และ low-power mode ปิด เก็บ environment ก่อน/หลังไว้ ไม่มี thermal/performance warning ที่ระบบบันทึก แต่ไม่ได้วัดอุณหภูมิจริง Background load 1 นาทีเปลี่ยนจาก 2.19 เป็น 3.15 จึงเป็นผลจากเครื่องใช้งานปกติหนึ่งเครื่อง

```sh
PYTHONPATH=Tests/NativeEngine python3 -m unittest test_benchmark_native_engine
python3 script/benchmark_native_engine.py --output local/worker-benchmark
```

Seed `20261006` สลับลำดับ workload/process-count มี warmup 1 block แยกออก และ measured 5 paired blocks ต่อจำนวน processes รวม 36 batches และ independently verified exports 1,080 ไฟล์ วัดตั้งแต่เริ่ม queue ถึง helper ทุกตัวถูก reap และ pipe อ่านถึง EOF รวม startup, filesystem reads, content hash, writes/fsync และ queue/pump overhead ตรวจ exact bytes/SHA-256/size นอกช่วงจับเวลา และตรวจ source/helper hashes ก่อน/หลังทุก batch ผล partial/failed ไม่ถูกนับเป็น completed throughput Harness safety regressions 7 tests ครอบคลุม timeout, pipe overflow, exact child CPU receipts, symlink rejection และ wrong content

นี่เป็น **warm-cache** experiment: การ prehash ก่อน batch อ่าน source ทั้งไฟล์ ไม่มี purge หรือ cold-cache claim Small NTFS เป็น 13 streams วน 4 รอบ รวม 52 jobs/142,452 bytes ต่อ batch; เน้น startup/dispatch และ repeated reads Large FAT32 เป็นไฟล์ known payload 128 MiB อ่านออก 8 ครั้ง รวม 1 GiB ต่อ batch ไม่ใช่ 8 independent disk images

| Workload | Processes | Wall median (range), s | Helper CPU median, s | Sampled aggregate RSS max, MiB | Kernel-derived RSS upper bound, MiB |
|---|---:|---:|---:|---:|---:|
| Small NTFS | 1 | 0.348834 (0.344094–0.358222) | 0.252423 | 9.08 | 9.09 |
| Small NTFS | 2 | 0.191603 (0.189947–0.201457) | 0.264933 | 17.05 | 18.19 |
| Small NTFS | 4 | 0.115336 (0.114376–0.118587) | 0.299721 | 20.23 | 36.48 |
| Large FAT32 | 1 | 0.699042 (0.694016–0.707312) | 0.652388 | 8.72 | 8.75 |
| Large FAT32 | 2 | 0.372212 (0.370474–0.376579) | 0.678008 | 17.42 | 17.48 |
| Large FAT32 | 4 | 0.274837 (0.273965–0.278948) | 0.724981 | 34.83 | 34.95 |

CPU คือผลรวม user/system CPU จาก `wait4` ของ exact owned helper PIDs ต่อ batch Sampled RSS ใช้ macOS libproc ทุก 2 ms ที่ร้องขอ; actual interval medians ต่อ batch อยู่ 2.52–3.20 ms การอ่านแต่ละ PID ไม่ atomic และอาจพลาด short-lived peaks โดยเฉพาะ Small NTFS Upper bound เป็นผลรวม kernel individual peaks ที่มากที่สุดตาม concurrency cap ซึ่งไม่ใช่ simultaneous sample จึงแสดงทั้งสองค่า ไม่อ้างค่า 20.23 MiB เป็นข้อรับรอง RAM สูงสุดของ 4 processes Parent Python, Swift และ GUI ไม่อยู่ใน CPU/RSS เหล่านี้ Disk counters เป็น block operations ไม่ใช่ disk bytes

Median ของ paired wall ratios เทียบ 1 process: 2 processes ลดเวลา Small NTFS 45.1% และ Large FAT32 46.6%; 4 processes ลด 66.8% และ 60.6% ตามลำดับ ทุกคู่ไปในทิศทางเดียวกัน แต่ 4 processes ใช้ CPU เพิ่มและ aggregate RAM สูงขึ้น ผลนี้สนับสนุนการทดลอง bounded concurrent extraction ต่อไป ยังไม่เปลี่ยน production policy: ต้องวัด Swift source prehash, staging/publication, case/cache/index, GUI responsiveness, cancellation, cold/large/mixed inputs และ battery/thermal workload รวมทั้งเครื่อง M5 จริงก่อนเลือก app defaults

เก็บ distribution, paired differences, batch CPU/RSS receipts, environment และ fixture/build/recipe digests ใน [sanitized JSON](benchmarks/2026-10-06-m2-helper-workers.json) `sourceRevision` คือ base commit ตอนวัด; recipe digests ระบุ working-tree harness ที่ใช้ Raw diagnostics/fixtures อยู่ใน ignored `local/` ชุดก่อนแก้ขอบเขตจับเวลาถูกยกเลิกและไม่ใช้ในตัวเลขนี้ การรัน `--smoke` ใช้ไฟล์ใหญ่เพียง 1 MiB และมี block เดียว จึงเป็น correctness smoke เท่านั้น

## Filesystem search and scheduling — app 0.2.3

การค้นหาเดิมรัน `Array(files.lazy.filter(...).prefix(50_000))` บน MainActor ทุกครั้งที่พิมพ์ สำหรับ collection chain นี้ การตรวจ `Array<Int>` probe แยกจากการจับเวลาบน toolchain นี้พบ predicate 100,001 calls สำหรับ input 50,000 ค่าและ matches 6,250 ค่า Command/output ของ diagnostic เก็บใน JSON ด้านล่าง เป็นการตรวจ traversal ของ collection chain แยกจาก path workload Candidate เก็บ immutable bounded snapshot, คืน array เดิมด้วย copy-on-write เมื่อ query ว่าง และสแกนครั้งเดียวด้วย Foundation `localizedCaseInsensitiveContains` เดิม ตรวจ cancellation ทุก 128 แถว Store debounce 120 ms, ส่ง scan ไป detached task และตรวจ generation/case URL/evidence/query ก่อน publish โดยยกเลิกงานเก่าเมื่อ query/selection เปลี่ยน

```sh
swift run -c release FilesystemSearchBenchmark --output local/search-release.json
swift run -c debug FilesystemSearchBenchmark --output local/search-debug.json
```

Fixed corpus มี 50,000 records รวมภาษาไทย, canonical Unicode accents, Straße, 東京, emoji และ long paths; 9 queries ต่อ scenario มี warmup 1 block และ measured 5 paired blocks สลับลำดับ baseline/candidate ทั้งสอง configurations รวม 20 measured scenarios / 180 queries ตรวจ full row equality, order, metadata และ ID digests นอกช่วงจับเวลา Input SHA-256 ตรงกันระหว่าง release/debug ผล raw และ source recipe digests อยู่ใน [sanitized JSON](benchmarks/2026-10-06-m2-filesystem-search.json)

| Configuration | Baseline query work median (range), ms | Candidate median (range), ms | Median paired time reduction |
|---|---:|---:|---:|
| Release | 1,878.08 (1,870.44–1,884.24) | 949.05 (944.05–968.84) | 49.47% |
| Debug | 1,958.05 (1,950.59–1,974.84) | 1,055.56 (1,051.14–1,079.33) | 46.03% |

ตัวเลข work เป็นผลรวมเวลา scan/result ของ 9 queries รวม dispatch/await ฝั่ง candidate เว้น input generation, validation และ 10 ms simulated event pacing ทุก output ตรงกัน ไม่เปลี่ยน Unicode semantics เป็น ASCII/lowercase matching Release MainActor heartbeat maximum-gap median ต่อ scenario ลด 519.71 → 3.18 ms (ร้องขอ heartbeat ทุก 2 ms) **นี่เป็น headless scheduling probe ไม่ใช่ SwiftUI frame rate หรือ measured interaction latency** ไม่รวม store debounce, cache loading, hashes, engine, exports หรือ full-app RAM Five cancellation trials ต่อ build ถูกยกเลิกก่อน scan เสร็จ; เวลา worker หลัง cancel ที่บันทึกไม่แทน GUI cancellation latency

GUI stress เป็นอีก gate: generated cache 50,000 แถวติดคำเตือน synthetic-only หลัง filter 6,250 Thai paths การเลือกแถวใน unbounded SwiftUI Table ทำให้ CPU สูงต่อเนื่อง และ sample อยู่ใน SwiftUI/AppKit cell layout/tracking จึงจำกัด table presentation ที่ 100 แถวต่อหน้า โดยค้นหาจากทุก saved entry และแสดง exact page range First/Next/Last, query reset, selection/inspector และกลับไป idle หลังเลือกแถวผ่าน ไม่ใช้เวลา tool/AX roundtrip เป็นข้ออ้าง app latency และไม่ใช้ cache สังเคราะห์นี้พิสูจน์ native format coverage

App Run/build bundle ใช้ optimized release ตามปกติ; `--debug` ยังเป็น debug/LLDB ไม่มีข้ออ้างเวลา launch หรือความเร็วทั้งแอปจากการเปลี่ยน configuration นี้ การวัด memory, event-to-frame latency, cold/mixed inputs และเครื่อง M5 ยังเป็นงานต่อไป

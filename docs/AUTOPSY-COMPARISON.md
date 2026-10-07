# NativeForensics เทียบกับ Autopsy — 6 October 2026

รายงานนี้เป็น historical diagnostic evidence อ่าน [รอบใหม่ 7 October ที่ซ่อม Autopsy และผ่าน independent timestamp/stream gates แล้ว](AUTOPSY-COMPARISON-2026-10-07.md) สำหรับตัวเลขที่ใช้หลังซ่อม รอบเก่าเก็บไว้ครบและไม่เปลี่ยนผลตาม installation ปัจจุบัน

NativeForensics 0.2.3 ใช้เวลาน้อยกว่า Autopsy 4.23.1 ที่ติดตั้งและปรับสำหรับ macOS ARM64 ในงาน **เริ่ม process ใหม่ → สร้างเคส → นำเข้า filesystem → บันทึกผล** ของ synthetic images สองชุด ผลนี้รวมต้นทุนเริ่ม NetBeans/JVM/Solr ฝั่ง Autopsy และวัด NativeForensics ผ่าน release application core จึงยังใช้สรุปความเร็วทั้งแอป, GUI หรือ engine เพียงอย่างเดียวไม่ได้ ทั้งสองระบบใช้สาย engine The Sleuth Kit 4.15.0 เดียวกัน

## เวลาของ imports ที่ทำ known payloads ครบ

แต่ละ workload มี warmup หนึ่งคู่ที่แยกออก และ successful measured pairs ห้าคู่ สลับลำดับด้วย seed ที่เก็บไว้ **สถิติด้านล่างมีเงื่อนไขว่า import และ payload verification สำเร็จ** Failed attempts ถูกเก็บแยก ไม่ถูกนับเป็นงานที่เสร็จเร็ว

| Synthetic workload | Native wall median (range), s | Autopsy wall median (range), s | Median ของ Autopsy/Native ต่อคู่ | Known payloads ที่ตรวจครบต่อ successful run |
|---|---:|---:|---:|---:|
| FAT16, image 2,560,000 bytes | 0.186345 (0.144947–0.202303) | 21.582391 (19.476532–21.938990) | 111.30 | 5/5 ทั้งสองฝั่ง |
| FAT32, image 286,720,000 bytes | 0.857995 (0.770289–0.889254) | 20.648569 (18.616117–21.242787) | 23.95 | 6/6 ทั้งสองฝั่ง |

FAT32 image มีขนาด 273.4375 MiB และมีไฟล์ `BENCH128.BIN` ขนาด 128 MiB รวมกับ empty/deleted/nested payloads ขนาดเล็ก ค่า ratio เป็น median ของ ratios **แต่ละคู่** จึงไม่จำเป็นต้องเท่ากับการหาร medians สองคอลัมน์ Median ของ paired wall reduction คือ 99.10% และ 95.83% ตามลำดับ เป็นผลของ workflow และขอบเขตจับเวลานี้

FAT16 ฝั่ง Autopsy ทำ measured attempts 6 ครั้ง: สำเร็จ 5 ครั้งและล้ม 1 ครั้ง ส่วน Native ทำครบ 5/5 attempts ครั้งที่ล้มใช้เวลา 15.105516 s และ JVM crash ที่ `__findenv_locked` ก่อนนำเข้าจบ (exit 137) อัตรา 1/6 เป็น observations ของชุดเล็กนี้ ไม่ใช่ประมาณการ failure rate ทั่วไป เก็บ successful pairs สี่คู่เดิมและ failure เดิมครบ แล้วรัน replacement ใหม่ทั้งสองแอปหนึ่งคู่ภายใต้ runtime/options เดิม FAT32 ทำครบ 5/5 measured attempts ทั้งสองฝั่ง

## ความถูกต้องที่ยังต่างกัน

Known payload gates ตรวจ paths, sizes, allocation/deleted flags, filesystem offsets, stream identity เมื่อ manifest ระบุ และ exports ที่ bytes/SHA-256 ตรงกับ synthetic oracle การ export และ independent readback อยู่นอกช่วงจับเวลา Source hashes และ runtime hashes ตรงก่อน/หลังทุกชุด แต่ **ไม่มี complete metadata parity** แม้ successful FAT imports จะทำ payloads ครบ

Autopsy เก็บ image timezone เป็น `UTC` แต่ FAT16/FAT32 ทั้ง created/modified/accessed epochs ของ known payloads ช้ากว่า Native และ UTC oracle 25,200 s หรือ 7 ชั่วโมง เช่น `HELLO.TXT` created epoch เป็น `1699974800` เทียบกับ Native/oracle `1700000000` ทุก raw epoch delta เก็บใน JSON; absent timestamp ใช้ zero→absent normalization เฉพาะการเปรียบเทียบ ระบบยังมี timestamp correctness gap ที่ต้องแก้และตรวจซ้ำก่อนเรียกผลเทียบว่า metadata เท่ากัน

NTFS control ใช้หนึ่งคู่เพื่อดู capabilities: Native ตรวจ known streams ครบ **13/13**, Autopsy **12/13** โดยไม่มี directory DATA ADS `หลักฐาน:directory-note` ขนาด 52 bytes ใน case database ทั้ง 12 payloads ที่ Autopsy พบมี exports ตรง oracle และ common timestamp fields ไม่ต่างใน control นี้ เก็บเวลาทั้งสอง attempt ไว้เพื่อวินิจฉัย แต่ **ไม่คำนวณ NTFS speed ratio** เพราะ expected output ไม่ครบเท่ากัน Counts ของ filesystem rows เช่น FAT16 Native 10/Autopsy 13 หรือ NTFS Native 25/Autopsy 28 รวม pseudo-files/directory representations ต่างกัน จึงใช้แทนจำนวน known payloads ไม่ได้

Source audit พบ TSK JNI 4.15.0 ส่ง pointer ของ buffer บน stack ให้ `putenv` ซึ่งมี lifetime ไม่พอสำหรับ environment storage ตาม [ข้อกำหนดของ Apple](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/putenv.3.html) อาการ timestamp offset และ crash ใน environment lookup สอดคล้องกับปัญหานี้ แต่ benchmark ชุดนี้ยังไม่ได้พิสูจน์ด้วย patched in-process reproduction ว่าเป็นสาเหตุของทั้งสองอาการ จึงเก็บเป็น causal inference พร้อมแยก observed failures ออกจาก source finding [TSK JNI source ที่ใช้เป็น reference](https://github.com/sleuthkit/sleuthkit/blob/01de0345edaa1ebf21dba6939a7c6bc7129e6e7d/bindings/java/jni/dataModel_SleuthkitJNI.cpp#L871-L884)

## ขอบเขตงานและ baseline

Native runner เรียก `CaseStore` → `ImageInspector` → source verification → `EngineClient.enumerate` → source verification → `EngineResultStore` ของแอปจริง เก็บ selected-file hash, logical image hash และ default source checks ครบ ใช้ JSON cache Autopsy runner ใช้ full NetBeans command-line create/add-data-source เข้า SQLite โดยไม่เปิด `--runIngest` และมี private Solr startup แม้ปิด ingest modules จึงมี persisted work และ bootstrap ต่างกัน [Autopsy CLI source](https://github.com/sleuthkit/autopsy/blob/autopsy-4.23.1/Core/src/org/sleuthkit/autopsy/commandlineingest/CommandLineIngestManager.java)

Timer หลักเริ่มก่อน `Popen` ถึง application process exit รวม startup และ persistence แต่หยุดก่อน readback/exports และ cleanup ของ owned Solr ซึ่งยังอยู่หลัง Autopsy exit ดังนั้นไม่ใช่เวลาปิดทุก dependency จนหมด Native core stages มี timer แยก: FAT32 median ของ selected-file inspection/hash 130.59 ms, pre-source verification 129.66 ms, post-source verification 142.50 ms และ helper enumeration/client 413.72 ms ค่า client รวม logical hashing, filesystem enumeration และ helper startup; ใช้แทน steady-state TSK throughput ไม่ได้

Reference ที่มี successful timings คือ **`installed-adapted`**: Autopsy 4.23.1 ที่ปรับไว้สำหรับ Mac ARM64 ไม่ใช่ pristine vendor Windows build ได้ทดลอง original upstream core/keyword/recentactivity JARs กับ unpatched native TSK ใน isolated Mac-compatible runtime ด้วย แต่ full CLI ไม่ผ่าน Solr readiness ภายใน 120 s แม้ private service healthy จึงไม่มี completed-import result ให้หารความเร็ว ทั้งสอง variants ยังมี common Mac compatibility dependencies และ adapter เปลี่ยน private `STOP.KEY` constant เพื่อป้องกัน process matching ไปโดน Solr อื่น เก็บ original/effective JAR hashes, native library hashes, ARM64 datamodel hash และ recipe digests ใน JSON

Run ใช้ fresh process/case/user/cache ทุกครั้ง ฝั่ง Autopsy เป็น fresh NetBeans module cache และ private Solr; ฝั่ง Native เป็น release core executable ใช้ UTC และ auto-detect sectors การ prehash อ่าน source ทั้งไฟล์ก่อน attempt จึงเป็น **warm OS/file-cache** experiment ไม่มีการ purge หรือ cold-cache claim ไม่มีการวัด Swing/SwiftUI rendering, interactive latency, carving, keyword/browser/artifact ingest หรือการใช้งาน engine ที่เปิดค้างอยู่ ไม่ใช้ผลนี้ยืนยัน Autopsy feature parity หรือความเร็วบน M5

## หน่วยความจำและ CPU

| Successful workload | Native sampled aggregate peak RSS median, MiB | Autopsy sampled aggregate peak RSS median, MiB |
|---|---:|---:|
| FAT16 | 8.84 | 1,944.67 |
| FAT32 | 8.92 | 1,935.14 |

RSS นี้เป็น sequential samples ของ **observed owned CLI/JVM processes** และ dependency children ร้องขอทุก 5 ms; actual intervals อยู่ในแต่ละ receipt ไม่ใช่ RAM สูงสุดที่รับรองได้ และไม่ใช่ memory ของ desktop app Native helper บางครั้งสั้นจนไม่ถูก sample ส่วน Autopsy bootstrap tools บางตัวถูกระบบปฏิเสธอ่าน `rusage` ด้วย `EPERM` เก็บ basename/errno/count ไว้ครบ การไม่มี recorded sample errors ไม่รับรองว่าพบทุก child process จึงไม่คำนวณ RAM reduction ratio จากตารางนี้

CPU และ disk counters ใน JSON เป็น **lower bounds** จาก last-live samples ของ owned processes ขาด exit tails และ short-lived/denied children ไม่ใช่ kernel `wait4` totals CPU ใช้ Mach timebase `125/3` แปลง absolute ticks เป็น seconds ไม่ใช้ nanoseconds โดยตรง Java process roles ใน receipt แยก main/bootstrap/Solr ไม่ได้ จึงรายงานเป็น owned JVM group และเก็บ observed executable counts Python coordinator และ GUI ไม่อยู่ใน resource totals

## เครื่องที่ทดสอบและการเก็บผล

Apple M2 arm64, RAM 16 GiB, macOS 27.0.1 build `26A434`, APFS บน SSD, AC, low-power mode ปิด Background load average 1 นาทีเปลี่ยนจาก 2.23 ก่อนชุดเดิม เป็น 1.90 ก่อน recovery และ 3.17 หลังจบ เครื่องใช้งานตามปกติ มี background work จึงไม่ใช่ dedicated lab ระบบไม่บันทึก thermal/performance warning แต่ไม่ได้วัดอุณหภูมิจริง

Seed เดิม `20261006`, recovery seed `20261007`; JSON เก็บ order จริงทุก attempt มี original timed recipe hashes และ recovery harness hash แยกกัน รวม warmups, successful attempts, failed attempt, stage timings, sampling gaps, fixture recipes/hashes และ metadata differences ทั้งหมด Failed preparation/partial experiments อื่นไม่ถูกนำมาปนใน medians; source experiment ที่กู้ต่อเก็บ successful observations และ failure ครบโดยตรวจว่า timed recipes/executables ไม่เปลี่ยน

ตรวจหลังวัด: Swift debug/release **49 tests ต่อ configuration** (45 core + 4 search-store), Python benchmark harness **13 tests**, strict code-signature verification ของ bundle เดิมผ่าน Healthcheck แบบ read-only ผ่าน **30 PASS / 0 FAIL / 0 WARN** และมี 3 SKIP สำหรับ installed Autopsy/Solr ที่ไม่ได้เปิด ไม่มีการ restart หรือวัด GUI ใหม่ใน turn นี้ Native GUI เดิมถูกคงไว้ และ source/runtime hashes ไม่เปลี่ยนระหว่างวัด

Timed tools ที่มี recipe hashes ในรายงานอยู่ใน commit `1d8192eb73c330c47e755aae326b0215f7e6a800`; sourceRevision เป็น base ก่อนเพิ่มเครื่องมือ หลังวัดเปลี่ยนเฉพาะชื่อ flag ของ sampler จาก `resourceCoverageComplete` เป็น `noSamplerErrors` พร้อมข้อความว่าความครอบคลุมยังพิสูจน์ไม่ครบ ไม่เปลี่ยน counters/timers หรือคำนวณเวลาใหม่

ผลที่ commit ได้อยู่ใน [sanitized JSON](benchmarks/2026-10-06-m2-autopsy-pipeline.json) โดย compact metadata differences ใช้ `differenceColumns` กับ `differenceRows` ไม่เก็บ absolute personal paths, PIDs, raw logs, source images/cases/exports, payload hex หรือ runtime binaries Raw receipts อยู่ใน ignored `local/`

## รันซ้ำ

ใช้ synthetic fixture manifest ที่ตรวจแล้ว และ isolated Autopsy setup เท่านั้น ระบุ paths ของ installation/JDK ผ่าน task-specific environment variables เครื่องอื่นต้องมี compatibility baseline และ hashes ตรงตาม script ก่อน ไม่ใช้ existing coursework case เป็น benchmark

```sh
swift build -c release --product ForensicsPipelineBenchmark
mkdir -p local/autopsy-comparison/verifier-classes
javac --release 17 -cp "$FORENSICS_AUTOPSY_RUNTIME/autopsy/modules/ext/*" \
  -d local/autopsy-comparison/verifier-classes \
  Benchmarks/AutopsyComparison/AutopsyCaseVerifier.java
python3 script/benchmark_autopsy_pipeline.py \
  --runtime "$FORENSICS_AUTOPSY_RUNTIME" --installer "$FORENSICS_AUTOPSY_INSTALLER" \
  --java-home "$FORENSICS_JAVA_HOME" --fixtures local/phase1-corpus-verified/fixtures \
  --output local/autopsy-comparison/prepared-v3
python3 script/compare_forensics_pipeline.py \
  --setup local/autopsy-comparison/prepared-v3/setup.json --variant installed-adapted
```

หาก experiment ล้มและเก็บ report แล้ว `script/continue_forensics_comparison.py --failed-report <owned-local-report>` กู้ได้เฉพาะรูปแบบที่ตรวจว่าเป็น source experiment สี่ successful FAT16 pairs กับ crash ครั้งที่ห้า และ timed recipes/executables ต้องตรงเดิม Recovery อนุญาต replacement ไม่เกินสอง measured pairs ต่อ image และเก็บ failures ครบ ไม่ใช่ retry จนได้ผลที่ต้องการ

งานถัดไปที่ควรวัดคือ startup ของ session ที่ตั้งค่าแล้ว, steady-state enumeration/extraction, cold/mixed/large inputs, GUI event-to-frame/idle memory/cancellation และ M5 จริง ควรแก้และตรวจ JNI timezone lifetime กับ FAT epochs แยกเป็น correctness change ก่อนทำ comparison ที่ต้องการ full metadata parity

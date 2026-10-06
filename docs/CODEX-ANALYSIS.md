# วิเคราะห์ไฟล์ด้วย Codex — NativeForensics 0.3.0

เลือกไฟล์ในผล filesystem แล้วใช้ **Analyze with Codex** จาก toolbar, inspector หรือเมนู Evidence (`⌥⌘A`) ถามและอ่านคำตอบในแอปได้ ฟีเจอร์นี้ส่งบริบทที่ตรวจแล้วผ่าน Codex CLI ไปยัง OpenAI และใช้โควตาของบัญชี ChatGPT ที่ล็อกอินอยู่ ผลตอบกลับเป็น **AI interpretation** ซึ่งต้องตรวจเทียบกับหลักฐาน

## ตั้งค่าและใช้งาน

1. ติดตั้ง Codex CLI จากแหล่งทางการ และล็อกอินแยกด้วย `codex login` รุ่นที่ตรวจจริงคือ **0.160.1** ตรวจ path ใน Settings → Codex file analysis แอปไม่ติดตั้ง CLI หรืออ่าน/คัดลอก credential files ให้เอง
2. เปิดเคส วิเคราะห์ filesystem และเลือกไฟล์ กด Analyze with Codex แอปเตรียม metadata ของไฟล์นั้นในเครื่องก่อน ยังไม่มีการส่งคำถาม
3. ใส่คำถาม หรือใช้ Summarize / Timeline / Findings ตรวจบริบททั้งหมด ถ้าต้องการเนื้อหาให้เลือก **Include a UTF-8 text excerpt** แล้วกด **Rebuild Context** การเปลี่ยนตัวเลือกนี้ทำให้บริบทเก่าส่งต่อไม่ได้จนกว่าจะเตรียมใหม่
4. ตรวจคำถามและบริบท เลือกช่องยินยอม แล้วกด **Send to Codex** การเปลี่ยนคำถาม/บริบทล้างการยืนยันเดิม คำตอบอยู่ในแท็บ Answer แบ่ง Summary, Observations, Hypotheses, Limitations และ Next Steps
5. ใช้ Copy Context / Copy Answer เมื่อต้องการเก็บข้อความเอง คำตอบมี request SHA-256 ที่แอปคำนวณเพื่อผูกกับ prompt ที่ส่ง การ Close/Quit/cancel รอ cleanup ของ process และ scratch งานที่ส่งไปแล้วอาจใช้โควตาแม้ยกเลิก

## ข้อมูลที่เปิดเผย

- Metadata: evidence UUID, exact file reference/path ภายใน image, ขนาด/allocated/deleted, integer timestamps/nanoseconds, evidence timezone, recorded analysis version/status และ hash scopes
- Hash ของ selected container file, ordered container hashes, logical image และ extracted file แยกกัน ไม่ใช้แทนกัน
- ไม่ใส่ host source paths, case directory/name หรือ diagnostics ของ engine ลง prompt ชื่อ/path ภายใน image และข้อความอาจเป็นข้อมูลส่วนตัวได้ จึงต้องตรวจในหน้าทบทวนก่อนส่ง
- Metadata-only เป็น historical snapshot ไม่ตรวจ source ปัจจุบันใหม่ เมื่อเลือกข้อความ แอป extract จาก reference ที่ตรงกับผลวิเคราะห์ ตรวจทุก ordered source hash และตรวจ size/SHA-256 ของ extracted bytes อย่างอิสระก่อนเตรียมบริบท
- รองรับข้อความ UTF-8 จากไฟล์ทั้งไฟล์ไม่เกิน **1 MiB** ส่ง prefix ไม่เกิน **32 KiB** โดยไม่ตัดกลาง Unicode scalar แสดงจำนวน bytes ที่รวม/ละไว้ และ hash ของ extracted file ทั้งไฟล์ ไฟล์ใหญ่/binary/encoding อื่นใช้ metadata ได้; PDF/ภาพ/Office ยังไม่มี content decoder
- Partial/deleted/truncated และข้อจำกัดของ parser เก่าปรากฏในบริบท การมี metadata ว่า deleted ไม่รับรองว่า recovered content เป็นข้อมูลเดิมหรือไม่ถูกเขียนทับ

## ขอบเขตของการเชื่อมต่อ

เรียก executable ตรงด้วย arguments แยกจาก prompt; ส่ง prompt ผ่าน stdin ใช้ private scratch และ `--ephemeral` ไม่มีการแก้ global Codex configuration หรือผูก MCP server ของแอปนี้เข้ากับบัญชี ใช้ OpenAI provider และ saved ChatGPT authentication โดยไม่รับ API keys ใน UI

แต่ละคำขอปิด user/project instructions, shell/web/apps/plugins/MCP-related capabilities ตาม flags ที่ตรวจ และใช้ named permission profile:

```toml
default_permissions = "nft_assistant"
[permissions.nft_assistant.filesystem]
":root" = "deny"
":minimal" = "read"
":tmpdir" = "deny"
":slash_tmp" = "deny"
":workspace_roots" = "read"
[permissions.nft_assistant.network]
enabled = false
```

Profile นี้จำกัด **คำสั่งที่ Codex จะรัน** ไม่ใช่ sandbox ของ provider harness ทั้ง process; harness ยังต้องเชื่อม OpenAI เพื่อรับคำตอบ Local OS probes ตรวจว่า scratch read ผ่าน แต่ sibling/symlink read, writes และ loopback command networking ถูกปฏิเสธ ไม่ใช้ legacy `--sandbox` ร่วมกับ named profile เพราะอาจเปลี่ยน policy ที่มีผลจริง

ตัวอ่าน JSONL จำกัดขนาด/เวลา รับเฉพาะคำตอบที่ครบและ exit 0 ตรวจ schema/ขนาดในแอปอีกครั้ง และยกเลิกเมื่อพบ tool actions คำตอบและชื่อไฟล์แสดงเป็น literal text ไม่มีการเปิดลิงก์หรือรัน next steps อัตโนมัติ CLI/provider diagnostics ไม่ถูกส่งต่อเป็น raw error messages ใน UI

CLI 0.160.1 อาจส่ง startup notice ว่า Code Mode host ถูกปิดตาม configuration นี้ ตัวอ่านยอมรับเฉพาะข้อความที่ตรงกับ stock notice นี้ก่อนเริ่ม turn และจำกัดจำนวน; warning/error อื่นหรือ tool actions ทำให้คำขอล้มเหลว หน้าคำตอบแสดงเพียงข้อความทั่วไปเมื่อมี notice ไม่ถือ notice เป็นคำตอบจาก AI

ใช้ตาม [OpenAI non-interactive documentation](https://learn.chatgpt.com/docs/non-interactive-mode), [configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference) และ [permission profiles](https://learn.chatgpt.com/docs/permissions) Permission profiles ยังเป็น beta จึงต้องตรวจ compatibility ใหม่เมื่อเปลี่ยน Codex รุ่นหรือ environment; ไม่รับรองทุก managed configuration หรือทุก CLI รุ่น

## การตรวจและข้อจำกัด

Tests ใช้ synthetic evidence และ fake CLI รวม exact selection/source hash, UTF-8 boundaries, privacy scopes, request binding, stale results, cancellation/process-group cleanup, output limits, failure/tool actions และ sidebar/workspace lifecycle มี opt-in real-helper test ที่ตรวจ exact text และ source-change refusal การทดสอบปกติ/CI ไม่เรียก provider และไม่ใช้ credential files

การตรวจบน Apple Silicon M2 / macOS 27.0.1 วันที่ 7 ตุลาคม 2026: Swift **90 core + 31 app tests** ผ่านทั้ง debug/release รวม real-helper corpus, Python harness/bundle **23 tests** ผ่าน และ release bundle build/validation/launch ผ่าน Live GUI ส่งคำถามภาษาไทยกับ synthetic FAT16 `/HELLO.TXT` **44/44 bytes** แล้วแสดงคำตอบครบทั้งห้าส่วน ตรวจ source SHA-256 หลังทดสอบตรงกับ record ทดสอบ Cmd-Q และ SIGTERM ขณะ review sheet เปิดอยู่แล้ว process เดิมออกและแอปใหม่เปิดได้ ไม่มี real coursework evidence ในคำขอทดสอบ

ดู [sanitized receipt](validation/2026-10-07-codex-analysis.json) สำหรับ hashes และขอบเขตที่ตรวจ การแก้ test barrier ของ manifest commit แยกจาก feature นี้ แก้ failure ของ CI รุ่น 0.2.5 โดยรอการเริ่ม commit จริงและไม่ใช้เวลานอนเป็นสัญญาณพร้อม ผล local ไม่แทนผล GitHub Actions ของ commit ใหม่

คำตอบ AI อาจผิดหรือไม่ครบ Schema/request hash ยืนยันรูปแบบและการผูกคำขอ ไม่รับรองข้อสรุป การตรวจจริงและความรับผิดชอบในการตีความยังอยู่ที่ผู้ตรวจหลักฐาน ผลตอบและ excerpt อยู่ใน session state; durable analysis ledger, follow-up conversation, PDF/image decoding และการวิเคราะห์หลายไฟล์ยังไม่อยู่ในรุ่นนี้

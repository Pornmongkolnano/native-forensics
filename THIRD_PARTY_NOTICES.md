# Dependency provenance และ third party notices

Foundation นี้เป็น private project code ยังไม่ได้เลือก blanket open-source license สำหรับโค้ดใหม่ และไม่ได้คัดลอก Autopsy หรือ Strata source/binaries เข้ามา การเลือกชื่อโครงการหรือ repository visibility ไม่เปลี่ยน license ของ dependency ที่ใช้ภายหลัง

Repository เก็บ [exFAT UTC-offset patch](patches/sleuthkit/exfat-utc-offset.patch) สำหรับ TSK 4.15.0 เป็น reproducibility artifact ของงานแก้ที่ตรวจมาก่อน ไม่ใช่ vendored toolkit หรือ compiled engine SHA-256 คือ `fe17dab7a4f83f774eb9b4992801033131e66bf9579e91bc0e5aa5a5309613cf` Patch มีบริบทของ upstream file; การ build/distribute TSK ที่แก้แล้วต้องรักษา provenance และ upstream notices ตาม exact component ที่รวม Phase 0 ไม่ได้ใช้ TSK runtime; Phase 1 build native helper จาก pinned TSK source โดยใช้ patch นี้

## Foundation ที่ใช้

| Component | ใช้เพื่อ | Provenance |
|---|---|---|
| Swift, SwiftPM และ macOS SDK | build และ desktop runtime | ใช้จาก installed Apple developer toolchain; ไม่ vendor toolchain ใน repository |
| Foundation, SwiftUI, AppKit, CryptoKit | case persistence, UI, panels, SHA-256 | macOS system frameworks; ไม่ redistribute framework binaries |

## Research references

| โครงการ | Revision ที่ตรวจ | การใช้ใน foundation |
|---|---|---|
| [Autopsy](https://github.com/sleuthkit/autopsy/tree/autopsy-4.23.1) | `autopsy-4.23.1` | architecture/reference behavior; ไม่มี Java/NetBeans runtime หรือ upstream code ใน foundation |
| [Strata](https://github.com/norbertbonnici/Strata/tree/v0.2.0) | `v0.2.0`, `c2b587a5aee921f9d15268d79fd7abbf42a8a25f` | research reference; ไม่มี copied source/binary |

Autopsy มี [Apache 2.0 license](https://github.com/sleuthkit/autopsy/blob/autopsy-4.23.1/LICENSE-2.0.txt) แต่ dependency แต่ละตัวต้องตรวจแยก หากจะคัดลอกส่วนใดจาก Strata ต้อง resolve exact-revision license และ attribution ก่อน ไม่มีข้อสรุปเรื่องสิทธิการนำโค้ดดังกล่าวมารวมจากการที่ repository เปิดอ่านได้เพียงอย่างเดียว

## Dependency candidates สำหรับ phase ถัดไป

| Component | Phase | ข้อมูล license/provenance ที่ต้องตรวจ |
|---|---|---|
| [PhotoRec](https://www.cgsecurity.org/wiki/PhotoRec) | 2 | ผู้ผลิตระบุ GPL v2 or later; retain source/provenance/notices ของ build ที่เลือก และตรวจรูปแบบ integration/distribution ก่อน bundling |
| SQLite และ FTS5 | 1/2 | เลือก system หรือ pinned implementation แล้วบันทึก exact provenance และ notices |
| Document extractors และ preview codecs | 2 | ยังไม่เลือก; เปรียบเทียบ coverage/security/performance และ inventory licenses ก่อนเพิ่ม |
| APFS/FileVault tooling | 3 | ยังไม่เลือก; exact supported APIs, revision, patches และ license inventory พร้อม encrypted-image validation |

[TSK license inventory](https://github.com/sleuthkit/sleuthkit/blob/sleuthkit-4.15.0/licenses/README.md) แสดงว่าไม่ควรใช้ label เดียวแทนทั้ง toolkit สัญญา helper process เป็นการตัดสินใจทางเทคนิค ไม่ใช่ข้อสรุปว่าการแยก process เปลี่ยน license obligations

## Gate ก่อนรวม source หรือแจก binary

สำหรับ dependency ใหม่ทุกตัว ให้บันทึกชื่อ/version/revision, upstream URL, archive SHA-256, exact license files และ copyright notices, patch provenance, build flags, enabled optional components, linking/invocation mode และ native closure

เก็บ upstream notices และ source availability ตามเงื่อนไขของ component ที่นำมารวม แยก original project code ออกจาก upstream modifications ใน inventory ตรวจ license compatibility และข้อกำหนดของรูปแบบ distribution จริงก่อนออก build ที่แจกได้ บันทึกนี้เป็นแผน inventory และ attribution ไม่ใช่ legal opinion หรือการอนุญาต blanket reuse

## Phase 1 native helper ที่รวมแล้ว

[`NativeEngine/dependencies.json`](NativeEngine/dependencies.json) pin version, source URL และ SHA-256 ของ dependency ที่ใช้ `script/build_native_engine.py` ดาวน์โหลดเข้า `.engine/downloads/` (ไม่ commit binary/source tarballs) และตรวจ checksum ก่อนใช้ Generated TSK `configure` ถูกปรับเฉพาะ 4 บรรทัดที่ inject Homebrew/`/usr/local` include/link paths โดย script เพื่อให้ค้น dependency จาก SDK และ owned prefix เท่านั้น; source modifications ทั้งสี่รายการอยู่ใน dependency specification ได้แก่ exFAT offsets, FAT 64-bit years, explicit EWF segments และ [one-line EWF adapter compatibility patch](NativeEngine/patches/ewf-20240506-read-api.patch) ที่ระบุใน pinned specification (`read_random` alias → current `read_buffer_at_offset` API ของ libewf 20240506) Build ใน private temporary worktree แล้ว publish ผลลง `.engine/prefix/` เพื่อรองรับ checkout และ SDK paths ที่มีช่องว่าง Build ด้วย installed Xcode toolchain ตั้ง deployment target macOS 14.0; จำกัด parallel build สูงสุด 4 jobs และตรวจว่า helper มี dynamic dependencies เฉพาะ system libraries

| Component | Linking / enabled components | Upstream notices ที่เก็บ |
|---|---|---|
| The Sleuth Kit 4.15.0 + four recorded patches | static `libtsk`; RAW/EWF; ไม่รวม Java/NetBeans, AFFLIB, libvhdi, libvmdk, libvslvm หรือ toolkit command-line executables | [upstream license inventory](NativeEngine/licenses/sleuthkit/README.md) และ exact license texts ใน directory เดียวกัน; IPL/CPL และ file-specific notices ไม่ใช่ blanket Apache label |
| libewf 20240506 experimental release | static `libewf` รวม libyal support libraries ของ tarball เดียวกัน; system zlib/bzip2; OpenSSL, FUSE, Python disabled; ewf tools สำหรับ synthetic integration tests อยู่ใน build cache | [LGPL v3](NativeEngine/licenses/libewf/COPYING.LESSER), [GPL v3 incorporated terms](NativeEngine/licenses/libewf/COPYING), [AUTHORS](NativeEngine/licenses/libewf/AUTHORS); headers/source retain component copyright notices |
| nlohmann/json 3.11.3 | single C++ header from exact tag; no runtime dynamic dependency | [MIT license and copyright](NativeEngine/licenses/nlohmann-json/LICENSE.MIT) |
| CommonCrypto, libc++, zlib, bzip2, iconv, CoreFoundation | macOS system implementation; system binaries are not copied into the helper bundle | SDK/system runtime, not redistributed dependencies |

SHA-256 values are in the pinned specification. `.engine/manifest.json` records actual helper digest, architecture, toolchain, aggregate digest ของ applied patch list (exFAT, EWF API, FAT 64-bit year range และ explicit EWF segments) พร้อม SHA ของแต่ละ patch, static dependency fingerprints and dynamic closure. `.engine/licenses/` copies the retained notices for app packaging. Generic compiled TSK filesystem support does not prove correctness or full format coverage; only capability tests justify advertised formats.

Static linking of LGPL libewf requires retaining source and the ability to relink a distributed helper with a modified libewf, in addition to notices. The build keeps `.engine/relink/NFTSKEngine.o`, both static archives, `link-command.json` and a portable `Relink.command`, plus the exact downloaded source tarballs. Before external binary distribution, provide these artifacts, corresponding source/patches, relevant notices, and the runnable `Relink.command` recipe. This local development build and a private source push do not by themselves complete that distribution package.

The exFAT patch is a separately identified upstream modification. Original NativeForensics code remains separate from third-party components, and build-time libewf tools are not packaged as application features. The dependency license inventory above describes this concrete configuration; it does not assert one license applies to all TSK source or all future integrations.

Phase 1 retains the [64-bit FAT year-range patch](NativeEngine/patches/fat-64-bit-year-range.patch), correcting the upstream 2037 truncation on macOS `time_t` while preserving its historical 32-bit fallback. FAT DOS years 1980–2107 are representable on this 64-bit host; the patch does not repair or write an evidence image.

The [explicit EWF-segments patch](NativeEngine/patches/ewf-explicit-segments.patch) disables upstream single-path convenience globbing in this local TSK build. The helper supplies the complete ordered segment list after preflight; even a single EWF file must use exactly the selected path, without reading unselected siblings or depending on its extension. Generic TSK command-line tools are not built/bundled with this changed behavior.

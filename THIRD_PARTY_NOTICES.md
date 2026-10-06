# Dependency provenance และ third party notices

Foundation นี้เป็น private project code ยังไม่ได้เลือก blanket open-source license สำหรับโค้ดใหม่ และไม่ได้คัดลอก Autopsy หรือ Strata source/binaries เข้ามา การเลือกชื่อโครงการหรือ repository visibility ไม่เปลี่ยน license ของ dependency ที่ใช้ภายหลัง

Repository เก็บ [exFAT UTC-offset patch](patches/sleuthkit/exfat-utc-offset.patch) สำหรับ TSK 4.15.0 เป็น reproducibility artifact ของงานแก้ที่ตรวจมาก่อน ไม่ใช่ vendored toolkit หรือ compiled engine SHA-256 คือ `fe17dab7a4f83f774eb9b4992801033131e66bf9579e91bc0e5aa5a5309613cf` Patch มีบริบทของ upstream file; การ build/distribute TSK ที่แก้แล้วต้องรักษา provenance และ upstream notices ตาม exact component ที่รวม Phase 0 ไม่ได้ใช้ TSK runtime

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

## Dependency candidates ที่ยังไม่รวม

| Component | Phase | ข้อมูล license/provenance ที่ต้องตรวจ |
|---|---|---|
| [The Sleuth Kit 4.15.0](https://github.com/sleuthkit/sleuthkit/tree/sleuthkit-4.15.0) พร้อม exFAT patch | 1 | upstream license inventory มี IPL/CPL และ notices รายส่วน รวม Apache 2.0, BSD, MIT, public-domain และ file-specific terms; ตรวจ exact linked/compiled files และ tools |
| Optional image libraries เช่น libewf | 1 | pin revision/config และ inventory licenses รวม transitive dependency ตาม build ที่เปิดใช้ |
| [PhotoRec](https://www.cgsecurity.org/wiki/PhotoRec) | 2 | ผู้ผลิตระบุ GPL v2 or later; retain source/provenance/notices ของ build ที่เลือก และตรวจรูปแบบ integration/distribution ก่อน bundling |
| SQLite และ FTS5 | 1/2 | เลือก system หรือ pinned implementation แล้วบันทึก exact provenance และ notices |
| Document extractors และ preview codecs | 2 | ยังไม่เลือก; เปรียบเทียบ coverage/security/performance และ inventory licenses ก่อนเพิ่ม |
| APFS/FileVault tooling | 3 | ยังไม่เลือก; exact supported APIs, revision, patches และ license inventory พร้อม encrypted-image validation |

[TSK license inventory](https://github.com/sleuthkit/sleuthkit/blob/sleuthkit-4.15.0/licenses/README.md) แสดงว่าไม่ควรใช้ label เดียวแทนทั้ง toolkit สัญญา helper process เป็นการตัดสินใจทางเทคนิค ไม่ใช่ข้อสรุปว่าการแยก process เปลี่ยน license obligations

## Gate ก่อนรวม source หรือแจก binary

สำหรับ dependency ใหม่ทุกตัว ให้บันทึกชื่อ/version/revision, upstream URL, archive SHA-256, exact license files และ copyright notices, patch provenance, build flags, enabled optional components, linking/invocation mode และ native closure

เก็บ upstream notices และ source availability ตามเงื่อนไขของ component ที่นำมารวม แยก original project code ออกจาก upstream modifications ใน inventory ตรวจ license compatibility และข้อกำหนดของรูปแบบ distribution จริงก่อนออก build ที่แจกได้ บันทึกนี้เป็นแผน inventory และ attribution ไม่ใช่ legal opinion หรือการอนุญาต blanket reuse

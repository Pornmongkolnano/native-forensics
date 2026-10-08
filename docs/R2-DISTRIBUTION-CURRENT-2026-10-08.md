# R2 local distribution acceptance — 8 October 2026

The local source/material/rebuild/relink/system-installer gates passed for the **D 0.7.0/build 16 development candidate** on Apple M2/macOS 27.0.1. Root executed the gates; a separate read-only audit checked retained reports and actual artifact bytes. This closes the executed local R2 scope in [the completion audit](GOAL-COMPLETION.md), while release trust, target machines and the full roadmap remain separate requirements. These receipts do not certify later source changes.

## Exact candidate and material correspondence

Verified v2 ZIP: **25,504,203 bytes**, SHA-256
`59d1600f7230e21830cdffc487754c57afb89ed5491e0e39ecd67ee7997173be`.

Its unchanged repack matches every byte and mode. It contains **511 members = 431 files + 80 directories**, with **429 payload files** in the outer manifest. The read-only audit checked every member, complete file inventory/SHA256SUMS, normalized permissions, fixed timestamps and absence of extra host ZIP records. No `.pyc` or `__pycache__` exists in the pristine v2 package.

The extracted app's **27 files / 43,340,702 bytes** exactly match D's bytes and modes. Source contains **378 files / 14,864,830 bytes**; all original inputs retain the same bytes and modes in the isolated rebuild root after the builds. Pinned dependency archives, five recorded patches, CPP/two-header capture, licenses/notices, retained object/static archives/Relink.command, portable system-link arguments and the original-link digest agree with the embedded receipts. Input container/derived/hash scopes were not weakened.

InstallSupport's source digest is `d4dbc45a518880a2cb523b50d079682215bec59b03fa912f84326ab5ef670f31`; its final builder digest is `664a56f4916513f3a80047890be62c2cdd40acfc527cd593d675c37878450ebc`. The independently hashed signed publisher is `85134f8f08dbcf65603d13de07ae87a7de968a0f08c66b91c5deeab51650539a`. Its recorded raw pre-sign digest, `44b4e67e8ee47df94c0fc5d374fea3cacfa1b757fc4723266ec69fbaba07a912`, remains build-receipt evidence; the audit did not have separately retained pre-sign publisher bytes.

## Actual extracted-source build and relink

Root seeded a new engine cache from the included archives, rebuilt the static dependencies/helper with `Rebuild-engine.command --jobs 4`, then built all four Swift products with `build_and_run.sh --build-only`. The pre-build copy receipt records no borrowed `.engine` or `.build`; that initial absence is recorded evidence, not reconstructed after those directories were generated. The current builder has no network-denial/`--offline` option: included cached archives avoid its input-download branch, which is narrower than an air-gap claim.

All four raw products match their pre-sign build-input receipt, and their source graph hashes match shipped D. The freshly staged release app passed Root's architecture/minimum/runtime-closure/signature/full-byte privacy/source-root validator. Rebuilt Swift executable hashes differ from shipped D, so graph correspondence is not byte-identical compiler reproducibility.

| Product | Inputs | Complete source graph SHA-256 |
|---|---:|---|
| App | 207 | `ca4c4b89129ee79549f28b865018afd58511637d6eea06d7ac2c50e32b707325` |
| CLI decoder | 123 | `55329fd0fd29d3e144dad12fabbef1d7bec1ce9eb58db342c7e57db974e20a59` |
| XPC broker | 117 | `8ca01152c747a899afc8975f8a3894d1d454aad1c31d9a95cd15909723b77561` |
| Parser worker | 123 | `d9b417d556a70bb3674d291587e1a198cce2e10dbeba84930889a34a885cf485` |

The new native helper is byte-identical to D's helper, SHA-256 `d200a9e1b764bf53781d1553a36a0c0168cabbe869db256c03408a49ddcb7a46`, engine `0.1.5-tsk4.15.0`. Its actual independent native corpus passed **196 checks / 0 failures / 0 warnings**. The final executed runner check verifies its original source set and unchanged helper; the audit matched report/log counts and the tested helper's current bytes.

An isolated copy of the shipped retained objects/static archives actually linked an ARM64/minimum-macOS-14 helper, with Root's system-only closure and strict signature checks passing. Its SHA-256 is `242adf60d54f15a966e6eec23af218323109b1b91aeaffa840e0f73753499393`; the original five relink inputs stayed unchanged. This relinked helper separately passed **196/0/0** native checks and **31/31** actual synthetic EFS checks. Four retained plaintext outputs match their reported complete size/digest. Separate observer processes checked zero certificate/key counts for **four generated identities** before and after the EFS matrix; this does not claim observation of the entire Keychain. Raw per-observer output is not retained in the aggregate report. The matrix explicitly does not establish Windows interoperability; other EFS evidence remains in [its own scope](EFS-KEY-PIPELINE.md).

These helper corpora establish their declared synthetic behavior, not full Autopsy module parity or every media/filesystem profile. The relinked artifact was not substituted into the sealed shipped app.

## Actual packaged installer and preserved artifacts

Root ran the real v2 `Install.command` with macOS system tools in separately owned temporary destinations. The actual app copies were not launched through this installer gate.

| Operation | Natural exit | Observed result |
|---|---:|---|
| Verify only | 0 | Full package verification; no target/stage creation |
| Fresh install | 0 | All 27 D files match packaged bytes/hashes/modes |
| Existing app without replacement | 1 | Expected refusal; target preserved |
| Explicit replacement | 0 | D target matches; backup matches the prior 27-file D app |
| 0.6/build 15 → D replacement | 0 | D target matches; backup matches all 22 old-app files |

Acceptance/progress/stdout publisher receipts and actual target/backup inventories agree. All three successful stage diagnostics identify retained real empty directories; no normal publisher lock remains. The audit confirms neighbor content and strict identity, and all **431 pristine package files / 63,546,923 bytes** retain recorded hashes/modes/identities. Backup roots are distinct from current target inodes; pre-replacement app inode baselines were not persisted, so exact original-inode retention is not separately established here.

The preserved 0.6 rollback ZIP remains **18,062,250 bytes**, SHA-256 `5fcd59748adee7b7689e5f82b8d50d3b93d4026c7f0d764214a2aa54b4c7ec8e`. Existing user evidence, cases and Autopsy were not selected by these gates.

Root's final eight-module Python gate passed **217 tests in 24.946 seconds**, including the separate **20 synthetic installer/publisher tests**. Publication ENOSPC and rollback EACCES shims remain test-only; they were not injected into the actual packaged D transaction. The unchanged publisher uses two exclusive renames and retains uncertain recovery copies. Ordinary install/replacement and these synthetic fault tests do not establish SIGKILL/power-loss recovery or arbitrary concurrent publication safety.

## Preserved failures and remaining boundaries

The first actual package/extraction passed, but its generated repack launcher used plain Python and created three bytecache files. Repack correctly rejected the changed inventory with exit 1. The fix uses `python3 -B`; a generated-launcher test imports a private synthetic module and checks no cache, with a plain-Python control that creates `.pyc`. Root's narrow two-test gate passed before fresh publisher capture/v2 packaging. The failed first extraction and outputs were retained; inventory enforcement was not relaxed.

The first installer harness recorded expected **0/0/1/0** operation results and matching app/backup bytes, then incorrectly compared the neighbor's whole stat tuple, including access time changed by hashing. The retained v2 harness excludes only read-sensitive access time; content plus device/inode/size/mtime/ctime remain strict. The original failure/progress/stdout/stderr remain evidence. The original relink validator JSON containing `null` from a void-return function is also retained alongside the corrected runtime receipt.

Ignored byte/metadata/final audit receipts retain detailed inputs, read-only hashing identities, output paths and natural-execution evidence; they are kept outside Git. They distinguish Root's executed gates from independent hash/parse review. No reviewer re-ran compilers, native helpers, signature tools, tests or UI actions during this audit.

The candidate remains **ad hoc development output** with a declared macOS 14 minimum. Developer ID/notarization/Gatekeeper trust, clean-machine/older-macOS/physical-M5 validation, source-license choice, final current app/XPC/GUI acceptance and the full goal remain separate. This local R2 result neither supplies an original-code license grant nor turns the candidate into a trusted public release. [Distribution instructions](DISTRIBUTION.md) preserve those boundaries.

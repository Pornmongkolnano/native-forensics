# Executed local PDF decoder acceptance — 8 October 2026

**The two scoped PDF runtime gates passed on the signed E development bundle, version 0.7.1/build 17.** The coordinator executed the actual bundled application and its embedded production XPC decoder. A subsequent independent audit read the retained artifacts, recomputed full hashes and checked their correspondence without rerunning a decoder, generator, signer or test.

This is a correctness receipt. It reports no benchmark, GUI, provider or CI result and does not establish trusted distribution or completion of the full roadmap.

## Executed inputs and outcomes

| Gate | Actual input | Result |
|---|---|---|
| `production-locked-pdf` | 1,806-byte PDF 1.6 with Standard security, V4/R4, AESV2/AES-128 and nonempty public synthetic user/owner passwords | Schema 2 PDF analysis, status `failed`, failure code `LOCKED_PDF`; empty text pages, metadata and warnings; no title, page count or thumbnail. No password was submitted to the application. |
| `production-unicode-pdf` | 1,527-byte, two-page PDF 1.4 with a fixed explicit `ToUnicode` CMap | Schema 2 `decoded` PDF, exactly two complete pages with `Page 1`/`Page 2` references and `referenceKind=page`; exact UTF-8 and raw UTF-16 output, without normalization or trimming. |

The fixture preparation receipt records pypdf 6.10.0 and cryptography 50.0.2. Its separate 1,272-byte plaintext control contains exactly `NF LOCK CONTROL` on one page. Preparation verified rejection of an empty password and an unopened-page read, then verified the known public fixture password against that exact plaintext control. The audit confirmed the encrypted dictionary and byte bindings; it did not perform another decryption. The public test passwords are constants in the [fixture recipe](../Tests/Runtime/run_pdf_runtime_gates.py), not user credentials.

| Fixture | Full SHA-256 |
|---|---|
| `locked.pdf` | `549a42872e5ef24ddf0cac06de47e7db6f301567e9d617ef377a46b33c6664da` |
| `locked-control.pdf` | `8642f6edd41808e095aacc4ca086a39b1713f1f309fcd6c01549623016f49246` |
| `unicode.pdf` | `43b19aaf9970e1d043db1d738c00382b2ee15f200b591d5adf2d9511a37eca49` |

## Exact Unicode scope

The page literals are `A😀ก้e\u0301Z` and `Bก้😀e\u0301Y`, where `\u0301` denotes the separate combining acute scalar following `e`. Each actual page contains **15 UTF-8 bytes and 8 UTF-16 code units**. The audited raw UTF-16LE bytes are:

| Page | UTF-16LE hex |
|---|---|
| 1 | `41003dd800de010e490e650001035a00` |
| 2 | `4200010e490e3dd800de650001035900` |

All twelve fixed slices matched the corresponding literal bytes:

| Literal | Page 1 offset/length | Page 2 offset/length |
|---|---:|---:|
| `😀` | 1 / 2 | 3 / 2 |
| `ก` | 3 / 1 | 1 / 1 |
| `้` | 4 / 1 | 2 / 1 |
| `e` + U+0301 | 5 / 2 | 5 / 2 |
| U+0301 | 6 / 1 | 6 / 1 |
| Terminal `Z` / `Y` | 7 / 1 | 7 / 1 |

These are zero-based offsets in **derived page text**, not original PDF byte positions. The Python oracle verifies fixed slices of actual decoder output; the bundled diagnostic does not return production search coordinates. The controlled CMap uses standard Helvetica proxy glyphs, so this result does not prove visual Thai/emoji shaping, font fallback or OCR. It does not certify every Unicode or encrypted PDF profile.

## Runtime ownership and provenance

Both natural host invocations returned 0. Each raw report contains one accepted worker start and its matching, ordered exit event, with no transport error. The two requests used distinct worker PIDs. For each request an independent `EVFILT_PROC/NOTE_EXIT` observation matched the accepted PID, the signed worker path and the separately sampled PID/PPID/start identity. This was normal production decoding: no substitute worker, re-signing, worker/broker signal or hidden-service invocation was used.

The schema 2 analyses bind decoder `NativeForensics.document-decoder` version 2.1.0, `appSandboxXPC` isolation and the exact worker/broker executable hashes and recorded CodeDirectory hashes. Their options and complete derived-text digests were independently recomputed. The declared limits remained 128 MiB input, 2 MiB response, 1 MiB extracted text, 200 pages and a 12-second timeout; `includesOCR` and `fetchesExternalResources` remained false. These policy limits are not an operating-system memory-limit measurement.

| Executed E role | Full signed executable SHA-256 |
|---|---|
| Application host | `a3fea4ee264e85148a660f0fec42d3739672f6dc584cabaa0be97a68dfa63b74` |
| XPC broker | `3f6a47a43e5d40cd3fab992ef24d01674ddb16c02914c0e1dfa9069c096fade9` |
| Parser worker | `fa7d768634309e3f9ebca687a3308192ce11d25ddd67e30a91ff470c6abdec9c` |

The locked result's derived-text digest is `4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945`, the canonical empty page array. The Unicode result's full page-array digest is `7df988cf31c843dd72fb5ebd59683dea06464f64569bfd35c1466475649a747a`. A bounded re-encoded PNG thumbnail was present for the decoded PDF; no visual-layout acceptance is claimed here.

## Preservation and retained evidence

The executed harness compared full source-app and runtime-copy inventories before and after both requests. It reported all three synthetic inputs unchanged. The independent audit then compared **all 27 app files / 43,793,529 bytes**, including signatures, resources and manifests, between the retained runtime copy and source E bundle; full bytes, hashes and modes matched. All three fixture files still matched the recorded before-run device/inode/size/mtime/ctime and full SHA-256 values.

The pre-run app inventories were held in memory rather than saved as separate artifacts. Their during-run identity preservation is therefore supported by the executed harness and its frozen source; the later audit independently proves current full byte/mode correspondence and does not reconstruct every pre-run app inode or timestamp.

Ignored local evidence retains `fixture-controls.json`, both raw host JSON/stderr files, both `.process-attempt.json` and `.driver.json` receipts, the final `summary.json`, all input PDFs and the signed application copy. Raw process/driver `oracleStatus=pending` is intentional: those records were saved before semantic validation. The final summary separately records both semantic and complete oracle results as passed, `complete=true` and exit status 0.

| Evidence binding | SHA-256 |
|---|---|
| Executed final summary | `45ca4dc9c6a86ea5147aaa789133d264a37bcf36aad01af43c8365187f211244` |
| Independent read-only audit | `33986458c1d52f2de59de8c22d10a44ef3a225765374686e320b1633ea8365b0` |
| Executed PDF gate recipe | `891f082c4d0e2869f04c01db48a27ee30f5b6584422bca28b02d5120d183f015` |
| Shared runtime observation recipe | `a1f1f8f40733f615610763b3175e825535cd79f63928f56da35999c9525d400e` |

The earlier unexecuted harness plan and frozen-D eight-fixture acceptance retain their original scopes. They are not retagged as this E run, and the earlier D fixture set is not evidence for this AES-128 encrypted input or this exact Unicode CMap. Historical locked-PDF receipts, [frozen-D distribution acceptance](R2-DISTRIBUTION-CURRENT-2026-10-08.md) and broader [XPC runtime evidence](XPC-RUNTIME-CURRENT-2026-10-08.md) remain separate. No user/course PDF or case was read or modified by these gates. Clean-machine/M5/older-system coverage, trust/notarization, general format coverage and the remaining roadmap gates stay outside this receipt.

## F18 follow-up — 9 October 2026

Both gates also passed on **F, 0.7.1/build 18**, with host exit 0, distinct accepted workers and one matching kernel-exit observation each. Locked refusal, both exact Unicode pages and all twelve UTF-16 spans were independently audited against retained raw reports. All three fixtures matched their full recorded stat/hash baselines. All **27 source-app files / 43,793,417 bytes** still matched the separately persisted pre-run F inventory, including identities, hashes and modes; the runtime copy matched full bytes/modes. Its own pre-run full stat inventory remains an in-memory harness check.

Summary SHA-256: `6255ed52d07a7a682429dcae122568571646c08876ab27d17448d40c340d8098`. Independent F audit: `d2d35afdd9b8ddd1a81440c9afd42a0b353acdf8ffb9fa3c1efc79480cd44629`. The original E document digest, **before this append**, was `a8ef034a37b671a6bf75e1be92b73f097915c8493151bce1331145c4ef82a2bb`; it is historical. Earlier scope limits remain unchanged.

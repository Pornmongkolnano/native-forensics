# Distribution validation — 8 October 2026

The new distribution workflow closes locally repeatable source/relink inventory,
deterministic ZIP generation and safe installer transaction gates. It does not
claim a trusted public release, a clean-machine GUI pass or physical M5 coverage.

Command:

```sh
PYTHONPATH=Tests/NativeEngine python3 -m unittest test_native_distribution -v
```

**34 distribution tests passed**, plus **13 bundle tests** (47 affected tests), on
local Apple Silicon/macOS 27 using temporary synthetic
artifacts, including an actual ad hoc signed minimal app and the actual zsh
installer. Tests cover pinned source/patch/object/build-recipe mismatch, complete
archive hashes/inventory, extra or changed file rejection, preserved existing
output, deterministic archive bytes after file timestamp changes, executable
permissions, release rejection for ad hoc signing, clean install, explicit
replacement with original backup, symlink/ancestor/overlap/ownership/permission
and concurrent lock refusal. A test-only compiled syscall shim simulates ENOSPC
at publication and EACCES at rollback; the original application is restored or
retained at the reported recovery path. No production failure/bypass flag exists.

Additional source-provenance tests cover app Swift, SQLite shim/modulemap,
Package.swift, build/package recipes and icon-input mutations; added/missing
relevant inputs; required input omissions; app/decoder shared-graph disagreement;
source changes between pre-compilation snapshot and sealing; post-compilation
binary changes; absolute/traversal paths and malformed graph digests. Explicit
legacy development inspection remains available, but cannot bypass current
0.6.0 bundle or distribution graph requirements.
Independent review identified late engine/installer source-copy races. The final
implementation pins corresponding engine input hashes at fingerprint validation,
checks them while copying, recomputes the copied engine fingerprint, compiles the
installer C from captured bytes and checks its shipped source against that digest.
Regression tests reject those late edits and extra dependency license inputs.
Three further privacy tests enforce full-byte cross-chunk detection, refusal to
distribute local debug bundles, and standard release debug-map removal while
preserving raw build bytes. A runtime path literal remains blocked after stripping.

Read-only identity inspection found **0 valid codesigning identities**. The app
available at that inspection was ad hoc signed. Developer ID, notarization,
stapling/Gatekeeper acceptance, fresh-machine GUI launch and physical M5
measurements remain separate prerequisites. The development installer uses only
system tools and never removes quarantine or changes Gatekeeper policy.

## Final 0.6.0 / build 15 artifact

The first complete-graph app was packaged twice independently. Both runs produced
the same **18,495,478-byte** ZIP with 283 inventoried payload files:

`bb7923be65d2f0a2a51d6d79cc8eeef839a899c773ecd0ecedd28c3c07d41d8e`

The output is `dist/NativeForensics-0.6.0-development-arm64.zip` with a SHA-256
sidecar. Exact source inputs, pinned archives/patches/licenses and static relink
materials accompany the app. A system-ditto extraction passed complete copied
source graph, nested signature/runtime closure and full file-hash validation.
The real installer passed `--verify-only`, fresh installation and explicit
replacement into an owned ignored scratch directory. Installed app bytes/modes
match the packaged app; the retained backup matches the previous app. No owned
stage or lock was left. The installed copy was validated without launching a
second GUI; root's separate GUI flow uses the final built bundle.

Graph digests:

- App: `066d0550a1b1cee93da81e77a1fa0ee121a12f0dc5329efd3607c4a4537a6d44`
- Decoder: `165100bf61cc6b9fc89623c9e89f1110c92d631f455d8b4acdba23d0b58d1776`

Fresh final retained materials linked an ARM64 helper with strict signature and
system-only dynamic closure. Its full native corpus passed **114 checks / 0
failures**, with all original synthetic source hashes unchanged. Relinked helper
SHA-256: `17394da21bca6dc0804f7008083f070e08e5e738a63d7618066ec3b7225c9467`.
This is relink usability/correctness within that corpus, not broad format parity.
An archive-member audit found personal host/temp paths embedded in linker
STABS/N_OSO debug maps: 265 occurrences in the app and 143 in the decoder.
Standard `strip -S` on owned probe copies removed all occurrences, with no
remaining runtime path metadata. Final staging now binds that release-only
transform and audits all executable bytes before signing. A fresh build/package
is required; the ZIP above must not be presented as
privacy-gate-complete. No evidence, credential or unselected local report was
included by the explicit input recipe.

## Earlier pre-fix comparison

An initial local relink smoke of retained materials proved ARM64, system-only
dynamic closure, strict signature validity and identical complete protocol frames
for a bounded invalid-request probe. The following full native corpus run exposed
five failures in the pre-fix engine against the newly expanded NTFS corpus;
therefore that earlier run is **not** the final corpus pass. The final receipts
above supersede it after source integration and a normal engine/app build.
Build fingerprint and document source checks intentionally
reject the older bundle while corresponding source changes are in progress.

The original publisher source, dependency license/source/relink package content
and usage are documented in [Distribution](DISTRIBUTION.md). The exact final
artifact receipt lives alongside the generated ZIP or in ignored local output;
no user evidence, personal paths or test runtime artifacts are committed here.

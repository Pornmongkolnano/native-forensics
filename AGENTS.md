# NativeForensics

Build a native macOS evidence workbench. SwiftUI owns desktop state; narrow AppKit services own file/directory panels. The selected long-term filesystem engine is the audited Autopsy/Sleuth Kit lineage. Autopsy Java/NetBeans and Strata are research references, not bundled runtimes.

## Scope and safety

- Work in this repository only. Preserve the existing Autopsy installation and all existing coursework evidence/cases.
- Evidence sources are read-only. Store generated manifests, indexes and exports outside the source. Never modify a source image, repair it in place, or extract onto it.
- Only synthetic test data belongs in Git. Do not commit user evidence, cases, absolute personal paths, credentials, runtime binaries, build products or local reports containing them.
- Keep image-container file hashes distinct from logical/decompressed image hashes. Phase 0 hashes exactly the selected file's bytes.
- New code is private project code; retain separate dependency provenance and notices when reusing upstream code. Do not copy Strata/Autopsy source into this foundation.
- Do not publish, change repository visibility, invite collaborators, or distribute builds unless the user requests it. Initial private repository creation and push are authorized in this task.

## Layout and workflow

- `Sources/ForensicsCore`: pure Swift models, read-only inspection and case persistence.
- `Sources/NativeForensics`: desktop app, split into App, Views, Stores and Services.
- `Tests/ForensicsCoreTests`: meaningful synthetic correctness/safety regressions.
- `docs`: decision record, architecture, roadmap and benchmark method.
- Run `swift test` and `./script/build_and_run.sh --verify` before reporting a runnable scaffold. Use the `.app` bundle for GUI launch.
- Never imply Phase 0 provides filesystem enumeration, recovery, artifact parsing or full Autopsy parity. Those are tracked milestones.
- Keep commits cohesive and verify the GitHub repository is private before every initial push.

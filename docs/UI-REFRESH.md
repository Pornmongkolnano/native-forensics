# NativeForensics 0.2.4 — native evidence workbench

The layout follows Autopsy's familiar source navigation, result listing and lower selection area, using native macOS toolbars, source lists, tables and an inspector. The right inspector separates Properties from Integrity. The lower area summarizes recorded metadata; it does not imply an implemented text, hex or media preview. [Autopsy UI layout reference](https://sleuthkit.org/autopsy/docs/user-docs/4.19.1/uilayout_page.html).

Data Sources lists the actual evidence records. Selecting a source opens its saved filesystem; All Data Sources returns to the evidence overview. File Views filters the selected source into All Files, Deleted Files, Documents, Images, Archives, and Audio & Video. These are filename-extension hints, not content identification. NTFS DATA streams use the base filename for the hint while ordinary colon-containing filenames remain unchanged.

The existing background search now composes the category and Unicode query in one cancellable scan. Publication retains generation, case, source, query and category guards. Busy operations cannot switch sources, and hidden selections cannot remain extractable. The All Files empty-query snapshot path and 100-entry presentation limit remain.

The original hound-and-magnifier artwork uses navy, amber and teal. PNG/ICNS assets and the reproducible AppKit drawing script are in `Assets/AppIcon` and `script/generate_app_icon.swift`. It is new artwork for NativeForensics. The bundle uses `CFBundleIconFile=AppIcon`, version 0.2.4/build 6, and explicitly sets its application icon on launch. ICNS includes ten representations from 16 to 1024 pixels.

Settings offers System, Light and Dark appearances for the app. Sidebars and toolbars keep system backgrounds. The inspector is hidden on the welcome screen. Selected table icons, path captions and allocation labels use the system selected-control text color for contrast.

Validation on this M2:

- Swift debug and release: 55 tests per configuration (45 core and 10 workspace tests). New navigation tests cover stale category/query publication, source changes, busy guards, Unicode matching and NTFS stream hints.
- Optimized bundle build/launch and strict signature verification passed. Packaged ICNS matches the committed artwork, and the packaged helper remains byte-identical to the pinned engine.
- The saved FAT16 case was opened in the actual app. Data Source navigation, Deleted Files, Documents plus path search, file selection, raw timestamps and Integrity hash scopes were observed.
- Light and Dark workbench appearances were viewed. The selected-row contrast fix was checked in Light. The app preference was restored to System after the checks.
- The explicitly synthetic 50,000-entry UI cache displayed its partial/synthetic warnings. First, next and last pages showed ranges 1–100, 101–200 and 49,901–50,000. Selecting a last-page entry updated the lower strip and inspector. This cache is UI stress data, not engine output.
- Resizing the real window to approximately 1055 × 712 logical pixels retained all table columns, page controls, selected-file strip and inspector. This is a usability check, not a latency or RAM benchmark.

Evidence parsing, extraction, source verification, case schema and the engine were not changed by this visual update. No new whole-app performance claim is made from the appearance changes.

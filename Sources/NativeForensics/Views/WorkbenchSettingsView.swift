import SwiftUI

struct WorkbenchSettingsView: View {
    @AppStorage("workbenchAppearance") private var appearance = "system"
    @AppStorage("codexCLIPath") private var codexCLIPath = CodexCLIAvailability.defaultPath

    var body: some View {
        Form {
            Section {
                Picker("Appearance", selection: $appearance) {
                    Text("System").tag("system")
                    Text("Light").tag("light")
                    Text("Dark").tag("dark")
                }
                .pickerStyle(.segmented)
                Text("Follow macOS, or choose an appearance for this workbench.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } header: {
                Text("Appearance")
            }
            Section("Analysis scope") {
                Text("Filesystem listing and extraction for RAW/EWF images. FAT16, FAT32, exFAT and NTFS are covered by synthetic tests.")
                Text("Local text/hex previews support files up to 1 MiB, showing up to 32 KiB. Examiner notes, bookmarks, saved AI analyses and export history are stored separately from evidence.")
                    .foregroundStyle(.secondary)
                Text("File Views use filename hints. Verified document previews inspect supported image, PDF, text, ZIP and Office content locally. Search covers decoded text in the selected file; partial text is labeled.")
                    .foregroundStyle(.secondary)
                Text("Recovery uses a separately installed PhotoRec executable for one RAW image. Optical History supports a bounded UDF 2.01 VAT profile. APFS, FileVault, OCR and computer activity artifacts remain unavailable. Deleted-file contents may have been overwritten.")
                    .foregroundStyle(.secondary)
            }
            Section("Codex file analysis") {
                TextField("Installed CLI path", text: $codexCLIPath)
                    .textFieldStyle(.roundedBorder)
                Text("Tested with Codex CLI 0.160.1. Sign in separately with codex login; compatibility must be checked after CLI upgrades. A reviewed question and optional text excerpt are sent to OpenAI only when you choose Send to Codex.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                if let issue = CodexCLIAvailability.issue(for: codexCLIPath) {
                    Text(issue).font(.caption).foregroundStyle(.orange)
                }
            }
            Section {
                LabeledContent("Version", value: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "Development")
                Text("Phase 1 · Development build, signed for local use. General distribution and clean-machine compatibility are not verified.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .frame(width: 480, height: 570)
    }
}
